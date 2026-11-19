"""CDK assertion tests for EnvaultStack.

The stack is synthesized in-process with the cdk-nag AwsSolutions pack applied,
as app.py does, and the CloudFormation template is inspected. Covered:

- M10: CloudWatch alarms can publish to the KMS-encrypted ops topic.
- L9: account-regional bucket names, and the opt-out for existing stacks.
- L10: validation of ``additional_kms_key_arns`` and the statements it feeds.
- M6: the HMAC key that names files, its alias, and the MAC grant on it alone.
- cdk-nag: no unsuppressed findings, and IAM5 suppressions are scoped.

These run in CI's cdk-synth job from infra/cdk/ (``python -m pytest``) and are
not collected by ``pytest tests/unit``.
"""

from __future__ import annotations

import copy
import fnmatch
import re
from pathlib import Path
from typing import Any

import aws_cdk as cdk
import pytest
from aws_cdk import aws_iam as iam
from aws_cdk.assertions import Annotations, Match, Template
from cdk_nag import AwsSolutionsChecks
from stacks import envault_stack

ACCOUNT = "111122223333"
REGION = "eu-west-1"
PSEUDO_PARAMETERS = {
    "AWS::Partition": "aws",
    "AWS::Region": REGION,
    "AWS::AccountId": ACCOUNT,
    "AWS::URLSuffix": "amazonaws.com",
}

# Logical IDs that must never change. The retained resources hold the data:
# a new logical ID makes CloudFormation create a replacement and orphan the
# original (and every S3 VersionId pinned in DynamoDB). Replacing the topic or
# its subscription would drop the confirmed alert email subscription.
DATA_KEY = "EnvaultKeyBB09333A"
# Every keyed record stores this key's ARN and is verified against it: a
# replacement key would leave all of them unverifiable.
ID_KEY = "EnvaultIdKey595DF692"
DATA_BUCKET = "EnvaultBucketE28C9184"
LOGS_BUCKET = "EnvaultAccessLogsBucket0E6D48BE"
STATE_TABLE = "EnvaultStateTableC0CCED58"
OPS_TOPIC = "EnvaultOpsTopic959F0C23"
RETAINED = {
    DATA_KEY: "AWS::KMS::Key",
    ID_KEY: "AWS::KMS::Key",
    DATA_BUCKET: "AWS::S3::Bucket",
    LOGS_BUCKET: "AWS::S3::Bucket",
    STATE_TABLE: "AWS::DynamoDB::Table",
}
NOT_REPLACED = {
    OPS_TOPIC: "AWS::SNS::Topic",
    "OpsTopicEmailSubscription": "AWS::SNS::Subscription",
    "EnvaultUserPolicy0F1FCA92": "AWS::IAM::ManagedPolicy",
}

CLOUDWATCH = "cloudwatch.amazonaws.com"
ALARM_SOURCE_ARN = f"arn:aws:cloudwatch:{REGION}:{ACCOUNT}:alarm:envault-*"

KEY_UUID = "1234abcd-12ab-34cd-56ef-1234567890ab"
KEY_ARN = f"arn:aws:kms:us-east-1:444455556666:key/{KEY_UUID}"
MRK_ARN = "arn:aws:kms:eu-west-1:444455556666:key/mrk-1234abcd12ab34cd56ef1234567890ab"

NAMING_PROPERTIES = ("BucketName", "BucketNamePrefix", "BucketNamespace")


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def synth(outdir: Path, context: dict[str, Any] | None = None) -> tuple[cdk.Stack, dict[str, Any]]:
    """Synthesize the stack like app.py does and return it with its template."""
    app = cdk.App(context=context or {}, outdir=str(outdir))
    cdk.Aspects.of(app).add(AwsSolutionsChecks())
    stack = envault_stack.EnvaultStack(app, "EnvaultStack")
    return stack, Template.from_stack(stack).to_json()


def resources(template: dict[str, Any], type_: str) -> dict[str, dict[str, Any]]:
    return {lid: r for lid, r in template["Resources"].items() if r["Type"] == type_}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def render(value: Any) -> str:
    """Render a CloudFormation expression to a string for assertions.

    Pseudo parameters become fixed example values; references to resources
    become ``<LogicalId>`` or ``<LogicalId.Attribute>``.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and len(value) == 1:
        ((fn, arg),) = value.items()
        if fn == "Ref":
            return PSEUDO_PARAMETERS.get(arg, f"<{arg}>")
        if fn == "Fn::GetAtt":
            return f"<{arg[0]}.{arg[1]}>"
        if fn == "Fn::Join":
            separator, parts = arg
            return separator.join(render(part) for part in parts)
    raise AssertionError(f"cannot render {value!r}")


def managed_policy_statements(template: dict[str, Any]) -> dict[str, dict[str, Any]]:
    (policy,) = resources(template, "AWS::IAM::ManagedPolicy").values()
    return {s["Sid"]: s for s in policy["Properties"]["PolicyDocument"]["Statement"]}


def cloudwatch_statements(statements: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [s for s in statements if s.get("Principal") == {"Service": CLOUDWATCH}]


def assert_alarm_conditions(statement: dict[str, Any]) -> None:
    """Confused-deputy guard: only CloudWatch alarms of this account, named envault-*."""
    condition = statement["Condition"]
    assert set(condition) == {"StringEquals", "ArnLike"}
    assert render(condition["StringEquals"]["aws:SourceAccount"]) == ACCOUNT
    assert render(condition["ArnLike"]["aws:SourceArn"]) == ALARM_SOURCE_ARN


def ops_topic_key_id(template: dict[str, Any]) -> str:
    topic = resources(template, "AWS::SNS::Topic")[OPS_TOPIC]
    key_ref = topic["Properties"]["KmsMasterKeyId"]
    assert set(key_ref) == {"Fn::GetAtt"} and key_ref["Fn::GetAtt"][1] == "Arn"
    return str(key_ref["Fn::GetAtt"][0])


@pytest.fixture(scope="module")
def default(tmp_path_factory: pytest.TempPathFactory) -> tuple[cdk.Stack, dict[str, Any]]:
    return synth(tmp_path_factory.mktemp("default"))


@pytest.fixture(scope="module")
def template(default: tuple[cdk.Stack, dict[str, Any]]) -> dict[str, Any]:
    return default[1]


# --------------------------------------------------------------------------- #
# Stability of existing deployments                                           #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("context", [{}, {"keep_generated_bucket_names": "true"}])
def test_stateful_resources_keep_their_logical_ids(tmp_path: Path, context: dict[str, Any]) -> None:
    _, tpl = synth(tmp_path, context)
    for logical_id, type_ in {**RETAINED, **NOT_REPLACED}.items():
        assert tpl["Resources"][logical_id]["Type"] == type_, logical_id
    for logical_id in RETAINED:
        resource = tpl["Resources"][logical_id]
        assert resource["DeletionPolicy"] == "Retain", logical_id
        assert resource["UpdateReplacePolicy"] == "Retain", logical_id


# --------------------------------------------------------------------------- #
# M10: alarms can publish to the encrypted ops topic                          #
# --------------------------------------------------------------------------- #


def test_ops_topic_uses_dedicated_rotating_key(template: dict[str, Any]) -> None:
    key_id = ops_topic_key_id(template)
    assert key_id != DATA_KEY, "alarm notifications must not depend on the data key"
    key = resources(template, "AWS::KMS::Key")[key_id]["Properties"]
    assert key["EnableKeyRotation"] is True


def test_ops_topic_key_policy_admits_cloudwatch_alarms(template: dict[str, Any]) -> None:
    """N7: no condition on the key statement; the topic policy decides who may publish.

    Whether SNS's KMS calls on CloudWatch's behalf carry aws:SourceArn and
    aws:SourceAccount is unverified. If they do not, a condition here would
    never match and silence every alarm (M10 again). The key encrypts this
    one topic and nothing else.
    """
    key = resources(template, "AWS::KMS::Key")[ops_topic_key_id(template)]
    (statement,) = cloudwatch_statements(key["Properties"]["KeyPolicy"]["Statement"])
    assert statement["Effect"] == "Allow"
    assert sorted(as_list(statement["Action"])) == ["kms:Decrypt", "kms:GenerateDataKey*"]
    assert statement["Resource"] == "*"
    assert "Condition" not in statement


def test_ops_topic_key_encrypts_only_the_ops_topic(template: dict[str, Any]) -> None:
    """What makes the unconditioned key statement safe: nothing else uses the key."""
    key_id = ops_topic_key_id(template)
    users = [
        logical_id
        for logical_id, resource in template["Resources"].items()
        if logical_id != key_id and key_id in str(resource.get("Properties", {}))
    ]
    assert users == [OPS_TOPIC], users


def test_data_key_policy_admits_no_service_principal(template: dict[str, Any]) -> None:
    statements = resources(template, "AWS::KMS::Key")[DATA_KEY]["Properties"]["KeyPolicy"][
        "Statement"
    ]
    for statement in statements:
        principal = statement.get("Principal")
        assert not (isinstance(principal, dict) and "Service" in principal), statement


def test_ops_topic_policy_allows_cloudwatch_publish(template: dict[str, Any]) -> None:
    (policy,) = resources(template, "AWS::SNS::TopicPolicy").values()
    assert policy["Properties"]["Topics"] == [{"Ref": OPS_TOPIC}]
    statements = policy["Properties"]["PolicyDocument"]["Statement"]

    (allow,) = cloudwatch_statements(statements)
    assert allow["Effect"] == "Allow"
    assert as_list(allow["Action"]) == ["sns:Publish"]
    assert allow["Resource"] == {"Ref": OPS_TOPIC}
    assert_alarm_conditions(allow)

    # enforce_ssl's deny on plaintext publishing is still in place.
    (deny,) = [s for s in statements if s["Effect"] == "Deny"]
    assert deny["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}
    assert as_list(deny["Action"]) == ["sns:Publish"]


def test_every_alarm_on_ops_topic_matches_the_policy_source_arn(
    template: dict[str, Any],
) -> None:
    alarms = resources(template, "AWS::CloudWatch::Alarm").values()
    publishing = [
        a for a in alarms if {"Ref": OPS_TOPIC} in a["Properties"].get("AlarmActions", [])
    ]
    assert len(publishing) >= 2
    for alarm in publishing:
        name = alarm["Properties"]["AlarmName"]
        arn = f"arn:aws:cloudwatch:{REGION}:{ACCOUNT}:alarm:{name}"
        assert fnmatch.fnmatchcase(arn, ALARM_SOURCE_ARN), name


# --------------------------------------------------------------------------- #
# L9: bucket names                                                            #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("value", [None, "false", "False", False])
def test_buckets_get_account_regional_names(tmp_path: Path, value: Any) -> None:
    context = {} if value is None else {"keep_generated_bucket_names": value}
    _, tpl = synth(tmp_path, context)
    buckets = resources(tpl, "AWS::S3::Bucket")
    expected_prefixes = {DATA_BUCKET: "envault-data", LOGS_BUCKET: "envault-access-logs"}
    for logical_id, prefix in expected_prefixes.items():
        props = buckets[logical_id]["Properties"]
        # CloudFormation names the bucket "<prefix>-<account-id>-<region>-an".
        assert props["BucketNamePrefix"] == prefix
        assert props["BucketNamespace"] == "account-regional"
        assert "BucketName" not in props


@pytest.mark.parametrize("region", ["us-east-1", "ap-southeast-7", "us-isof-south-1"])
def test_bucket_names_fit_s3_limits(template: dict[str, Any], region: str) -> None:
    for bucket in resources(template, "AWS::S3::Bucket").values():
        prefix = bucket["Properties"]["BucketNamePrefix"]
        assert re.fullmatch(r"[a-z0-9][a-z0-9-]*[a-z0-9]", prefix)
        assert len(prefix) <= 37  # aws-cdk-lib's limit for bucketNamePrefix
        name = f"{prefix}-{ACCOUNT}-{region}-an"
        assert len(name) <= 63, name


@pytest.mark.parametrize("value", ["true", "TRUE", True])
def test_keep_generated_bucket_names_opt_out(
    tmp_path: Path, template: dict[str, Any], value: Any
) -> None:
    _, kept = synth(tmp_path, {"keep_generated_bucket_names": value})
    for logical_id in (DATA_BUCKET, LOGS_BUCKET):
        props = resources(kept, "AWS::S3::Bucket")[logical_id]["Properties"]
        assert not set(NAMING_PROPERTIES) & set(props)
        # Apart from the naming properties, the buckets are defined exactly as
        # with the new names, so existing stacks see no bucket change at all.
        named = resources(template, "AWS::S3::Bucket")[logical_id]["Properties"]
        assert props == {k: v for k, v in named.items() if k not in NAMING_PROPERTIES}
    # Nothing else in the template depends on the naming mode.
    named_rest = copy.deepcopy(template)
    for logical_id in (DATA_BUCKET, LOGS_BUCKET):
        del named_rest["Resources"][logical_id]
        del kept["Resources"][logical_id]
    assert kept == named_rest


@pytest.mark.parametrize("value", ["yes", "1", "ture", "", 1, ["true"]])
def test_keep_generated_bucket_names_rejects_other_values(tmp_path: Path, value: Any) -> None:
    with pytest.raises(ValueError, match="keep_generated_bucket_names"):
        synth(tmp_path, {"keep_generated_bucket_names": value})


@pytest.mark.parametrize("context", [{}, {"keep_generated_bucket_names": "true"}])
def test_outputs_point_at_the_data_bucket(tmp_path: Path, context: dict[str, Any]) -> None:
    _, tpl = synth(tmp_path, context)
    outputs = tpl["Outputs"]
    assert outputs["BucketName"]["Value"] == {"Ref": DATA_BUCKET}
    assert render(outputs["EnvaultEnvVars"]["Value"]) == (
        "export ENVAULT_KEY_ID=alias/envault\n"
        "export ENVAULT_ID_KEY_ID=alias/envault-id\n"
        f"export ENVAULT_BUCKET=<{DATA_BUCKET}>\n"
        f"export ENVAULT_TABLE=<{STATE_TABLE}>\n"
        f"export ENVAULT_ALLOWED_ACCOUNT_IDS={ACCOUNT}"
    )


# --------------------------------------------------------------------------- #
# L10: additional_kms_key_arns                                                #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, []),
        ("", []),
        (" , ", []),
        (KEY_ARN, [KEY_ARN]),
        (f" {KEY_ARN} , {MRK_ARN} ", [KEY_ARN, MRK_ARN]),
        (f"{KEY_ARN},{KEY_ARN}", [KEY_ARN]),
        ([KEY_ARN, MRK_ARN], [KEY_ARN, MRK_ARN]),
        (
            f"arn:aws-us-gov:kms:us-gov-west-1:444455556666:key/{KEY_UUID}",
            [f"arn:aws-us-gov:kms:us-gov-west-1:444455556666:key/{KEY_UUID}"],
        ),
        (
            f"arn:aws-cn:kms:cn-north-1:444455556666:key/{KEY_UUID}",
            [f"arn:aws-cn:kms:cn-north-1:444455556666:key/{KEY_UUID}"],
        ),
        (
            f"arn:aws-iso-b:kms:us-isob-east-1:444455556666:key/{KEY_UUID}",
            [f"arn:aws-iso-b:kms:us-isob-east-1:444455556666:key/{KEY_UUID}"],
        ),
        (
            f"arn:aws-eusc:kms:eusc-de-east-1:444455556666:key/{KEY_UUID}",
            [f"arn:aws-eusc:kms:eusc-de-east-1:444455556666:key/{KEY_UUID}"],
        ),
    ],
)
def test_parse_additional_kms_key_arns_accepts_key_arns(raw: Any, expected: list[str]) -> None:
    assert envault_stack.parse_additional_kms_key_arns(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "arn:aws:kms:*:*:key/*",
        "arn:aws:kms:us-east-1:444455556666:key/*",
        f"arn:aws:kms:us-east-1:*:key/{KEY_UUID}",
        f"arn:aws:kms:*:444455556666:key/{KEY_UUID}",
        "arn:aws:kms:us-east-1:444455556666:key/1234abcd-*",
        f"arn:aws:kms:us-east-1:44445555666?:key/{KEY_UUID}",
        f"arn:*:kms:us-east-1:444455556666:key/{KEY_UUID}",
        "arn:aws:kms:us-east-1:444455556666:alias/envault",
        "arn:aws:kms:us-east-1:444455556666:alias/*",
        f"arn:aws:kms:us-east-1:4444555566:key/{KEY_UUID}",
        f"arn:aws:kms:us-east-1:4444555566667:key/{KEY_UUID}",
        f"arn:aws:kms:us-east-1:444455556666:key/{KEY_UUID.upper()}",
        f"arn:aws:kms:us-east-1:444455556666:key/{KEY_UUID}/extra",
        f"arn:aws:kms:us-east-1:444455556666:key/{KEY_UUID} trailing",
        f"arn:aws:kms::444455556666:key/{KEY_UUID}",
        f"arn:aws:kms:us-east-1::key/{KEY_UUID}",
        "arn:aws:kms:us-east-1:444455556666:key/not-a-key-id",
        "arn:aws:kms:us-east-1:444455556666:key/mrk-1234",
        "arn:aws:s3:::envault-data",
        "arn:aws:iam::444455556666:root",
        "alias/envault",
        KEY_UUID,
        f"{KEY_ARN},arn:aws:kms:*:*:key/*",
        [KEY_ARN, 5],
        {"arn": KEY_ARN},
        42,
    ],
)
def test_parse_additional_kms_key_arns_rejects_everything_else(raw: Any) -> None:
    with pytest.raises(ValueError, match="additional_kms_key_arns"):
        envault_stack.parse_additional_kms_key_arns(raw)


def test_alias_arn_error_explains_why() -> None:
    with pytest.raises(ValueError, match=r"(?s)alias.*describe-key"):
        envault_stack.parse_additional_kms_key_arns(
            "arn:aws:kms:us-east-1:444455556666:alias/rotation-target"
        )


def test_wildcard_error_says_wildcard() -> None:
    with pytest.raises(ValueError, match="wildcard"):
        envault_stack.parse_additional_kms_key_arns("arn:aws:kms:*:*:key/*")


def test_wildcard_context_fails_synth(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="additional_kms_key_arns"):
        synth(tmp_path, {"additional_kms_key_arns": "arn:aws:kms:*:*:key/*"})


def test_default_kms_statements_reference_only_the_stack_key(template: dict[str, Any]) -> None:
    statements = managed_policy_statements(template)
    for sid in ("KmsEnvelopeEncryption", "KmsViaStorageServices", "KmsDescribeKey"):
        assert as_list(statements[sid]["Resource"]) == [{"Fn::GetAtt": [DATA_KEY, "Arn"]}]


def test_additional_kms_key_arns_reach_every_kms_statement(tmp_path: Path) -> None:
    _, tpl = synth(tmp_path, {"additional_kms_key_arns": f"{KEY_ARN},{MRK_ARN}"})
    statements = managed_policy_statements(tpl)
    expected = [{"Fn::GetAtt": [DATA_KEY, "Arn"]}, KEY_ARN, MRK_ARN]
    for sid in ("KmsEnvelopeEncryption", "KmsViaStorageServices", "KmsDescribeKey"):
        assert as_list(statements[sid]["Resource"]) == expected, sid

    # The conditions that scope each statement are unchanged.
    assert statements["KmsEnvelopeEncryption"]["Condition"] == {
        "StringEquals": {"kms:EncryptionContext:purpose": ["envault-backup", "backup"]}
    }
    via = statements["KmsViaStorageServices"]["Condition"]["StringEquals"]["kms:ViaService"]
    assert sorted(render(v) for v in via) == [
        f"dynamodb.{REGION}.amazonaws.com",
        f"s3.{REGION}.amazonaws.com",
    ]
    assert "Condition" not in statements["KmsDescribeKey"]


# --------------------------------------------------------------------------- #
# M6: the HMAC key that names files                                           #
# --------------------------------------------------------------------------- #


def test_id_key_is_an_hmac_key_without_automatic_rotation(template: dict[str, Any]) -> None:
    props = resources(template, "AWS::KMS::Key")[ID_KEY]["Properties"]
    assert props["KeySpec"] == "HMAC_256"
    assert props["KeyUsage"] == "GENERATE_VERIFY_MAC"
    # KMS rotates only symmetric encryption keys automatically; a new HMAC key
    # would also give every file a new identifier.
    assert props.get("EnableKeyRotation", False) is False


def test_id_key_is_retained_and_its_deletion_denied(template: dict[str, Any]) -> None:
    key = resources(template, "AWS::KMS::Key")[ID_KEY]
    assert key["DeletionPolicy"] == "Retain"
    assert key["UpdateReplacePolicy"] == "Retain"
    (deny,) = [s for s in key["Properties"]["KeyPolicy"]["Statement"] if s["Effect"] == "Deny"]
    assert deny["Sid"] == "DenyScheduleKeyDeletion"
    assert as_list(deny["Action"]) == ["kms:ScheduleKeyDeletion"]
    assert deny["Principal"] == {"AWS": "*"}
    for statement in key["Properties"]["KeyPolicy"]["Statement"]:  # no AWS service is admitted
        principal = statement.get("Principal")
        assert not (isinstance(principal, dict) and "Service" in principal), statement


def test_id_key_alias_is_what_the_cli_is_told(template: dict[str, Any]) -> None:
    aliases = resources(template, "AWS::KMS::Alias").values()
    (alias,) = [a for a in aliases if a["Properties"]["AliasName"] == "alias/envault-id"]
    assert alias["Properties"]["TargetKeyId"] == {"Fn::GetAtt": [ID_KEY, "Arn"]}
    assert envault_stack.ID_KEY_ALIAS == "alias/envault-id"
    assert template["Outputs"]["IdKeyAlias"]["Value"] == "alias/envault-id"


def test_user_policy_may_mac_with_the_id_key_and_nothing_else(template: dict[str, Any]) -> None:
    statements = managed_policy_statements(template)
    grant = statements["KmsFileIdentifiers"]
    assert grant["Effect"] == "Allow"
    assert sorted(as_list(grant["Action"])) == ["kms:GenerateMac", "kms:VerifyMac"]
    assert as_list(grant["Resource"]) == [{"Fn::GetAtt": [ID_KEY, "Arn"]}]
    assert "Condition" not in grant
    for sid, statement in statements.items():
        if sid == "KmsFileIdentifiers":
            continue
        # MAC operations nowhere else, and the ID key in no other statement.
        assert not [a for a in as_list(statement["Action"]) if "Mac" in a or a == "kms:*"], sid
        assert {"Fn::GetAtt": [ID_KEY, "Arn"]} not in as_list(statement["Resource"]), sid


def test_additional_kms_key_arns_never_reach_the_mac_grant(tmp_path: Path) -> None:
    _, tpl = synth(tmp_path, {"additional_kms_key_arns": f"{KEY_ARN},{MRK_ARN}"})
    grant = managed_policy_statements(tpl)["KmsFileIdentifiers"]
    assert as_list(grant["Resource"]) == [{"Fn::GetAtt": [ID_KEY, "Arn"]}]


def test_id_key_needs_no_cdk_nag_waiver(template: dict[str, Any]) -> None:
    """cdk-nag's KMS5 (rotation) covers symmetric keys only: nothing is suppressed for it."""
    key = resources(template, "AWS::KMS::Key")[ID_KEY]
    assert "cdk_nag" not in key.get("Metadata", {})


# --------------------------------------------------------------------------- #
# cdk-nag                                                                     #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "context",
    [
        {},
        {"keep_generated_bucket_names": "true"},
        {"additional_kms_key_arns": f"{KEY_ARN},{MRK_ARN}"},
    ],
    ids=["default", "keep-generated-names", "additional-key-arns"],
)
def test_cdk_nag_reports_nothing_unsuppressed(tmp_path: Path, context: dict[str, Any]) -> None:
    # Equivalent of `cdk synth --strict`: no error or warning annotations.
    stack, _ = synth(tmp_path, context)
    annotations = Annotations.from_stack(stack)
    assert annotations.find_error("*", Match.any_value()) == []
    assert annotations.find_warning("*", Match.any_value()) == []


def test_iam5_suppressions_are_scoped_with_applies_to(template: dict[str, Any]) -> None:
    (policy,) = resources(template, "AWS::IAM::ManagedPolicy").values()
    rules = policy["Metadata"]["cdk_nag"]["rules_to_suppress"]
    assert {rule["id"] for rule in rules} == {"AwsSolutions-IAM5"}
    # Without applies_to a suppression waives every IAM5 finding on the policy.
    assert all(rule.get("applies_to") for rule in rules), rules
    assert sorted(a for rule in rules for a in rule["applies_to"]) == sorted(
        [
            f"Resource::<{DATA_BUCKET}.Arn>/encrypted/*",
            f"Resource::<{STATE_TABLE}.Arn>/index/*",
            "Resource::*",
        ]
    )


def test_unexpected_wildcard_in_user_policy_is_reported(tmp_path: Path) -> None:
    app = cdk.App(outdir=str(tmp_path))
    cdk.Aspects.of(app).add(AwsSolutionsChecks())
    stack = envault_stack.EnvaultStack(app, "EnvaultStack")
    policy = stack.node.find_child("EnvaultUserPolicy")
    assert isinstance(policy, iam.ManagedPolicy)
    policy.add_statements(
        iam.PolicyStatement(actions=["kms:Decrypt"], resources=["arn:aws:kms:*:*:key/*"])
    )
    Template.from_stack(stack)
    errors = Annotations.from_stack(stack).find_error(
        "*", Match.string_like_regexp(r"AwsSolutions-IAM5\[Resource::arn:aws:kms:\*:\*:key/\*\]")
    )
    assert errors, "a wildcard KMS resource must not be covered by the IAM5 suppressions"
