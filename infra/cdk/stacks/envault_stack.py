"""CDK stack for envault — provisions DynamoDB, S3, KMS, and IAM resources."""

from __future__ import annotations

import re

import aws_cdk as cdk
from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
)
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_cloudwatch_actions as cw_actions
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_sns as sns
from cdk_nag import NagPackSuppression, NagSuppressions
from constructs import Construct

#: Every CloudWatch alarm that notifies the ops topic is named with this prefix.
#: The ops topic's policy lets only alarms whose ARN matches
#: ``...:alarm:<prefix>*`` publish, so a new alarm must keep the prefix.
ALARM_NAME_PREFIX = "envault-"

#: Alias of the HMAC key that names files (the CLI's ENVAULT_ID_KEY_ID).
ID_KEY_ALIAS = "alias/envault-id"

#: Bucket name prefixes. Unless ``keep_generated_bucket_names`` is set, the
#: buckets are created in the S3 account-regional namespace and CloudFormation
#: names them ``<prefix>-<account-id>-<region>-an``.
DATA_BUCKET_PURPOSE = "envault-data"
ACCESS_LOGS_BUCKET_PURPOSE = "envault-access-logs"

# A KMS *key* ARN with every component concrete: partition (aws, aws-cn,
# aws-us-gov, aws-iso-b, ...), region, 12-digit account, and a key ID that is
# either a UUID or a multi-Region key ID (mrk- plus 32 hex digits).
_KMS_KEY_ARN = re.compile(
    r"arn:aws(?:-[a-z]+)*"
    r":kms:[a-z]+(?:-[a-z]+)+-[0-9]+"
    r":[0-9]{12}"
    r":key/(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})"
)

# The bucket name prefixes aws-cdk-lib (2.256.0 and later) accepts for
# bucketNamePrefix: at most 37 lowercase letters, digits and hyphens, starting
# and ending with a letter or digit.
_BUCKET_NAME_PREFIX = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,35}[a-z0-9])?")


def parse_additional_kms_key_arns(raw: object) -> list[str]:
    """Validate the ``additional_kms_key_arns`` context value.

    Extra KMS keys the CLI user policy may use, for ``rotate-key --new-key-id``.
    Pass a comma-separated string at deploy time, or a list of strings in
    cdk.json::

        cdk deploy -c additional_kms_key_arns=arn:aws:kms:us-east-1:111122223333:key/<key-id>

    Every entry must be a KMS key ARN with a concrete partition, region,
    12-digit account and key ID. Wildcards are rejected, so a typo cannot widen
    the policy beyond named keys.

    Alias ARNs are rejected too: IAM authorizes KMS cryptographic operations
    against the key ARN, so an alias ARN in ``Resource`` grants no use of the
    key it points to (it only governs alias management such as kms:UpdateAlias).
    ``rotate-key --new-key-id`` may still be given the alias at run time.

    Returns the ARNs in the order given, without duplicates.
    """
    if raw is None:
        return []
    if isinstance(raw, str):
        entries = raw.split(",")
    elif isinstance(raw, list | tuple) and all(isinstance(entry, str) for entry in raw):
        entries = list(raw)
    else:
        raise ValueError(
            "additional_kms_key_arns must be a comma-separated string or a list of "
            f"strings, got {raw!r}"
        )

    arns: list[str] = []
    for entry in (e.strip() for e in entries):
        if not entry:
            continue
        if "*" in entry or "?" in entry:
            raise ValueError(f"additional_kms_key_arns must not contain wildcards, got {entry!r}")
        if entry.startswith("alias/") or ":alias/" in entry:
            raise ValueError(
                f"additional_kms_key_arns takes key ARNs, not aliases: got {entry!r}. "
                "IAM authorizes KMS use against the key ARN, so an alias ARN in the "
                "policy would grant nothing. Look up the key ARN with: "
                "aws kms describe-key --key-id <alias> --query KeyMetadata.Arn --output text"
            )
        if not _KMS_KEY_ARN.fullmatch(entry):
            raise ValueError(
                "additional_kms_key_arns entries must be KMS key ARNs of the form "
                "arn:<partition>:kms:<region>:<12-digit account>:key/<key id>, "
                f"got {entry!r}"
            )
        if entry not in arns:
            arns.append(entry)
    return arns


def _additional_kms_key_arns(scope: Construct) -> list[str]:
    """Read and validate the ``additional_kms_key_arns`` context value."""
    return parse_additional_kms_key_arns(scope.node.try_get_context("additional_kms_key_arns"))


def _context_flag(scope: Construct, name: str) -> bool:
    """Read a boolean context flag: absent (false), a JSON boolean, or true/false."""
    value = scope.node.try_get_context(name)
    if value is None or isinstance(value, bool):
        return bool(value)
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    raise ValueError(f"{name} must be true or false, got {value!r}")


def _cfn_element(construct: Construct) -> cdk.CfnElement:
    """Return the CloudFormation resource behind an L2 construct."""
    child = construct.node.default_child
    if not isinstance(child, cdk.CfnElement):
        raise TypeError(f"{construct.node.path} has no CloudFormation resource")
    return child


def _use_account_regional_name(bucket: s3.Bucket, purpose: str) -> None:
    """Name ``bucket`` ``<purpose>-<account-id>-<region>-an``.

    The bucket is created in the S3 account-regional namespace: CloudFormation
    appends ``-<account-id>-<region>-an`` to ``BucketNamePrefix``. Only this
    account can create buckets in its namespace, so the name cannot be claimed
    first by another account. Dots in ``purpose`` become hyphens.

    aws-cdk-lib 2.256.0 and later expose this as the ``bucket_name_prefix`` and
    ``bucket_namespace`` props of ``s3.Bucket``; the pinned version predates
    them, hence the L1 property overrides.
    """
    prefix = purpose.replace(".", "-")
    if not _BUCKET_NAME_PREFIX.fullmatch(prefix):
        raise ValueError(f"invalid S3 bucket name prefix {prefix!r}")
    cfn_bucket = _cfn_element(bucket)
    if not isinstance(cfn_bucket, s3.CfnBucket):
        raise TypeError(f"expected an s3.CfnBucket under {bucket.node.path}")
    cfn_bucket.add_property_override("BucketNamePrefix", prefix)
    cfn_bucket.add_property_override("BucketNamespace", "account-regional")


class EnvaultStack(Stack):
    """Provisions all AWS resources required by envault.

    Resources:
      - KMS Customer Managed Key with annual rotation
      - KMS HMAC key that names files (file identifiers, ``alias/envault-id``)
      - S3 bucket with versioning, SSE-KMS, and block public access
      - DynamoDB table with single-table design, GSIs, PITR, and KMS encryption
      - IAM managed policy for least-privilege access
      - SNS topic (with its own KMS key) and CloudWatch alarms for operations

    Context flags:
      - ``additional_kms_key_arns``: extra KMS key ARNs for rotate-key
        (see :func:`parse_additional_kms_key_arns`).
      - ``keep_generated_bucket_names``: ``true`` for stacks deployed before
        the buckets were named ``envault-{data,access-logs}-<account>-<region>-an``.
        Adding a name to an existing bucket makes CloudFormation replace it
        (the old bucket is retained but orphaned, with every S3 version that
        DynamoDB records pin), so existing stacks must keep this set.
    """

    def __init__(self, scope: Construct, construct_id: str, **kwargs: object) -> None:
        super().__init__(scope, construct_id, **kwargs)

        keep_generated_bucket_names = _context_flag(self, "keep_generated_bucket_names")
        extra_kms_key_arns = _additional_kms_key_arns(self)

        # ------------------------------------------------------------------ #
        # Parameters                                                            #
        # ------------------------------------------------------------------ #
        table_name_param = cdk.CfnParameter(
            self,
            "TableNameParam",
            type="String",
            default="envault-state",
            description="Name for the DynamoDB state table.",
            allowed_pattern=r"[a-zA-Z0-9_.\-]+",
            min_length=3,
            max_length=255,
        )
        policy_name_param = cdk.CfnParameter(
            self,
            "PolicyNameParam",
            type="String",
            default="EnvaultUserPolicy",
            description="Name for the IAM managed policy.",
            allowed_pattern=r"[\w+=,.@\-]+",
            min_length=1,
            max_length=128,
        )
        alert_email_param = cdk.CfnParameter(
            self,
            "AlertEmailParam",
            type="String",
            default="",
            description="Email address subscribed to envault operational alarms (optional).",
        )

        # ------------------------------------------------------------------ #
        # KMS Customer Managed Key                                             #
        # ------------------------------------------------------------------ #
        encryption_key = kms.Key(
            self,
            "EnvaultKey",
            description="envault — envelope encryption key for file data keys",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN,  # never auto-delete a KMS key
        )
        kms.Alias(
            self,
            "EnvaultKeyAlias",
            alias_name="alias/envault",
            target_key=encryption_key,
        )

        # Deny key deletion for all principals — requires removing this
        # policy statement first (break-glass procedure). DisableKey is
        # intentionally allowed so operators can freeze a compromised CMK
        # during incident response without a CloudFormation change.
        encryption_key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="DenyScheduleKeyDeletion",
                effect=iam.Effect.DENY,
                principals=[iam.AnyPrincipal()],
                actions=["kms:ScheduleKeyDeletion"],
                resources=["*"],
            )
        )

        # ------------------------------------------------------------------ #
        # KMS HMAC key: file identifiers                                       #
        # ------------------------------------------------------------------ #
        # The CLI names each new file by HMAC-SHA-256(this key, SHA-256 of the
        # plaintext), so S3 keys, DynamoDB keys and the KMS encryption context
        # (which CloudTrail records) say nothing about a file's content: for a
        # short secret the bare SHA-256 would. Every record stores this key's
        # ARN and is verified against it (VerifyMac) on every read, so losing
        # the key makes those records unreadable through envault: retained,
        # and its deletion denied like the data key's. KMS does not rotate HMAC
        # keys automatically (and a new key would give every file a new
        # identifier), so automatic rotation stays off.
        id_key = kms.Key(
            self,
            "EnvaultIdKey",
            description="envault — names files: HMAC of each file's SHA-256 (file identifiers)",
            key_spec=kms.KeySpec.HMAC_256,
            key_usage=kms.KeyUsage.GENERATE_VERIFY_MAC,
            removal_policy=RemovalPolicy.RETAIN,  # never auto-delete a KMS key
        )
        kms.Alias(
            self,
            "EnvaultIdKeyAlias",
            alias_name=ID_KEY_ALIAS,
            target_key=id_key,
        )
        id_key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="DenyScheduleKeyDeletion",
                effect=iam.Effect.DENY,
                principals=[iam.AnyPrincipal()],
                actions=["kms:ScheduleKeyDeletion"],
                resources=["*"],
            )
        )

        # ------------------------------------------------------------------ #
        # S3 Access Logging Bucket                                              #
        # ------------------------------------------------------------------ #
        access_logs_bucket = s3.Bucket(
            self,
            "EnvaultAccessLogsBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                s3.LifecycleRule(
                    expiration=Duration.days(365),
                )
            ],
        )

        # ------------------------------------------------------------------ #
        # S3 Bucket                                                            #
        # ------------------------------------------------------------------ #
        bucket = s3.Bucket(
            self,
            "EnvaultBucket",
            versioned=True,
            encryption=s3.BucketEncryption.KMS,
            encryption_key=encryption_key,
            bucket_key_enabled=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            server_access_logs_bucket=access_logs_bucket,
            server_access_logs_prefix="envault-access-logs/",
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                # Expire non-current versions after 365 days to bound growth from
                # key rotation. No Glacier transition: DynamoDB pins each file to
                # a specific VersionId, and GetObject on an archived version fails,
                # so a record left pointing at a non-current version (e.g. after
                # a failed state write) would become undecryptable at 90 days.
                s3.LifecycleRule(
                    noncurrent_version_expiration=Duration.days(365),
                )
            ],
        )

        # Bucket names: <purpose>-<account-id>-<region>-an in the account's own
        # S3 namespace. Both naming properties are create-only, so stacks that
        # already exist set keep_generated_bucket_names=true to keep their
        # buckets (see the class docstring).
        if keep_generated_bucket_names:
            cdk.Annotations.of(self).add_info(
                "keep_generated_bucket_names=true: the S3 buckets keep their "
                "CloudFormation-generated names."
            )
        else:
            _use_account_regional_name(access_logs_bucket, ACCESS_LOGS_BUCKET_PURPOSE)
            _use_account_regional_name(bucket, DATA_BUCKET_PURPOSE)

        # ------------------------------------------------------------------ #
        # DynamoDB Table (single-table design)                                 #
        # ------------------------------------------------------------------ #
        table = dynamodb.Table(
            self,
            "EnvaultStateTable",
            table_name=table_name_param.value_as_string,
            partition_key=dynamodb.Attribute(name="PK", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="SK", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=encryption_key,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
            deletion_protection=True,
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.RETAIN,
        )

        # GSI: query all files in a given state.
        # Projection ALL is required: rotate-key reads all attributes from this index.
        # Changing projection type would cause CloudFormation table replacement.
        table.add_global_secondary_index(
            index_name="state-index",
            partition_key=dynamodb.Attribute(
                name="current_state", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(name="encrypted_at", type=dynamodb.AttributeType.STRING),
            projection_type=dynamodb.ProjectionType.ALL,
        )

        # GSI: query all events on a given calendar date.
        # Projection ALL kept to avoid CloudFormation table replacement on existing stacks.
        # For new deployments, INCLUDE with [SK, file_name, file_id (sha256_hash on
        # legacy rows), correlation_id, operation] would reduce storage and exposure surface.
        table.add_global_secondary_index(
            index_name="date-index",
            partition_key=dynamodb.Attribute(name="date", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="last_updated", type=dynamodb.AttributeType.STRING),
            projection_type=dynamodb.ProjectionType.ALL,
        )

        # ------------------------------------------------------------------ #
        # IAM Managed Policy (least-privilege)                                 #
        # ------------------------------------------------------------------ #
        # The stack key plus any extra keys for rotate-key --new-key-id. The
        # extra keys appear in every KMS statement: rotate-key wraps data keys
        # under the new key and re-uploads with SSE-KMS under it, and reading a
        # rotated file back uses both again.
        kms_key_arns = [encryption_key.key_arn, *extra_kms_key_arns]

        policy = iam.ManagedPolicy(
            self,
            "EnvaultUserPolicy",
            managed_policy_name=policy_name_param.value_as_string,
            description="Least-privilege access for envault CLI users",
            statements=[
                # Direct KMS use is limited to envault envelope ciphertexts
                # ("backup" is the legacy shell scripts' context). Without this,
                # the policy is a general-purpose decrypt grant on a key that
                # also protects the bucket and table.
                iam.PolicyStatement(
                    sid="KmsEnvelopeEncryption",
                    actions=["kms:GenerateDataKey", "kms:Decrypt"],
                    resources=kms_key_arns,
                    conditions={
                        "StringEquals": {
                            "kms:EncryptionContext:purpose": ["envault-backup", "backup"]
                        }
                    },
                ),
                # SSE-KMS on the bucket and table: only when S3/DynamoDB call
                # KMS on the user's behalf.
                iam.PolicyStatement(
                    sid="KmsViaStorageServices",
                    actions=["kms:GenerateDataKey", "kms:Decrypt"],
                    resources=kms_key_arns,
                    conditions={
                        "StringEquals": {
                            "kms:ViaService": [
                                f"s3.{self.region}.amazonaws.com",
                                f"dynamodb.{self.region}.amazonaws.com",
                            ]
                        }
                    },
                ),
                iam.PolicyStatement(
                    sid="KmsDescribeKey",
                    actions=["kms:DescribeKey"],
                    resources=kms_key_arns,
                ),
                # File identifiers: GenerateMac names a file (encrypt, migrate,
                # lookups by SHA-256), VerifyMac checks one on every read of a
                # keyed record. Either is an oracle for guessing a file's
                # content from its identifier, so it goes to the people who may
                # decrypt the file anyway, on this one key.
                iam.PolicyStatement(
                    sid="KmsFileIdentifiers",
                    actions=["kms:GenerateMac", "kms:VerifyMac"],
                    resources=[id_key.key_arn],
                ),
                iam.PolicyStatement(
                    sid="S3EncryptedObjects",
                    actions=[
                        "s3:PutObject",
                        "s3:GetObject",
                        "s3:GetObjectVersion",
                    ],
                    resources=[f"{bucket.bucket_arn}/encrypted/*"],
                ),
                iam.PolicyStatement(
                    sid="DynamoDBStateAccess",
                    actions=[
                        "dynamodb:PutItem",
                        "dynamodb:GetItem",
                        "dynamodb:Query",
                    ],
                    resources=[table.table_arn, f"{table.table_arn}/index/*"],
                ),
                iam.PolicyStatement(
                    sid="StsCallerIdentity",
                    actions=["sts:GetCallerIdentity"],
                    resources=["*"],
                ),
            ],
        )

        # ------------------------------------------------------------------ #
        # cdk-nag suppressions for scoped wildcards                            #
        # ------------------------------------------------------------------ #
        # NagPackSuppression objects, not dicts: with a plain dict the
        # snake_case "applies_to" key never reached cdk-nag, so each entry
        # waived every IAM5 finding on the policy, including any new wildcard.
        # applies_to must name the resources' CloudFormation logical IDs,
        # which is how cdk-nag spells the finding.
        bucket_logical_id = self.get_logical_id(_cfn_element(bucket))
        table_logical_id = self.get_logical_id(_cfn_element(table))
        NagSuppressions.add_resource_suppressions(
            policy,
            [
                NagPackSuppression(
                    id="AwsSolutions-IAM5",
                    reason=(
                        "S3 object-level actions require a key prefix wildcard."
                        " Access is scoped to encrypted/* on the single envault"
                        " bucket — the CLI never lists or reads other prefixes."
                    ),
                    applies_to=[f"Resource::<{bucket_logical_id}.Arn>/encrypted/*"],
                ),
                NagPackSuppression(
                    id="AwsSolutions-IAM5",
                    reason=(
                        "DynamoDB GSI queries require table/index/* wildcard."
                        " Access is scoped to the single envault table and"
                        " only allows PutItem/GetItem/Query."
                    ),
                    applies_to=[f"Resource::<{table_logical_id}.Arn>/index/*"],
                ),
                NagPackSuppression(
                    id="AwsSolutions-IAM5",
                    reason=(
                        "sts:GetCallerIdentity does not support resource-level"
                        " authorization; Resource * is required by the API."
                        " Used only to attribute audit events to the caller."
                    ),
                    applies_to=["Resource::*"],
                ),
            ],
        )

        # ------------------------------------------------------------------ #
        # Monitoring — SNS + CloudWatch Alarms                                #
        # ------------------------------------------------------------------ #
        # SNS encrypts each message with the topic's KMS key using the
        # publisher's permissions, so CloudWatch (the alarms' publisher) must
        # be allowed to use the key, and the topic policy must let it publish.
        # The topic gets its own key instead of the data key: the data key's
        # policy then admits no AWS service, and disabling the data key during
        # incident response does not also silence the alarms. Only in-flight
        # notifications are encrypted with this key, so it is deleted with the
        # stack (after KMS's 30-day waiting period).
        ops_topic_key = kms.Key(
            self,
            "EnvaultOpsTopicKey",
            description="envault — encrypts the operational alerts SNS topic",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.DESTROY,
            pending_window=Duration.days(30),
        )
        # Confused-deputy guard: only CloudWatch alarms in this account whose
        # names start with ALARM_NAME_PREFIX may publish. It is on the topic
        # policy below.
        alarm_publisher = iam.ServicePrincipal("cloudwatch.amazonaws.com")
        alarm_publisher_conditions = {
            "StringEquals": {"aws:SourceAccount": self.account},
            "ArnLike": {
                "aws:SourceArn": self.format_arn(
                    service="cloudwatch",
                    resource="alarm",
                    resource_name=f"{ALARM_NAME_PREFIX}*",
                    arn_format=cdk.ArnFormat.COLON_RESOURCE_NAME,
                )
            },
        }
        # The key statement deliberately has no such conditions:
        # - the key is dedicated to this one topic, and encrypts nothing else;
        # - the topic policy decides which alarms may publish, and SNS uses
        #   the key only for messages that policy let through;
        # - whether the KMS calls SNS makes on CloudWatch's behalf carry
        #   aws:SourceArn and aws:SourceAccount is unverified, and a condition
        #   that never matches would silently disable every alarm, which is
        #   the original M10 failure.
        ops_topic_key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudWatchAlarmsToUseKey",
                principals=[alarm_publisher],
                actions=["kms:Decrypt", "kms:GenerateDataKey*"],
                resources=["*"],
            )
        )

        ops_topic = sns.Topic(
            self,
            "EnvaultOpsTopic",
            display_name="envault operational alerts",
            enforce_ssl=True,
            master_key=ops_topic_key,
        )
        ops_topic.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudWatchAlarmsToPublish",
                principals=[alarm_publisher],
                actions=["sns:Publish"],
                resources=[ops_topic.topic_arn],
                conditions=alarm_publisher_conditions,
            )
        )

        # DynamoDB throttle alarm
        table.metric_throttled_requests_for_operation("PutItem").create_alarm(
            self,
            "DynamoThrottleAlarm",
            alarm_name=f"{ALARM_NAME_PREFIX}dynamodb-throttle",
            evaluation_periods=1,
            threshold=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        ).add_alarm_action(cw_actions.SnsAction(ops_topic))

        # DynamoDB system errors — use a math expression over the three
        # operations envault actually calls to stay within the 10-metric
        # alarm limit imposed by CloudWatch.
        sys_err_metrics: dict[str, cloudwatch.IMetric] = {}
        for op in ("PutItem", "GetItem", "Query"):
            sys_err_metrics[op.lower()] = cloudwatch.Metric(
                namespace="AWS/DynamoDB",
                metric_name="SystemErrors",
                dimensions_map={
                    "TableName": table.table_name,
                    "Operation": op,
                },
                statistic="Sum",
                period=Duration.minutes(5),
            )
        sys_err_expression = cloudwatch.MathExpression(
            expression=" + ".join(sys_err_metrics.keys()),
            using_metrics=sys_err_metrics,
            label="DynamoDB SystemErrors (envault operations)",
            period=Duration.minutes(5),
        )
        sys_err_expression.create_alarm(
            self,
            "DynamoSystemErrorAlarm",
            alarm_name=f"{ALARM_NAME_PREFIX}dynamodb-system-errors",
            evaluation_periods=1,
            threshold=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        ).add_alarm_action(cw_actions.SnsAction(ops_topic))

        has_alert_email = cdk.CfnCondition(
            self,
            "HasAlertEmail",
            expression=cdk.Fn.condition_not(
                cdk.Fn.condition_equals(alert_email_param.value_as_string, "")
            ),
        )
        alert_subscription = sns.CfnSubscription(
            self,
            "OpsTopicEmailSubscription",
            topic_arn=ops_topic.topic_arn,
            protocol="email",
            endpoint=alert_email_param.value_as_string,
        )
        alert_subscription.cfn_options.condition = has_alert_email

        cdk.CfnOutput(self, "OpsTopicArn", value=ops_topic.topic_arn)

        # ------------------------------------------------------------------ #
        # CloudFormation Outputs                                               #
        # ------------------------------------------------------------------ #
        cdk.CfnOutput(self, "KmsKeyAlias", value="alias/envault")
        cdk.CfnOutput(self, "IdKeyAlias", value=ID_KEY_ALIAS)
        cdk.CfnOutput(self, "BucketName", value=bucket.bucket_name)
        cdk.CfnOutput(self, "TableName", value=table.table_name)
        cdk.CfnOutput(self, "ManagedPolicyArn", value=policy.managed_policy_arn)

        cdk.CfnOutput(
            self,
            "EnvaultEnvVars",
            value=(
                f"export ENVAULT_KEY_ID=alias/envault\n"
                f"export ENVAULT_ID_KEY_ID={ID_KEY_ALIAS}\n"
                f"export ENVAULT_BUCKET={bucket.bucket_name}\n"
                f"export ENVAULT_TABLE={table.table_name}"
            ),
            description="Copy-paste these env vars to configure the envault CLI",
        )
