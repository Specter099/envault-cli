"""`envault migrate` against the legacy shell workflow's real layout (M4).

The legacy workflow ran, from ``<repo>/code``::

    aws-encryption-cli @encrypt.conf -i ../encrypt -r -o ../encrypted  # writes output.json
    aws s3 sync ../encrypted s3://$S3_BUCKET/encrypted

so ``code/output.json`` holds one JSON record per file, with ABSOLUTE ``input``
and ``output`` paths (``os.path.abspath``) outside ``code/``, a base64 header
(``key_info`` is the base64 KMS key ARN), and the objects live in S3 at
``encrypted/<path relative to ../encrypted>``. The layout here is generated in
tmp_path with real Encryption SDK ciphertext under a moto KMS key, and each
record is built from that ciphertext's header exactly as aws-encryption-cli
4.3.0 builds it (``json_ready_header``). ``GENUINE_RECORD`` is a record from a
real aws-encryption-cli 4.3.0 run (paths replaced), used to check that the
generated records have the same shape.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import pathlib
from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum
from typing import Any
from unittest.mock import patch

import attr
import aws_encryption_sdk
import boto3
import botocore.client
import pytest
from aws_encryption_sdk import CommitmentPolicy, StrictAwsKmsMasterKeyProvider
from aws_encryption_sdk.identifiers import Algorithm
from aws_encryption_sdk.internal.formatting.deserialize import deserialize_header
from botocore.exceptions import ClientError
from click.testing import CliRunner, Result
from moto import mock_aws

from envault import identity
from envault.cli import main
from envault.state import (
    ENCRYPTED,
    S3_KEY_CONTENT_ADDRESSED,
    S3_KEY_LEGACY_SYNC,
    FileRecord,
    StateStore,
)

from ._id_key import file_id_of, id_key_env

TABLE = "envault-test-state"
BUCKET = "envault-test-bucket"
REGION = "us-east-1"
LEGACY_ALIAS = "alias/s3_key"
NEW_ALIAS = "alias/new-key"
ALPHA = b"alpha secret line\n"
BETA = b"beta secret line!!\n"

GENUINE_RECORD: dict[str, Any] = {
    "header": {
        "algorithm": "AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384",
        "commitment_key": "BJIxJnpAPJ82aZhk3cANM+6l1judb7PEjVC9cg3pM+E=",
        "content_type": 2,
        "encrypted_data_keys": [
            {
                "encrypted_data_key": (
                    "YmYyYzg1ZDktNmQ0OC00NzhmLWEzZTYtNTEyYTIxNWE3YmIxUkMSkavWJ34oTIJNEtz1AxY7"
                    "mu8mqUr0TjzWxQ+YrwuWZ3KO7lSoYArDuEZwMsheInNpeZpOv5zgyxG7"
                ),
                "key_provider": {
                    "key_info": (
                        "YXJuOmF3czprbXM6dXMtZWFzdC0xOjEyMzQ1Njc4OTAxMjprZXkvYmYyYzg1ZDktNmQ0OC00"
                        "NzhmLWEzZTYtNTEyYTIxNWE3YmIx"
                    ),
                    "provider_id": "YXdzLWttcw==",
                },
            }
        ],
        "encryption_context": {
            "aws-crypto-public-key": (
                "Agn7z2UHm0GqWSnkTPM4kk7MJti+A4VFWWg+bt2awEdCuQoN7dpDlyAVkuIR0jUp7g=="
            ),
            "purpose": "backup",
        },
        "frame_length": 4096,
        "header_iv_length": None,
        "message_id": "Bm4ZjPV5YdewFZ0yYdos7myyR89cDQfw1lUch0ginoQ=",
        "type": None,
        "version": "2.0",
    },
    "input": "<PROJ>/encrypt/alpha.txt",
    "mode": "encrypt",
    "output": "<PROJ>/encrypted/alpha.txt.encrypted",
}


@pytest.fixture(autouse=True)
def _clear_identity_cache() -> Iterator[None]:
    identity.reset_cache()
    yield
    identity.reset_cache()


# ---------------------------------------------------------------------------
# The legacy layout
# ---------------------------------------------------------------------------


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("utf-8")


def _json_ready_header(header: Any) -> dict[str, Any]:
    """aws-encryption-cli 4.3.0's ``metadata.json_ready_header``, verbatim in effect."""
    dict_header = attr.asdict(header)
    del dict_header["content_aad_length"]
    dict_header["version"] = str(float(dict_header["version"].value))
    dict_header["algorithm"] = dict_header["algorithm"].name
    for key, value in dict_header.items():
        if isinstance(value, Enum):
            dict_header[key] = value.value
    dict_header["message_id"] = _b64(dict_header["message_id"])
    dict_header["encrypted_data_keys"] = sorted(
        dict_header["encrypted_data_keys"],
        key=lambda x: x["key_provider"]["provider_id"].encode() + x["key_provider"]["key_info"],
    )
    for data_key in dict_header["encrypted_data_keys"]:
        provider = data_key["key_provider"]
        provider["provider_id"] = _b64(provider["provider_id"].encode())
        provider["key_info"] = _b64(provider["key_info"])
        data_key["encrypted_data_key"] = _b64(data_key["encrypted_data_key"])
    if dict_header["commitment_key"]:
        dict_header["commitment_key"] = _b64(dict_header["commitment_key"])
    return dict_header


@dataclass
class Legacy:
    """A legacy project after `make encrypt` (encrypt.sh) ran once."""

    proj: pathlib.Path
    key_arn: str
    env: dict[str, str]
    headers: dict[str, dict[str, Any]]  # by relative plaintext path

    @property
    def output_json(self) -> pathlib.Path:
        return self.proj / "code" / "output.json"

    def records(self) -> dict[str, FileRecord]:
        store = StateStore(table_name=TABLE, region=REGION)
        return {r.file_name: r for r in store.list_by_state(ENCRYPTED)}

    def write_lines(self, *entries: dict[str, Any] | str) -> None:
        lines = [e if isinstance(e, str) else json.dumps(e, sort_keys=True) for e in entries]
        self.output_json.write_text("".join(line + os.linesep for line in lines))

    def entry(self, rel: str) -> dict[str, Any]:
        return {
            "header": json.loads(json.dumps(self.headers[rel])),
            "input": os.path.abspath(self.proj / "encrypt" / rel),
            "mode": "encrypt",
            "output": os.path.abspath(self.proj / "encrypted" / f"{rel}.encrypted"),
        }


def _encrypt_like_aws_encryption_cli(key_arn: str, plaintext: bytes) -> bytes:
    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )
    provider = StrictAwsKmsMasterKeyProvider(key_ids=[key_arn])
    ciphertext, _ = client.encrypt(
        source=plaintext, key_provider=provider, encryption_context={"purpose": "backup"}
    )
    return bytes(ciphertext)


def _provision() -> tuple[str, dict[str, str]]:
    ddb = boto3.client("dynamodb", region_name=REGION)
    ddb.create_table(
        TableName=TABLE,
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[
            {"AttributeName": n, "AttributeType": "S"}
            for n in ("PK", "SK", "current_state", "encrypted_at", "date", "last_updated")
        ],
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "state-index",
                "KeySchema": [
                    {"AttributeName": "current_state", "KeyType": "HASH"},
                    {"AttributeName": "encrypted_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "date-index",
                "KeySchema": [
                    {"AttributeName": "date", "KeyType": "HASH"},
                    {"AttributeName": "last_updated", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
    )
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket=BUCKET)
    s3.put_bucket_versioning(Bucket=BUCKET, VersioningConfiguration={"Status": "Enabled"})
    kms = boto3.client("kms", region_name=REGION)
    legacy = kms.create_key(Description="legacy s3_key")["KeyMetadata"]
    kms.create_alias(AliasName=LEGACY_ALIAS, TargetKeyId=legacy["KeyId"])
    kms.create_alias(AliasName=NEW_ALIAS, TargetKeyId=kms.create_key()["KeyMetadata"]["KeyId"])
    account = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
    env = {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",  # noqa: S105
        "AWS_DEFAULT_REGION": REGION,
        "ENVAULT_KEY_ID": NEW_ALIAS,
        "ENVAULT_TABLE": TABLE,
        "ENVAULT_REGION": REGION,
        "ENVAULT_ALLOWED_ACCOUNT_IDS": str(account),
        "COLUMNS": "250",
        **id_key_env(),
    }
    return str(legacy["Arn"]), env


@pytest.fixture
def legacy(tmp_path: pathlib.Path) -> Iterator[Legacy]:
    with mock_aws():
        key_arn, env = _provision()
        proj = tmp_path / "proj"
        for directory in ("code", "encrypt/sub", "encrypted/sub"):
            (proj / directory).mkdir(parents=True)
        s3 = boto3.client("s3", region_name=REGION)
        headers: dict[str, dict[str, Any]] = {}
        for rel, content in (("alpha.txt", ALPHA), ("sub/beta.txt", BETA)):
            (proj / "encrypt" / rel).write_bytes(content)
            ciphertext = _encrypt_like_aws_encryption_cli(key_arn, content)
            (proj / "encrypted" / f"{rel}.encrypted").write_bytes(ciphertext)
            header, _ = deserialize_header(io.BytesIO(ciphertext))
            headers[rel] = _json_ready_header(header)
            # aws s3 sync ../encrypted s3://$S3_BUCKET/encrypted
            s3.put_object(Bucket=BUCKET, Key=f"encrypted/{rel}.encrypted", Body=ciphertext)
        layout = Legacy(proj=proj, key_arn=key_arn, env=env, headers=headers)
        layout.write_lines(layout.entry("alpha.txt"), layout.entry("sub/beta.txt"))
        yield layout


def _migrate(legacy: Legacy, *args: str, env: dict[str, str] | None = None) -> Result:
    return CliRunner().invoke(
        main, ["migrate", str(legacy.output_json), *args], env=env or legacy.env
    )


def _shape(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _shape(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_shape(v) for v in value]
    return type(value).__name__


def test_fixture_matches_genuine_aws_encryption_cli_record_shape(legacy: Legacy) -> None:
    generated = json.loads(legacy.output_json.read_text().splitlines()[0])
    assert _shape(generated) == _shape(GENUINE_RECORD)
    assert os.path.isabs(generated["input"])
    assert (
        base64.b64decode(
            generated["header"]["encrypted_data_keys"][0]["key_provider"]["key_info"]
        ).decode()
        == legacy.key_arn
    )


# ---------------------------------------------------------------------------
# Importing the genuine format
# ---------------------------------------------------------------------------


def test_migrate_imports_real_aws_encryption_cli_output(legacy: Legacy) -> None:
    result = _migrate(legacy)

    assert result.exit_code == 0, result.output
    assert "Migrated 2 records" in result.output
    assert "errors 0" in result.output
    records = legacy.records()
    assert set(records) == {"alpha.txt", "sub/beta.txt"}
    assert records["alpha.txt"].file_id == file_id_of(ALPHA)
    assert records["sub/beta.txt"].file_size_bytes == len(BETA)
    assert records["alpha.txt"].tags == {"source": "migrated"}


def test_migrate_creates_keyed_records(legacy: Legacy) -> None:
    """M6: migrated records are named by the keyed identifier, never by the SHA-256."""
    result = _migrate(legacy)

    assert result.exit_code == 0, result.output
    table = boto3.resource("dynamodb", region_name=REGION).Table(TABLE)
    for content in (ALPHA, BETA):
        sha = hashlib.sha256(content).hexdigest()
        file_id = file_id_of(content)
        row = table.get_item(Key={"PK": f"FILE#{file_id}", "SK": "CURRENT"})["Item"]
        assert row["file_id"] == file_id
        assert row["id_scheme"] == "hmac-sha256-v1"
        assert row["id_key_arn"].startswith(f"arn:aws:kms:{REGION}:")
        assert "sha256_hash" not in row
        assert sha[:16] not in str(row)
        assert "Item" not in table.get_item(Key={"PK": f"FILE#{sha}", "SK": "CURRENT"})
        assert sha[:16] not in result.output


def test_migrate_records_legacy_sync_s3_key(legacy: Legacy) -> None:
    """The keys `aws s3 sync ../encrypted s3://$S3_BUCKET/encrypted` produced (M4 c)."""
    assert _migrate(legacy).exit_code == 0
    records = legacy.records()

    assert records["alpha.txt"].s3_key == "encrypted/alpha.txt.encrypted"
    assert records["sub/beta.txt"].s3_key == "encrypted/sub/beta.txt.encrypted"
    for record in records.values():
        assert record.s3_key_scheme == S3_KEY_LEGACY_SYNC
        assert record.s3_version_id == ""  # not pinned without --bucket


def test_migrate_decodes_kms_key_arn(legacy: Legacy) -> None:
    """key_info and message_id are base64 in the metadata (M4 d)."""
    assert _migrate(legacy).exit_code == 0
    record = legacy.records()["alpha.txt"]
    header = legacy.headers["alpha.txt"]

    assert record.kms_key_id == legacy.key_arn
    assert record.message_id == base64.b64decode(header["message_id"]).hex()
    assert record.algorithm == "AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384"
    # The SDK's own context key is not part of what envault verifies.
    assert record.encryption_context == {"purpose": "backup"}


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("key_info", _b64(b"alias/s3_key"), "KMS key ARN"),
        ("key_info", "not base64 at all!", "KMS key ARN"),
        ("provider_id", _b64(b"raw-aes"), "aws-kms"),
    ],
)
def test_migrate_rejects_key_provider_that_is_not_a_kms_key_arn(
    legacy: Legacy, field: str, value: str, message: str
) -> None:
    entry = legacy.entry("alpha.txt")
    entry["header"]["encrypted_data_keys"][0]["key_provider"][field] = value
    legacy.write_lines(entry, legacy.entry("sub/beta.txt"))

    result = _migrate(legacy)

    assert result.exit_code == 1
    assert message in result.output
    assert set(legacy.records()) == {"sub/beta.txt"}


def test_migrate_accepts_unencoded_key_arn(legacy: Legacy) -> None:
    """Hand-written or other-tool records may carry the ARN as plain text."""
    entry = legacy.entry("alpha.txt")
    provider = entry["header"]["encrypted_data_keys"][0]["key_provider"]
    provider["key_info"], provider["provider_id"] = legacy.key_arn, "aws-kms"
    legacy.write_lines(entry)

    result = _migrate(legacy)

    assert result.exit_code == 0, result.output
    assert legacy.records()["alpha.txt"].kms_key_id == legacy.key_arn


def test_migrate_rejects_messages_envault_cannot_decrypt(legacy: Legacy) -> None:
    """Non-committing suites and several data keys are refused on decrypt: refuse them now."""
    non_committing = legacy.entry("alpha.txt")
    non_committing["header"]["algorithm"] = (
        Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384.name
    )
    two_keys = legacy.entry("sub/beta.txt")
    edks = two_keys["header"]["encrypted_data_keys"]
    edks.append(json.loads(json.dumps(edks[0])))
    legacy.write_lines(non_committing, two_keys)

    result = _migrate(legacy)

    assert result.exit_code == 1
    assert "errors 2" in result.output
    assert "committing" in result.output
    assert "data keys" in result.output
    assert legacy.records() == {}


def test_migrate_exits_nonzero_when_records_fail(legacy: Legacy) -> None:
    """M4 b: the summary is printed and the exit status says not everything was imported."""
    (legacy.proj / "encrypt" / "sub" / "beta.txt").unlink()

    result = _migrate(legacy)

    assert result.exit_code == 1
    assert "Migrated 1 records" in result.output
    assert "errors 1" in result.output
    assert "line 2" in result.output
    assert "not found" in result.output


# ---------------------------------------------------------------------------
# Confinement of the paths a metadata file names
# ---------------------------------------------------------------------------


def test_migrate_rejects_input_outside_plaintext_root(
    legacy: Legacy, tmp_path: pathlib.Path
) -> None:
    """Checked lexically, before the path outside is touched in any way."""
    outside = tmp_path / "elsewhere" / "id_rsa"
    outside.parent.mkdir()
    outside.write_bytes(b"-----BEGIN PRIVATE KEY-----\n")
    entry = legacy.entry("alpha.txt")
    entry["input"] = str(outside)
    legacy.write_lines(entry)
    touched: list[str] = []
    real_stat, real_lstat, real_open = os.stat, os.lstat, os.open

    def spy(real):  # type: ignore[no-untyped-def]
        def call(path, *args, **kwargs):  # type: ignore[no-untyped-def]
            touched.append(os.fspath(path) if isinstance(path, (str, os.PathLike)) else "")
            return real(path, *args, **kwargs)

        return call

    with (
        patch("os.stat", spy(real_stat)),
        patch("os.lstat", spy(real_lstat)),
        patch("os.open", spy(real_open)),
    ):
        result = _migrate(legacy)

    assert result.exit_code == 1
    assert "outside the plaintext root" in result.output
    assert not [p for p in touched if "elsewhere" in p], "the outside path was accessed"
    assert legacy.records() == {}


def test_migrate_rejects_traversal_out_of_the_plaintext_root(legacy: Legacy) -> None:
    entry = legacy.entry("alpha.txt")
    entry["input"] = str(legacy.proj / "encrypt" / ".." / ".." / "etc" / "passwd")
    relative = legacy.entry("sub/beta.txt")
    relative["input"] = "../encrypt/../../outside.txt"
    legacy.write_lines(entry, relative)

    result = _migrate(legacy)

    assert result.exit_code == 1
    assert result.output.count("Path traversal not allowed") == 2


def test_migrate_relative_input_resolves_against_the_metadata_directory(legacy: Legacy) -> None:
    """Relative paths are relative to code/, the legacy scripts' working directory."""
    entry = legacy.entry("alpha.txt")
    entry["input"] = "../encrypt/alpha.txt"
    entry["output"] = "../encrypted/alpha.txt.encrypted"
    legacy.write_lines(entry)

    result = _migrate(legacy)

    assert result.exit_code == 0, result.output
    assert legacy.records()["alpha.txt"].s3_key == "encrypted/alpha.txt.encrypted"


def test_migrate_rejects_output_outside_ciphertext_root(legacy: Legacy) -> None:
    entry = legacy.entry("alpha.txt")
    entry["output"] = str(legacy.proj / "other" / "alpha.txt.encrypted")
    legacy.write_lines(entry)

    result = _migrate(legacy)

    assert result.exit_code == 1
    assert "outside the ciphertext root" in result.output


@pytest.mark.parametrize("where", ["directory", "file"])
def test_migrate_rejects_symlinks_inside_the_plaintext_root(
    legacy: Legacy, tmp_path: pathlib.Path, where: str
) -> None:
    secret_dir = tmp_path / "secrets"
    secret_dir.mkdir()
    (secret_dir / "beta.txt").write_bytes(BETA)
    sub = legacy.proj / "encrypt" / "sub"
    if where == "directory":
        (sub / "beta.txt").unlink()
        sub.rmdir()
        sub.symlink_to(secret_dir)
    else:
        (sub / "beta.txt").unlink()
        (sub / "beta.txt").symlink_to(secret_dir / "beta.txt")

    result = _migrate(legacy)

    assert result.exit_code == 1
    assert "Symlink not allowed" in result.output or "symbolic link" in result.output
    assert set(legacy.records()) == {"alpha.txt"}


def test_migrate_root_options(legacy: Legacy, tmp_path: pathlib.Path) -> None:
    """The metadata file can live anywhere when the roots are given explicitly."""
    moved = tmp_path / "metadata.json"
    moved.write_text(legacy.output_json.read_text())

    implicit = CliRunner().invoke(main, ["migrate", str(moved), "--dry-run"], env=legacy.env)
    explicit = CliRunner().invoke(
        main,
        [
            "migrate",
            str(moved),
            "--plaintext-root",
            str(legacy.proj / "encrypt"),
            "--ciphertext-root",
            str(legacy.proj / "encrypted"),
        ],
        env=legacy.env,
    )

    assert implicit.exit_code == 1  # defaults point next to tmp_path, not at the project
    assert explicit.exit_code == 0, explicit.output
    assert set(legacy.records()) == {"alpha.txt", "sub/beta.txt"}


# ---------------------------------------------------------------------------
# Robustness of the import
# ---------------------------------------------------------------------------


def test_migrate_skips_non_object_json_and_continues(legacy: Legacy) -> None:
    legacy.write_lines("[]", legacy.entry("alpha.txt"), "null", "{not json")

    result = _migrate(legacy, "--dry-run")

    assert result.exit_code == 1
    assert "Migrated 1" in result.output
    assert "errors 3" in result.output
    assert legacy.records() == {}  # dry run


def test_migrate_ignores_decrypt_records(legacy: Legacy) -> None:
    """decrypt.sh appends its own (mode "decrypt") records to the same file."""
    decrypt_record = {**legacy.entry("alpha.txt"), "mode": "decrypt"}
    legacy.write_lines(legacy.entry("alpha.txt"), decrypt_record)

    result = _migrate(legacy)

    assert result.exit_code == 0, result.output
    assert "skipped 1" in result.output


def test_migrate_uses_the_latest_record_for_a_file_encrypted_twice(legacy: Legacy) -> None:
    """The metadata file is appended to; the newest record describes the object in S3."""
    older = legacy.entry("alpha.txt")
    older["header"]["message_id"] = _b64(b"\x01" * 32)
    legacy.write_lines(older, legacy.entry("alpha.txt"))

    result = _migrate(legacy)

    assert result.exit_code == 0, result.output
    assert "skipped 1" in result.output
    header = legacy.headers["alpha.txt"]
    assert legacy.records()["alpha.txt"].message_id == base64.b64decode(header["message_id"]).hex()


def test_migrate_reports_unreadable_metadata(legacy: Legacy) -> None:
    legacy.output_json.write_bytes(b"\xff\xfe not utf-8")

    result = _migrate(legacy)

    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_migrate_aws_errors_are_reported_per_record(legacy: Legacy) -> None:
    real = botocore.client.BaseClient._make_api_call

    def deny_put(self, op, kwargs):  # type: ignore[no-untyped-def]
        if op == "PutItem":
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, op)
        return real(self, op, kwargs)

    with patch.object(botocore.client.BaseClient, "_make_api_call", deny_put):
        result = _migrate(legacy)

    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "errors 2" in result.output
    assert "Traceback" not in result.output


def test_migrate_twice_skips_existing_records(legacy: Legacy) -> None:
    assert _migrate(legacy).exit_code == 0

    again = _migrate(legacy)

    assert again.exit_code == 0, again.output
    assert "Migrated 0 records" in again.output
    assert "skipped 2" in again.output


# ---------------------------------------------------------------------------
# Using migrated records
# ---------------------------------------------------------------------------


def _decrypt(legacy: Legacy, name: str, out: pathlib.Path, *args: str) -> Result:
    env = {**legacy.env, "ENVAULT_BUCKET": BUCKET}
    return CliRunner().invoke(main, ["decrypt", name, "-o", str(out), *args], env=env)


def test_decrypt_migrated_record_from_its_legacy_key(
    legacy: Legacy, tmp_path: pathlib.Path
) -> None:
    assert _migrate(legacy).exit_code == 0

    alpha = _decrypt(legacy, "alpha.txt", tmp_path / "alpha.out", "--latest")
    beta = _decrypt(legacy, "sub/beta.txt", tmp_path / "beta.out", "--latest")
    by_basename = _decrypt(legacy, "beta.txt", tmp_path / "beta2.out", "--latest")
    unpinned = _decrypt(legacy, "alpha.txt", tmp_path / "refused.out")

    assert alpha.exit_code == 0, alpha.output
    assert (tmp_path / "alpha.out").read_bytes() == ALPHA
    assert beta.exit_code == 0, beta.output
    assert (tmp_path / "beta.out").read_bytes() == BETA
    assert by_basename.exit_code == 0, by_basename.output
    assert unpinned.exit_code == 1  # no VersionId pinned: --latest is required
    assert "--latest" in unpinned.output


def test_migrate_with_bucket_pins_versions(legacy: Legacy, tmp_path: pathlib.Path) -> None:
    current = boto3.client("s3", region_name=REGION).head_object(
        Bucket=BUCKET, Key="encrypted/alpha.txt.encrypted"
    )["VersionId"]

    result = _migrate(legacy, "--bucket", BUCKET)

    assert result.exit_code == 0, result.output
    assert legacy.records()["alpha.txt"].s3_version_id == current
    out = tmp_path / "alpha.out"
    decrypted = _decrypt(legacy, "alpha.txt", out)  # no --latest needed
    assert decrypted.exit_code == 0, decrypted.output
    assert out.read_bytes() == ALPHA


def test_migrate_with_bucket_reports_missing_objects(legacy: Legacy) -> None:
    boto3.client("s3", region_name=REGION).delete_object(
        Bucket=BUCKET, Key="encrypted/sub/beta.txt.encrypted"
    )

    result = _migrate(legacy, "--bucket", BUCKET)

    assert result.exit_code == 1
    assert "encrypted/sub/beta.txt.encrypted" in result.output
    assert set(legacy.records()) == {"alpha.txt"}


def test_exec_and_rotate_key_handle_migrated_records(
    legacy: Legacy, tmp_path: pathlib.Path
) -> None:
    assert _migrate(legacy).exit_code == 0
    env = {**legacy.env, "ENVAULT_BUCKET": BUCKET}
    captured: dict[str, str] = {}
    with patch("os.execvpe", lambda f, argv, e: captured.update(e)):
        ran = CliRunner().invoke(
            main, ["exec", "--latest", "-s", "alpha.txt=SECRET", "--", "/bin/true"], env=env
        )
    assert ran.exit_code == 0, ran.output
    assert captured["SECRET"] == ALPHA.decode().rstrip("\n")

    rotated = CliRunner().invoke(
        main, ["rotate-key", "--new-key-id", NEW_ALIAS, "--latest"], env=env
    )

    assert rotated.exit_code == 0, rotated.output
    record = legacy.records()["alpha.txt"]
    assert record.s3_key_scheme == S3_KEY_CONTENT_ADDRESSED
    assert record.s3_key.startswith(f"encrypted/{record.file_id[:2]}/{record.file_id}/")
    # The legacy object is left as it was.
    s3 = boto3.client("s3", region_name=REGION)
    assert s3.head_object(Bucket=BUCKET, Key="encrypted/alpha.txt.encrypted")
    out = tmp_path / "after-rotation.out"
    decrypted = _decrypt(legacy, "alpha.txt", out)  # pinned by the rotation
    assert decrypted.exit_code == 0, decrypted.output
    assert out.read_bytes() == ALPHA


@pytest.mark.parametrize(
    ("scheme", "key", "message"),
    [
        (S3_KEY_LEGACY_SYNC, "other-prefix/alpha.txt.encrypted", "legacy-sync"),
        (S3_KEY_LEGACY_SYNC, "encrypted/../../alpha.txt.encrypted", "legacy-sync"),
        ("made-up", "encrypted/alpha.txt.encrypted", "key scheme"),
    ],
)
def test_record_key_is_validated_by_its_scheme(
    legacy: Legacy, tmp_path: pathlib.Path, scheme: str, key: str, message: str
) -> None:
    assert _migrate(legacy).exit_code == 0
    record = legacy.records()["alpha.txt"]
    table = boto3.resource("dynamodb", region_name=REGION).Table(TABLE)
    table.update_item(
        Key={"PK": f"FILE#{record.file_id}", "SK": "CURRENT"},
        UpdateExpression="SET s3_key = :k, s3_key_scheme = :s",
        ExpressionAttributeValues={":k": key, ":s": scheme},
    )

    result = _decrypt(legacy, "alpha.txt", tmp_path / "out", "--latest")

    assert result.exit_code == 1
    assert message in result.output
    assert not (tmp_path / "out").exists()


def test_migrate_null_header_is_a_per_record_error(legacy: Legacy) -> None:
    """A record without a header object cannot name its key: an error, not a crash."""
    broken = {**legacy.entry("alpha.txt"), "header": None}
    legacy.write_lines(broken, legacy.entry("sub/beta.txt"))

    result = _migrate(legacy)

    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "no header" in result.output
    assert set(legacy.records()) == {"sub/beta.txt"}
