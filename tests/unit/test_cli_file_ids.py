"""File identifiers through the CLI (M6), with real crypto against moto.

The SHA-256 of a file's plaintext was its public identifier: the DynamoDB key,
part of the S3 key, a value in the KMS encryption context (which CloudTrail
logs), and in console and log output. For a short or guessable file that hash
is the content (r20 recovered a 6-digit PIN from an S3 key in 0.28 s). New
records are named by ``file_id = HMAC-SHA-256(ID key, SHA-256(plaintext))``
instead, computed by KMS GenerateMac, and nothing envault writes or prints for
them carries the raw hash.

Records written before (rows without ``id_scheme``, identified by the raw
SHA-256) must keep working. ``_legacy_record`` stores one exactly as envault
did then, attribute for attribute, without going through today's code.
"""

from __future__ import annotations

import hashlib
import pathlib
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Any
from unittest.mock import patch

import boto3
import pytest
from click.testing import CliRunner, Result
from moto import mock_aws

from envault import cli as cli_mod
from envault import identity
from envault.cli import main
from envault.crypto import encrypt_file

from ._id_key import ID_KEY_ALIAS, create_id_key

TABLE = "envault-test-state"
BUCKET = "envault-test-bucket"
ALIAS = "alias/envault-test"
NEW_ALIAS = "alias/new-key"
REGION = "us-east-1"

#: A low-entropy secret: its SHA-256 can be inverted by trying a million PINs.
PIN = b"493017\n"
OTHER = b"DATABASE_URL=postgres://app@db.internal/app\n"


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


@pytest.fixture(autouse=True)
def _clear_identity_cache() -> Iterator[None]:
    identity.reset_cache()
    yield
    identity.reset_cache()


@pytest.fixture
def env() -> Iterator[dict[str, str]]:
    with mock_aws():
        boto3.client("dynamodb", region_name=REGION).create_table(
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
        for alias in (ALIAS, NEW_ALIAS):
            kms.create_alias(AliasName=alias, TargetKeyId=kms.create_key()["KeyMetadata"]["KeyId"])
        create_id_key()
        account = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
        yield {
            "AWS_ACCESS_KEY_ID": "testing",
            "AWS_SECRET_ACCESS_KEY": "testing",  # noqa: S105
            "AWS_DEFAULT_REGION": REGION,
            "ENVAULT_KEY_ID": ALIAS,
            "ENVAULT_BUCKET": BUCKET,
            "ENVAULT_TABLE": TABLE,
            "ENVAULT_REGION": REGION,
            "ENVAULT_ALLOWED_ACCOUNT_IDS": str(account),
            "ENVAULT_ID_KEY_ID": ID_KEY_ALIAS,
            "COLUMNS": "250",
        }


def _run(env: dict[str, str], *args: str) -> Result:
    return CliRunner().invoke(main, list(args), env=env)


class _Exec:
    """Stands in for os.execvpe and records the environment the child would get."""

    def __init__(self) -> None:
        self.env: dict[str, str] | None = None

    def __call__(self, file: str, argv: list[str], env: dict[str, str]) -> None:
        self.env = dict(env)


def _exec(env: dict[str, str], identifier: str) -> tuple[Result, _Exec]:
    rec = _Exec()
    with patch("os.execvpe", rec):
        result = _run(env, "exec", "-s", f"{identifier}=SECRET", "--", "/bin/true")
    return result, rec


def _table() -> Any:
    return boto3.resource("dynamodb", region_name=REGION).Table(TABLE)


def _current(pk_id: str) -> dict[str, Any]:
    return dict(_table().get_item(Key={"PK": f"FILE#{pk_id}", "SK": "CURRENT"})["Item"])


# ---------------------------------------------------------------------------
# Records as envault wrote them before keyed identifiers
# ---------------------------------------------------------------------------


def _legacy_record(
    content: bytes, name: str, tmp_path: pathlib.Path, *, per_upload_key: bool = True
) -> dict[str, Any]:
    """Store ``content`` exactly as envault did before keyed identifiers; return the row.

    Ciphertext under the legacy encryption context (which names the raw
    SHA-256), at a key embedding that SHA-256, and a CURRENT row plus an
    ENCRYPT event in the attribute layout ``FileRecord.to_dynamo_item`` wrote
    then: ``sha256_hash``, no ``id_scheme``. ``per_upload_key=False`` gives the
    key format used before per-upload keys (M7).
    """
    sha = _sha256(content)
    work = tmp_path / f"legacy-{sha[:12]}"
    work.mkdir()
    (work / "plain").write_bytes(content)
    context = {
        "purpose": "envault-backup",
        "sha256": sha,
        "file_name": name,
        "kms_key_alias": ALIAS,
    }
    result = encrypt_file(work / "plain", ALIAS, context, work / "cipher", REGION)
    base = pathlib.PurePosixPath(name).name
    s3_key = (
        f"encrypted/{sha[:2]}/{sha}/{result.message_id}/{base}.encrypted"
        if per_upload_key
        else f"encrypted/{sha[:2]}/{sha}/{base}.encrypted"
    )
    put = boto3.client("s3", region_name=REGION).put_object(
        Bucket=BUCKET, Key=s3_key, Body=(work / "cipher").read_bytes()
    )
    for path in work.iterdir():
        path.unlink()
    work.rmdir()

    now = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    row = {
        "PK": f"FILE#{sha}",
        "SK": "CURRENT",
        "sha256_hash": sha,
        "file_name": name,
        "current_state": "ENCRYPTED",
        "s3_key": s3_key,
        "kms_key_id": ALIAS,
        "encryption_context": context,
        "algorithm": result.algorithm,
        "message_id": result.message_id,
        "file_size_bytes": len(content),
        "tags": {},
        "s3_version_id": put["VersionId"],
        "encrypted_at": now,
        "last_updated": now,
        "s3_key_scheme": "content-addressed",
    }
    _table().put_item(Item=row)
    event = {k: v for k, v in row.items() if k != "current_state"}
    event.update(
        SK=f"EVENT#{now}#ENCRYPT#0000beef",
        record_state="ENCRYPTED",
        operation="ENCRYPT",
        correlation_id="legacy-run",
        principal_arn="arn:aws:iam::123456789012:user/legacy",
        date=now[:10],
        ttl=int(time.time()) + 86400,
    )
    _table().put_item(Item=event)
    return row


def _substitute_ciphertext(row: dict[str, Any], donor: dict[str, Any]) -> None:
    """Point ``row`` (keeping its own identifier) at ``donor``'s ciphertext and context.

    The donor's object is copied to a key shaped for ``row``'s identifier, so
    every attribute check passes: only the content check can catch it.
    """
    pk_id = str(row["PK"]).removeprefix("FILE#")
    s3 = boto3.client("s3", region_name=REGION)
    body = s3.get_object(Bucket=BUCKET, Key=donor["s3_key"], VersionId=donor["s3_version_id"])
    forged_key = f"encrypted/{pk_id[:2]}/{pk_id}/{donor['message_id']}/forged.encrypted"
    put = s3.put_object(Bucket=BUCKET, Key=forged_key, Body=body["Body"].read())
    _table().put_item(
        Item={
            **row,
            "s3_key": forged_key,
            "s3_version_id": put["VersionId"],
            "message_id": donor["message_id"],
            "encryption_context": donor["encryption_context"],
        }
    )


# ---------------------------------------------------------------------------
# The plaintext's own hash never reaches a message (either scheme)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", ["decrypt", "exec"])
def test_checksum_mismatch_output_names_no_plaintext_hash(
    env: dict[str, str], tmp_path: pathlib.Path, command: str
) -> None:
    """A legacy record pointed at the PIN's ciphertext: refused, and the PIN's hash unsaid."""
    victim = _legacy_record(OTHER, "db.env", tmp_path)
    donor = _legacy_record(PIN, "pin.txt", tmp_path)
    _substitute_ciphertext(victim, donor)
    out = tmp_path / "out.txt"

    if command == "decrypt":
        result = _run(env, "decrypt", _sha256(OTHER), "-o", str(out))
        assert not out.exists()
    else:
        result, rec = _exec(env, _sha256(OTHER))
        assert rec.env is None, "the command must not run"

    assert result.exit_code == 1, result.output
    assert "checksum mismatch" in result.output.lower()
    assert _sha256(PIN)[:16] not in result.output


def test_encrypt_of_a_file_modified_while_encrypting_names_no_hash(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    (tmp_path / "pin.txt").write_bytes(PIN)
    real = cli_mod.encrypt_fd
    changed = b"493018\n"

    def encrypt_changed_file(fd: int, **kwargs: Any) -> Any:
        result = real(fd, **kwargs)
        result.sha256_hash = _sha256(changed)
        return result

    with patch.object(cli_mod, "encrypt_fd", encrypt_changed_file):
        result = _run(env, "encrypt", str(tmp_path / "pin.txt"))

    assert result.exit_code == 1, result.output
    assert "modified during encryption" in result.output
    for content in (PIN, changed):
        assert _sha256(content)[:16] not in result.output
