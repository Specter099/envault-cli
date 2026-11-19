"""`envault rotate-key` with real crypto against moto (M7, L2)."""

from __future__ import annotations

import logging
import pathlib
from collections.abc import Iterator
from unittest.mock import patch

import boto3
import pytest
from click.testing import CliRunner, Result
from moto import mock_aws

from envault import identity
from envault.cli import main
from envault.state import ENCRYPTED, FileRecord, StateStore

from ._id_key import id_key_env

TABLE = "envault-test-state"
BUCKET = "envault-test-bucket"
ALIAS = "alias/envault-test"
NEW_ALIAS = "alias/new-key"
REGION = "us-east-1"
SECRET = b"postgres://user:hunter2@db.internal:5432/app\n"  # pragma: allowlist secret


@pytest.fixture(autouse=True)
def _clear_identity_cache() -> Iterator[None]:
    identity.reset_cache()
    yield
    identity.reset_cache()


@pytest.fixture
def env(tmp_path: pathlib.Path) -> Iterator[dict[str, str]]:
    """Provisioned moto account with one file, db.env, encrypted under ALIAS."""
    with mock_aws():
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
        for alias in (ALIAS, NEW_ALIAS):
            kms.create_alias(AliasName=alias, TargetKeyId=kms.create_key()["KeyMetadata"]["KeyId"])
        account = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
        environment = {
            "AWS_ACCESS_KEY_ID": "testing",
            "AWS_SECRET_ACCESS_KEY": "testing",  # noqa: S105  # pragma: allowlist secret
            "AWS_DEFAULT_REGION": REGION,
            "ENVAULT_KEY_ID": ALIAS,
            "ENVAULT_BUCKET": BUCKET,
            "ENVAULT_TABLE": TABLE,
            "ENVAULT_REGION": REGION,
            "ENVAULT_ALLOWED_ACCOUNT_IDS": str(account),
            "COLUMNS": "250",
            **id_key_env(),
        }
        (tmp_path / "db.env").write_bytes(SECRET)
        result = CliRunner().invoke(main, ["encrypt", str(tmp_path / "db.env")], env=environment)
        assert result.exit_code == 0, result.output
        yield environment


def _run(env: dict[str, str], *args: str) -> Result:
    return CliRunner().invoke(main, list(args), env=env)


def _record() -> FileRecord:
    [record] = StateStore(table_name=TABLE, region=REGION).list_by_state(ENCRYPTED)
    return record


def _versions_at(key: str) -> list[dict[str, object]]:
    listing = boto3.client("s3", region_name=REGION).list_object_versions(Bucket=BUCKET)
    return [v for v in listing.get("Versions", []) if v["Key"] == key]


def _decrypts(env: dict[str, str], tmp_path: pathlib.Path) -> bool:
    out = tmp_path / "check.env"
    out.unlink(missing_ok=True)
    result = _run(env, "decrypt", "db.env", "-o", str(out))
    return result.exit_code == 0 and out.read_bytes() == SECRET


def test_rotate_key_repoints_to_a_new_key_and_leaves_the_old_object(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    before = _record()
    [old_version] = _versions_at(before.s3_key)

    result = _run(env, "rotate-key", "--new-key-id", NEW_ALIAS)

    assert result.exit_code == 0, result.output
    after = _record()
    assert after.kms_key_id == NEW_ALIAS
    sha = after.file_id
    assert after.s3_key == f"encrypted/{sha[:2]}/{sha}/{after.message_id}/db.env.encrypted"
    assert after.message_id != before.message_id
    assert _versions_at(before.s3_key) == [old_version]  # untouched, still current
    [new_version] = _versions_at(after.s3_key)
    assert new_version["VersionId"] == after.s3_version_id
    assert _decrypts(env, tmp_path)


def test_rotate_key_state_write_failure_leaves_record_on_the_intact_old_object(
    env: dict[str, str], tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The re-encrypted upload is an orphan; the record still decrypts from the old key."""
    from envault.exceptions import StateConflictError

    before = _record()
    with (
        patch.object(StateStore, "put_current_state", side_effect=StateConflictError("raced")),
        caplog.at_level(logging.ERROR, logger="envault.cli"),
    ):
        result = _run(env, "rotate-key", "--new-key-id", NEW_ALIAS)

    assert result.exit_code == 1
    assert "Rotation incomplete" in result.output
    assert _record() == before
    logged = [r for r in caplog.records if "orphan" in r.getMessage()]
    assert logged
    orphan = logged[0].__dict__
    assert orphan["s3_key"] != before.s3_key
    assert orphan["old_kms_key"] == ALIAS
    assert orphan["new_kms_key"] == NEW_ALIAS
    assert _decrypts(env, tmp_path)
