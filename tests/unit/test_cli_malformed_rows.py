"""A state-table row of the wrong shape (N2): skipped by listings, refused by lookups.

Anyone with write access to the DynamoDB table can put a row there whose
attributes have types envault never writes: a file name that is a list or a
number, an encryption context that is a string. One such row used to crash
every basename lookup (decrypt NAME and exec -s NAME, whenever the basename
fallback ran), and status and rotate-key, with a traceback. Now:

- listings skip such a row and say so: status warns, rotate-key reports a ✗
  for it, rotates the others and exits 1;
- the basename fallback ignores it;
- an exact-name or hash lookup that lands on it is refused (exit 1).
"""

from __future__ import annotations

import hashlib
import pathlib
from collections.abc import Iterator
from decimal import Decimal
from typing import Any
from unittest.mock import patch

import boto3
import pytest
from click.testing import CliRunner, Result
from moto import mock_aws

from envault import identity
from envault.cli import main

from ._id_key import ID_KEY_ALIAS, create_id_key, file_id_of

TABLE = "envault-test-state"
BUCKET = "envault-test-bucket"
ALIAS = "alias/envault-test"
NEW_ALIAS = "alias/new-key"
REGION = "us-east-1"
GOOD = b"DATABASE_URL=postgres://app@db.internal/app\n"
BAD_ID = "e" * 64


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
            "AWS_SECRET_ACCESS_KEY": "testing",  # noqa: S105  # pragma: allowlist secret
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


def _table() -> Any:
    return boto3.resource("dynamodb", region_name=REGION).Table(TABLE)


def _current(file_id: str) -> dict[str, Any]:
    return dict(_table().get_item(Key={"PK": f"FILE#{file_id}", "SK": "CURRENT"})["Item"])


class _Exec:
    """Stands in for os.execvpe and records the environment the child would get."""

    def __init__(self) -> None:
        self.env: dict[str, str] | None = None

    def __call__(self, file: str, argv: list[str], env: dict[str, str]) -> None:
        self.env = dict(env)


def _encrypt_tree(env: dict[str, str], tmp_path: pathlib.Path) -> str:
    """Encrypt dir/db.env (stored under that relative name); return its identifier."""
    tree = tmp_path / "tree"
    (tree / "dir").mkdir(parents=True)
    (tree / "dir" / "db.env").write_bytes(GOOD)
    result = _run(env, "encrypt", str(tree))
    assert result.exit_code == 0, result.output
    return file_id_of(GOOD)


def _plant(source_id: str, **attributes: object) -> None:
    """A copy of a good row under another key, with some attributes of the wrong type."""
    row = {**_current(source_id), "PK": f"FILE#{BAD_ID}", "file_id": BAD_ID, **attributes}
    _table().put_item(Item=row)


def _no_traceback(result: Result) -> None:
    assert result.exception is None or isinstance(result.exception, SystemExit), repr(
        result.exception
    )


# ---------------------------------------------------------------------------
# Listings and the basename fallback skip the row
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("file_name", [["db.env"], Decimal(7)], ids=["list", "number"])
def test_basename_lookup_ignores_row_with_non_string_file_name(
    env: dict[str, str], tmp_path: pathlib.Path, file_name: object
) -> None:
    """decrypt db.env / exec -s db.env fall back to basenames and must not trip on the row."""
    _plant(_encrypt_tree(env, tmp_path), file_name=file_name)
    out = tmp_path / "out.txt"
    rec = _Exec()

    decrypted = _run(env, "decrypt", "db.env", "-o", str(out))
    with patch("os.execvpe", rec):
        ran = _run(env, "exec", "-s", "db.env=SECRET", "--", "/bin/true")

    for result in (decrypted, ran):
        _no_traceback(result)
        assert result.exit_code == 0, result.output
    assert out.read_bytes() == GOOD
    assert rec.env is not None and rec.env["SECRET"] == GOOD.decode().rstrip("\n")


def test_status_and_rotate_key_survive_row_with_non_map_context(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    good_id = _encrypt_tree(env, tmp_path)
    _plant(good_id, encryption_context="purpose=envault-backup", file_name="evil.env")

    status = _run(env, "status")
    dry_run = _run(env, "rotate-key", "--new-key-id", NEW_ALIAS, "--dry-run")
    rotated = _run(env, "rotate-key", "--new-key-id", NEW_ALIAS)

    for result in (status, dry_run, rotated):
        _no_traceback(result)
    # status: the good file is listed, the bad row gets one warning line.
    assert status.exit_code == 0, status.output
    assert "dir/db.env" in status.output
    assert status.output.count("is malformed") == 1
    assert f"{BAD_ID[:16]}..." in status.output
    assert "encryption_context is not a map of strings" in status.output
    assert "evil.env" not in status.output
    # rotate-key: a ✗ for the bad row, the good file is rotated, exit 1.
    for result in (dry_run, rotated):
        assert result.exit_code == 1, result.output
        assert result.output.count("✗") == 1
        assert "encryption_context is not a map of strings" in result.output
    assert "Would rotate: dir/db.env" in dry_run.output
    assert "Rotation incomplete" in rotated.output
    assert _current(good_id)["kms_key_id"] == NEW_ALIAS
    assert _current(BAD_ID)["kms_key_id"] == ALIAS  # left alone


# ---------------------------------------------------------------------------
# Lookups that land on the row refuse it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "how", ["decrypt-by-id", "decrypt-by-sha256", "exec-by-id", "status-by-id"]
)
def test_hash_lookup_refuses_malformed_row(
    env: dict[str, str], tmp_path: pathlib.Path, how: str
) -> None:
    file_id = _encrypt_tree(env, tmp_path)
    _table().put_item(Item={**_current(file_id), "tags": "project=x"})
    typed = hashlib.sha256(GOOD).hexdigest() if how == "decrypt-by-sha256" else file_id
    out = tmp_path / "out.txt"
    rec = _Exec()

    with patch("os.execvpe", rec):
        if how.startswith("decrypt"):
            result = _run(env, "decrypt", typed, "-o", str(out))
        elif how.startswith("exec"):
            result = _run(env, "exec", "-s", f"{typed}=SECRET", "--", "/bin/true")
        else:
            result = _run(env, "status", "--file", typed)

    _no_traceback(result)
    assert result.exit_code == 1, result.output
    assert "is malformed" in result.output
    assert "tags is not a map of strings" in result.output
    assert not out.exists()
    assert rec.env is None


def test_exact_name_lookup_refuses_malformed_row(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    """A row stored under exactly the name asked for, but malformed: no guessing."""
    good_id = _encrypt_tree(env, tmp_path)
    _plant(good_id, file_size_bytes="many")  # still named dir/db.env
    out = tmp_path / "out.txt"

    result = _run(env, "decrypt", "dir/db.env", "-o", str(out))

    _no_traceback(result)
    assert result.exit_code == 1, result.output
    assert "'dir/db.env' matches a malformed record" in result.output
    assert "file_size_bytes is not a whole number of bytes" in result.output
    assert not out.exists()


def test_encrypt_reports_a_malformed_existing_record_for_that_file(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    file_id = _encrypt_tree(env, tmp_path)
    _table().put_item(Item={**_current(file_id), "message_id": Decimal(1)})
    (tmp_path / "db.env").write_bytes(GOOD)

    result = _run(env, "encrypt", "--force", str(tmp_path / "db.env"))

    _no_traceback(result)
    assert result.exit_code == 1, result.output
    assert "✗ db.env" in result.output
    assert "message_id is a Decimal, not a string" in result.output
