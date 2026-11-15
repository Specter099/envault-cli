"""How decrypt and exec turn IDENTIFIER into a record (M5, M8).

Hash identifiers: the row stored under a hash must describe that hash, and the
plaintext must hash to what the operator typed (M5). A table writer can copy
another file's attributes under any key; that must not deliver the other file.

Names: encrypt stores each file's path relative to the encrypted directory, so
two files with the same basename stay distinguishable. A name that matches more
than one stored path is ambiguous, and decrypt and exec refuse it rather than
pick one (M8).

Real crypto against moto throughout: the checksum and context checks under test
live in the interaction with the Encryption SDK.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
from collections.abc import Iterator
from unittest.mock import patch

import boto3
import pytest
from click.testing import CliRunner, Result
from moto import mock_aws

from envault import identity
from envault.cli import main
from envault.state import ENCRYPTED, StateStore

from ._id_key import id_key_env

TABLE = "envault-test-state"
BUCKET = "envault-test-bucket"
ALIAS = "alias/envault-test"
REGION = "us-east-1"

A = b"DATABASE_URL=postgres://prod-db.internal/app\n"
B = b"DATABASE_URL=postgres://attacker.example/app\n"
HA = hashlib.sha256(A).hexdigest()
HB = hashlib.sha256(B).hexdigest()
PROD = b"postgres://PROD\n"
STAGING = b"postgres://STAGING\n"


@pytest.fixture(autouse=True)
def _clear_identity_cache() -> Iterator[None]:
    identity.reset_cache()
    yield
    identity.reset_cache()


@pytest.fixture
def env() -> Iterator[dict[str, str]]:
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
        kms.create_alias(AliasName=ALIAS, TargetKeyId=kms.create_key()["KeyMetadata"]["KeyId"])
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
            "COLUMNS": "250",
            **id_key_env(),
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


def _table() -> object:
    return boto3.resource("dynamodb", region_name=REGION).Table(TABLE)


def _current(sha: str) -> dict[str, object]:
    item = _table().get_item(Key={"PK": f"FILE#{sha}", "SK": "CURRENT"})["Item"]  # type: ignore[attr-defined]
    return dict(item)


def _encrypt_pair(env: dict[str, str], tmp_path: pathlib.Path) -> None:
    for name, content in (("a.env", A), ("b.env", B)):
        (tmp_path / name).write_bytes(content)
        assert _run(env, "encrypt", str(tmp_path / name)).exit_code == 0


# ---------------------------------------------------------------------------
# M5: a hash identifier must match the row it resolves to
# ---------------------------------------------------------------------------


def _copy_row_b_onto_a() -> None:
    """r03: a plain PutItem copying row B's attributes under row A's key."""
    _table().put_item(Item={**_current(HB), "PK": f"FILE#{HA}"})  # type: ignore[attr-defined]


def test_decrypt_by_hash_rejects_row_with_different_sha256(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    _encrypt_pair(env, tmp_path)
    _copy_row_b_onto_a()
    out = tmp_path / "out.env"

    result = _run(env, "decrypt", HA, "-o", str(out))

    assert result.exit_code == 1, result.output
    assert not out.exists()
    assert "different file" in result.output
    assert list(tmp_path.glob(".out.env*")) == []


def test_exec_by_hash_rejects_row_with_different_sha256(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    _encrypt_pair(env, tmp_path)
    _copy_row_b_onto_a()

    result, rec = _exec(env, HA)

    assert result.exit_code == 1, result.output
    assert rec.env is None, "the command must not run"
    assert "different file" in result.output


def test_decrypt_by_hash_checks_plaintext_against_the_typed_hash(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    """Row A, with its own hash kept, pointed at B's ciphertext copied to an A-shaped key.

    Every attribute check passes (the key embeds A's hash, the context is B's
    real context), so only hashing the plaintext against what the operator
    typed stops B being delivered as A.
    """
    _encrypt_pair(env, tmp_path)
    row_a, row_b = _current(HA), _current(HB)
    s3 = boto3.client("s3", region_name=REGION)
    body = s3.get_object(Bucket=BUCKET, Key=row_b["s3_key"], VersionId=row_b["s3_version_id"])
    forged_key = str(row_b["s3_key"]).replace(HB[:2] + "/" + HB, HA[:2] + "/" + HA)
    put = s3.put_object(Bucket=BUCKET, Key=forged_key, Body=body["Body"].read())
    _table().put_item(  # type: ignore[attr-defined]
        Item={
            **row_a,
            "s3_key": forged_key,
            "s3_version_id": put["VersionId"],
            "message_id": row_b["message_id"],
            "encryption_context": row_b["encryption_context"],
        }
    )
    out = tmp_path / "out.env"

    result = _run(env, "decrypt", HA, "-o", str(out))
    exec_result, rec = _exec(env, HA)

    assert result.exit_code == 1, result.output
    assert "checksum mismatch" in result.output.lower()
    assert not out.exists()
    assert exec_result.exit_code == 1
    assert rec.env is None


def test_decrypt_refuses_record_whose_identifier_is_malformed(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    """A name lookup returns whatever the row says its hash is; it must be a hash."""
    _encrypt_pair(env, tmp_path)
    _table().update_item(  # type: ignore[attr-defined]
        Key={"PK": f"FILE#{HA}", "SK": "CURRENT"},
        UpdateExpression="SET sha256_hash = :h",
        ExpressionAttributeValues={":h": "../../../tmp/evil"},
    )
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    result = _run(env, "decrypt", "a.env", "-o", str(out_dir))

    assert result.exit_code == 1, result.output
    assert list(out_dir.iterdir()) == []


# ---------------------------------------------------------------------------
# M8: names are paths relative to the encrypted directory
# ---------------------------------------------------------------------------


@pytest.fixture
def two_db_envs(env: dict[str, str], tmp_path: pathlib.Path) -> dict[str, str]:
    """`encrypt secrets/` with secrets/prod/db.env and secrets/staging/db.env (r12 R12)."""
    secrets = tmp_path / "secrets"
    (secrets / "prod").mkdir(parents=True)
    (secrets / "staging").mkdir()
    (secrets / "prod" / "db.env").write_bytes(PROD)
    (secrets / "staging" / "db.env").write_bytes(STAGING)
    result = _run(env, "encrypt", str(secrets))
    assert result.exit_code == 0, result.output
    return env


def test_encrypt_dir_stores_relative_paths(two_db_envs: dict[str, str]) -> None:
    store = StateStore(table_name=TABLE, region=REGION)
    records = {r.file_name: r for r in store.list_by_state(ENCRYPTED)}

    assert set(records) == {"prod/db.env", "staging/db.env"}
    for record in records.values():
        # The S3 key keeps the sanitized basename; the context binds the stored name.
        assert record.s3_key.endswith("/db.env.encrypted")
        assert record.encryption_context["file_name"] == record.file_name


def test_encrypt_single_file_stores_its_basename(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "one.env").write_bytes(PROD)

    assert _run(env, "encrypt", str(tmp_path / "sub" / "one.env")).exit_code == 0

    [record] = StateStore(table_name=TABLE, region=REGION).list_by_state(ENCRYPTED)
    assert record.file_name == "one.env"


def test_new_records_have_microsecond_encrypted_at(two_db_envs: dict[str, str]) -> None:
    for record in StateStore(table_name=TABLE, region=REGION).list_by_state(ENCRYPTED):
        assert len(record.encrypted_at) == len("2026-11-15T10:00:00.123456+00:00")


def test_exec_refuses_ambiguous_filename(two_db_envs: dict[str, str]) -> None:
    """r12 R12: `exec -s db.env=...` delivered one of the two arbitrarily."""
    result, rec = _exec(two_db_envs, "db.env")

    assert result.exit_code == 1, result.output
    assert rec.env is None, "the command must not run"
    assert "ambiguous" in result.output.lower()
    assert "prod/db.env" in result.output
    assert "staging/db.env" in result.output


def test_decrypt_ambiguous_basename_lists_candidates(
    two_db_envs: dict[str, str], tmp_path: pathlib.Path
) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    result = _run(two_db_envs, "decrypt", "db.env", "-o", str(out_dir))

    assert result.exit_code == 1, result.output
    assert "ambiguous" in result.output.lower()
    for name, content in (("prod/db.env", PROD), ("staging/db.env", STAGING)):
        line = next(line for line in result.output.splitlines() if name in line)
        assert hashlib.sha256(content).hexdigest()[:16] in line
    assert list(out_dir.iterdir()) == []


def test_decrypt_full_relative_name_selects_file(
    two_db_envs: dict[str, str], tmp_path: pathlib.Path
) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    result = _run(two_db_envs, "decrypt", "prod/db.env", "-o", str(out_dir))

    assert result.exit_code == 0, result.output
    # The output keeps the safe basename, never the stored directory part.
    assert (out_dir / "db.env").read_bytes() == PROD
    assert sorted(p.name for p in out_dir.iterdir()) == ["db.env"]


def test_exec_full_relative_name_selects_file(two_db_envs: dict[str, str]) -> None:
    result, rec = _exec(two_db_envs, "staging/db.env")

    assert result.exit_code == 0, result.output
    assert rec.env is not None
    assert rec.env["SECRET"] == STAGING.decode().rstrip("\n")


def test_unknown_relative_name_does_not_fall_back_to_basename(
    two_db_envs: dict[str, str],
) -> None:
    """`qa/db.env` must not quietly match `prod/db.env` through its basename."""
    result, rec = _exec(two_db_envs, "qa/db.env")

    assert result.exit_code == 1
    assert rec.env is None
    assert "No encrypted files found" in result.output


def test_rows_storing_a_basename_still_resolve(env: dict[str, str], tmp_path: pathlib.Path) -> None:
    """Single-file encrypts, and rows written before relative names, store a basename."""
    (tmp_path / "db.env").write_bytes(PROD)
    assert _run(env, "encrypt", str(tmp_path / "db.env")).exit_code == 0

    result, rec = _exec(env, "db.env")

    assert result.exit_code == 0, result.output
    assert rec.env is not None
    assert rec.env["SECRET"] == PROD.decode().rstrip("\n")


def test_exact_name_wins_over_basename_matches(
    two_db_envs: dict[str, str], tmp_path: pathlib.Path
) -> None:
    """A row stored as exactly `db.env` is what `db.env` means; nested files are not candidates."""
    (tmp_path / "db.env").write_bytes(A)
    assert _run(two_db_envs, "encrypt", str(tmp_path / "db.env")).exit_code == 0

    result, rec = _exec(two_db_envs, "db.env")

    assert result.exit_code == 0, result.output
    assert rec.env is not None
    assert rec.env["SECRET"] == A.decode().rstrip("\n")


@pytest.fixture
def two_versions(env: dict[str, str], tmp_path: pathlib.Path) -> dict[str, str]:
    """Two files stored under the same exact name, encrypted one after the other."""
    for content in (A, B):
        (tmp_path / "db.env").write_bytes(content)
        result = _run(env, "encrypt", str(tmp_path / "db.env"))
        assert result.exit_code == 0, result.output
    os.unlink(tmp_path / "db.env")
    return env


def test_decrypt_version_applies_within_one_name(
    two_versions: dict[str, str], tmp_path: pathlib.Path
) -> None:
    newest = _run(two_versions, "decrypt", "db.env", "-o", str(tmp_path / "newest"))
    older = _run(two_versions, "decrypt", "db.env", "--version", "2", "-o", str(tmp_path / "old"))
    beyond = _run(two_versions, "decrypt", "db.env", "--version", "3", "-o", str(tmp_path / "x"))

    assert newest.exit_code == 0, newest.output
    assert (tmp_path / "newest").read_bytes() == B
    assert "2 versions found" in newest.output
    assert older.exit_code == 0, older.output
    assert (tmp_path / "old").read_bytes() == A
    assert beyond.exit_code == 1
    assert "out of range" in beyond.output


def test_versions_are_ordered_by_time_not_by_string(
    two_versions: dict[str, str], tmp_path: pathlib.Path
) -> None:
    """12:00+02:00 is 10:00 UTC: earlier than 11:00 UTC although it sorts later as text."""
    _table().update_item(  # type: ignore[attr-defined]
        Key={"PK": f"FILE#{HA}", "SK": "CURRENT"},
        UpdateExpression="SET encrypted_at = :t",
        ExpressionAttributeValues={":t": "2026-11-15T11:00:00+00:00"},
    )
    _table().update_item(  # type: ignore[attr-defined]
        Key={"PK": f"FILE#{HB}", "SK": "CURRENT"},
        UpdateExpression="SET encrypted_at = :t",
        ExpressionAttributeValues={":t": "2026-11-15T12:00:00+02:00"},
    )

    result = _run(two_versions, "decrypt", "db.env", "-o", str(tmp_path / "newest"))

    assert result.exit_code == 0, result.output
    assert (tmp_path / "newest").read_bytes() == A


def _tie(seconds: str = "2026-11-01T09:00:00+00:00") -> None:
    for sha in (HA, HB):
        _table().update_item(  # type: ignore[attr-defined]
            Key={"PK": f"FILE#{sha}", "SK": "CURRENT"},
            UpdateExpression="SET encrypted_at = :t",
            ExpressionAttributeValues={":t": seconds},
        )


def test_exec_refuses_when_newest_versions_share_encrypted_at(
    two_versions: dict[str, str],
) -> None:
    """Second-precision legacy timestamps can tie: "newest" is then a coin toss."""
    _tie()

    result, rec = _exec(two_versions, "db.env")

    assert result.exit_code == 1, result.output
    assert rec.env is None
    assert "same time" in result.output


def test_decrypt_tie_needs_an_explicit_version(
    two_versions: dict[str, str], tmp_path: pathlib.Path
) -> None:
    _tie()

    implicit = _run(two_versions, "decrypt", "db.env", "-o", str(tmp_path / "a"))
    explicit = _run(two_versions, "decrypt", "db.env", "--version", "1", "-o", str(tmp_path / "b"))
    again = _run(two_versions, "decrypt", "db.env", "--version", "1", "-o", str(tmp_path / "c"))

    assert implicit.exit_code == 1, implicit.output
    assert "--version" in implicit.output
    assert not (tmp_path / "a").exists()
    assert explicit.exit_code == 0, explicit.output
    assert again.exit_code == 0, again.output
    # The order of tied versions is deterministic, so --version N is too.
    assert (tmp_path / "b").read_bytes() == (tmp_path / "c").read_bytes()
