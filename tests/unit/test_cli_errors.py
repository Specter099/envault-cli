"""Failures become one-line errors and a non-zero exit, never a traceback (L2).

Batch commands (encrypt of a directory, rotate-key) report each failed file and
carry on with the rest, then summarise.
"""

from __future__ import annotations

import pathlib
from collections.abc import Iterator
from unittest.mock import patch

import boto3
import botocore.client
import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from click.testing import CliRunner, Result
from moto import mock_aws

from envault import cli as cli_mod
from envault import identity
from envault.cli import main
from envault.state import ENCRYPTED, StateStore

from ._id_key import id_key_env

TABLE = "envault-test-state"
BUCKET = "envault-test-bucket"
ALIAS = "alias/envault-test"
NEW_ALIAS = "alias/new-key"
REGION = "us-east-1"


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
        for alias in (ALIAS, NEW_ALIAS):
            kms.create_alias(AliasName=alias, TargetKeyId=kms.create_key()["KeyMetadata"]["KeyId"])
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
            "COLUMNS": "250",
            **id_key_env(),
        }


def _run(env: dict[str, str], *args: str) -> Result:
    return CliRunner().invoke(main, list(args), env=env)


def _assert_clean_exit(result: Result, code: int = 1) -> None:
    assert result.exit_code == code, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit), repr(
        result.exception
    )
    assert "Traceback" not in result.output


_REAL_CALL = botocore.client.BaseClient._make_api_call


def _failing(operation: str, error: Exception):  # type: ignore[no-untyped-def]
    def call(self, op, kwargs):  # type: ignore[no-untyped-def]
        if op == operation:
            raise error
        return _REAL_CALL(self, op, kwargs)

    return patch.object(botocore.client.BaseClient, "_make_api_call", call)


def _client_error(code: str, operation: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": f"simulated {code}"}}, operation)


@pytest.fixture
def batch(tmp_path: pathlib.Path) -> pathlib.Path:
    batch = tmp_path / "batch"
    batch.mkdir()
    for name in ("a.txt", "b.txt", "c.txt"):
        (batch / name).write_text(f"content of {name}\n")
    return batch


# ---------------------------------------------------------------------------
# encrypt
# ---------------------------------------------------------------------------


def test_encrypt_reports_kms_failure_per_file(
    env: dict[str, str], batch: pathlib.Path, no_retry_sleep: list[float]
) -> None:
    """r11 (a): KMS denies GenerateDataKey -> one line per file, a summary, exit 1."""
    with _failing("GenerateDataKey", _client_error("AccessDeniedException", "GenerateDataKey")):
        result = _run(env, "encrypt", str(batch))

    _assert_clean_exit(result)
    assert result.output.count("✗") == 3
    assert "AccessDeniedException" in result.output
    assert "3 file(s) failed to encrypt" in result.output
    assert no_retry_sleep == []  # a denied key is not retried


def test_encrypt_keeps_going_after_a_local_file_error(
    env: dict[str, str], batch: pathlib.Path
) -> None:
    """An OSError on one file (it vanished after the walk) is that file's error only."""
    real = cli_mod._collect_files

    def collect_then_remove(path: pathlib.Path, *args):  # type: ignore[no-untyped-def]
        files = real(path, *args)
        (batch / "b.txt").unlink()
        return files

    with patch.object(cli_mod, "_collect_files", collect_then_remove):
        result = _run(env, "encrypt", str(batch))

    _assert_clean_exit(result)
    assert "✗ b.txt" in result.output
    assert "1 file(s) failed to encrypt" in result.output
    names = {r.file_name for r in StateStore(TABLE, REGION).list_by_state(ENCRYPTED)}
    assert names == {"a.txt", "c.txt"}


# ---------------------------------------------------------------------------
# decrypt
# ---------------------------------------------------------------------------


@pytest.fixture
def encrypted(env: dict[str, str], batch: pathlib.Path) -> dict[str, str]:
    result = _run(env, "encrypt", str(batch / "a.txt"))
    assert result.exit_code == 0, result.output
    return env


@pytest.mark.parametrize("identifier", ["a.txt", "f" * 64])
def test_decrypt_dynamodb_error_is_friendly(
    encrypted: dict[str, str], tmp_path: pathlib.Path, identifier: str
) -> None:
    """r11 (c): DynamoDB refuses the lookup (Query for names, GetItem for hashes)."""
    operation = "GetItem" if len(identifier) == 64 else "Query"
    with _failing(operation, _client_error("AccessDeniedException", operation)):
        result = _run(encrypted, "decrypt", identifier, "-o", str(tmp_path / "out"))

    _assert_clean_exit(result)
    assert "AWS error" in result.output
    assert "simulated AccessDeniedException" in result.output


def test_decrypt_kms_access_denied_is_a_kms_error_not_tampering(
    encrypted: dict[str, str], tmp_path: pathlib.Path
) -> None:
    with _failing("Decrypt", _client_error("AccessDeniedException", "Decrypt")):
        result = _run(encrypted, "decrypt", "a.txt", "-o", str(tmp_path / "out"))

    _assert_clean_exit(result)
    assert "KMS error:" in result.output
    assert "tamper" not in result.output.lower()
    assert not (tmp_path / "out").exists()


def test_decrypt_local_error_creating_temporary_files_is_friendly(
    encrypted: dict[str, str], tmp_path: pathlib.Path
) -> None:
    with patch.object(cli_mod.tempfile, "mkstemp", side_effect=PermissionError("read-only")):
        result = _run(encrypted, "decrypt", "a.txt", "-o", str(tmp_path / "out"))

    _assert_clean_exit(result)
    assert "read-only" in result.output


# ---------------------------------------------------------------------------
# exec
# ---------------------------------------------------------------------------


def test_exec_dynamodb_error_is_friendly(encrypted: dict[str, str]) -> None:
    with (
        patch("os.execvpe") as execvpe,
        _failing("Query", _client_error("AccessDeniedException", "Query")),
    ):
        result = _run(encrypted, "exec", "-s", "a.txt=VAR", "--", "/bin/true")

    _assert_clean_exit(result)
    assert not execvpe.called
    assert "Refusing to run" in result.output


def test_exec_credential_fd_failure_is_friendly(encrypted: dict[str, str]) -> None:
    """An OSError creating the anonymous file is a refusal, not a traceback."""
    with (
        patch("os.execvpe") as execvpe,
        patch.object(cli_mod, "CredentialFd", side_effect=OSError("memfd_create: no memory")),
    ):
        result = _run(encrypted, "exec", "-f", "a.txt=VAR", "--", "/bin/true")

    _assert_clean_exit(result)
    assert not execvpe.called
    assert "no memory" in result.output


# ---------------------------------------------------------------------------
# rotate-key
# ---------------------------------------------------------------------------


def test_rotate_key_reports_incomplete_on_kms_failure(
    encrypted: dict[str, str], no_retry_sleep: list[float]
) -> None:
    """r11 (b): GenerateDataKey denied on the new key -> per-file error, then the summary."""
    with _failing("GenerateDataKey", _client_error("AccessDeniedException", "GenerateDataKey")):
        result = _run(encrypted, "rotate-key", "--new-key-id", NEW_ALIAS)

    _assert_clean_exit(result)
    assert "Error rotating a.txt" in result.output
    assert "Rotation incomplete" in result.output
    [record] = StateStore(TABLE, REGION).list_by_state(ENCRYPTED)
    assert record.kms_key_id == ALIAS


def test_rotate_key_listing_failure_is_friendly(encrypted: dict[str, str]) -> None:
    with _failing("Query", _client_error("AccessDeniedException", "Query")):
        result = _run(encrypted, "rotate-key", "--new-key-id", NEW_ALIAS)

    _assert_clean_exit(result)
    assert "AWS error" in result.output


def test_rotate_key_preflight_network_failure_is_friendly(
    encrypted: dict[str, str], no_retry_sleep: list[float]
) -> None:
    """A BotoCoreError from DescribeKey (unreachable endpoint), not just a ClientError."""
    unreachable = EndpointConnectionError(endpoint_url="https://kms.us-east-1.amazonaws.com")
    with _failing("DescribeKey", unreachable):
        result = _run(encrypted, "rotate-key", "--new-key-id", NEW_ALIAS)

    _assert_clean_exit(result)
    assert "Cannot use KMS key" in result.output
    assert "Rotation did not download or decrypt any files" in result.output
