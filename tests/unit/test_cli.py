from __future__ import annotations

import glob
import hashlib
from pathlib import Path
from unittest.mock import patch

import boto3
import click
import pytest
from botocore.exceptions import ClientError
from click.testing import CliRunner
from moto import mock_aws

from envault.cli import (
    _best_effort_delete,
    _collect_files,
    _friendly_message,
    _parse_output_json_entry,
    _parse_tags,
    _validate_date,
    cli,
    main,
)
from envault.crypto import DecryptResult, EncryptResult, verify_encryption_context
from envault.exceptions import ChecksumMismatchError, EnvaultError, MigrationError
from envault.state import DECRYPTED, ENCRYPTED, FileRecord, StateStore

TABLE_NAME = "envault-test-state"
BUCKET_NAME = "envault-test-bucket"
REGION = "us-east-1"
KEY_ID = "alias/envault-test"
FAKE_SHA = "a" * 64
ACCOUNT_IDS = "123456789012"
_CLI_ENV = {
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",  # noqa: S105
    "AWS_DEFAULT_REGION": REGION,
}


def _create_table() -> None:
    client = boto3.client("dynamodb", region_name=REGION)
    client.create_table(
        TableName=TABLE_NAME,
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
            {"AttributeName": "current_state", "AttributeType": "S"},
            {"AttributeName": "encrypted_at", "AttributeType": "S"},
            {"AttributeName": "date", "AttributeType": "S"},
            {"AttributeName": "last_updated", "AttributeType": "S"},
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


def _create_bucket() -> None:
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket=BUCKET_NAME)
    s3.put_bucket_versioning(Bucket=BUCKET_NAME, VersioningConfiguration={"Status": "Enabled"})


def _ensure_kms_alias(alias: str) -> None:
    """Create a moto KMS key and alias so rotate-key DescribeKey preflight succeeds."""
    kms = boto3.client("kms", region_name=REGION)
    key_id = kms.create_key(Description="envault-test")["KeyMetadata"]["KeyId"]
    kms.create_alias(AliasName=alias, TargetKeyId=key_id)


def _upload_fake_ciphertext(s3_key: str) -> str:
    """Upload fake ciphertext to S3 and return the real VersionId."""
    s3 = boto3.client("s3", region_name=REGION)
    resp = s3.put_object(Bucket=BUCKET_NAME, Key=s3_key, Body=b"fake-ciphertext")
    return str(resp.get("VersionId", ""))


def _seed_encrypted_record(
    store: StateStore,
    sha256: str = FAKE_SHA,
    enc_context: dict[str, str] | None = None,
    s3_version_id: str = "",
) -> FileRecord:
    if enc_context is None:
        enc_context = {
            "purpose": "envault-backup",
            "sha256": sha256,
            "file_name": "test.txt",
            "kms_key_alias": KEY_ID,
        }
    record = FileRecord(
        sha256_hash=sha256,
        file_name="test.txt",
        current_state=ENCRYPTED,
        s3_key=f"encrypted/{sha256[:2]}/{sha256}/test.txt.encrypted",
        s3_version_id=s3_version_id,
        kms_key_id=KEY_ID,
        encryption_context=enc_context,
        algorithm="AES_256_GCM_HKDF_SHA512_COMMIT_KEY",
        message_id="msg001",
        file_size_bytes=100,
        encrypted_at="2024-01-01T00:00:00+00:00",
        last_updated="2024-01-01T00:00:00+00:00",
    )
    store.put_current_state(record)
    return record


def _make_entry(input_path: str) -> dict[str, object]:
    return {
        "mode": "encrypt",
        "input": input_path,
        "header": {
            "algorithm": "AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384",
            "message_id": "abcd1234",
            "encryption_context": {"purpose": "backup"},
            "encrypted_data_keys": [{"key_provider": {"key_info": "alias/envault"}}],
        },
    }


def test_parse_entry_uses_content_hash(tmp_path: Path) -> None:
    """_parse_output_json_entry must hash file CONTENT, not the path string."""
    plaintext = tmp_path / "secret.txt"
    content = b"sensitive data\n"
    plaintext.write_bytes(content)
    expected_hash = hashlib.sha256(content).hexdigest()

    entry = _make_entry(str(plaintext))
    record = _parse_output_json_entry(entry, base_dir=tmp_path)

    assert record is not None
    assert record.sha256_hash == expected_hash


def test_parse_entry_skips_missing_file(tmp_path: Path) -> None:
    """_parse_output_json_entry returns None when the plaintext file doesn't exist."""
    entry = _make_entry("nonexistent/file.txt")
    record = _parse_output_json_entry(entry)
    assert record is None


def test_parse_entry_skips_non_encrypt_mode() -> None:
    entry = {"mode": "decrypt", "input": "some/file"}
    assert _parse_output_json_entry(entry) is None


def test_parse_entry_rejects_path_traversal() -> None:
    """Paths with '..' components must raise MigrationError."""
    entry = _make_entry("../../etc/passwd")
    with pytest.raises(MigrationError, match="Path traversal not allowed"):
        _parse_output_json_entry(entry)


def test_parse_entry_records_file_size(tmp_path: Path) -> None:
    """Migrated records must store actual file size, not zero."""
    plaintext = tmp_path / "sized.txt"
    content = b"hello world\n"
    plaintext.write_bytes(content)

    entry = _make_entry(str(plaintext))
    record = _parse_output_json_entry(entry, base_dir=tmp_path)

    assert record is not None
    assert record.file_size_bytes == len(content)


def test_validate_date_accepts_valid() -> None:
    """Valid YYYY-MM-DD dates must pass validation."""
    assert _validate_date("2024-01-15") == "2024-01-15"
    assert _validate_date("2026-12-31") == "2026-12-31"


def test_validate_date_rejects_invalid() -> None:
    """Invalid date strings must cause SystemExit."""
    with pytest.raises(SystemExit):
        _validate_date("not-a-date")
    with pytest.raises(SystemExit):
        _validate_date("01/15/2024")
    with pytest.raises(SystemExit):
        _validate_date("2024-13-01")


def test_best_effort_delete_overwrites_before_removal(tmp_path: Path) -> None:
    """_best_effort_delete must zero-out file contents before unlinking."""
    p = tmp_path / "sensitive.bin"
    p.write_bytes(b"TOP SECRET DATA")
    assert p.exists()

    _best_effort_delete(p)

    assert not p.exists()


def test_best_effort_delete_missing_file_is_noop(tmp_path: Path) -> None:
    """_best_effort_delete on a non-existent path must not raise."""
    p = tmp_path / "does_not_exist"
    _best_effort_delete(p)  # should not raise


def test_best_effort_delete_zero_length_file(tmp_path: Path) -> None:
    p = tmp_path / "empty"
    p.write_bytes(b"")
    _best_effort_delete(p)
    assert not p.exists()


def test_best_effort_delete_logs_warning_on_oserror(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """_best_effort_delete must log a warning if overwrite fails with OSError."""
    import logging
    from unittest.mock import patch

    p = tmp_path / "readonly.bin"
    p.write_bytes(b"data")

    with (
        patch.object(Path, "open", side_effect=OSError("Permission denied")),
        caplog.at_level(logging.WARNING, logger="envault.fileutils"),
    ):
        _best_effort_delete(p)

    assert any("best-effort" in r.message.lower() for r in caplog.records)


def test_parse_tags_valid() -> None:
    result = _parse_tags(("project=finance", "env=prod"))
    assert result == {"project": "finance", "env": "prod"}


def test_parse_tags_invalid_key_raises() -> None:
    """Tag keys with special characters must raise UsageError."""
    with pytest.raises(click.UsageError, match="Invalid tag key"):
        _parse_tags(("bad key!=value",))


def test_parse_tags_key_too_long_raises() -> None:
    """Tag key longer than 64 chars must raise UsageError."""
    long_key = "k" * 65
    with pytest.raises(click.UsageError, match="Invalid tag key"):
        _parse_tags((f"{long_key}=value",))


def test_parse_tags_value_too_long_raises() -> None:
    """Tag value longer than 256 chars must raise UsageError."""
    long_val = "v" * 257
    with pytest.raises(click.UsageError, match="exceeds"):
        _parse_tags((f"key={long_val}",))


def test_parse_tags_empty_key_raises() -> None:
    with pytest.raises(click.UsageError, match="Invalid tag key"):
        _parse_tags(("=value",))


@mock_aws
def test_decrypt_rejects_invalid_sha256_format() -> None:
    """decrypt treats non-SHA256 input as a filename lookup."""
    _create_table()
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "decrypt",
            "not-a-valid-hash",
            "--table",
            TABLE_NAME,
            "--bucket",
            "b",
        ],
        env={
            "AWS_ACCESS_KEY_ID": "testing",
            "AWS_SECRET_ACCESS_KEY": "testing",
            "AWS_DEFAULT_REGION": "us-east-1",
            "ENVAULT_ALLOWED_ACCOUNT_IDS": ACCOUNT_IDS,
        },
    )
    assert result.exit_code != 0
    assert "no encrypted files" in result.output.lower()


@mock_aws
def test_decrypt_accepts_filename_identifier() -> None:
    """decrypt command should accept a filename and resolve it."""
    _create_table()
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["decrypt", "myfile.txt", "--table", TABLE_NAME, "--bucket", "b"],
        env={
            "AWS_ACCESS_KEY_ID": "testing",
            "AWS_SECRET_ACCESS_KEY": "testing",
            "AWS_DEFAULT_REGION": "us-east-1",
            "ENVAULT_ALLOWED_ACCOUNT_IDS": ACCOUNT_IDS,
        },
    )
    assert result.exit_code != 0
    # Should NOT say "Invalid SHA256" — should say "no encrypted files"
    assert "invalid sha256" not in result.output.lower()


@mock_aws
def test_decrypt_version_flag_out_of_range() -> None:
    """--version N where N > number of matches should error."""
    _create_table()
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "decrypt",
            "myfile.txt",
            "--version",
            "5",
            "--table",
            TABLE_NAME,
            "--bucket",
            "b",
        ],
        env={
            "AWS_ACCESS_KEY_ID": "testing",
            "AWS_SECRET_ACCESS_KEY": "testing",
            "AWS_DEFAULT_REGION": "us-east-1",
            "ENVAULT_ALLOWED_ACCOUNT_IDS": ACCOUNT_IDS,
        },
    )
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# C-3: CLI integration tests (encrypt, decrypt, rotate-key)
# ---------------------------------------------------------------------------


def _mock_encrypt_file(
    input_path: Path,
    key_id: str,
    encryption_context: dict[str, str],
    output_path: Path,
    region: str = "us-east-1",
) -> EncryptResult:
    """Fake encrypt_file that writes dummy ciphertext and returns EncryptResult."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(b"fake-ciphertext")
    content = input_path.read_bytes()
    return EncryptResult(
        sha256_hash=hashlib.sha256(content).hexdigest(),
        file_size_bytes=len(content),
        algorithm="AES_256_GCM_HKDF_SHA512_COMMIT_KEY",
        message_id="msg001",
        output_path=output_path,
    )


@mock_aws
def test_encrypt_command_end_to_end(tmp_path: Path) -> None:
    """encrypt command: mocked crypto, real DynamoDB + S3."""
    _create_table()
    _create_bucket()

    plaintext = tmp_path / "secret.txt"
    plaintext.write_bytes(b"sensitive data")
    sha = hashlib.sha256(b"sensitive data").hexdigest()

    runner = CliRunner()
    with (
        patch("envault.cli.encrypt_file", side_effect=_mock_encrypt_file),
        patch("envault.crypto.sha256_file", return_value=sha),
    ):
        result = runner.invoke(
            main,
            [
                "encrypt",
                str(plaintext),
                "--key-id",
                KEY_ID,
                "--bucket",
                BUCKET_NAME,
                "--table",
                TABLE_NAME,
                "--region",
                REGION,
            ],
            env=_CLI_ENV,
        )

    assert result.exit_code == 0, result.output
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    record = store.get_current_state(sha)
    assert record is not None
    assert record.current_state == ENCRYPTED


_MATCHING_CONTEXT = {
    "purpose": "envault-backup",
    "sha256": FAKE_SHA,
    "file_name": "test.txt",
    "kms_key_alias": KEY_ID,
}


def _make_mock_decrypt(header_context: dict[str, str], content: bytes = b"decrypted content"):
    """Build a fake decrypt_file that mirrors the real ordering guarantee.

    The real implementation verifies the encryption context against the
    ciphertext header *before* writing any plaintext, so the fake does too —
    otherwise these tests would assert against a laxer contract than the code
    they stand in for.
    """

    def _mock(
        input_path: Path,
        output_path: Path,
        expected_sha256: str | None = None,
        region: str = "us-east-1",
        allowed_account_ids: list[str] | None = None,
        expected_context: dict[str, str] | None = None,
    ) -> DecryptResult:
        if expected_context is not None:
            verify_encryption_context(expected_context, header_context)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(content)
        return DecryptResult(
            sha256_hash=FAKE_SHA,
            file_size_bytes=len(content),
            output_path=output_path,
            encryption_context=header_context,
        )

    return _mock


_mock_decrypt_file_ok = _make_mock_decrypt(_MATCHING_CONTEXT)


@mock_aws
def test_decrypt_command_end_to_end(tmp_path: Path) -> None:
    """decrypt command: mocked crypto, pre-seeded DynamoDB + S3."""
    _create_table()
    _create_bucket()
    s3_key = f"encrypted/{FAKE_SHA[:2]}/{FAKE_SHA}/test.txt.encrypted"
    version_id = _upload_fake_ciphertext(s3_key)
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    _seed_encrypted_record(store, s3_version_id=version_id)

    runner = CliRunner()
    with patch("envault.cli.decrypt_file", side_effect=_mock_decrypt_file_ok):
        result = runner.invoke(
            main,
            [
                "decrypt",
                FAKE_SHA,
                "--output",
                str(tmp_path),
                "--table",
                TABLE_NAME,
                "--bucket",
                BUCKET_NAME,
                "--region",
                REGION,
                "--allowed-account-ids",
                ACCOUNT_IDS,
            ],
            env=_CLI_ENV,
        )

    assert result.exit_code == 0, result.output
    assert "decrypted" in result.output.lower() or "✓" in result.output


@mock_aws
def test_decrypt_checksum_mismatch(tmp_path: Path) -> None:
    """decrypt must surface ChecksumMismatchError from the crypto layer."""
    _create_table()
    _create_bucket()
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    record = _seed_encrypted_record(store)
    _upload_fake_ciphertext(record.s3_key)

    runner = CliRunner()
    with patch(
        "envault.cli.decrypt_file",
        side_effect=ChecksumMismatchError(expected="aaa", actual="bbb"),
    ):
        result = runner.invoke(
            main,
            [
                "decrypt",
                FAKE_SHA,
                "--output",
                str(tmp_path),
                "--table",
                TABLE_NAME,
                "--bucket",
                BUCKET_NAME,
                "--region",
                REGION,
                "--allowed-account-ids",
                ACCOUNT_IDS,
            ],
            env=_CLI_ENV,
        )

    assert result.exit_code != 0


@mock_aws
def test_decrypt_encryption_context_mismatch(tmp_path: Path) -> None:
    """decrypt must fail when encryption context from ciphertext doesn't match DynamoDB."""
    _create_table()
    _create_bucket()
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    record = _seed_encrypted_record(store)
    _upload_fake_ciphertext(record.s3_key)

    _mock_decrypt_mismatched_ctx = _make_mock_decrypt(
        {"purpose": "TAMPERED", "sha256": FAKE_SHA}, content=b"data"
    )

    runner = CliRunner()
    with patch("envault.cli.decrypt_file", side_effect=_mock_decrypt_mismatched_ctx):
        result = runner.invoke(
            main,
            [
                "decrypt",
                FAKE_SHA,
                "--output",
                str(tmp_path),
                "--table",
                TABLE_NAME,
                "--bucket",
                BUCKET_NAME,
                "--region",
                REGION,
                "--allowed-account-ids",
                ACCOUNT_IDS,
            ],
            env=_CLI_ENV,
        )

    assert result.exit_code != 0
    assert "encryption context mismatch" in result.output.lower()
    # Stronger than "cleaned up afterwards": verification happens before the
    # plaintext is written, so it must never have reached the destination.
    assert not list(tmp_path.glob("test.txt"))


@mock_aws
def test_decrypt_succeeds_with_sdk_extra_keys(tmp_path: Path) -> None:
    """decrypt must pass when ciphertext has extra SDK-added keys like aws-crypto-public-key."""
    _create_table()
    _create_bucket()
    s3_key = f"encrypted/{FAKE_SHA[:2]}/{FAKE_SHA}/test.txt.encrypted"
    version_id = _upload_fake_ciphertext(s3_key)
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    _seed_encrypted_record(store, s3_version_id=version_id)

    _mock_decrypt_with_extra_keys = _make_mock_decrypt(
        # SDK-added key — must NOT cause mismatch
        {**_MATCHING_CONTEXT, "aws-crypto-public-key": "A4f3example..."}
    )

    runner = CliRunner()
    with patch("envault.cli.decrypt_file", side_effect=_mock_decrypt_with_extra_keys):
        result = runner.invoke(
            main,
            [
                "decrypt",
                FAKE_SHA,
                "--output",
                str(tmp_path),
                "--table",
                TABLE_NAME,
                "--bucket",
                BUCKET_NAME,
                "--region",
                REGION,
                "--allowed-account-ids",
                ACCOUNT_IDS,
            ],
            env=_CLI_ENV,
        )

    assert result.exit_code == 0, result.output
    assert "decrypted" in result.output.lower() or "✓" in result.output


@mock_aws
def test_decrypt_checksum_mismatch_shows_friendly_message(tmp_path: Path) -> None:
    """decrypt surfaces ChecksumMismatchError as a human-readable message, not a traceback."""
    _create_table()
    _create_bucket()
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    record = _seed_encrypted_record(store)
    _upload_fake_ciphertext(record.s3_key)

    runner = CliRunner()
    with patch(
        "envault.cli.decrypt_file",
        side_effect=ChecksumMismatchError(expected="aaa", actual="bbb"),
    ):
        result = runner.invoke(
            main,
            [
                "decrypt",
                FAKE_SHA,
                "--output",
                str(tmp_path),
                "--table",
                TABLE_NAME,
                "--bucket",
                BUCKET_NAME,
                "--region",
                REGION,
                "--allowed-account-ids",
                ACCOUNT_IDS,
            ],
            env=_CLI_ENV,
        )

    assert result.exit_code != 0
    assert "checksum mismatch" in result.output.lower()
    # Should NOT show a Python traceback
    assert "Traceback" not in result.output


@mock_aws
def test_decrypt_aws_error_shows_friendly_message(tmp_path: Path) -> None:
    """decrypt surfaces AWS ClientError as a human-readable message, not a traceback."""
    _create_table()
    _create_bucket()
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    record = _seed_encrypted_record(store)
    _upload_fake_ciphertext(record.s3_key)

    error_response = {"Error": {"Code": "AccessDenied", "Message": "Access Denied to KMS key"}}
    runner = CliRunner()
    with patch(
        "envault.cli.decrypt_file",
        side_effect=ClientError(error_response, "Decrypt"),  # type: ignore[arg-type]
    ):
        result = runner.invoke(
            main,
            [
                "decrypt",
                FAKE_SHA,
                "--output",
                str(tmp_path),
                "--table",
                TABLE_NAME,
                "--bucket",
                BUCKET_NAME,
                "--region",
                REGION,
                "--allowed-account-ids",
                ACCOUNT_IDS,
            ],
            env=_CLI_ENV,
        )

    assert result.exit_code != 0
    assert "aws error" in result.output.lower()
    assert "Access Denied" in result.output
    assert "Traceback" not in result.output


@mock_aws
def test_rotate_key_end_to_end(tmp_path: Path) -> None:
    """rotate-key: mocked decrypt + re-encrypt, real DynamoDB + S3."""
    _create_table()
    _create_bucket()
    s3_key = f"encrypted/{FAKE_SHA[:2]}/{FAKE_SHA}/test.txt.encrypted"
    version_id = _upload_fake_ciphertext(s3_key)
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    record = _seed_encrypted_record(store, s3_version_id=version_id)

    new_key_id = "alias/new-key"
    _ensure_kms_alias(new_key_id)

    _mock_decrypt = _make_mock_decrypt(record.encryption_context, content=b"plaintext")

    runner = CliRunner()
    with (
        patch("envault.cli.decrypt_file", side_effect=_mock_decrypt),
        patch("envault.cli.encrypt_file", side_effect=_mock_encrypt_file),
    ):
        result = runner.invoke(
            main,
            [
                "rotate-key",
                "--new-key-id",
                new_key_id,
                "--table",
                TABLE_NAME,
                "--bucket",
                BUCKET_NAME,
                "--region",
                REGION,
                "--allowed-account-ids",
                ACCOUNT_IDS,
            ],
            env=_CLI_ENV,
        )

    assert result.exit_code == 0, result.output
    updated = store.get_current_state(FAKE_SHA)
    assert updated is not None
    assert updated.kms_key_id == new_key_id


# ---------------------------------------------------------------------------
# H-8: Temp file cleanup on failure
# ---------------------------------------------------------------------------


@mock_aws
def test_encrypt_temp_file_cleanup_on_failure(tmp_path: Path) -> None:
    """Temp encrypted file must be cleaned up even if encrypt_file raises."""
    _create_table()
    _create_bucket()

    plaintext = tmp_path / "secret.txt"
    plaintext.write_bytes(b"data")
    sha = hashlib.sha256(b"data").hexdigest()

    runner = CliRunner()
    with (
        patch("envault.cli.encrypt_file", side_effect=EnvaultError("boom")),
        patch("envault.crypto.sha256_file", return_value=sha),
    ):
        result = runner.invoke(
            main,
            [
                "encrypt",
                str(plaintext),
                "--key-id",
                KEY_ID,
                "--bucket",
                BUCKET_NAME,
                "--table",
                TABLE_NAME,
                "--region",
                REGION,
            ],
            env=_CLI_ENV,
        )

    assert result.exit_code != 0
    # No lingering temp files with the envault_enc_ prefix
    import tempfile

    leftover = glob.glob(f"{tempfile.gettempdir()}/envault_enc_*")
    assert leftover == []


@mock_aws
def test_decrypt_temp_file_cleanup_on_failure(tmp_path: Path) -> None:
    """Temp downloaded file must be cleaned up even if decrypt_file raises."""
    _create_table()
    _create_bucket()
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    record = _seed_encrypted_record(store)
    _upload_fake_ciphertext(record.s3_key)

    runner = CliRunner()
    with patch("envault.cli.decrypt_file", side_effect=EnvaultError("boom")):
        result = runner.invoke(
            main,
            [
                "decrypt",
                FAKE_SHA,
                "--output",
                str(tmp_path),
                "--table",
                TABLE_NAME,
                "--bucket",
                BUCKET_NAME,
                "--region",
                REGION,
                "--allowed-account-ids",
                ACCOUNT_IDS,
            ],
            env=_CLI_ENV,
        )

    assert result.exit_code != 0
    import tempfile

    leftover = glob.glob(f"{tempfile.gettempdir()}/envault_dl_*")
    assert leftover == []


# ---------------------------------------------------------------------------
# C-1: Partial-failure resilience — recovery logging on state write failure
# ---------------------------------------------------------------------------


@mock_aws
def test_encrypt_logs_recovery_info_on_state_write_failure(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """If DynamoDB write fails after S3 upload, log S3 key for recovery."""
    import logging

    _create_table()
    _create_bucket()

    plaintext = tmp_path / "secret.txt"
    plaintext.write_bytes(b"sensitive data")
    sha = hashlib.sha256(b"sensitive data").hexdigest()

    runner = CliRunner()
    with (
        patch("envault.cli.encrypt_file", side_effect=_mock_encrypt_file),
        patch("envault.crypto.sha256_file", return_value=sha),
        patch.object(StateStore, "put_current_state", side_effect=EnvaultError("DynamoDB down")),
        caplog.at_level(logging.ERROR, logger="envault.cli"),
    ):
        result = runner.invoke(
            main,
            [
                "encrypt",
                str(plaintext),
                "--key-id",
                KEY_ID,
                "--bucket",
                BUCKET_NAME,
                "--table",
                TABLE_NAME,
                "--region",
                REGION,
            ],
            env=_CLI_ENV,
        )

    assert result.exit_code != 0
    # Recovery info must be in logs
    assert any("state write failed" in r.message.lower() for r in caplog.records)


@mock_aws
def test_decrypt_reports_audit_write_failure(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A failed audit write must be surfaced, not swallowed.

    The plaintext is already on disk by then, so the command cannot undo it —
    but exiting 0 would leave an unlogged read looking like a clean one.
    """
    import logging

    _create_table()
    _create_bucket()
    s3_key = f"encrypted/{FAKE_SHA[:2]}/{FAKE_SHA}/test.txt.encrypted"
    version_id = _upload_fake_ciphertext(s3_key)
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    _seed_encrypted_record(store, s3_version_id=version_id)

    runner = CliRunner()
    with (
        patch("envault.cli.decrypt_file", side_effect=_mock_decrypt_file_ok),
        patch.object(StateStore, "put_event", side_effect=EnvaultError("DynamoDB down")),
        caplog.at_level(logging.ERROR, logger="envault.cli"),
    ):
        result = runner.invoke(
            main,
            [
                "decrypt",
                FAKE_SHA,
                "--output",
                str(tmp_path),
                "--table",
                TABLE_NAME,
                "--bucket",
                BUCKET_NAME,
                "--region",
                REGION,
                "--allowed-account-ids",
                ACCOUNT_IDS,
            ],
            env=_CLI_ENV,
        )

    assert result.exit_code != 0
    assert any("audit event write failed" in r.message.lower() for r in caplog.records)
    assert "audit trail" in result.output.lower()


@mock_aws
def test_rotate_key_logs_recovery_info_on_state_write_failure(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """If DynamoDB write fails after S3 re-upload during rotation, log recovery info."""
    import logging

    _create_table()
    _create_bucket()
    _ensure_kms_alias("alias/new-key")
    s3_key = f"encrypted/{FAKE_SHA[:2]}/{FAKE_SHA}/test.txt.encrypted"
    version_id = _upload_fake_ciphertext(s3_key)
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    _seed_encrypted_record(store, s3_version_id=version_id)

    _mock_decrypt = _make_mock_decrypt(_MATCHING_CONTEXT, content=b"plaintext")

    runner = CliRunner()
    with (
        patch("envault.cli.decrypt_file", side_effect=_mock_decrypt),
        patch("envault.cli.encrypt_file", side_effect=_mock_encrypt_file),
        patch.object(StateStore, "put_current_state", side_effect=EnvaultError("DynamoDB down")),
        caplog.at_level(logging.ERROR, logger="envault.cli"),
    ):
        result = runner.invoke(
            main,
            [
                "rotate-key",
                "--new-key-id",
                "alias/new-key",
                "--table",
                TABLE_NAME,
                "--bucket",
                BUCKET_NAME,
                "--region",
                REGION,
                "--allowed-account-ids",
                ACCOUNT_IDS,
            ],
            env=_CLI_ENV,
        )

    # Per-file errors are caught and counted, but a rotation that left files
    # under the old key must still exit non-zero.
    assert result.exit_code != 0
    assert any("state write failed" in r.message.lower() for r in caplog.records)


@mock_aws
def test_rotate_key_recovery_log_records_old_key(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The recovery log must record the PREVIOUS key as old_kms_key.

    Regression: the record was mutated to the new key before the failure
    handler logged it, so both old_kms_key and new_kms_key showed the new key.
    """
    import logging

    _create_table()
    _create_bucket()
    _ensure_kms_alias("alias/new-key")
    s3_key = f"encrypted/{FAKE_SHA[:2]}/{FAKE_SHA}/test.txt.encrypted"
    version_id = _upload_fake_ciphertext(s3_key)
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    _seed_encrypted_record(store, s3_version_id=version_id)

    _mock_decrypt = _make_mock_decrypt(_MATCHING_CONTEXT, content=b"plaintext")

    runner = CliRunner()
    with (
        patch("envault.cli.decrypt_file", side_effect=_mock_decrypt),
        patch("envault.cli.encrypt_file", side_effect=_mock_encrypt_file),
        patch.object(StateStore, "put_current_state", side_effect=EnvaultError("DynamoDB down")),
        caplog.at_level(logging.ERROR, logger="envault.cli"),
    ):
        result = runner.invoke(
            main,
            [
                "rotate-key",
                "--new-key-id",
                "alias/new-key",
                "--table",
                TABLE_NAME,
                "--bucket",
                BUCKET_NAME,
                "--region",
                REGION,
                "--allowed-account-ids",
                ACCOUNT_IDS,
            ],
            env=_CLI_ENV,
        )

    # The file failed to rotate, so the command must not report success.
    assert result.exit_code != 0
    recovery = [r for r in caplog.records if "state write failed" in r.message.lower()]
    assert recovery, "expected a recovery log record"
    extra = recovery[0].__dict__
    assert extra["old_kms_key"] == KEY_ID  # the key the file was encrypted under
    assert extra["new_kms_key"] == "alias/new-key"


@mock_aws
def test_rotate_key_mkstemp_failure_is_handled(tmp_path: Path) -> None:
    """A temp-file creation failure must surface as a per-file error message,
    not an UnboundLocalError from the cleanup block referencing unset paths."""
    _create_table()
    _create_bucket()
    _ensure_kms_alias("alias/new-key")
    s3_key = f"encrypted/{FAKE_SHA[:2]}/{FAKE_SHA}/test.txt.encrypted"
    version_id = _upload_fake_ciphertext(s3_key)
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    _seed_encrypted_record(store, s3_version_id=version_id)

    runner = CliRunner()
    with patch("envault.cli.tempfile.mkstemp", side_effect=OSError("disk full")):
        result = runner.invoke(
            main,
            [
                "rotate-key",
                "--new-key-id",
                "alias/new-key",
                "--table",
                TABLE_NAME,
                "--bucket",
                BUCKET_NAME,
                "--region",
                REGION,
                "--allowed-account-ids",
                ACCOUNT_IDS,
            ],
            env=_CLI_ENV,
        )

    # Non-zero: a partially-rotated corpus still has files under the old key,
    # and reporting that as success is what made incomplete rotations invisible.
    assert result.exit_code != 0, result.output
    assert "disk full" in result.output
    assert "1 errors" in result.output
    assert "rotation incomplete" in result.output.lower()


# ---------------------------------------------------------------------------
# friendly error formatting tests
# ---------------------------------------------------------------------------


class TestFriendlyErrors:
    """Test that CLI errors are human-readable (no raw Click format or tracebacks)."""

    def test_decrypt_no_args_friendly_error(self) -> None:
        """cli() wrapper shows descriptive guidance for missing IDENTIFIER."""
        from io import StringIO

        from rich.console import Console as RichConsole

        output = StringIO()
        test_console = RichConsole(file=output, force_terminal=False)
        with (
            patch("sys.argv", ["envault", "decrypt"]),
            patch("envault.cli.console", test_console),
        ):
            with pytest.raises(SystemExit) as exc_info:
                cli()
        assert exc_info.value.code == 2
        text = output.getvalue()
        assert "decrypt command requires a SHA256 hash or filename" in text
        assert "envault decrypt --help" in text
        assert not text.strip().startswith("Error:")
        assert not text.strip().startswith("Usage:")

    def test_no_subcommand_shows_help_cleanly(self) -> None:
        """Running 'envault' with no subcommand shows help without error prefix."""
        runner = CliRunner()
        result = runner.invoke(main, [])
        assert result.exit_code == 0
        assert "Commands:" in result.output
        assert "Error:" not in result.output
        # Should NOT have a redundant --help hint at the bottom
        assert "Run 'envault --help' for usage info." not in result.output

    def test_encrypt_no_args_friendly_error(self) -> None:
        """cli() wrapper shows descriptive guidance for missing INPUT_PATH."""
        from io import StringIO

        from rich.console import Console as RichConsole

        output = StringIO()
        test_console = RichConsole(file=output, force_terminal=False)
        with (
            patch("sys.argv", ["envault", "encrypt"]),
            patch("envault.cli.console", test_console),
        ):
            with pytest.raises(SystemExit) as exc_info:
                cli()
        assert exc_info.value.code == 2
        text = output.getvalue()
        assert "encrypt command requires a file or directory to encrypt" in text
        assert "envault encrypt --help" in text
        assert not text.strip().startswith("Error:")

    @pytest.mark.parametrize(
        ("arg_name", "cmd_name", "expected_fragment"),
        [
            ("IDENTIFIER", "decrypt", "decrypt command requires a SHA256 hash or filename"),
            ("INPUT_PATH", "encrypt", "encrypt command requires a file or directory"),
            ("FROM_PATH", "migrate", "migrate command requires the path to output.json"),
        ],
    )
    def test_friendly_message_rewrites_missing_arg(
        self, arg_name: str, cmd_name: str, expected_fragment: str
    ) -> None:
        """_friendly_message maps each argument to a descriptive sentence."""
        ctx = click.Context(click.Command(cmd_name), info_name=cmd_name)
        err = click.UsageError(f"Missing argument '{arg_name}'.", ctx=ctx)
        result = _friendly_message(err)
        assert expected_fragment in result

    def test_friendly_message_passes_through_unknown_errors(self) -> None:
        """Non-missing-argument errors are returned unchanged."""
        ctx = click.Context(click.Command("decrypt"))
        err = click.UsageError("No such option: --foo", ctx=ctx)
        assert _friendly_message(err) == "No such option: --foo"

    @mock_aws
    def test_status_aws_error_shows_friendly_message(self) -> None:
        """status command shows friendly message on DynamoDB failure."""
        runner = CliRunner()
        with patch.object(
            StateStore,
            "list_by_state",
            side_effect=ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": "Table not found"}},
                "Scan",
            ),
        ):
            result = runner.invoke(
                main,
                ["status", "--table", TABLE_NAME, "--region", REGION],
                env=_CLI_ENV,
            )
        assert result.exit_code == 1
        assert "AWS error:" in result.output
        assert "Table not found" in result.output
        assert "Traceback" not in result.output

    @mock_aws
    def test_dashboard_aws_error_shows_friendly_message(self) -> None:
        """dashboard command shows friendly message on DynamoDB failure."""
        runner = CliRunner()
        with patch.object(
            StateStore,
            "summary",
            side_effect=ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": "Table not found"}},
                "Scan",
            ),
        ):
            result = runner.invoke(
                main,
                ["dashboard", "--table", TABLE_NAME, "--region", REGION],
                env=_CLI_ENV,
            )
        assert result.exit_code == 1
        assert "AWS error:" in result.output
        assert "Table not found" in result.output
        assert "Traceback" not in result.output


# ---------------------------------------------------------------------------
# Lifecycle regressions: reading a secret must not consume it
# ---------------------------------------------------------------------------


@mock_aws
def test_decrypt_is_repeatable(tmp_path: Path) -> None:
    """C-1: decrypting must not flip state and lock the file out of a second read."""
    _create_table()
    _create_bucket()
    s3_key = f"encrypted/{FAKE_SHA[:2]}/{FAKE_SHA}/test.txt.encrypted"
    version_id = _upload_fake_ciphertext(s3_key)
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    _seed_encrypted_record(store, s3_version_id=version_id)

    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    first_dir.mkdir()
    second_dir.mkdir()

    def _args(out: Path) -> list[str]:
        return [
            "decrypt",
            FAKE_SHA,
            "--output",
            str(out),
            "--table",
            TABLE_NAME,
            "--bucket",
            BUCKET_NAME,
            "--region",
            REGION,
            "--allowed-account-ids",
            ACCOUNT_IDS,
        ]

    runner = CliRunner()
    with patch("envault.cli.decrypt_file", side_effect=_mock_decrypt_file_ok):
        first = runner.invoke(main, _args(first_dir), env=_CLI_ENV)
        second = runner.invoke(main, _args(second_dir), env=_CLI_ENV)

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    # The stored object is still ciphertext, so the state must still say so.
    assert store.get_current_state(FAKE_SHA).current_state == ENCRYPTED


@mock_aws
def test_decrypt_records_access_event_with_principal(tmp_path: Path) -> None:
    """The read is captured in the audit trail, attributed to a principal."""
    _create_table()
    _create_bucket()
    s3_key = f"encrypted/{FAKE_SHA[:2]}/{FAKE_SHA}/test.txt.encrypted"
    version_id = _upload_fake_ciphertext(s3_key)
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    _seed_encrypted_record(store, s3_version_id=version_id)

    runner = CliRunner()
    with patch("envault.cli.decrypt_file", side_effect=_mock_decrypt_file_ok):
        result = runner.invoke(
            main,
            [
                "decrypt",
                FAKE_SHA,
                "--output",
                str(tmp_path),
                "--table",
                TABLE_NAME,
                "--bucket",
                BUCKET_NAME,
                "--region",
                REGION,
                "--allowed-account-ids",
                ACCOUNT_IDS,
            ],
            env=_CLI_ENV,
        )

    assert result.exit_code == 0, result.output
    events = [e for e in store.list_events_for_file(FAKE_SHA) if e["operation"] == "DECRYPT"]
    assert len(events) == 1
    assert events[0]["principal_arn"].startswith("arn:aws:")


@mock_aws
def test_rotate_key_covers_records_left_decrypted_by_old_versions(tmp_path: Path) -> None:
    """C-2: a record stuck in DECRYPTED still has ciphertext in S3 and must rotate."""
    _create_table()
    _create_bucket()
    _ensure_kms_alias("alias/new-key")
    s3_key = f"encrypted/{FAKE_SHA[:2]}/{FAKE_SHA}/test.txt.encrypted"
    version_id = _upload_fake_ciphertext(s3_key)
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    record = _seed_encrypted_record(store, s3_version_id=version_id)

    # Simulate the state an older envault left behind after a single decrypt.
    record.current_state = DECRYPTED
    store.put_current_state(record, expected_last_updated=record.last_updated)

    _mock_decrypt = _make_mock_decrypt(record.encryption_context, content=b"plaintext")
    runner = CliRunner()
    with (
        patch("envault.cli.decrypt_file", side_effect=_mock_decrypt),
        patch("envault.cli.encrypt_file", side_effect=_mock_encrypt_file),
    ):
        result = runner.invoke(
            main,
            [
                "rotate-key",
                "--new-key-id",
                "alias/new-key",
                "--table",
                TABLE_NAME,
                "--bucket",
                BUCKET_NAME,
                "--region",
                REGION,
                "--allowed-account-ids",
                ACCOUNT_IDS,
            ],
            env=_CLI_ENV,
        )

    assert result.exit_code == 0, result.output
    updated = store.get_current_state(FAKE_SHA)
    assert updated.kms_key_id == "alias/new-key"
    assert updated.current_state == ENCRYPTED


@mock_aws
def test_rotate_key_dry_run_lists_legacy_decrypted_records() -> None:
    """The dry run must not under-report what needs rotating."""
    _create_table()
    _create_bucket()
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    record = _seed_encrypted_record(store)
    record.current_state = DECRYPTED
    store.put_current_state(record, expected_last_updated=record.last_updated)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "rotate-key",
            "--new-key-id",
            "alias/new-key",
            "--dry-run",
            "--table",
            TABLE_NAME,
            "--bucket",
            BUCKET_NAME,
            "--region",
            REGION,
            "--allowed-account-ids",
            ACCOUNT_IDS,
        ],
        env=_CLI_ENV,
    )

    assert result.exit_code == 0, result.output
    assert "Found 1 files to rotate" in result.output


@mock_aws
def test_status_escapes_markup_in_file_names() -> None:
    """A filename containing Rich markup must render literally, not as style."""
    _create_table()
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    record = _seed_encrypted_record(store)
    record.file_name = "[bold red]not-my-name[/bold red]"
    store.put_current_state(record, expected_last_updated=record.last_updated)

    runner = CliRunner()
    # Wide terminal so the cell is not truncated before we can inspect it.
    result = runner.invoke(
        main,
        ["status", "--table", TABLE_NAME, "--region", REGION],
        env={**_CLI_ENV, "COLUMNS": "200"},
    )
    assert result.exit_code == 0, result.output
    # Markup must be visible as text, not consumed as styling. Wrapping may
    # split "[bold red]" across lines depending on terminal width.
    assert "not-my-name" in result.output
    assert "[bold" in result.output


@mock_aws
def test_status_survives_unmatched_markup_in_file_names() -> None:
    """An unbalanced tag used to raise MarkupError and abort the whole table."""
    _create_table()
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    record = _seed_encrypted_record(store)
    record.file_name = "[/nope].txt"
    store.put_current_state(record, expected_last_updated=record.last_updated)

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["status", "--table", TABLE_NAME, "--region", REGION],
        env=_CLI_ENV,
    )
    assert result.exit_code == 0, result.output


@mock_aws
def test_rotate_key_dry_run_escapes_markup_in_file_names() -> None:
    """The preview for a destructive operation must not abort on a crafted name."""
    _create_table()
    _create_bucket()
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    record = _seed_encrypted_record(store)
    record.file_name = "[/nope].txt"
    store.put_current_state(record, expected_last_updated=record.last_updated)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "rotate-key",
            "--new-key-id",
            "alias/new-key",
            "--dry-run",
            "--table",
            TABLE_NAME,
            "--bucket",
            BUCKET_NAME,
            "--region",
            REGION,
            "--allowed-account-ids",
            ACCOUNT_IDS,
        ],
        env={**_CLI_ENV, "COLUMNS": "200"},
    )
    assert result.exit_code == 0, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "Would rotate" in result.output


@mock_aws
def test_status_reports_persistent_aws_failure_cleanly() -> None:
    """Retry exhaustion must surface as a message, not a tenacity traceback."""
    _create_table()
    runner = CliRunner()
    with patch.object(
        StateStore,
        "list_by_state",
        side_effect=ClientError(
            {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "throttled"}},
            "Query",
        ),
    ):
        result = runner.invoke(
            main, ["status", "--table", TABLE_NAME, "--region", REGION], env=_CLI_ENV
        )
    assert result.exit_code != 0
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "AWS error" in result.output


def test_cli_entrypoint_escapes_markup_in_usage_errors() -> None:
    """The error handler must not itself become a crash path.

    Usage errors echo back the value the user typed, so an argument containing
    an unbalanced Rich tag would replace the help message with a MarkupError.
    """
    from io import StringIO

    from rich.console import Console as RichConsole

    output = StringIO()
    test_console = RichConsole(file=output, force_terminal=False, width=200)
    argv = ["envault", "exec", "-s", "[/nope]", "--", "/bin/true"]
    with (
        patch("sys.argv", argv),
        patch("envault.cli.console", test_console),
        patch.dict(
            "os.environ",
            {
                "ENVAULT_TABLE": "t",
                "ENVAULT_BUCKET": "b",
                # Set so validation reaches the spec parse, which is what echoes
                # the user's argument back into the error message.
                "ENVAULT_ALLOWED_ACCOUNT_IDS": "123456789012",
            },
            clear=False,
        ),
    ):
        with pytest.raises(SystemExit) as exc_info:
            cli()
    assert exc_info.value.code == 2
    assert "[/nope]" in output.getvalue()


def test_parse_entry_rejects_path_outside_base(tmp_path: Path) -> None:
    """Absolute paths that resolve outside the import directory must be rejected."""
    base = tmp_path / "import"
    base.mkdir()
    outsider = tmp_path / "passwd"
    outsider.write_text("nope")
    with pytest.raises(MigrationError, match="outside"):
        _parse_output_json_entry(_make_entry(str(outsider)), base_dir=base)


def test_parse_entry_rejects_symlink(tmp_path: Path) -> None:
    """A symlink in the migration path must not be followed to another tree."""
    other = tmp_path / "other"
    other.mkdir()
    real = other / "secret.txt"
    real.write_text("leaked")
    base = tmp_path / "import"
    base.mkdir()
    link = base / "secret.txt"
    link.symlink_to(real)
    with pytest.raises(MigrationError, match="Symlink"):
        _parse_output_json_entry(_make_entry(str(link)), base_dir=base)


def test_collect_files_skips_directory_symlink(tmp_path: Path) -> None:
    """Directory symlinks must not pull files from outside the target tree."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("should-not-be-collected")
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "ok.txt").write_text("ok")
    (tree / "linkdir").symlink_to(outside)
    names = {p.name for p in _collect_files(tree)}
    assert names == {"ok.txt"}


@mock_aws
def test_decrypt_refuses_overwrite_without_force(tmp_path: Path) -> None:
    """Decrypt must not clobber an existing plaintext unless --force is given."""
    _create_table()
    _create_bucket()
    s3_key = f"encrypted/{FAKE_SHA[:2]}/{FAKE_SHA}/test.txt.encrypted"
    version_id = _upload_fake_ciphertext(s3_key)
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    _seed_encrypted_record(store, s3_version_id=version_id)

    existing = tmp_path / "test.txt"
    existing.write_bytes(b"do-not-clobber")

    runner = CliRunner()
    with patch("envault.cli.decrypt_file", side_effect=_mock_decrypt_file_ok):
        result = runner.invoke(
            main,
            [
                "decrypt",
                FAKE_SHA,
                "--output",
                str(tmp_path),
                "--table",
                TABLE_NAME,
                "--bucket",
                BUCKET_NAME,
                "--region",
                REGION,
                "--allowed-account-ids",
                ACCOUNT_IDS,
            ],
            env=_CLI_ENV,
        )

    assert result.exit_code != 0
    assert "overwrite" in result.output.lower()
    assert existing.read_bytes() == b"do-not-clobber"


@mock_aws
def test_decrypt_force_overwrites(tmp_path: Path) -> None:
    """--force must replace an existing output file after verification."""
    _create_table()
    _create_bucket()
    s3_key = f"encrypted/{FAKE_SHA[:2]}/{FAKE_SHA}/test.txt.encrypted"
    version_id = _upload_fake_ciphertext(s3_key)
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    _seed_encrypted_record(store, s3_version_id=version_id)

    existing = tmp_path / "test.txt"
    existing.write_bytes(b"stale")

    runner = CliRunner()
    with patch("envault.cli.decrypt_file", side_effect=_mock_decrypt_file_ok):
        result = runner.invoke(
            main,
            [
                "decrypt",
                FAKE_SHA,
                "--output",
                str(tmp_path),
                "--force",
                "--table",
                TABLE_NAME,
                "--bucket",
                BUCKET_NAME,
                "--region",
                REGION,
                "--allowed-account-ids",
                ACCOUNT_IDS,
            ],
            env=_CLI_ENV,
        )

    assert result.exit_code == 0, result.output
    assert existing.read_bytes() == b"decrypted content"


@mock_aws
def test_decrypt_rejects_untrusted_s3_key(tmp_path: Path) -> None:
    """A CURRENT record whose s3_key does not match this file must not be fetched."""
    _create_table()
    _create_bucket()
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    _seed_encrypted_record(store)
    fetched = store.get_current_state(FAKE_SHA)
    assert fetched is not None
    fetched.s3_key = "other-prefix/not-ours.bin"
    store.put_current_state(fetched, expected_last_updated=fetched.last_updated)

    runner = CliRunner()
    with patch("envault.cli.decrypt_file", side_effect=_mock_decrypt_file_ok) as decrypt:
        result = runner.invoke(
            main,
            [
                "decrypt",
                FAKE_SHA,
                "--output",
                str(tmp_path),
                "--table",
                TABLE_NAME,
                "--bucket",
                BUCKET_NAME,
                "--region",
                REGION,
                "--allowed-account-ids",
                ACCOUNT_IDS,
            ],
            env=_CLI_ENV,
        )

    assert result.exit_code != 0
    assert decrypt.call_count == 0
    assert "content-addressed" in result.output.lower()


@mock_aws
def test_rotate_key_refuses_inaccessible_new_key() -> None:
    """DescribeKey must fail closed before any ciphertext is downloaded."""
    _create_table()
    _create_bucket()
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    _seed_encrypted_record(store)

    runner = CliRunner()
    with patch("envault.cli.decrypt_file") as decrypt:
        result = runner.invoke(
            main,
            [
                "rotate-key",
                "--new-key-id",
                "alias/does-not-exist",
                "--table",
                TABLE_NAME,
                "--bucket",
                BUCKET_NAME,
                "--region",
                REGION,
                "--allowed-account-ids",
                ACCOUNT_IDS,
            ],
            env=_CLI_ENV,
        )

    assert result.exit_code != 0
    assert decrypt.call_count == 0
    assert "Cannot use --new-key-id" in result.output


@mock_aws
def test_encrypt_honours_audit_ttl_days(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI flag construction of Config must still apply ENVAULT_AUDIT_TTL_DAYS."""
    import time

    monkeypatch.setenv("ENVAULT_AUDIT_TTL_DAYS", "7")
    _create_table()
    _create_bucket()

    plaintext = tmp_path / "secret.txt"
    plaintext.write_bytes(b"sensitive data")
    sha = hashlib.sha256(b"sensitive data").hexdigest()

    runner = CliRunner()
    with (
        patch("envault.cli.encrypt_file", side_effect=_mock_encrypt_file),
        patch("envault.crypto.sha256_file", return_value=sha),
    ):
        result = runner.invoke(
            main,
            [
                "encrypt",
                str(plaintext),
                "--key-id",
                KEY_ID,
                "--bucket",
                BUCKET_NAME,
                "--table",
                TABLE_NAME,
                "--region",
                REGION,
            ],
            env=_CLI_ENV,
        )

    assert result.exit_code == 0, result.output
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    events = store.list_events_for_file(sha)
    assert events
    ttl = int(events[0]["ttl"])
    assert ttl < int(time.time()) + 8 * 86400
    assert ttl > int(time.time()) + 5 * 86400
