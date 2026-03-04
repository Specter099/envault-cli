from __future__ import annotations

import glob
import hashlib
from pathlib import Path
from unittest.mock import patch

import boto3
import click
import pytest
from click.testing import CliRunner
from moto import mock_aws

from envault.cli import _best_effort_delete, _parse_output_json_entry, _parse_tags, main
from envault.crypto import DecryptResult, EncryptResult
from envault.exceptions import ChecksumMismatchError, EnvaultError
from envault.state import ENCRYPTED, FileRecord, StateStore

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


def _upload_fake_ciphertext(s3_key: str) -> str:
    """Upload fake ciphertext to S3 and return the real VersionId."""
    s3 = boto3.client("s3", region_name=REGION)
    resp = s3.put_object(Bucket=BUCKET_NAME, Key=s3_key, Body=b"fake-ciphertext")
    return resp.get("VersionId", "")


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


def _make_entry(input_path: str) -> dict:
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


def test_parse_entry_uses_content_hash(tmp_path: Path):
    """_parse_output_json_entry must hash file CONTENT, not the path string."""
    plaintext = tmp_path / "secret.txt"
    content = b"sensitive data\n"
    plaintext.write_bytes(content)
    expected_hash = hashlib.sha256(content).hexdigest()

    entry = _make_entry(str(plaintext))
    record = _parse_output_json_entry(entry)

    assert record is not None
    assert record.sha256_hash == expected_hash


def test_parse_entry_skips_missing_file(tmp_path: Path):
    """_parse_output_json_entry returns None when the plaintext file doesn't exist."""
    entry = _make_entry("/nonexistent/path/file.txt")
    record = _parse_output_json_entry(entry)
    assert record is None


def test_parse_entry_skips_non_encrypt_mode():
    entry = {"mode": "decrypt", "input": "/some/file"}
    assert _parse_output_json_entry(entry) is None


def test_best_effort_delete_overwrites_before_removal(tmp_path: Path):
    """_best_effort_delete must zero-out file contents before unlinking."""
    p = tmp_path / "sensitive.bin"
    p.write_bytes(b"TOP SECRET DATA")
    assert p.exists()

    _best_effort_delete(p)

    assert not p.exists()


def test_best_effort_delete_missing_file_is_noop(tmp_path: Path):
    """_best_effort_delete on a non-existent path must not raise."""
    p = tmp_path / "does_not_exist"
    _best_effort_delete(p)  # should not raise


def test_best_effort_delete_zero_length_file(tmp_path: Path):
    p = tmp_path / "empty"
    p.write_bytes(b"")
    _best_effort_delete(p)
    assert not p.exists()


def test_best_effort_delete_logs_warning_on_oserror(tmp_path: Path, caplog):
    """_best_effort_delete must log a warning if overwrite fails with OSError."""
    import logging
    from unittest.mock import patch

    p = tmp_path / "readonly.bin"
    p.write_bytes(b"data")

    with (
        patch.object(Path, "open", side_effect=OSError("Permission denied")),
        caplog.at_level(logging.WARNING, logger="envault.cli"),
    ):
        _best_effort_delete(p)

    assert any("best-effort" in r.message.lower() for r in caplog.records)


def test_parse_tags_valid():
    result = _parse_tags(("project=finance", "env=prod"))
    assert result == {"project": "finance", "env": "prod"}


def test_parse_tags_invalid_key_raises():
    """Tag keys with special characters must raise UsageError."""
    with pytest.raises(click.UsageError, match="Invalid tag key"):
        _parse_tags(("bad key!=value",))


def test_parse_tags_key_too_long_raises():
    """Tag key longer than 64 chars must raise UsageError."""
    long_key = "k" * 65
    with pytest.raises(click.UsageError, match="Invalid tag key"):
        _parse_tags((f"{long_key}=value",))


def test_parse_tags_value_too_long_raises():
    """Tag value longer than 256 chars must raise UsageError."""
    long_val = "v" * 257
    with pytest.raises(click.UsageError, match="exceeds"):
        _parse_tags((f"key={long_val}",))


def test_parse_tags_empty_key_raises():
    with pytest.raises(click.UsageError, match="Invalid tag key"):
        _parse_tags(("=value",))


def test_decrypt_rejects_invalid_sha256_format():
    """decrypt must reject hash arguments that are not 64-char hex strings."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "decrypt",
            "not-a-valid-hash",
            "--table",
            "t",
            "--bucket",
            "b",
        ],
        env={
            "AWS_ACCESS_KEY_ID": "testing",
            "AWS_SECRET_ACCESS_KEY": "testing",
            "AWS_DEFAULT_REGION": "us-east-1",
        },
    )
    assert result.exit_code != 0
    assert "invalid" in result.output.lower() or "sha256" in result.output.lower()


# ---------------------------------------------------------------------------
# C-3: CLI integration tests (encrypt, decrypt, rotate-key)
# ---------------------------------------------------------------------------


def _mock_encrypt_file(input_path, key_id, encryption_context, output_path, region="us-east-1"):
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
def test_encrypt_command_end_to_end(tmp_path: Path):
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


def _mock_decrypt_file_ok(
    input_path, output_path, expected_sha256=None, region="us-east-1", allowed_account_ids=None
):
    """Fake decrypt_file that writes plaintext and returns matching context."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(b"decrypted content")
    return DecryptResult(
        sha256_hash=FAKE_SHA,
        file_size_bytes=17,
        output_path=output_path,
        encryption_context={
            "purpose": "envault-backup",
            "sha256": FAKE_SHA,
            "file_name": "test.txt",
            "kms_key_alias": KEY_ID,
        },
    )


@mock_aws
def test_decrypt_command_end_to_end(tmp_path: Path):
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
def test_decrypt_checksum_mismatch(tmp_path: Path):
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
def test_decrypt_encryption_context_mismatch(tmp_path: Path):
    """decrypt must fail when encryption context from ciphertext doesn't match DynamoDB."""
    _create_table()
    _create_bucket()
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    record = _seed_encrypted_record(store)
    _upload_fake_ciphertext(record.s3_key)

    def _mock_decrypt_mismatched_ctx(
        input_path, output_path, expected_sha256=None, region="us-east-1", allowed_account_ids=None
    ):
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(b"data")
        return DecryptResult(
            sha256_hash=FAKE_SHA,
            file_size_bytes=4,
            output_path=output_path,
            encryption_context={"purpose": "TAMPERED", "sha256": FAKE_SHA},
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
    # Output file should have been cleaned up
    decrypted_files = list(tmp_path.glob("test.txt"))
    assert not decrypted_files or not decrypted_files[0].exists()


@mock_aws
def test_rotate_key_end_to_end(tmp_path: Path):
    """rotate-key: mocked decrypt + re-encrypt, real DynamoDB + S3."""
    _create_table()
    _create_bucket()
    s3_key = f"encrypted/{FAKE_SHA[:2]}/{FAKE_SHA}/test.txt.encrypted"
    version_id = _upload_fake_ciphertext(s3_key)
    store = StateStore(table_name=TABLE_NAME, region=REGION)
    record = _seed_encrypted_record(store, s3_version_id=version_id)

    new_key_id = "alias/new-key"

    def _mock_decrypt(
        input_path, output_path, expected_sha256=None, region="us-east-1", allowed_account_ids=None
    ):
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(b"plaintext")
        return DecryptResult(
            sha256_hash=FAKE_SHA,
            file_size_bytes=9,
            output_path=output_path,
            encryption_context=record.encryption_context,
        )

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
def test_encrypt_temp_file_cleanup_on_failure(tmp_path: Path):
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
def test_decrypt_temp_file_cleanup_on_failure(tmp_path: Path):
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
