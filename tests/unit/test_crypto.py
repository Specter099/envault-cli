"""Unit tests for envault.crypto.

Covers:
  - sha256_file: pure-Python, no AWS needed
  - _HashingReader and result dataclasses
  - Full encrypt/decrypt round-trips against moto-mocked KMS (the
    aws-encryption-sdk only sends the DEK to KMS for wrapping, which moto
    supports — the AES-GCM enveloping happens client-side)
  - Failure-path hygiene: corrupted ciphertext, checksum mismatch, and
    explicit region handling
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from envault.crypto import (
    DecryptResult,
    EncryptResult,
    _HashingReader,
    decrypt_file,
    encrypt_file,
    sha256_file,
)
from envault.exceptions import ChecksumMismatchError, DecryptionError

KMS_KEY_ALIAS = "alias/envault-test"
REGION = "us-east-1"
MOTO_ACCOUNT_ID = "123456789012"


def test_sha256_file_correct_hash(tmp_path: Path) -> None:
    content = b"hello world\n"
    p = tmp_path / "test.txt"
    p.write_bytes(content)

    expected = hashlib.sha256(content).hexdigest()
    assert sha256_file(p) == expected


def test_sha256_file_empty(tmp_path: Path) -> None:
    p = tmp_path / "empty.txt"
    p.write_bytes(b"")
    expected = hashlib.sha256(b"").hexdigest()
    assert sha256_file(p) == expected


def test_sha256_file_large(tmp_path: Path) -> None:
    # Ensure chunked reading works correctly
    content = b"X" * (200 * 1024)  # 200 KB, forces multiple 65536-byte chunks
    p = tmp_path / "large.bin"
    p.write_bytes(content)
    expected = hashlib.sha256(content).hexdigest()
    assert sha256_file(p) == expected


def test_encrypt_result_dataclass() -> None:
    result = EncryptResult(
        sha256_hash="abc123",
        file_size_bytes=1024,
        algorithm="AES_256_GCM",
        message_id="msg-001",
        output_path=Path("/tmp/out.enc"),  # noqa: S108
    )
    assert result.sha256_hash == "abc123"
    assert result.file_size_bytes == 1024
    assert result.algorithm == "AES_256_GCM"
    assert result.message_id == "msg-001"
    assert result.output_path == Path("/tmp/out.enc")  # noqa: S108


def test_decrypt_result_dataclass() -> None:
    ctx = {"purpose": "envault-backup", "sha256": "def456"}
    result = DecryptResult(
        sha256_hash="def456",
        file_size_bytes=2048,
        output_path=Path("/tmp/out.txt"),  # noqa: S108
        encryption_context=ctx,
    )
    assert result.sha256_hash == "def456"
    assert result.file_size_bytes == 2048
    assert result.output_path == Path("/tmp/out.txt")  # noqa: S108
    assert result.encryption_context == ctx


def test_decrypt_file_requires_account_ids(tmp_path: Path) -> None:
    """decrypt_file must raise ConfigurationError when allowed_account_ids is empty."""

    from envault.exceptions import ConfigurationError

    dummy_input = tmp_path / "dummy.enc"
    dummy_input.write_bytes(b"fake ciphertext")
    dummy_output = tmp_path / "out.txt"

    with pytest.raises(ConfigurationError, match="allowed_account_ids"):
        decrypt_file(
            input_path=dummy_input,
            output_path=dummy_output,
            region="us-east-1",
            allowed_account_ids=[],
        )

    with pytest.raises(ConfigurationError, match="allowed_account_ids"):
        decrypt_file(
            input_path=dummy_input,
            output_path=dummy_output,
            region="us-east-1",
            allowed_account_ids=None,
        )


def test_checksum_mismatch_error() -> None:
    err = ChecksumMismatchError(expected="aaa", actual="bbb")
    assert "aaa" in str(err)
    assert "bbb" in str(err)


# ---------------------------------------------------------------------------
# _HashingReader tests
# ---------------------------------------------------------------------------


def test_hashing_reader_computes_sha256(tmp_path: Path) -> None:
    """_HashingReader must produce correct SHA256 after multiple reads."""
    content = b"hello world" * 100
    p = tmp_path / "data.bin"
    p.write_bytes(content)

    with p.open("rb") as f:
        reader = _HashingReader(f)
        chunks = []
        while True:
            chunk = reader.read(64)
            if not chunk:
                break
            chunks.append(chunk)

    assert b"".join(chunks) == content
    assert reader.hexdigest == hashlib.sha256(content).hexdigest()


def test_hashing_reader_empty_read(tmp_path: Path) -> None:
    """_HashingReader must handle empty files correctly."""
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")

    with p.open("rb") as f:
        reader = _HashingReader(f)
        data = reader.read()

    assert data == b""
    assert reader.hexdigest == hashlib.sha256(b"").hexdigest()


def test_hashing_reader_delegates_attributes(tmp_path: Path) -> None:
    """_HashingReader must delegate unknown attributes to the wrapped file."""
    p = tmp_path / "test.bin"
    p.write_bytes(b"some data")

    with p.open("rb") as f:
        reader = _HashingReader(f)
        # .name is a file attribute, not defined on _HashingReader
        assert reader.name == f.name
        # .seekable() is a method on the file object
        assert reader.seekable() == f.seekable()


# ---------------------------------------------------------------------------
# Round-trip tests against moto-mocked KMS
# ---------------------------------------------------------------------------


def _write_multiframe_plaintext(path: Path) -> bytes:
    """Write plaintext large enough to span multiple 64 KiB read chunks.

    This matters for the corruption test: a corrupted late frame must fail
    only after earlier chunks were already written to disk.
    """
    content = os.urandom(200 * 1024)
    path.write_bytes(content)
    return content


def test_roundtrip_encrypt_decrypt(kms_key: str, tmp_path: Path) -> None:
    """Encrypt then decrypt restores the exact content and encryption context."""
    plaintext = tmp_path / "secret.txt"
    content = _write_multiframe_plaintext(plaintext)
    encrypted = tmp_path / "secret.enc"
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    output = out_dir / "secret.txt"

    result = encrypt_file(
        input_path=plaintext,
        key_id=KMS_KEY_ALIAS,
        encryption_context={"purpose": "envault-backup", "file_name": "secret.txt"},
        output_path=encrypted,
        region=REGION,
    )
    assert result.sha256_hash == hashlib.sha256(content).hexdigest()
    assert result.file_size_bytes == len(content)

    dec = decrypt_file(
        input_path=encrypted,
        output_path=output,
        expected_sha256=result.sha256_hash,
        region=REGION,
        allowed_account_ids=[MOTO_ACCOUNT_ID],
    )
    assert output.read_bytes() == content
    assert dec.sha256_hash == result.sha256_hash
    assert dec.encryption_context["purpose"] == "envault-backup"
    assert dec.encryption_context["file_name"] == "secret.txt"


def test_decrypt_corrupted_ciphertext_raises_and_cleans_up(kms_key: str, tmp_path: Path) -> None:
    """A late-frame corruption surfaces as DecryptionError, is not retried,
    and leaves no partial plaintext in the destination directory."""
    plaintext = tmp_path / "secret.txt"
    _write_multiframe_plaintext(plaintext)
    encrypted = tmp_path / "secret.enc"
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    output = out_dir / "secret.txt"

    result = encrypt_file(
        input_path=plaintext,
        key_id=KMS_KEY_ALIAS,
        encryption_context={"purpose": "envault-backup"},
        output_path=encrypted,
        region=REGION,
    )

    data = bytearray(encrypted.read_bytes())
    data[int(len(data) * 0.9)] ^= 0xFF  # corrupt a late AES-GCM frame
    encrypted.write_bytes(bytes(data))

    with pytest.raises(DecryptionError):
        decrypt_file(
            input_path=encrypted,
            output_path=output,
            expected_sha256=result.sha256_hash,
            region=REGION,
            allowed_account_ids=[MOTO_ACCOUNT_ID],
        )

    assert not output.exists()
    assert list(out_dir.iterdir()) == []  # no partial or temp files left behind
    stats = decrypt_file.statistics
    assert stats["attempt_number"] == 1  # deterministic failure must not be retried


def test_decrypt_checksum_mismatch_leaves_no_output(kms_key: str, tmp_path: Path) -> None:
    """On checksum mismatch the plaintext never appears at output_path and no
    temp file remains in the destination directory."""
    plaintext = tmp_path / "secret.txt"
    _write_multiframe_plaintext(plaintext)
    encrypted = tmp_path / "secret.enc"
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    output = out_dir / "secret.txt"

    encrypt_file(
        input_path=plaintext,
        key_id=KMS_KEY_ALIAS,
        encryption_context={"purpose": "envault-backup"},
        output_path=encrypted,
        region=REGION,
    )

    with pytest.raises(ChecksumMismatchError):
        decrypt_file(
            input_path=encrypted,
            output_path=output,
            expected_sha256="0" * 64,
            region=REGION,
            allowed_account_ids=[MOTO_ACCOUNT_ID],
        )

    assert not output.exists()
    assert list(out_dir.iterdir()) == []
    stats = decrypt_file.statistics
    assert stats["attempt_number"] == 1


def test_encrypt_decrypt_respects_explicit_region(tmp_path: Path) -> None:
    """encrypt_file must resolve the key alias in the requested region, not
    the ambient AWS_DEFAULT_REGION (us-east-1 in the test environment)."""
    with mock_aws():
        kms = boto3.client("kms", region_name="us-west-2")
        key_id = kms.create_key(Description="west-only")["KeyMetadata"]["KeyId"]
        kms.create_alias(AliasName="alias/west-only", TargetKeyId=key_id)

        plaintext = tmp_path / "secret.txt"
        content = b"regional content\n" * 100
        plaintext.write_bytes(content)
        encrypted = tmp_path / "secret.enc"
        output = tmp_path / "out.txt"

        result = encrypt_file(
            input_path=plaintext,
            key_id="alias/west-only",
            encryption_context={"purpose": "envault-backup"},
            output_path=encrypted,
            region="us-west-2",
        )
        decrypt_file(
            input_path=encrypted,
            output_path=output,
            expected_sha256=result.sha256_hash,
            region="us-west-2",
            allowed_account_ids=[MOTO_ACCOUNT_ID],
        )
        assert output.read_bytes() == content


# ---------------------------------------------------------------------------
# Streaming decrypt: verification ordering
# ---------------------------------------------------------------------------


@mock_aws
def test_decrypt_to_stream_rejects_context_before_writing_plaintext():
    """A mismatched context must be caught before any plaintext reaches the sink."""
    import io

    from envault.crypto import decrypt_to_stream
    from envault.exceptions import EncryptionContextMismatchError

    kms = boto3.client("kms", region_name=REGION)
    key_id = kms.create_key(Description="stream-test")["KeyMetadata"]["KeyId"]
    account = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
    ctx = {"purpose": "envault-backup", "sha256": "a" * 64}

    ciphertext = io.BytesIO()
    plaintext = b"the actual secret bytes"
    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "in.txt"
        src.write_bytes(plaintext)
        out = Path(tmpdir) / "out.enc"
        encrypt_file(src, key_id, ctx, out, REGION)
        ciphertext = io.BytesIO(out.read_bytes())

    sink = io.BytesIO()
    with pytest.raises(EncryptionContextMismatchError):
        decrypt_to_stream(
            ciphertext,
            sink,
            expected_context={"purpose": "SOMETHING-ELSE"},
            region=REGION,
            allowed_account_ids=[account],
        )
    assert sink.getvalue() == b"", "plaintext must not be written on a context mismatch"


@mock_aws
def test_decrypt_to_stream_roundtrip():
    import io

    from envault.crypto import decrypt_to_stream

    kms = boto3.client("kms", region_name=REGION)
    key_id = kms.create_key(Description="stream-test")["KeyMetadata"]["KeyId"]
    account = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
    plaintext = b"round trip content"
    ctx = {"purpose": "envault-backup"}

    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "in.txt"
        src.write_bytes(plaintext)
        out = Path(tmpdir) / "out.enc"
        encrypt_file(src, key_id, ctx, out, REGION)
        ciphertext = io.BytesIO(out.read_bytes())

    sink = io.BytesIO()
    result = decrypt_to_stream(
        ciphertext,
        sink,
        expected_sha256=hashlib.sha256(plaintext).hexdigest(),
        expected_context=ctx,
        region=REGION,
        allowed_account_ids=[account],
    )
    assert sink.getvalue() == plaintext
    assert result.output_path is None


def test_partition_for_region():
    """Discovery filters must not silently exclude GovCloud or China partitions."""
    from envault.crypto import _partition_for_region

    assert _partition_for_region("us-east-1") == "aws"
    assert _partition_for_region("eu-west-2") == "aws"
    assert _partition_for_region("us-gov-west-1") == "aws-us-gov"
    assert _partition_for_region("cn-north-1") == "aws-cn"
