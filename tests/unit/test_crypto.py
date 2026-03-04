"""Unit tests for envault.crypto (SHA256 and checksum verification).

Note: encrypt_file/decrypt_file require real KMS calls (aws-encryption-sdk
does not support moto KMS due to its custom cryptographic protocol). These
functions are tested in tests/integration/. Here we test:
  - sha256_file: pure-Python, no AWS needed
  - decrypt_file checksum mismatch behaviour
  - EncryptResult / DecryptResult dataclass structure
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from envault.crypto import DecryptResult, EncryptResult, _HashingReader, sha256_file
from envault.exceptions import ChecksumMismatchError


def test_sha256_file_correct_hash(tmp_path: Path):
    content = b"hello world\n"
    p = tmp_path / "test.txt"
    p.write_bytes(content)

    expected = hashlib.sha256(content).hexdigest()
    assert sha256_file(p) == expected


def test_sha256_file_empty(tmp_path: Path):
    p = tmp_path / "empty.txt"
    p.write_bytes(b"")
    expected = hashlib.sha256(b"").hexdigest()
    assert sha256_file(p) == expected


def test_sha256_file_large(tmp_path: Path):
    # Ensure chunked reading works correctly
    content = b"X" * (200 * 1024)  # 200 KB, forces multiple 65536-byte chunks
    p = tmp_path / "large.bin"
    p.write_bytes(content)
    expected = hashlib.sha256(content).hexdigest()
    assert sha256_file(p) == expected


def test_encrypt_result_dataclass():
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


def test_decrypt_result_dataclass():
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


def test_decrypt_file_requires_account_ids(tmp_path: Path):
    """decrypt_file must raise ConfigurationError when allowed_account_ids is empty."""
    import pytest

    from envault.crypto import decrypt_file
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


def test_checksum_mismatch_error():
    err = ChecksumMismatchError(expected="aaa", actual="bbb")
    assert "aaa" in str(err)
    assert "bbb" in str(err)


# ---------------------------------------------------------------------------
# _HashingReader tests
# ---------------------------------------------------------------------------


def test_hashing_reader_computes_sha256(tmp_path: Path):
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


def test_hashing_reader_empty_read(tmp_path: Path):
    """_HashingReader must handle empty files correctly."""
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")

    with p.open("rb") as f:
        reader = _HashingReader(f)
        data = reader.read()

    assert data == b""
    assert reader.hexdigest == hashlib.sha256(b"").hexdigest()


def test_hashing_reader_delegates_attributes(tmp_path: Path):
    """_HashingReader must delegate unknown attributes to the wrapped file."""
    p = tmp_path / "test.bin"
    p.write_bytes(b"some data")

    with p.open("rb") as f:
        reader = _HashingReader(f)
        # .name is a file attribute, not defined on _HashingReader
        assert reader.name == f.name
        # .seekable() is a method on the file object
        assert reader.seekable() == f.seekable()
