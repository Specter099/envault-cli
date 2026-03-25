"""Encryption and decryption using aws-encryption-sdk (pure Python, no subprocess)."""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

import aws_encryption_sdk
from aws_encryption_sdk import (
    CommitmentPolicy,
    DiscoveryAwsKmsMasterKeyProvider,
    StrictAwsKmsMasterKeyProvider,
)
from tenacity import retry, retry_if_not_exception_type, stop_after_attempt, wait_exponential

from envault.exceptions import ChecksumMismatchError, ConfigurationError

logger = logging.getLogger(__name__)

_CHUNK_SIZE = 65536


@dataclass
class EncryptResult:
    """Result of an encryption operation."""

    sha256_hash: str
    file_size_bytes: int
    algorithm: str
    message_id: str
    output_path: Path


@dataclass
class DecryptResult:
    """Result of a decryption operation."""

    sha256_hash: str
    file_size_bytes: int
    output_path: Path
    encryption_context: dict[str, str]


class _HashingReader:
    """File wrapper that computes SHA256 as data is read through it."""

    def __init__(self, file_obj: BinaryIO) -> None:
        self._file = file_obj
        self._hasher = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        data = self._file.read(size)
        if data:
            self._hasher.update(data)
        return data

    @property
    def hexdigest(self) -> str:
        return self._hasher.hexdigest()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._file, name)


def sha256_file(path: Path) -> str:
    """Compute SHA256 hash of a file's contents."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_not_exception_type(ConfigurationError),
)
def encrypt_file(
    input_path: Path,
    key_id: str,
    encryption_context: dict[str, str],
    output_path: Path,
    region: str = "us-east-1",
) -> EncryptResult:
    """Encrypt a file using AWS KMS envelope encryption (streaming).

    Uses streaming mode to avoid holding the full plaintext or ciphertext
    in memory. SHA256 is computed incrementally as data flows through the
    encryption stream, eliminating the TOCTOU window between hashing and
    encrypting.

    The plaintext never leaves this machine — only the data encryption key (DEK)
    is sent to KMS for wrapping. The file is encrypted locally with AES-256-GCM.

    Args:
        input_path: Path to the plaintext file to encrypt.
        key_id: KMS key alias (e.g. 'alias/s3_key') or full ARN.
        encryption_context: Key-value pairs bound to the ciphertext (authenticated but not secret).
        output_path: Destination path for the encrypted file.
        region: AWS region where the KMS key lives.

    Returns:
        EncryptResult with hash, size, algorithm, and message_id.
    """
    file_size = input_path.stat().st_size

    logger.info("Encrypting file", extra={"input": str(input_path), "key_id": key_id})

    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )
    key_provider = StrictAwsKmsMasterKeyProvider(key_ids=[key_id])

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(output_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)

    with input_path.open("rb") as raw_input:
        hashing_reader = _HashingReader(raw_input)
        with client.stream(
            source=hashing_reader,
            mode="e",
            key_provider=key_provider,
            encryption_context=encryption_context,
            frame_length=4096,
        ) as encryptor:
            with os.fdopen(fd, "wb") as out:
                while True:
                    chunk = encryptor.read(_CHUNK_SIZE)
                    if not chunk:
                        break
                    out.write(chunk)
            header = encryptor.header

    sha256_hash = hashing_reader.hexdigest

    algorithm = (
        header.algorithm.name if hasattr(header.algorithm, "name") else str(header.algorithm)
    )
    message_id = (
        header.message_id.hex() if isinstance(header.message_id, bytes) else str(header.message_id)
    )

    logger.info(
        "Encryption complete",
        extra={
            "sha256": sha256_hash[:16],
            "output": str(output_path),
            "algorithm": algorithm,
            "message_id": message_id,
        },
    )

    return EncryptResult(
        sha256_hash=sha256_hash,
        file_size_bytes=file_size,
        algorithm=algorithm,
        message_id=message_id,
        output_path=output_path,
    )


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_not_exception_type((ConfigurationError, ChecksumMismatchError)),
)
def decrypt_file(
    input_path: Path,
    output_path: Path,
    expected_sha256: str | None = None,
    region: str = "us-east-1",
    allowed_account_ids: list[str] | None = None,
) -> DecryptResult:
    """Decrypt a file using AWS KMS (streaming).

    Uses streaming mode to avoid holding the full plaintext in memory.
    SHA256 is computed incrementally as decrypted data is written to disk.
    On checksum mismatch the partially-written output is deleted.

    Args:
        input_path: Path to the encrypted file.
        output_path: Destination path for the decrypted plaintext.
        expected_sha256: If provided, verifies the checksum after decryption.
        region: AWS region where the KMS key lives.
        allowed_account_ids: AWS account IDs trusted to have encrypted the data.

    Returns:
        DecryptResult with hash and size of the decrypted file.

    Raises:
        ChecksumMismatchError: If expected_sha256 is provided and doesn't match.
    """
    if not allowed_account_ids:
        raise ConfigurationError(
            "allowed_account_ids is required for decryption. "
            "Set ENVAULT_ALLOWED_ACCOUNT_IDS to a comma-separated list of AWS account IDs "
            "that are trusted to have encrypted the data."
        )

    logger.info("Decrypting file", extra={"input": str(input_path)})

    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        max_encrypted_data_keys=1,
    )
    from aws_encryption_sdk.key_providers.kms import DiscoveryFilter

    key_provider = DiscoveryAwsKmsMasterKeyProvider(
        discovery_filter=DiscoveryFilter(
            account_ids=tuple(allowed_account_ids),
            partition="aws",
        )
    )

    # Decrypt to a temp file in the same directory so os.rename() is atomic
    # (same filesystem). Only rename to output_path after hash verification.
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _fd_tmp, _tmp_path = tempfile.mkstemp(
        dir=output_path.parent, prefix=".envault_dec_", suffix=".tmp"
    )
    os.fchmod(_fd_tmp, 0o600)
    tmp_path = Path(_tmp_path)

    try:
        with input_path.open("rb") as encrypted_file:
            with client.stream(
                source=encrypted_file,
                mode="d",
                key_provider=key_provider,
            ) as decryptor:
                enc_context = dict(decryptor.header.encryption_context)

                hasher = hashlib.sha256()
                file_size = 0
                with os.fdopen(_fd_tmp, "wb") as out:
                    while True:
                        chunk = decryptor.read(_CHUNK_SIZE)
                        if not chunk:
                            break
                        hasher.update(chunk)
                        out.write(chunk)
                        file_size += len(chunk)

        actual_sha256 = hasher.hexdigest()

        if expected_sha256 and actual_sha256 != expected_sha256:
            raise ChecksumMismatchError(expected=expected_sha256, actual=actual_sha256)

        os.rename(tmp_path, output_path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise

    logger.info(
        "Decryption complete",
        extra={"sha256": actual_sha256[:16], "output": str(output_path)},
    )

    return DecryptResult(
        sha256_hash=actual_sha256,
        file_size_bytes=file_size,
        output_path=output_path,
        encryption_context=enc_context,
    )
