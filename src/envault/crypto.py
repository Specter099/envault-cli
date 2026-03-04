"""Encryption and decryption using aws-encryption-sdk (pure Python, no subprocess)."""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass
from pathlib import Path

import aws_encryption_sdk
from aws_encryption_sdk import (
    CommitmentPolicy,
    DiscoveryAwsKmsMasterKeyProvider,
    StrictAwsKmsMasterKeyProvider,
)
from tenacity import retry, retry_if_not_exception_type, stop_after_attempt, wait_exponential

from envault.exceptions import ChecksumMismatchError, ConfigurationError

logger = logging.getLogger(__name__)


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


def sha256_file(path: Path) -> str:
    """Compute SHA256 hash of a file's contents."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
def encrypt_file(
    input_path: Path,
    key_id: str,
    encryption_context: dict[str, str],
    output_path: Path,
    region: str = "us-east-1",
) -> EncryptResult:
    """Encrypt a file using AWS KMS envelope encryption.

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
    sha256_hash = sha256_file(input_path)
    file_size = input_path.stat().st_size

    logger.info("Encrypting file", extra={"input": str(input_path), "key_id": key_id})

    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )
    key_provider = StrictAwsKmsMasterKeyProvider(key_ids=[key_id])

    with input_path.open("rb") as plaintext_file:
        ciphertext, header = client.encrypt(
            source=plaintext_file,
            key_provider=key_provider,
            encryption_context=encryption_context,
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as out:
        out.write(ciphertext)
    os.chmod(output_path, 0o600)

    algorithm = (
        header.algorithm.name if hasattr(header.algorithm, "name") else str(header.algorithm)
    )
    message_id = (
        header.message_id.hex() if isinstance(header.message_id, bytes) else str(header.message_id)
    )

    logger.info(
        "Encryption complete",
        extra={
            "sha256": sha256_hash,
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
    """Decrypt a file using AWS KMS.

    Args:
        input_path: Path to the encrypted file.
        output_path: Destination path for the decrypted plaintext.
        expected_sha256: If provided, verifies the checksum after decryption.
        region: AWS region where the KMS key lives.

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
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )
    from aws_encryption_sdk.key_providers.kms import DiscoveryFilter

    key_provider = DiscoveryAwsKmsMasterKeyProvider(
        discovery_filter=DiscoveryFilter(
            account_ids=tuple(allowed_account_ids),
            partition="aws",
        )
    )

    with input_path.open("rb") as encrypted_file:
        plaintext, header = client.decrypt(
            source=encrypted_file,
            key_provider=key_provider,
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as out:
        out.write(plaintext)
    os.chmod(output_path, 0o600)

    actual_sha256 = sha256_file(output_path)
    file_size = output_path.stat().st_size

    if expected_sha256 and actual_sha256 != expected_sha256:
        output_path.unlink(missing_ok=True)
        raise ChecksumMismatchError(expected=expected_sha256, actual=actual_sha256)

    logger.info(
        "Decryption complete",
        extra={"sha256": actual_sha256, "output": str(output_path)},
    )

    return DecryptResult(
        sha256_hash=actual_sha256,
        file_size_bytes=file_size,
        output_path=output_path,
        encryption_context=dict(header.encryption_context),
    )
