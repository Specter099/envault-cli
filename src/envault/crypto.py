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
import botocore.session
from aws_encryption_sdk import (
    CommitmentPolicy,
    DiscoveryAwsKmsMasterKeyProvider,
    StrictAwsKmsMasterKeyProvider,
)
from aws_encryption_sdk.exceptions import AWSEncryptionSDKClientError
from cryptography.exceptions import InvalidTag
from tenacity import retry, retry_if_not_exception_type, stop_after_attempt, wait_exponential

from envault.config import boto_config
from envault.exceptions import (
    ChecksumMismatchError,
    ConfigurationError,
    DecryptionError,
    EncryptionContextMismatchError,
)
from envault.fileutils import best_effort_delete

logger = logging.getLogger(__name__)

_CHUNK_SIZE = 65536


def verify_encryption_context(expected: dict[str, str], actual: dict[str, str]) -> None:
    """Verify that every expected encryption context key matches the ciphertext.

    The AWS Encryption SDK adds its own keys (e.g. ``aws-crypto-public-key``) to
    the header under algorithms with key commitment. Those are legitimate, so
    only application-level keys recorded in DynamoDB are checked.

    Raises:
        EncryptionContextMismatchError: If any expected key is missing or differs.
    """
    if any(actual.get(key) != value for key, value in expected.items()):
        raise EncryptionContextMismatchError(expected=expected, actual=actual)


def _kms_session() -> botocore.session.Session:
    """Botocore session for the KMS clients the encryption SDK creates.

    The master key providers build their own KMS clients; without this they
    would get default timeouts and default boto retries, which compound with
    tenacity's application-level retries (the same amplification boto_config
    exists to prevent for S3 and DynamoDB).
    """
    session = botocore.session.Session()
    session.set_default_client_config(boto_config)
    return session


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
    """Result of a decryption operation.

    ``output_path`` is None when the plaintext was streamed to a caller-supplied
    sink (a memfd, a buffer) rather than written to a file.
    """

    sha256_hash: str
    file_size_bytes: int
    encryption_context: dict[str, str]
    output_path: Path | None = None


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
    reraise=True,
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
    key_provider = StrictAwsKmsMasterKeyProvider(
        key_ids=[key_id],
        region_names=[region],
        botocore_session=_kms_session(),
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(output_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)

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


def _discovery_key_provider(
    region: str, allowed_account_ids: list[str]
) -> DiscoveryAwsKmsMasterKeyProvider:
    """Build a discovery provider restricted to explicitly trusted accounts."""
    from aws_encryption_sdk.key_providers.kms import DiscoveryFilter

    return DiscoveryAwsKmsMasterKeyProvider(
        discovery_filter=DiscoveryFilter(
            account_ids=tuple(allowed_account_ids),
            partition=_partition_for_region(region),
        ),
        region_names=[region],
        botocore_session=_kms_session(),
    )


def _partition_for_region(region: str) -> str:
    """Map an AWS region to its partition so GovCloud and China aren't excluded."""
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    if region.startswith("cn-"):
        return "aws-cn"
    return "aws"


def decrypt_to_stream(
    source: BinaryIO,
    out: BinaryIO,
    *,
    expected_sha256: str | None = None,
    expected_context: dict[str, str] | None = None,
    region: str = "us-east-1",
    allowed_account_ids: list[str] | None = None,
) -> DecryptResult:
    """Decrypt ``source`` into ``out``, verifying before the caller exposes it.

    The encryption context is checked against ``expected_context`` as soon as the
    ciphertext header is parsed — before a single plaintext byte is written — so
    a substituted ciphertext is rejected without ever materialising. The checksum
    is verified after the stream completes.

    ``out`` may be any writable binary sink: a memfd from
    :class:`~envault.isolation.CredentialFd`, a buffer, or a file. The caller is
    responsible for keeping that sink private until this returns successfully;
    on any exception the sink holds unverified bytes and must be discarded.

    Not retried, deliberately — ``source`` is a stream and cannot be replayed.
    Callers that need retries should reopen the source and call again, as
    :func:`decrypt_file` does.

    Args:
        source: Readable binary stream of ciphertext.
        out: Writable binary sink for the plaintext.
        expected_sha256: If provided, the plaintext checksum must match.
        expected_context: If provided, every key must match the ciphertext header.
        region: AWS region where the KMS key lives.
        allowed_account_ids: AWS account IDs trusted to have encrypted the data.

    Returns:
        DecryptResult with the plaintext hash, size, and encryption context.

    Raises:
        ConfigurationError: If allowed_account_ids is empty.
        EncryptionContextMismatchError: If the header context doesn't match.
        ChecksumMismatchError: If the plaintext checksum doesn't match.
        DecryptionError: If the ciphertext is corrupted, truncated, or tampered.
    """
    if not allowed_account_ids:
        raise ConfigurationError(
            "allowed_account_ids is required for decryption. "
            "Set ENVAULT_ALLOWED_ACCOUNT_IDS to a comma-separated list of AWS account IDs "
            "that are trusted to have encrypted the data."
        )

    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        max_encrypted_data_keys=1,
    )
    key_provider = _discovery_key_provider(region, allowed_account_ids)

    hasher = hashlib.sha256()
    file_size = 0
    try:
        with client.stream(source=source, mode="d", key_provider=key_provider) as decryptor:
            enc_context = dict(decryptor.header.encryption_context)
            # Before any plaintext is written: a ciphertext whose context does
            # not match the record is never materialised, anywhere.
            if expected_context is not None:
                verify_encryption_context(expected_context, enc_context)
            while True:
                chunk = decryptor.read(_CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
                out.write(chunk)
                file_size += len(chunk)
    except (AWSEncryptionSDKClientError, InvalidTag) as exc:
        # InvalidTag escapes the SDK raw when AES-GCM frame authentication
        # fails (corrupted or tampered ciphertext).
        raise DecryptionError(
            f"Failed to decrypt: {exc}. "
            "The ciphertext may be corrupted, truncated, or tampered with."
        ) from exc

    actual_sha256 = hasher.hexdigest()
    if expected_sha256 and actual_sha256 != expected_sha256:
        raise ChecksumMismatchError(expected=expected_sha256, actual=actual_sha256)

    return DecryptResult(
        sha256_hash=actual_sha256,
        file_size_bytes=file_size,
        encryption_context=enc_context,
    )


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    reraise=True,
    retry=retry_if_not_exception_type(
        (
            ConfigurationError,
            ChecksumMismatchError,
            DecryptionError,
            EncryptionContextMismatchError,
        )
    ),
)
def decrypt_file(
    input_path: Path,
    output_path: Path,
    expected_sha256: str | None = None,
    region: str = "us-east-1",
    allowed_account_ids: list[str] | None = None,
    expected_context: dict[str, str] | None = None,
) -> DecryptResult:
    """Decrypt a file to a path, verifying before the plaintext becomes reachable.

    Plaintext is streamed to a temporary file in the destination directory and
    renamed into place only after the encryption context and checksum both
    verify, so a failed, truncated, or tampered decrypt never leaves partial or
    unverified plaintext at the destination. On any failure the temporary file
    is zero-overwritten and removed.

    Args:
        input_path: Path to the encrypted file.
        output_path: Destination path for the decrypted plaintext.
        expected_sha256: If provided, verifies the checksum after decryption.
        region: AWS region where the KMS key lives.
        allowed_account_ids: AWS account IDs trusted to have encrypted the data.
        expected_context: If provided, verified against the ciphertext header
            before any plaintext is written.

    Returns:
        DecryptResult with hash and size of the decrypted file.

    Raises:
        ChecksumMismatchError: If expected_sha256 is provided and doesn't match.
        EncryptionContextMismatchError: If expected_context doesn't match.
        DecryptionError: If the SDK fails to decrypt (corrupted/tampered
            ciphertext, failed frame authentication, untrusted key). Never
            retried — these failures are deterministic.
    """
    logger.info("Decrypting file", extra={"input": str(input_path)})

    output_path.parent.mkdir(parents=True, exist_ok=True)
    # mkstemp creates the file 0o600; renamed over output_path only on success.
    tmp_fd, _tmp_name = tempfile.mkstemp(
        dir=output_path.parent, prefix=f".{output_path.name}.", suffix=".part"
    )
    tmp_path = Path(_tmp_name)

    try:
        with os.fdopen(tmp_fd, "wb") as out, input_path.open("rb") as encrypted_file:
            result = decrypt_to_stream(
                encrypted_file,
                out,
                expected_sha256=expected_sha256,
                expected_context=expected_context,
                region=region,
                allowed_account_ids=allowed_account_ids,
            )
        os.replace(tmp_path, output_path)
    finally:
        # No-op after a successful rename; zero-overwrites partial plaintext
        # left behind by any failure above.
        best_effort_delete(tmp_path)

    logger.info(
        "Decryption complete",
        extra={"sha256": result.sha256_hash[:16], "output": str(output_path)},
    )

    result.output_path = output_path
    return result
