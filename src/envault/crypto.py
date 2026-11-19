"""Encryption and decryption using aws-encryption-sdk (pure Python, no subprocess)."""

from __future__ import annotations

import functools
import hashlib
import logging
import os
import tempfile
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

import aws_encryption_sdk
import botocore.session
from aws_encryption_sdk import (
    CommitmentPolicy,
    DiscoveryAwsKmsMasterKeyProvider,
    StrictAwsKmsMasterKeyProvider,
)
from aws_encryption_sdk.exceptions import (
    AWSEncryptionSDKClientError,
    DecryptKeyError,
    MasterKeyProviderError,
)
from botocore.exceptions import ClientError
from cryptography.exceptions import InvalidTag

from envault.config import boto_config, partition_for_region
from envault.exceptions import (
    ChecksumMismatchError,
    ConfigurationError,
    DecryptionError,
    EncryptionContextMismatchError,
    EncryptionError,
    EnvaultError,
    KMSError,
)
from envault.fileutils import best_effort_delete, open_regular_nofollow
from envault.retry import aws_retry, is_transient_aws_error

logger = logging.getLogger(__name__)

_CHUNK_SIZE = 65536

# Deterministic failures: fail on the first attempt even if a transient error is
# somewhere in their cause chain.
_DECRYPT_NEVER: tuple[type[BaseException], ...] = (
    ConfigurationError,
    ChecksumMismatchError,
    DecryptionError,
    EncryptionContextMismatchError,
    OSError,
)
_ENCRYPT_NEVER: tuple[type[BaseException], ...] = (ConfigurationError, EncryptionError, OSError)

# KMS answers to Decrypt that implicate the ciphertext rather than KMS: the
# encrypted data key or encryption context does not verify, or the header names
# a key that cannot have produced it. NotFoundException is here too: an altered
# key ARN in the header and a deleted key look the same, and both mean the data
# cannot be decrypted. Its message names both explanations.
_KMS_INTEGRITY_ERROR_CODES = frozenset(
    {
        "InvalidCiphertextException",
        "IncorrectKeyException",
        "InvalidKeyUsageException",
        "NotFoundException",
    }
)

# KMS client methods the Encryption SDK calls for data keys, by API operation.
_KMS_DATA_KEY_METHODS = {
    "decrypt": "Decrypt",
    "generate_data_key": "GenerateDataKey",
    "encrypt": "Encrypt",
}


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


@dataclass(frozen=True)
class _KmsFailure:
    """One failed KMS data-key call, as seen at the KMS client."""

    operation: str
    key_id: str
    error: Exception


class _KmsCallRecorder:
    """Records the KMS data-key calls the Encryption SDK makes, and how they fail.

    The SDK turns a failed KMS Decrypt into ``DecryptKeyError("Unable to decrypt
    any data key")``. Its key provider catches the per-key error and raises a new
    exception after the loop, so the original error is not chained. By then a
    throttled call is indistinguishable from a header naming an untrusted key.
    Recording at the KMS client keeps the AWS error code.

    Only the operation name, the ``KeyId`` parameter and the exception are kept:
    never request or response payloads, which carry encrypted and plaintext
    data keys.
    """

    def __init__(self) -> None:
        self.calls: Counter[str] = Counter()
        self.failures: list[_KmsFailure] = []

    def instrument_client_class(self, **kwargs: Any) -> None:
        """botocore ``creating-client-class.kms`` handler: wrap the data-key methods.

        botocore emits the event with keyword arguments only; ``class_attributes``
        is the namespace the new client class is about to be built from.
        """
        class_attributes: dict[str, Any] = kwargs["class_attributes"]
        for method_name, operation in _KMS_DATA_KEY_METHODS.items():
            method = class_attributes.get(method_name)
            if callable(method):
                class_attributes[method_name] = self._recording(method, operation)

    def _recording(self, method: Callable[..., Any], operation: str) -> Callable[..., Any]:
        recorder = self

        @functools.wraps(method)
        def call(client: Any, *args: Any, **kwargs: Any) -> Any:
            recorder.calls[operation] += 1
            try:
                return method(client, *args, **kwargs)
            except Exception as exc:
                recorder.failures.append(_KmsFailure(operation, str(kwargs.get("KeyId", "")), exc))
                raise

        return call

    def last_failure(self, *operations: str) -> _KmsFailure | None:
        """The most recent failure of any of ``operations``, if there was one."""
        for failure in reversed(self.failures):
            if failure.operation in operations:
                return failure
        return None


def _kms_session(recorder: _KmsCallRecorder | None = None) -> botocore.session.Session:
    """Botocore session for the KMS clients the encryption SDK creates.

    The master key providers build their own KMS clients; without this they
    would get default timeouts and default boto retries, which compound with
    tenacity's application-level retries (the same amplification boto_config
    exists to prevent for S3 and DynamoDB). With a ``recorder``, every KMS
    client created from the session reports its data-key call failures to it.
    """
    session = botocore.session.Session()
    session.set_default_client_config(boto_config)
    if recorder is not None:
        session.register("creating-client-class.kms", recorder.instrument_client_class)
    return session


def _aws_error_code(exc: BaseException) -> str:
    if isinstance(exc, ClientError):
        return str(exc.response.get("Error", {}).get("Code", "")) or "UnknownError"
    return type(exc).__name__


def _aws_error_detail(exc: BaseException) -> str:
    """``Code: message`` for a ClientError, the exception text otherwise."""
    if isinstance(exc, ClientError):
        message = str(exc.response.get("Error", {}).get("Message", ""))
        code = _aws_error_code(exc)
        return f"{code}: {message}" if message else code
    return f"{type(exc).__name__}: {exc}"


def _kms_failure_in_chain(exc: BaseException, operation: str) -> _KmsFailure | None:
    """Fallback when no recorder saw the call: the SDK chains ClientErrors on encrypt."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ClientError):
            return _KmsFailure(operation, "", current)
        current = current.__cause__ or current.__context__
    return None


def _encrypt_failure(
    exc: AWSEncryptionSDKClientError, recorder: _KmsCallRecorder, key_id: str
) -> tuple[EnvaultError, BaseException]:
    """Map an Encryption SDK failure on encrypt to (error to raise, cause to chain)."""
    failure = recorder.last_failure("GenerateDataKey", "Encrypt") or _kms_failure_in_chain(
        exc, "GenerateDataKey"
    )
    if failure is None:
        return (
            EncryptionError(f"Encryption failed for key {key_id!r}: {type(exc).__name__}: {exc}"),
            exc,
        )
    transient = is_transient_aws_error(failure.error)
    advice = (
        "KMS is throttling or unavailable; try again later."
        if transient
        else "Check that the key exists, is enabled, and that this principal may use it "
        "(kms:GenerateDataKey)."
    )
    return (
        KMSError(
            f"KMS could not generate a data key with {key_id!r} "
            f"({_aws_error_detail(failure.error)}). {advice}",
            operation=failure.operation,
            error_code=_aws_error_code(failure.error),
            transient=transient,
            key_id=failure.key_id or key_id,
        ),
        failure.error,
    )


def _decrypt_failure(
    exc: AWSEncryptionSDKClientError | InvalidTag,
    recorder: _KmsCallRecorder,
    region: str,
    allowed_account_ids: list[str],
) -> tuple[EnvaultError, BaseException]:
    """Map an Encryption SDK failure on decrypt to (error to raise, cause to chain).

    Only a ``DecryptKeyError`` with a recorded KMS failure is a KMS problem.
    Everything else (header, frame or signature verification, commitment,
    discovery filter, key count) is about the ciphertext and stays a
    :class:`DecryptionError`.
    """
    failure = recorder.last_failure("Decrypt") if isinstance(exc, DecryptKeyError) else None
    if failure is None:
        detail = str(exc) or type(exc).__name__
        no_trusted_key = isinstance(exc, (DecryptKeyError, MasterKeyProviderError))
        if no_trusted_key and recorder.calls["Decrypt"] == 0:
            # The discovery filter (or the EDK's own shape) ruled every
            # encrypted data key out before any KMS call.
            return (
                DecryptionError(
                    "Failed to decrypt: no encrypted data key in the message belongs to a KMS "
                    f"key in the trusted account(s) {', '.join(allowed_account_ids)} "
                    f"({partition_for_region(region)} partition), so KMS was never asked "
                    f"({detail}). The ciphertext may have been substituted or tampered with, "
                    "or ENVAULT_ALLOWED_ACCOUNT_IDS lacks the account that encrypted it."
                ),
                exc,
            )
        return (
            DecryptionError(
                f"Failed to decrypt: {detail}. "
                "The ciphertext may be corrupted, truncated, or tampered with."
            ),
            exc,
        )

    code = _aws_error_code(failure.error)
    detail = _aws_error_detail(failure.error)
    key = failure.key_id or "the key named in the ciphertext"
    if code == "NotFoundException":
        return (
            DecryptionError(
                f"Failed to decrypt: KMS has no key {key} ({detail}). Either that key was "
                "deleted, and data encrypted under it cannot be recovered, or the ciphertext "
                "header was corrupted or tampered with."
            ),
            failure.error,
        )
    if code in _KMS_INTEGRITY_ERROR_CODES:
        return (
            DecryptionError(
                f"Failed to decrypt: KMS rejected the message's encrypted data key for {key} "
                f"({detail}). The ciphertext may be corrupted or tampered with."
            ),
            failure.error,
        )
    transient = is_transient_aws_error(failure.error)
    advice = (
        "KMS is throttling or unavailable; try again later."
        if transient
        else "Check this principal's kms:Decrypt permission and the key's state."
    )
    return (
        KMSError(
            f"KMS could not decrypt the data key with {key} ({detail}). {advice} "
            "This is a KMS availability or permission problem; it says nothing about "
            "the ciphertext.",
            operation="Decrypt",
            error_code=code,
            transient=transient,
            key_id=failure.key_id,
        ),
        failure.error,
    )


@dataclass
class EncryptResult:
    """Result of an encryption operation.

    ``sha256_hash`` is the plaintext's SHA-256 (hex). It is kept out of the
    repr: for a short file it is as good as the content, and envault never
    logs or prints it.
    """

    sha256_hash: str = field(repr=False)
    file_size_bytes: int
    algorithm: str
    message_id: str
    output_path: Path


@dataclass
class DecryptResult:
    """Result of a decryption operation.

    ``output_path`` is None when the plaintext was streamed to a caller-supplied
    sink (a memfd, a buffer) rather than written to a file. ``sha256_hash``,
    the plaintext's SHA-256, is kept out of the repr (see :class:`EncryptResult`).
    """

    sha256_hash: str = field(repr=False)
    file_size_bytes: int
    encryption_context: dict[str, str]
    output_path: Path | None = None


class _HashingReader:
    """File wrapper that computes SHA256 as data is read through it."""

    def __init__(self, file_obj: BinaryIO) -> None:
        self._file = file_obj
        self._hasher = hashlib.sha256()
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        data = self._file.read(size)
        if data:
            self._hasher.update(data)
            self.bytes_read += len(data)
        return data

    @property
    def hexdigest(self) -> str:
        return self._hasher.hexdigest()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._file, name)


class _WriteTracker:
    """Forwards plaintext to the caller's sink and remembers whether any was written."""

    def __init__(self, out: Any) -> None:
        self._out = out
        self.touched = False

    def write(self, data: bytes) -> None:
        # Set before the write: a partial write still leaves plaintext behind.
        self.touched = True
        self._out.write(data)


def _sha256_stream(stream: BinaryIO) -> str:
    h = hashlib.sha256()
    for chunk in iter(lambda: stream.read(_CHUNK_SIZE), b""):
        h.update(chunk)
    return h.hexdigest()


def sha256_file(path: Path) -> str:
    """Compute SHA256 hash of a file's contents.

    Opens ``path`` normally (a symlink is followed). To hash exactly the file
    that will be encrypted, open it once with
    :func:`envault.fileutils.open_regular_nofollow` and use :func:`sha256_fd`.
    """
    with path.open("rb") as f:
        return _sha256_stream(f)


def sha256_fd(fd: int) -> str:
    """SHA-256 of the whole file behind ``fd``, read from offset 0.

    The descriptor stays open (the caller owns it) and its offset is left at
    end of file; :func:`encrypt_fd` rewinds before reading.
    """
    with open(fd, "rb", closefd=False) as f:
        f.seek(0)
        return _sha256_stream(f)


def encrypt_file(
    input_path: Path,
    key_id: str,
    encryption_context: dict[str, str],
    output_path: Path,
    region: str = "us-east-1",
) -> EncryptResult:
    """Encrypt a file using AWS KMS envelope encryption (streaming).

    Opens ``input_path`` with :func:`~envault.fileutils.open_regular_nofollow`
    (a symlink or a non-regular file is refused) and encrypts from that
    descriptor with :func:`encrypt_fd`. A caller that has already hashed the
    file should open it once and call :func:`sha256_fd` and :func:`encrypt_fd`
    on the same descriptor instead.

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

    Raises:
        UnsafeFileError: ``input_path`` is a symlink or not a regular file.
        KMSError: KMS refused or failed to generate the data key.
        EncryptionError: Any other Encryption SDK failure.
    """
    logger.info("Encrypting file", extra={"input": str(input_path), "key_id": key_id})
    fd = open_regular_nofollow(input_path)
    try:
        return encrypt_fd(fd, key_id, encryption_context, output_path, region)
    finally:
        os.close(fd)


@aws_retry(never=_ENCRYPT_NEVER)
def encrypt_fd(
    input_fd: int,
    key_id: str,
    encryption_context: dict[str, str],
    output_path: Path,
    region: str = "us-east-1",
) -> EncryptResult:
    """Encrypt the file behind an open descriptor (streaming), reading it from offset 0.

    Uses streaming mode to avoid holding the full plaintext or ciphertext
    in memory. SHA256 is computed incrementally as data flows through the
    encryption stream, so the returned hash describes exactly the bytes that
    were encrypted.

    The descriptor is not closed (the caller owns it) and is rewound before
    every attempt, so it can come straight from :func:`sha256_fd`. Transient
    KMS failures are retried from the start of the file; deterministic ones
    fail at once.

    Args:
        input_fd: Readable descriptor of the plaintext, e.g. from
            :func:`envault.fileutils.open_regular_nofollow`.
        key_id: KMS key alias (e.g. 'alias/s3_key') or full ARN.
        encryption_context: Key-value pairs bound to the ciphertext.
        output_path: Destination path for the encrypted file (created 0600,
            truncated, never through a symlink).
        region: AWS region where the KMS key lives.

    Returns:
        EncryptResult with hash and size of the bytes encrypted, algorithm,
        and message_id (64 lowercase hex characters).

    Raises:
        KMSError: KMS refused or failed to generate the data key (``transient``
            tells whether a later retry may help; transient ones were already
            retried).
        EncryptionError: Any other Encryption SDK failure.
    """
    recorder = _KmsCallRecorder()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(output_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)

    try:
        with open(input_fd, "rb", closefd=False) as raw_input:
            raw_input.seek(0)
            hashing_reader = _HashingReader(raw_input)
            try:
                client = aws_encryption_sdk.EncryptionSDKClient(
                    commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
                )
                key_provider = StrictAwsKmsMasterKeyProvider(
                    key_ids=[key_id],
                    region_names=[region],
                    botocore_session=_kms_session(recorder),
                )
                with client.stream(
                    source=hashing_reader,
                    mode="e",
                    key_provider=key_provider,
                    encryption_context=encryption_context,
                    frame_length=4096,
                ) as encryptor:
                    with os.fdopen(fd, "wb") as out:
                        fd = -1  # ownership transferred; fdopen closes on exit
                        while True:
                            chunk = encryptor.read(_CHUNK_SIZE)
                            if not chunk:
                                break
                            out.write(chunk)
                    header = encryptor.header
            except AWSEncryptionSDKClientError as exc:
                error, cause = _encrypt_failure(exc, recorder, key_id)
                raise error from cause

        sha256_hash = hashing_reader.hexdigest
        algorithm = (
            header.algorithm.name if hasattr(header.algorithm, "name") else str(header.algorithm)
        )
        message_id = (
            header.message_id.hex()
            if isinstance(header.message_id, bytes)
            else str(header.message_id)
        )
        # No hash of the plaintext here or in any other log record: under -v
        # these records reach stderr with every extra as a JSON field (M6).
        logger.info(
            "Encryption complete",
            extra={
                "output": str(output_path),
                "algorithm": algorithm,
                "message_id": message_id,
            },
        )
        return EncryptResult(
            sha256_hash=sha256_hash,
            file_size_bytes=hashing_reader.bytes_read,
            algorithm=algorithm,
            message_id=message_id,
            output_path=output_path,
        )
    finally:
        # If stream() (or anything before fdopen) fails, close the raw fd so
        # we neither leak descriptors nor leave an unlinked 0600 file open.
        if fd >= 0:
            os.close(fd)


def _discovery_key_provider(
    region: str,
    allowed_account_ids: list[str],
    recorder: _KmsCallRecorder | None = None,
) -> DiscoveryAwsKmsMasterKeyProvider:
    """Build a discovery provider restricted to explicitly trusted accounts."""
    from aws_encryption_sdk.key_providers.kms import DiscoveryFilter

    return DiscoveryAwsKmsMasterKeyProvider(
        discovery_filter=DiscoveryFilter(
            account_ids=tuple(allowed_account_ids),
            partition=partition_for_region(region),
        ),
        region_names=[region],
        botocore_session=_kms_session(recorder),
    )


#: Kept under its earlier private name; the function lives in envault.config,
#: shared with the identifier-key checks in envault.fileid.
_partition_for_region = partition_for_region


def _rewind_point(source: BinaryIO) -> int | None:
    """Current offset of ``source`` if it can be replayed from there, else None."""
    try:
        if not source.seekable():
            return None
        return source.tell()
    except (AttributeError, OSError, ValueError):
        return None


#: Set on an exception a ``verify_digest`` callback raised. :func:`decrypt_file`
#: does not retry such a failure: the callback has retried whatever was worth
#: retrying, and decrypting again would repeat every KMS call for nothing (L1).
_RAISED_BY_VERIFY_DIGEST = "_envault_raised_by_verify_digest"


def _verify_digest(verify_digest: Callable[[bytes], None], result: DecryptResult) -> None:
    """Hand the plaintext's raw SHA-256 digest to ``verify_digest``, marking what it raises."""
    try:
        verify_digest(bytes.fromhex(result.sha256_hash))
    except Exception as exc:
        setattr(exc, _RAISED_BY_VERIFY_DIGEST, True)
        raise


def _not_raised_by_verify_digest(exc: BaseException) -> bool:
    return not getattr(exc, _RAISED_BY_VERIFY_DIGEST, False)


def decrypt_to_stream(
    source: BinaryIO,
    out: BinaryIO,
    *,
    expected_sha256: str | None = None,
    expected_context: dict[str, str] | None = None,
    region: str = "us-east-1",
    allowed_account_ids: list[str] | None = None,
    retry_transient: bool = True,
    verify_digest: Callable[[bytes], None] | None = None,
) -> DecryptResult:
    """Decrypt ``source`` into ``out``, verifying before the caller exposes it.

    The encryption context is checked against ``expected_context`` as soon as the
    ciphertext header is parsed — before a single plaintext byte is written — so
    a substituted ciphertext is rejected without ever materialising. The checksum
    is verified after the stream completes, and then ``verify_digest``, if given,
    is called with the plaintext's raw 32-byte SHA-256 digest: a further check
    the caller makes (envault's keyed identifiers: KMS VerifyMac) before this
    returns. Whatever it raises propagates, and it is called once, outside the
    retries described below.

    ``out`` may be any writable binary sink: a memfd from
    :class:`~envault.isolation.CredentialFd`, a buffer, or a file. The caller is
    responsible for keeping that sink private until this returns successfully;
    on any exception the sink holds unverified bytes and must be discarded.

    Transient KMS failures (throttling, KMS internal errors, an unreachable
    endpoint) are retried, up to 3 attempts with backoff, but only when it is
    safe. ``source`` must be seekable (it is rewound to where it started), and
    not one byte may have reached ``out``. The data key is decrypted while the
    header is read, before any plaintext exists, so in practice every
    transient KMS failure qualifies. A failure after the first plaintext byte
    is never retried.

    Args:
        source: Readable binary stream of ciphertext.
        out: Writable binary sink for the plaintext.
        expected_sha256: If provided, the plaintext checksum must match.
        expected_context: If provided, every key must match the ciphertext header.
        region: AWS region where the KMS key lives.
        allowed_account_ids: AWS account IDs trusted to have encrypted the data.
        retry_transient: False makes exactly one attempt. :func:`decrypt_file`
            passes False because it retries at its own level, with a fresh
            temporary file per attempt.
        verify_digest: Called with the plaintext's raw SHA-256 digest once
            it has been written to ``out`` and has passed the checksum.

    Returns:
        DecryptResult with the plaintext hash, size, and encryption context.

    Raises:
        ConfigurationError: If allowed_account_ids is empty.
        EncryptionContextMismatchError: If the header context doesn't match.
        ChecksumMismatchError: If the plaintext checksum doesn't match.
        DecryptionError: If the ciphertext is corrupted, truncated, tampered,
            or not from a trusted KMS key, or KMS rejected its data key.
        KMSError: If KMS was throttled, unreachable, or refused the request
            (access denied, key disabled or pending deletion). Not evidence of
            tampering.
        Exception: Whatever ``verify_digest`` raises.
    """
    if not allowed_account_ids:
        raise ConfigurationError(
            "allowed_account_ids is required for decryption. "
            "Set ENVAULT_ALLOWED_ACCOUNT_IDS to a comma-separated list of AWS account IDs "
            "that are trusted to have encrypted the data."
        )
    account_ids = list(allowed_account_ids)
    sink = _WriteTracker(out)
    start = _rewind_point(source) if retry_transient else None

    def once() -> DecryptResult:
        return _decrypt_stream_once(
            source,
            sink,
            expected_sha256=expected_sha256,
            expected_context=expected_context,
            region=region,
            allowed_account_ids=account_ids,
        )

    if start is None:
        result = once()
    else:

        @aws_retry(never=_DECRYPT_NEVER, when=lambda _exc: not sink.touched)
        def attempt() -> DecryptResult:
            source.seek(start)
            return once()

        result = attempt()
    if verify_digest is not None:
        verify_digest(bytes.fromhex(result.sha256_hash))
    return result


def _decrypt_stream_once(
    source: BinaryIO,
    sink: _WriteTracker,
    *,
    expected_sha256: str | None,
    expected_context: dict[str, str] | None,
    region: str,
    allowed_account_ids: list[str],
) -> DecryptResult:
    """One decryption attempt; SDK failures are translated, nothing is retried."""
    recorder = _KmsCallRecorder()
    try:
        key_provider = _discovery_key_provider(region, allowed_account_ids, recorder)
    except AWSEncryptionSDKClientError as exc:
        raise ConfigurationError(f"Invalid decryption configuration: {exc}") from exc
    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        max_encrypted_data_keys=1,
    )

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
                sink.write(chunk)
                file_size += len(chunk)
    except (AWSEncryptionSDKClientError, InvalidTag) as exc:
        # InvalidTag escapes the SDK raw when AES-GCM frame authentication
        # fails (corrupted or tampered ciphertext).
        error, cause = _decrypt_failure(exc, recorder, region, allowed_account_ids)
        raise error from cause

    actual_sha256 = hasher.hexdigest()
    if expected_sha256 and actual_sha256 != expected_sha256:
        # The actual hash stays out of the error (M6): see ChecksumMismatchError.
        raise ChecksumMismatchError(expected=expected_sha256)

    return DecryptResult(
        sha256_hash=actual_sha256,
        file_size_bytes=file_size,
        encryption_context=enc_context,
    )


@aws_retry(never=_DECRYPT_NEVER, when=_not_raised_by_verify_digest)
def decrypt_file(
    input_path: Path,
    output_path: Path,
    expected_sha256: str | None = None,
    region: str = "us-east-1",
    allowed_account_ids: list[str] | None = None,
    expected_context: dict[str, str] | None = None,
    *,
    verify_digest: Callable[[bytes], None] | None = None,
) -> DecryptResult:
    """Decrypt a file to a path, verifying before the plaintext becomes reachable.

    Plaintext is streamed to a temporary file in the destination directory and
    renamed into place only after the encryption context, the checksum and
    ``verify_digest`` all pass, so a failed, truncated, or tampered decrypt
    never leaves partial or unverified plaintext at the destination. On any
    failure the temporary file is zero-overwritten and removed.

    Transient KMS failures are retried (up to 3 attempts), each attempt with a
    new temporary file; integrity failures and interrupts never are, and
    neither is anything ``verify_digest`` raises.

    Args:
        input_path: Path to the encrypted file.
        output_path: Destination path for the decrypted plaintext.
        expected_sha256: If provided, verifies the checksum after decryption.
        region: AWS region where the KMS key lives.
        allowed_account_ids: AWS account IDs trusted to have encrypted the data.
        expected_context: If provided, verified against the ciphertext header
            before any plaintext is written.
        verify_digest: Called with the plaintext's raw 32-byte SHA-256 digest
            after the checksum passed and before the rename: the file at
            ``output_path`` exists only if it returns.

    Returns:
        DecryptResult with hash and size of the decrypted file.

    Raises:
        ChecksumMismatchError: If expected_sha256 is provided and doesn't match.
        EncryptionContextMismatchError: If expected_context doesn't match.
        DecryptionError: If the SDK fails to decrypt (corrupted/tampered
            ciphertext, failed frame authentication, untrusted key, KMS
            rejecting the data key). Never retried — these failures are
            deterministic.
        KMSError: If KMS was throttled or unavailable on every attempt, or
            refused the request (access denied, key disabled).
        Exception: Whatever ``verify_digest`` raises.
    """
    logger.info("Decrypting file", extra={"input": str(input_path)})

    output_path.parent.mkdir(parents=True, exist_ok=True)
    # mkstemp creates the file 0o600; renamed over output_path only on success.
    tmp_fd, _tmp_name = tempfile.mkstemp(
        dir=output_path.parent, prefix=f".{output_path.name}.", suffix=".part"
    )
    tmp_path = Path(_tmp_name)

    try:
        # Nest fdopen so ownership is marked transferred before any later
        # open() can fail; a combined `with a, b` would leave tmp_fd >= 0
        # after fdopen already closed it, and os.close in finally would
        # raise EBADF and skip cleanup.
        with os.fdopen(tmp_fd, "wb") as out:
            tmp_fd = -1  # ownership transferred; fdopen closes on exit
            with input_path.open("rb") as encrypted_file:
                result = decrypt_to_stream(
                    encrypted_file,
                    out,
                    expected_sha256=expected_sha256,
                    expected_context=expected_context,
                    region=region,
                    allowed_account_ids=allowed_account_ids,
                    retry_transient=False,
                )
        # Still under its hidden .part name: the plaintext gets the name the
        # caller asked for only once every check has passed.
        if verify_digest is not None:
            _verify_digest(verify_digest, result)
        os.replace(tmp_path, output_path)
    finally:
        if tmp_fd >= 0:
            try:
                os.close(tmp_fd)
            except OSError:
                pass
        # No-op after a successful rename; zero-overwrites partial plaintext
        # left behind by any failure above.
        best_effort_delete(tmp_path)

    logger.info("Decryption complete", extra={"output": str(output_path)})

    result.output_path = output_path
    return result
