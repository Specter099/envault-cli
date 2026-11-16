"""Custom exceptions for envault."""

from collections.abc import Sequence


def _printable(text: str) -> str:
    """``text`` with every character outside printable ASCII written as a Python escape."""
    return "".join(ch if " " <= ch <= "~" and ch != "\\" else ascii(ch)[1:-1] for ch in text)


class EnvaultError(Exception):
    """Base exception for all envault errors."""


class AlreadyEncryptedError(EnvaultError):
    """Raised when attempting to encrypt a file that is already in ENCRYPTED state.

    ``file_id`` is the record's identifier (keyed for new records, see
    :mod:`envault.fileid`), never a hash of the plaintext computed for the
    occasion.
    """

    def __init__(self, file_id: str, file_name: str) -> None:
        self.file_id = file_id
        self.file_name = file_name
        super().__init__(
            f"File '{file_name}' (id: {file_id[:16]}...) is already ENCRYPTED. "
            "Use --force to re-encrypt."
        )


class StateConflictError(EnvaultError):
    """Raised when a state transition is not valid."""


class MalformedRecordError(EnvaultError):
    """A state-table row does not have the shape envault writes, so it is not used.

    An attribute has the wrong type: a file name that is not a string, an
    encryption context that is not a map of strings, a size that is not a
    whole number of bytes. Rows come from DynamoDB, which anyone with write
    access to the table can edit, so such a row is refused rather than guessed
    at. Listings skip it and report it; a lookup that lands on it fails.

    The message names the row by the first 16 characters of the identifier in
    its key (``FILE#<identifier>``), with anything but printable ASCII
    escaped, and names the attributes at fault, never their values.

    Attributes:
        row_id: The identifier part of the row's key, as stored.
        problems: What is wrong, one entry per attribute.
    """

    def __init__(self, row_id: str, problems: Sequence[str]) -> None:
        self.row_id = row_id
        self.problems = tuple(problems)
        shown = _printable(row_id[:16]) or "(an empty key)"
        super().__init__(
            f"The record stored under {shown}... is malformed: {'; '.join(self.problems)}. "
            "Refusing to use it: the state table may have been tampered with."
        )


class ChecksumMismatchError(EnvaultError):
    """The decrypted plaintext is not the file its record identifies.

    Raised before the plaintext is published, sealed or handed to a command.
    Neither the message nor the exception carries the plaintext's actual
    SHA-256, or any prefix of it: for a short or guessable file (a PIN, a
    password) that hash is as good as the content. Callers that want to name
    the file print the identifier they expected.

    Attributes:
        expected: The value the plaintext was checked against: a SHA-256 (the
            crypto layer's ``expected_sha256``) or a keyed file identifier
            (:class:`FileIdMismatchError`).
    """

    def __init__(self, expected: str, message: str | None = None) -> None:
        self.expected = expected
        super().__init__(
            message
            or "Checksum mismatch: the decrypted content does not match the file its "
            "record identifies."
        )


class FileIdMismatchError(ChecksumMismatchError):
    """The decrypted plaintext does not have the record's keyed identifier.

    KMS VerifyMac says ``file_id`` is not the HMAC of the plaintext's SHA-256
    under the record's identifier key: the ciphertext was substituted or the
    record altered. An integrity failure, like any checksum mismatch; the
    plaintext is never published, sealed or re-encrypted. The message names
    the expected identifier (a keyed value, safe to show), never the
    plaintext's hash.
    """

    def __init__(self, file_id: str) -> None:
        super().__init__(
            expected=file_id,
            message=(
                f"Checksum mismatch: the decrypted content is not file {file_id[:16]}...; "
                "its keyed identifier does not verify."
            ),
        )


class UntrustedIdKeyError(EnvaultError):
    """A record names an identifier key envault does not trust.

    The record's ``id_key_arn`` is not a KMS key ARN, or names a key outside
    the partition or the trusted accounts (``ENVAULT_ALLOWED_ACCOUNT_IDS``).
    Raised before any KMS call is made with it.
    """


class DecryptionError(EnvaultError):
    """Raised when a ciphertext fails integrity or trust checks on decryption.

    The ciphertext is corrupted, truncated or tampered with, uses a
    non-committing algorithm suite, carries more than one encrypted data key,
    names a KMS key outside the trusted accounts, or KMS itself rejected its
    encrypted data key (InvalidCiphertextException and similar). Deterministic,
    so it is never retried.

    KMS being throttled, unreachable, or refusing access is *not* reported this
    way: see :class:`KMSError`.
    """


class KMSError(EnvaultError):
    """KMS did not complete a request: a data-key request or a file-identifier MAC.

    Data keys: GenerateDataKey on encrypt, Decrypt on decrypt. File
    identifiers (:mod:`envault.fileid`): GenerateMac, VerifyMac.

    Throttling, KMS internal errors and unreachable endpoints are transient. Access
    denied, a disabled key or one pending deletion are not. In neither case
    does it say anything about the integrity of a ciphertext: KMS answers that
    implicate the ciphertext itself are raised as :class:`DecryptionError`.
    Messages carry the AWS error code and message and the key identifier, never
    plaintext or key material.

    Attributes:
        operation: KMS API operation that failed: "GenerateDataKey", "Encrypt",
            "Decrypt", "GenerateMac" or "VerifyMac".
        error_code: AWS error code (e.g. "AccessDeniedException"), or the
            botocore exception class name for a network failure.
        transient: True if a later attempt may succeed (throttling, 5xx,
            network). The original error stays chained as ``__cause__``, which
            is what :func:`envault.retry.is_transient_aws_error` inspects.
        key_id: Key id, alias or ARN the request named ("" if unknown).
    """

    def __init__(
        self,
        message: str,
        *,
        operation: str = "",
        error_code: str = "",
        transient: bool = False,
        key_id: str = "",
    ) -> None:
        super().__init__(message)
        self.operation = operation
        self.error_code = error_code
        self.transient = transient
        self.key_id = key_id


class EncryptionError(EnvaultError):
    """The Encryption SDK could not encrypt a file, for a reason other than KMS.

    For example, an invalid key identifier or encryption context. Deterministic,
    never retried. KMS failures while generating the data key raise
    :class:`KMSError` instead.
    """


class EncryptionContextMismatchError(EnvaultError):
    """Raised when ciphertext encryption context doesn't match DynamoDB."""

    def __init__(self, expected: dict[str, str], actual: dict[str, str]) -> None:
        self.expected = expected
        self.actual = actual
        # Identify which application-level keys differ
        diff_keys = [k for k in expected if actual.get(k) != expected[k]]
        detail = ", ".join(diff_keys) if diff_keys else "unknown"
        super().__init__(
            f"Encryption context mismatch on key(s): {detail}. "
            "The encrypted file in S3 does not match the record in DynamoDB."
        )


class ConfigurationError(EnvaultError):
    """Raised when required configuration is missing or invalid."""


class MigrationError(EnvaultError):
    """Raised when a migration from output.json fails."""


class UnsafeFileError(EnvaultError):
    """Raised when a local path is not the regular file envault expected to read.

    The path is a symbolic link, not a regular file (directory, FIFO, device),
    or no longer the inode recorded when it was collected. Opening it anyway
    could encrypt a file the operator never selected.
    """


class InvalidS3KeyError(EnvaultError):
    """Raised when an S3 object key fails validation.

    Keys come from DynamoDB rows, which anyone with table write access can edit.
    A key that is not the expected shape must never be fetched or written.
    """


class S3ObjectExistsError(EnvaultError):
    """Raised when a conditional upload finds an object already at its key.

    envault uploads with ``If-None-Match: *`` so that no upload can replace an
    object that a record may pin by VersionId. Seeing this means the key was
    taken by someone else. A retry of envault's own upload (lost reply) is
    recognised and not reported.
    """

    def __init__(self, bucket: str, s3_key: str) -> None:
        self.bucket = bucket
        self.s3_key = s3_key
        super().__init__(
            f"Refusing to overwrite S3 object {s3_key!r} in bucket {bucket!r}: an object "
            "already exists at that key and was not written by this upload."
        )
