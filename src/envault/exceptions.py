"""Custom exceptions for envault."""


class EnvaultError(Exception):
    """Base exception for all envault errors."""


class AlreadyEncryptedError(EnvaultError):
    """Raised when attempting to encrypt a file that is already in ENCRYPTED state."""

    def __init__(self, sha256_hash: str, file_name: str) -> None:
        self.sha256_hash = sha256_hash
        self.file_name = file_name
        super().__init__(
            f"File '{file_name}' (sha256: {sha256_hash[:16]}...) is already ENCRYPTED. "
            "Use --force to re-encrypt."
        )


class StateConflictError(EnvaultError):
    """Raised when a state transition is not valid."""


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
    """KMS did not complete a data-key request: GenerateDataKey on encrypt, Decrypt on decrypt.

    Throttling, KMS internal errors and unreachable endpoints are transient. Access
    denied, a disabled key or one pending deletion are not. In neither case
    does it say anything about the integrity of a ciphertext: KMS answers that
    implicate the ciphertext itself are raised as :class:`DecryptionError`.
    Messages carry the AWS error code and message and the key identifier, never
    plaintext or key material.

    Attributes:
        operation: KMS API operation that failed: "GenerateDataKey", "Encrypt"
            or "Decrypt".
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
