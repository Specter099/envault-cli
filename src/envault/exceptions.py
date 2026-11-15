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
    """Raised when SHA256 checksum does not match after decryption."""

    def __init__(self, expected: str, actual: str) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Checksum mismatch: expected SHA256 {expected[:16]}..., "
            f"got {actual[:16]}... "
            "The decrypted content does not match the original file."
        )


class DecryptionError(EnvaultError):
    """Raised when the AWS Encryption SDK fails to decrypt a ciphertext.

    Typically indicates the ciphertext is corrupted, truncated, or was
    tampered with — not a transient AWS error, so it is never retried.
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
