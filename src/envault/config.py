"""Configuration for envault — values arrive via CLI options or ENVAULT_* env vars."""

from __future__ import annotations

from dataclasses import dataclass

from botocore.config import Config as BotoConfig

# Shared boto3 client config:
# - Explicit timeouts prevent indefinite hangs under partial network failure
# - Retries disabled at boto3 level — tenacity handles retries at the application layer
#   to avoid compounding (boto3 5x * tenacity 3x = 15x amplification)
#
# Every tenacity @retry in this package sets reraise=True. Without it, exhausting
# the attempts raises tenacity.RetryError instead of the underlying error, which
# slips past every `except ClientError` / `except BotoCoreError` handler in the
# CLI and surfaces as a traceback — skipping the error message and the cleanup
# those handlers exist to perform.
boto_config = BotoConfig(
    connect_timeout=5,
    read_timeout=30,
    retries={"max_attempts": 1},
)


@dataclass
class Config:
    """Settings needed to encrypt a file, resolved from CLI options / ENVAULT_* vars."""

    key_id: str
    bucket: str
    region: str
    audit_ttl_days: int = 365

    def build_encryption_context(self, sha256_hash: str, file_name: str) -> dict[str, str]:
        """Build per-file encryption context bound to the ciphertext as AAD.

        Returns a dict that is unique per file, preventing cross-file
        ciphertext substitution attacks.
        """
        return {
            "purpose": "envault-backup",
            "sha256": sha256_hash,
            "file_name": file_name,
            "kms_key_alias": self.key_id,
        }
