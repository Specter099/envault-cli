"""Configuration management for envault — loaded from environment variables only."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from botocore.config import Config as BotoConfig

from envault.exceptions import ConfigurationError

_ACCOUNT_ID_RE = re.compile(r"^[0-9]{12}$")

# Shared boto3 client config:
# - Explicit timeouts prevent indefinite hangs under partial network failure
# - Retries disabled at boto3 level — tenacity handles retries at the application layer
#   to avoid compounding (boto3 5x * tenacity 3x = 15x amplification)
boto_config = BotoConfig(
    connect_timeout=5,
    read_timeout=30,
    retries={"max_attempts": 1},
)


@dataclass
class Config:
    """Runtime configuration loaded from environment variables."""

    key_id: str
    bucket: str
    table_name: str
    region: str
    audit_ttl_days: int = 365
    allowed_account_ids: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate allowed_account_ids format at construction time."""
        for account_id in self.allowed_account_ids:
            if not _ACCOUNT_ID_RE.match(account_id):
                raise ConfigurationError(
                    f"Invalid AWS account ID: {account_id!r}. Must be exactly 12 digits."
                )

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

    @classmethod
    def from_env(cls) -> Config:
        """Load configuration from environment variables.

        Required env vars:
            ENVAULT_KEY_ID   — KMS key alias or ARN (prefer alias)
            ENVAULT_BUCKET   — S3 bucket name for encrypted files
            ENVAULT_TABLE    — DynamoDB table name

        Optional env vars:
            ENVAULT_REGION           — AWS region (default: us-east-1)
            ENVAULT_AUDIT_TTL_DAYS   — Days to keep event records (default: 365)
        """
        missing = []
        key_id = os.environ.get("ENVAULT_KEY_ID", "")
        bucket = os.environ.get("ENVAULT_BUCKET", "")
        table_name = os.environ.get("ENVAULT_TABLE", "")

        if not key_id:
            missing.append("ENVAULT_KEY_ID")
        if not bucket:
            missing.append("ENVAULT_BUCKET")
        if not table_name:
            missing.append("ENVAULT_TABLE")

        if missing:
            raise ConfigurationError(
                f"Missing required environment variables: {', '.join(missing)}\n"
                "Set them before running envault commands."
            )

        region = os.environ.get("ENVAULT_REGION", "us-east-1")
        _ttl_raw = os.environ.get("ENVAULT_AUDIT_TTL_DAYS", "365")
        try:
            audit_ttl_days = int(_ttl_raw)
            if audit_ttl_days <= 0:
                raise ValueError("must be positive")
        except ValueError as exc:
            raise ConfigurationError(
                f"ENVAULT_AUDIT_TTL_DAYS must be a positive integer (days). Got: {_ttl_raw!r}"
            ) from exc

        _account_ids_raw = os.environ.get("ENVAULT_ALLOWED_ACCOUNT_IDS", "")
        allowed_account_ids = [a.strip() for a in _account_ids_raw.split(",") if a.strip()]
        if "ENVAULT_ALLOWED_ACCOUNT_IDS" in os.environ and not allowed_account_ids:
            raise ConfigurationError(
                "ENVAULT_ALLOWED_ACCOUNT_IDS is set but contains no valid account IDs.\n"
                "Provide a comma-separated list of 12-digit AWS account IDs, "
                "or unset the variable."
            )

        return cls(
            key_id=key_id,
            bucket=bucket,
            table_name=table_name,
            region=region,
            audit_ttl_days=audit_ttl_days,
            allowed_account_ids=allowed_account_ids,
        )
