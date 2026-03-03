"""Configuration management for envault — loaded from environment variables only."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from envault.exceptions import ConfigurationError


@dataclass
class Config:
    """Runtime configuration loaded from environment variables."""

    key_id: str
    bucket: str
    table_name: str
    region: str
    encryption_context: dict[str, str] = field(default_factory=lambda: {"purpose": "backup"})
    audit_ttl_days: int = 365
    allowed_account_ids: list[str] = field(default_factory=list)

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
        except ValueError:
            raise ConfigurationError(
                f"ENVAULT_AUDIT_TTL_DAYS must be a positive integer (days). Got: {_ttl_raw!r}"
            )

        _account_ids_raw = os.environ.get("ENVAULT_ALLOWED_ACCOUNT_IDS", "")
        allowed_account_ids = [a.strip() for a in _account_ids_raw.split(",") if a.strip()]

        return cls(
            key_id=key_id,
            bucket=bucket,
            table_name=table_name,
            region=region,
            audit_ttl_days=audit_ttl_days,
            allowed_account_ids=allowed_account_ids,
        )
