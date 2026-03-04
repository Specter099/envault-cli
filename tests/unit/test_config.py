"""Unit tests for envault.config."""

from __future__ import annotations

import pytest

from envault.config import Config
from envault.exceptions import ConfigurationError


def test_config_from_env_required_vars(monkeypatch):
    monkeypatch.setenv("ENVAULT_KEY_ID", "alias/my-key")
    monkeypatch.setenv("ENVAULT_BUCKET", "my-bucket")
    monkeypatch.setenv("ENVAULT_TABLE", "my-table")
    monkeypatch.delenv("ENVAULT_REGION", raising=False)
    monkeypatch.delenv("ENVAULT_AUDIT_TTL_DAYS", raising=False)

    cfg = Config.from_env()

    assert cfg.key_id == "alias/my-key"
    assert cfg.bucket == "my-bucket"
    assert cfg.table_name == "my-table"
    assert cfg.region == "us-east-1"
    assert cfg.audit_ttl_days == 365


def test_config_custom_region(monkeypatch):
    monkeypatch.setenv("ENVAULT_KEY_ID", "alias/k")
    monkeypatch.setenv("ENVAULT_BUCKET", "b")
    monkeypatch.setenv("ENVAULT_TABLE", "t")
    monkeypatch.setenv("ENVAULT_REGION", "eu-west-1")

    cfg = Config.from_env()
    assert cfg.region == "eu-west-1"


def test_config_custom_ttl(monkeypatch):
    monkeypatch.setenv("ENVAULT_KEY_ID", "alias/k")
    monkeypatch.setenv("ENVAULT_BUCKET", "b")
    monkeypatch.setenv("ENVAULT_TABLE", "t")
    monkeypatch.setenv("ENVAULT_AUDIT_TTL_DAYS", "90")

    cfg = Config.from_env()
    assert cfg.audit_ttl_days == 90


def test_config_missing_key_id_raises(monkeypatch):
    monkeypatch.delenv("ENVAULT_KEY_ID", raising=False)
    monkeypatch.setenv("ENVAULT_BUCKET", "b")
    monkeypatch.setenv("ENVAULT_TABLE", "t")

    with pytest.raises(ConfigurationError, match="ENVAULT_KEY_ID"):
        Config.from_env()


def test_config_missing_bucket_raises(monkeypatch):
    monkeypatch.setenv("ENVAULT_KEY_ID", "alias/k")
    monkeypatch.delenv("ENVAULT_BUCKET", raising=False)
    monkeypatch.setenv("ENVAULT_TABLE", "t")

    with pytest.raises(ConfigurationError, match="ENVAULT_BUCKET"):
        Config.from_env()


def test_config_missing_table_raises(monkeypatch):
    monkeypatch.setenv("ENVAULT_KEY_ID", "alias/k")
    monkeypatch.setenv("ENVAULT_BUCKET", "b")
    monkeypatch.delenv("ENVAULT_TABLE", raising=False)

    with pytest.raises(ConfigurationError, match="ENVAULT_TABLE"):
        Config.from_env()


def test_config_non_integer_ttl_raises_config_error(monkeypatch):
    monkeypatch.setenv("ENVAULT_KEY_ID", "alias/k")
    monkeypatch.setenv("ENVAULT_BUCKET", "b")
    monkeypatch.setenv("ENVAULT_TABLE", "t")
    monkeypatch.setenv("ENVAULT_AUDIT_TTL_DAYS", "30d")

    with pytest.raises(ConfigurationError, match="ENVAULT_AUDIT_TTL_DAYS"):
        Config.from_env()


def test_config_zero_ttl_raises_config_error(monkeypatch):
    monkeypatch.setenv("ENVAULT_KEY_ID", "alias/k")
    monkeypatch.setenv("ENVAULT_BUCKET", "b")
    monkeypatch.setenv("ENVAULT_TABLE", "t")
    monkeypatch.setenv("ENVAULT_AUDIT_TTL_DAYS", "0")

    with pytest.raises(ConfigurationError, match="ENVAULT_AUDIT_TTL_DAYS"):
        Config.from_env()


def test_config_negative_ttl_raises_config_error(monkeypatch):
    monkeypatch.setenv("ENVAULT_KEY_ID", "alias/k")
    monkeypatch.setenv("ENVAULT_BUCKET", "b")
    monkeypatch.setenv("ENVAULT_TABLE", "t")
    monkeypatch.setenv("ENVAULT_AUDIT_TTL_DAYS", "-1")

    with pytest.raises(ConfigurationError, match="ENVAULT_AUDIT_TTL_DAYS"):
        Config.from_env()


def test_config_allowed_account_ids_parsed(monkeypatch):
    monkeypatch.setenv("ENVAULT_KEY_ID", "alias/k")
    monkeypatch.setenv("ENVAULT_BUCKET", "b")
    monkeypatch.setenv("ENVAULT_TABLE", "t")
    monkeypatch.setenv("ENVAULT_ALLOWED_ACCOUNT_IDS", "111111111111,222222222222")

    cfg = Config.from_env()
    assert cfg.allowed_account_ids == ["111111111111", "222222222222"]


def test_config_allowed_account_ids_empty_by_default(monkeypatch):
    monkeypatch.setenv("ENVAULT_KEY_ID", "alias/k")
    monkeypatch.setenv("ENVAULT_BUCKET", "b")
    monkeypatch.setenv("ENVAULT_TABLE", "t")
    monkeypatch.delenv("ENVAULT_ALLOWED_ACCOUNT_IDS", raising=False)

    cfg = Config.from_env()
    assert cfg.allowed_account_ids == []


def test_config_build_encryption_context():
    """build_encryption_context returns per-file context with required keys."""
    cfg = Config(
        key_id="alias/my-key",
        bucket="b",
        table_name="t",
        region="us-east-1",
    )
    ctx = cfg.build_encryption_context(sha256_hash="abc123", file_name="secret.env")

    assert ctx == {
        "purpose": "envault-backup",
        "sha256": "abc123",
        "file_name": "secret.env",
        "kms_key_alias": "alias/my-key",
    }


def test_config_build_encryption_context_unique_per_file():
    """Different files must produce different encryption contexts."""
    cfg = Config(key_id="alias/k", bucket="b", table_name="t", region="us-east-1")

    ctx1 = cfg.build_encryption_context(sha256_hash="aaa", file_name="file1.txt")
    ctx2 = cfg.build_encryption_context(sha256_hash="bbb", file_name="file2.txt")

    assert ctx1 != ctx2
    assert ctx1["sha256"] == "aaa"
    assert ctx2["sha256"] == "bbb"
