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
