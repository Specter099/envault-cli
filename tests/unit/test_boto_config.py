"""Tests for shared boto3 configuration."""

from __future__ import annotations

from envault.config import boto_config


def test_boto_config_has_explicit_timeouts():
    """Shared config must set connect and read timeouts."""
    assert boto_config.connect_timeout == 5
    assert boto_config.read_timeout == 30


def test_boto_config_disables_builtin_retries():
    """Shared config must disable boto3 retries (tenacity handles retries)."""
    assert boto_config.retries["max_attempts"] == 1
