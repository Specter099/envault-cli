"""Unit tests for envault.config."""

from __future__ import annotations

from envault.config import Config


def test_config_build_encryption_context():
    """build_encryption_context returns per-file context with required keys."""
    cfg = Config(
        key_id="alias/my-key",
        bucket="b",
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
    cfg = Config(key_id="alias/k", bucket="b", region="us-east-1")

    ctx1 = cfg.build_encryption_context(sha256_hash="aaa", file_name="file1.txt")
    ctx2 = cfg.build_encryption_context(sha256_hash="bbb", file_name="file2.txt")

    assert ctx1 != ctx2
    assert ctx1["sha256"] == "aaa"
    assert ctx2["sha256"] == "bbb"
