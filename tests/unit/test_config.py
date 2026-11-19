"""Unit tests for envault.config."""

from __future__ import annotations

import pytest

from envault.config import Config, partition_for_region


def test_config_build_encryption_context():
    """build_encryption_context returns per-file context with required keys.

    New records are named by their keyed identifier; the context, which
    CloudTrail records, has no ``sha256`` key (M6).
    """
    cfg = Config(
        key_id="alias/my-key",
        bucket="b",
        region="us-east-1",
    )
    ctx = cfg.build_encryption_context(file_id="abc123", file_name="secret.env")

    assert ctx == {
        "purpose": "envault-backup",
        "file_id": "abc123",
        "file_name": "secret.env",
        "kms_key_alias": "alias/my-key",
    }


def test_config_build_encryption_context_of_a_legacy_record():
    """Records identified by the raw SHA-256 keep the context layout they always had."""
    cfg = Config(key_id="alias/my-key", bucket="b", region="us-east-1")

    ctx = cfg.build_encryption_context(file_id="abc123", file_name="secret.env", legacy=True)

    assert ctx == {
        "purpose": "envault-backup",
        "sha256": "abc123",
        "file_name": "secret.env",
        "kms_key_alias": "alias/my-key",
    }


def test_config_build_encryption_context_unique_per_file():
    """Different files must produce different encryption contexts."""
    cfg = Config(key_id="alias/k", bucket="b", region="us-east-1")

    ctx1 = cfg.build_encryption_context(file_id="aaa", file_name="file1.txt")
    ctx2 = cfg.build_encryption_context(file_id="bbb", file_name="file2.txt")

    assert ctx1 != ctx2
    assert ctx1["file_id"] == "aaa"
    assert ctx2["file_id"] == "bbb"


@pytest.mark.parametrize(
    ("region", "partition"),
    [("us-east-1", "aws"), ("us-gov-west-1", "aws-us-gov"), ("cn-north-1", "aws-cn")],
)
def test_partition_for_region(region: str, partition: str) -> None:
    assert partition_for_region(region) == partition
