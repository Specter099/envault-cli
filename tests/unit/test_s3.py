# tests/unit/test_s3.py
from __future__ import annotations

import logging
from pathlib import Path

import boto3
from moto import mock_aws

from envault.s3 import S3Store

BUCKET = "test-bucket"
REGION = "us-east-1"


def _create_versioned_bucket(s3_client) -> None:
    s3_client.create_bucket(Bucket=BUCKET)
    s3_client.put_bucket_versioning(
        Bucket=BUCKET,
        VersioningConfiguration={"Status": "Enabled"},
    )


@mock_aws
def test_upload_returns_version_id(tmp_path: Path):
    """upload_file must return a non-empty VersionId."""
    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)

    p = tmp_path / "secret.txt.encrypted"
    p.write_bytes(b"fake ciphertext")

    store = S3Store(bucket=BUCKET, region=REGION)
    version_id = store.upload_file(local_path=p, s3_key="encrypted/aa/aaa.../secret.txt.encrypted")

    assert isinstance(version_id, str)
    assert len(version_id) > 0


@mock_aws
def test_upload_two_versions_return_distinct_ids(tmp_path: Path):
    """Each upload must return a unique VersionId."""
    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)

    p = tmp_path / "file.enc"
    p.write_bytes(b"version one")
    store = S3Store(bucket=BUCKET, region=REGION)

    v1 = store.upload_file(local_path=p, s3_key="encrypted/aa/aaa.../file.enc")
    p.write_bytes(b"version two")
    v2 = store.upload_file(local_path=p, s3_key="encrypted/aa/aaa.../file.enc")

    assert v1 != v2


@mock_aws
def test_download_specific_version(tmp_path: Path):
    """download_file with version_id must retrieve the correct version."""
    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)

    store = S3Store(bucket=BUCKET, region=REGION)

    p = tmp_path / "data.enc"
    p.write_bytes(b"first content")
    v1 = store.upload_file(p, "encrypted/aa/aaa.../data.enc")

    p.write_bytes(b"second content")
    store.upload_file(p, "encrypted/aa/aaa.../data.enc")

    out = tmp_path / "retrieved.enc"
    store.download_file("encrypted/aa/aaa.../data.enc", out, version_id=v1)
    assert out.read_bytes() == b"first content"


@mock_aws
def test_download_empty_version_id_logs_warning(tmp_path: Path, caplog):
    """download_file with empty version_id must emit a WARNING."""
    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)
    s3_client.put_object(Bucket=BUCKET, Key="encrypted/aa/aaa.../file.enc", Body=b"data")

    store = S3Store(bucket=BUCKET, region=REGION)
    out = tmp_path / "file.enc"

    with caplog.at_level(logging.WARNING, logger="envault.s3"):
        store.download_file("encrypted/aa/aaa.../file.enc", out, version_id="")

    assert any("version" in r.message.lower() for r in caplog.records), (
        f"Expected a version warning, got: {[r.message for r in caplog.records]}"
    )


def test_s3_key_for_file_is_content_addressed():
    """S3 key must include sha256 hash to prevent filename collisions."""
    store = S3Store(bucket="b", region="us-east-1")
    sha = "a" * 64

    key = store.s3_key_for_file(sha256_hash=sha, file_name="report.xlsx")

    # Key must contain the hash prefix (sharding) and full hash
    assert sha[:2] in key
    assert sha in key
    assert "report.xlsx.encrypted" in key

    # Two files with same name but different hashes get different keys
    sha2 = "b" * 64
    key2 = store.s3_key_for_file(sha256_hash=sha2, file_name="report.xlsx")
    assert key != key2
