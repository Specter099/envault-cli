"""Shared pytest fixtures for envault tests."""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

TABLE_NAME = "envault-test-state"
BUCKET_NAME = "envault-test-bucket"
KMS_KEY_ALIAS = "alias/envault-test"
REGION = "us-east-1"


@pytest.fixture(autouse=True)
def aws_credentials():
    """Set fake AWS credentials so moto works without real AWS."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"  # noqa: S105
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"  # noqa: S105
    os.environ["AWS_SECURITY_TOKEN"] = "testing"  # noqa: S105
    os.environ["AWS_SESSION_TOKEN"] = "testing"  # noqa: S105
    os.environ["AWS_DEFAULT_REGION"] = REGION


@pytest.fixture
def dynamodb_table():
    """Create a moto-backed DynamoDB table matching the envault schema."""
    with mock_aws():
        client = boto3.client("dynamodb", region_name=REGION)
        client.create_table(
            TableName=TABLE_NAME,
            BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[
                {"AttributeName": "PK", "AttributeType": "S"},
                {"AttributeName": "SK", "AttributeType": "S"},
                {"AttributeName": "current_state", "AttributeType": "S"},
                {"AttributeName": "encrypted_at", "AttributeType": "S"},
                {"AttributeName": "date", "AttributeType": "S"},
                {"AttributeName": "last_updated", "AttributeType": "S"},
            ],
            KeySchema=[
                {"AttributeName": "PK", "KeyType": "HASH"},
                {"AttributeName": "SK", "KeyType": "RANGE"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "state-index",
                    "KeySchema": [
                        {"AttributeName": "current_state", "KeyType": "HASH"},
                        {"AttributeName": "encrypted_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "date-index",
                    "KeySchema": [
                        {"AttributeName": "date", "KeyType": "HASH"},
                        {"AttributeName": "last_updated", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
        )
        yield TABLE_NAME


@pytest.fixture
def s3_bucket():
    """Create a moto-backed S3 bucket."""
    with mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket=BUCKET_NAME)
        s3.put_bucket_versioning(
            Bucket=BUCKET_NAME,
            VersioningConfiguration={"Status": "Enabled"},
        )
        yield BUCKET_NAME


@pytest.fixture
def kms_key():
    """Create a moto-backed KMS key."""
    with mock_aws():
        kms = boto3.client("kms", region_name=REGION)
        key = kms.create_key(Description="envault-test-key")
        key_id = key["KeyMetadata"]["KeyId"]
        kms.create_alias(AliasName=KMS_KEY_ALIAS, TargetKeyId=key_id)
        yield key_id


@pytest.fixture
def tmp_plaintext(tmp_path: Path) -> Path:
    """Create a small plaintext file for testing."""
    p = tmp_path / "test.txt"
    p.write_text("hello envault test content\n")
    return p


@pytest.fixture
def correlation_id() -> str:
    return str(uuid.uuid4())
