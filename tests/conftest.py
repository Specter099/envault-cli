"""Shared pytest fixtures for envault tests."""

from __future__ import annotations

import os

import boto3
import pytest
from moto import mock_aws

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
def kms_key():
    """Create a moto-backed KMS key."""
    with mock_aws():
        kms = boto3.client("kms", region_name=REGION)
        key = kms.create_key(Description="envault-test-key")
        key_id = key["KeyMetadata"]["KeyId"]
        kms.create_alias(AliasName=KMS_KEY_ALIAS, TargetKeyId=key_id)
        yield key_id
