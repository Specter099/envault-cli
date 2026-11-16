"""Shared pytest fixtures for envault tests."""

from __future__ import annotations

import os
import signal
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import boto3
import pytest
from moto import mock_aws
from unit._id_key import ID_KEY_ALIAS, create_id_key, generate_mac_reporting_key_arn

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


_PROCESS_SIGNALS = tuple(
    getattr(signal, name)
    for name in ("SIGINT", "SIGTERM", "SIGHUP", "SIGPIPE", "SIGXFSZ")
    if hasattr(signal, name)
)


@pytest.fixture(autouse=True)
def _restore_signal_dispositions() -> Iterator[None]:
    """Put back the signal dispositions and signal mask a test changed.

    `envault exec` sets the stop signals, SIGPIPE and SIGXFSZ to their
    defaults just before os.execvpe, which in-process tests replace: without
    this, a test that ran exec would leave the whole test run with a default
    SIGINT (no KeyboardInterrupt) and SIGPIPE.
    """
    saved = {signum: signal.getsignal(signum) for signum in _PROCESS_SIGNALS}
    has_mask = hasattr(signal, "pthread_sigmask")
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, []) if has_mask else None
    yield
    for signum, handler in saved.items():
        if handler is not None:
            signal.signal(signum, handler)
    if mask is not None:
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)


@pytest.fixture(autouse=True)
def _kms_generate_mac_reports_key_arn(monkeypatch: pytest.MonkeyPatch) -> None:
    """moto's GenerateMac answers with the key ARN in KeyId, as KMS does.

    See ``unit._id_key.generate_mac_reporting_key_arn``: moto 5.2.5 returns the
    bare key ID, and envault records the ARN as the identifier key's trust anchor.
    """
    from moto.kms.models import KmsBackend

    monkeypatch.setattr(
        KmsBackend, "generate_mac", generate_mac_reporting_key_arn(KmsBackend.generate_mac)
    )


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
    """Create a moto-backed KMS key, plus the HMAC key that names files.

    The data key is aliased KMS_KEY_ALIAS; the HMAC_256 / GENERATE_VERIFY_MAC
    file-identifier key is aliased ID_KEY_ALIAS (see the ``id_key`` fixture).
    """
    with mock_aws():
        kms = boto3.client("kms", region_name=REGION)
        key = kms.create_key(Description="envault-test-key")
        key_id = key["KeyMetadata"]["KeyId"]
        kms.create_alias(AliasName=KMS_KEY_ALIAS, TargetKeyId=key_id)
        create_id_key(REGION, ID_KEY_ALIAS)
        yield key_id


@pytest.fixture
def id_key(kms_key: str) -> str:
    """ARN of the HMAC file-identifier key the ``kms_key`` fixture creates."""
    kms = boto3.client("kms", region_name=REGION)
    return str(kms.describe_key(KeyId=ID_KEY_ALIAS)["KeyMetadata"]["Arn"])


@pytest.fixture
def tmp_plaintext(tmp_path: Path) -> Path:
    """Create a small plaintext file for testing."""
    p = tmp_path / "test.txt"
    p.write_text("hello envault test content\n")
    return p


@pytest.fixture
def correlation_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def no_retry_sleep(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Skip tenacity's backoff sleeps and record each delay that was requested.

    tenacity's default sleep looks up ``time.sleep`` at call time, so this also
    reaches functions that were decorated at import. An empty list after a
    failing call proves the failure was not retried.
    """
    delays: list[float] = []
    monkeypatch.setattr(time, "sleep", delays.append)
    return delays
