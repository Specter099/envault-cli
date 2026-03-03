"""Unit tests for envault.state using moto DynamoDB mocks."""

from __future__ import annotations

import time

import boto3
from moto import mock_aws

from envault.state import DECRYPTED, ENCRYPTED, FileRecord, StateStore

TABLE = "envault-test-state"
REGION = "us-east-1"


def _make_record(**kwargs) -> FileRecord:
    defaults = {
        "sha256_hash": "a" * 64,
        "file_name": "test.txt",
        "current_state": ENCRYPTED,
        "s3_key": "encrypted/test.txt.encrypted",
        "kms_key_id": "alias/envault",
        "encryption_context": {"purpose": "backup"},
        "algorithm": "AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384",
        "message_id": "msg-abc123",
        "file_size_bytes": 1024,
        "tags": {"project": "test"},
        "s3_version_id": "v1",
        "encrypted_at": "2026-03-03T10:00:00+00:00",
    }
    defaults.update(kwargs)
    return FileRecord(**defaults)


def _create_table() -> StateStore:
    client = boto3.client("dynamodb", region_name=REGION)
    client.create_table(
        TableName=TABLE,
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
    return StateStore(table_name=TABLE, region=REGION)


@mock_aws
def test_put_and_get_current_state():
    store = _create_table()
    record = _make_record()
    store.put_current_state(record)

    fetched = store.get_current_state(record.sha256_hash)
    assert fetched is not None
    assert fetched.sha256_hash == record.sha256_hash
    assert fetched.file_name == "test.txt"
    assert fetched.current_state == ENCRYPTED


@mock_aws
def test_get_current_state_not_found_returns_none():
    store = _create_table()
    result = store.get_current_state("nonexistent" * 6)
    assert result is None


@mock_aws
def test_put_event_appends_to_audit_log():
    store = _create_table()
    record = _make_record()
    store.put_current_state(record)
    store.put_event(record, operation="ENCRYPT", correlation_id="corr-1")
    store.put_event(record, operation="DECRYPT", correlation_id="corr-2")

    events = store.list_events_for_file(record.sha256_hash)
    assert len(events) == 2
    operations = {e["operation"] for e in events}
    assert operations == {"ENCRYPT", "DECRYPT"}


@mock_aws
def test_list_by_state_encrypted():
    store = _create_table()
    r1 = _make_record(
        sha256_hash="b" * 64, current_state=ENCRYPTED, encrypted_at="2026-03-03T10:00:00+00:00"
    )
    r2 = _make_record(
        sha256_hash="c" * 64, current_state=DECRYPTED, encrypted_at="2026-03-03T11:00:00+00:00"
    )
    store.put_current_state(r1)
    store.put_current_state(r2)

    encrypted = store.list_by_state(ENCRYPTED)
    assert len(encrypted) == 1
    assert encrypted[0].sha256_hash == "b" * 64


@mock_aws
def test_put_current_state_upserts():
    store = _create_table()
    record = _make_record()
    store.put_current_state(record)

    record.current_state = DECRYPTED
    store.put_current_state(record)

    fetched = store.get_current_state(record.sha256_hash)
    assert fetched is not None
    assert fetched.current_state == DECRYPTED


@mock_aws
def test_summary_counts():
    store = _create_table()
    r1 = _make_record(
        sha256_hash="d" * 64, current_state=ENCRYPTED, encrypted_at="2026-03-03T10:00:00+00:00"
    )
    r2 = _make_record(
        sha256_hash="e" * 64, current_state=ENCRYPTED, encrypted_at="2026-03-03T11:00:00+00:00"
    )
    r3 = _make_record(
        sha256_hash="f" * 64, current_state=DECRYPTED, encrypted_at="2026-03-03T12:00:00+00:00"
    )
    store.put_current_state(r1)
    store.put_current_state(r2)
    store.put_current_state(r3)

    summary = store.summary()
    assert summary["total"] == 3
    assert summary["encrypted"] == 2
    assert summary["decrypted"] == 1


@mock_aws
def test_tags_preserved_in_roundtrip():
    store = _create_table()
    tags = {"project": "finance", "owner": "brian", "env": "prod"}
    record = _make_record(tags=tags)
    store.put_current_state(record)

    fetched = store.get_current_state(record.sha256_hash)
    assert fetched is not None
    assert fetched.tags == tags


@mock_aws
def test_s3_version_id_preserved():
    store = _create_table()
    record = _make_record(s3_version_id="abc-version-123")
    store.put_current_state(record)

    fetched = store.get_current_state(record.sha256_hash)
    assert fetched is not None
    assert fetched.s3_version_id == "abc-version-123"


@mock_aws
def test_events_have_ttl():
    store = _create_table()
    record = _make_record()
    store.put_event(record, operation="ENCRYPT", correlation_id="corr", audit_ttl_days=30)

    events = store.list_events_for_file(record.sha256_hash)
    assert len(events) == 1
    ttl = int(events[0].get("ttl", 0))
    assert ttl > int(time.time())
    assert ttl < int(time.time()) + 31 * 86400
