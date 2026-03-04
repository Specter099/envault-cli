"""Unit tests for envault.state using moto DynamoDB mocks."""

from __future__ import annotations

import time
from unittest.mock import patch

import boto3
from moto import mock_aws

from envault.exceptions import StateConflictError
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

    fetched = store.get_current_state(record.sha256_hash)
    assert fetched is not None
    original_last_updated = fetched.last_updated

    record.current_state = DECRYPTED
    store.put_current_state(record, expected_last_updated=original_last_updated)

    fetched2 = store.get_current_state(record.sha256_hash)
    assert fetched2 is not None
    assert fetched2.current_state == DECRYPTED


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


@mock_aws
def test_list_by_state_follows_pagination():
    """list_by_state must follow LastEvaluatedKey until exhausted."""
    store = _create_table()

    call_count = 0

    r1_item = {
        "PK": "FILE#" + "a" * 64,
        "SK": "CURRENT",
        "sha256_hash": "a" * 64,
        "file_name": "file1.txt",
        "current_state": "ENCRYPTED",
        "s3_key": "encrypted/aa/file1.txt.encrypted",
        "kms_key_id": "alias/envault",
        "encryption_context": {"purpose": "backup"},
        "algorithm": "AES_256_GCM",
        "message_id": "msg1",
        "file_size_bytes": 100,
        "tags": {},
        "s3_version_id": "v1",
        "encrypted_at": "2026-03-03T10:00:00+00:00",
        "decrypted_at": "",
        "last_updated": "2026-03-03T10:00:00+00:00",
        "ttl": 0,
    }
    r2_item = {
        **r1_item,
        "PK": "FILE#" + "b" * 64,
        "sha256_hash": "b" * 64,
        "file_name": "file2.txt",
    }

    def paged_query(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return {
                "Items": [r1_item],
                "LastEvaluatedKey": {"PK": "FILE#" + "a" * 64, "SK": "CURRENT"},
                "Count": 1,
                "ResponseMetadata": {},
            }
        return {"Items": [r2_item], "Count": 1, "ResponseMetadata": {}}

    with patch.object(store._table, "query", side_effect=paged_query):
        records = store.list_by_state("ENCRYPTED")

    assert call_count == 2
    assert len(records) == 2


@mock_aws
def test_list_events_by_date_excludes_current_records():
    """list_events_by_date must return only EVENT records, not CURRENT-state records."""
    store = _create_table()
    record = _make_record()
    # Write a CURRENT record (which also gets 'date' attribute and appears in date-index)
    store.put_current_state(record)
    # Write an event record
    store.put_event(record, operation="ENCRYPT", correlation_id="corr-1")

    from datetime import datetime, timezone

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    events = store.list_events_by_date(today)

    # Must not contain the CURRENT state record
    sks = [e.get("SK", "") for e in events]
    assert all(sk.startswith("EVENT#") for sk in sks), f"Found non-EVENT records: {sks}"
    assert len(events) >= 1


@mock_aws
def test_put_current_state_conflict_raises():
    """Updating with wrong expected_last_updated must raise StateConflictError."""
    import pytest

    store = _create_table()
    record = _make_record()
    store.put_current_state(record)

    record.current_state = DECRYPTED
    with pytest.raises(StateConflictError, match="Concurrent modification"):
        store.put_current_state(record, expected_last_updated="1970-01-01T00:00:00+00:00")


@mock_aws
def test_put_current_state_new_record_succeeds():
    """A new record (no expected_last_updated) should succeed when no record exists."""
    store = _create_table()
    record = _make_record()
    store.put_current_state(record)

    fetched = store.get_current_state(record.sha256_hash)
    assert fetched is not None
    assert fetched.current_state == ENCRYPTED


@mock_aws
def test_put_current_state_fails_if_already_exists():
    """A new record (no expected_last_updated) must fail if the PK already exists."""
    import pytest

    store = _create_table()
    record = _make_record()
    store.put_current_state(record)

    record2 = _make_record()
    with pytest.raises(StateConflictError, match="Concurrent modification"):
        store.put_current_state(record2)
