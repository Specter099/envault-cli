"""DynamoDB state store — single-table design with current state + append-only event log."""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)

# Record type constants
CURRENT = "CURRENT"
EVENT_PREFIX = "EVENT#"
FILE_PREFIX = "FILE#"

# States
ENCRYPTED = "ENCRYPTED"
DECRYPTED = "DECRYPTED"


@dataclass
class FileRecord:
    """Represents the state of a file tracked by envault."""

    sha256_hash: str
    file_name: str
    current_state: str
    s3_key: str
    kms_key_id: str
    encryption_context: dict[str, str]
    algorithm: str
    message_id: str
    file_size_bytes: int
    tags: dict[str, str] = field(default_factory=dict)
    s3_version_id: str = ""
    encrypted_at: str = ""
    decrypted_at: str = ""
    last_updated: str = ""
    ttl: int = 0

    def to_dynamo_item(self, sk: str) -> dict[str, Any]:
        """Serialize to a DynamoDB item dict."""
        now = _now_iso()
        if not self.last_updated:
            self.last_updated = now
        item: dict[str, Any] = {
            "PK": f"{FILE_PREFIX}{self.sha256_hash}",
            "SK": sk,
            **asdict(self),
        }
        return item


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _today_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _ttl_epoch(days: int) -> int:
    return int(time.time()) + days * 86400


class StateStore:
    """DynamoDB-backed state store for envault file records.

    Table design:
      PK: FILE#{sha256_hash}
      SK: CURRENT  (current operational state, upserted)
          EVENT#{iso_timestamp}#{operation}  (immutable audit trail)

    GSIs:
      state-index: PK=current_state, SK=encrypted_at
      date-index:  PK=date, SK=last_updated
      tag-index:   PK=tag_key, SK=tag_value
    """

    def __init__(self, table_name: str, region: str = "us-east-1") -> None:
        self._table_name = table_name
        self._region = region
        self._dynamodb = boto3.resource("dynamodb", region_name=region)
        self._table = self._dynamodb.Table(table_name)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    def put_current_state(self, record: FileRecord) -> None:
        """Upsert the current state record for a file (PK=FILE#hash, SK=CURRENT)."""
        record.last_updated = _now_iso()
        item = record.to_dynamo_item(sk=CURRENT)
        # Add GSI keys
        item["current_state"] = record.current_state
        item["date"] = _today_str()
        self._table.put_item(Item=item)
        logger.debug(
            "put_current_state",
            extra={"sha256": record.sha256_hash[:16], "state": record.current_state},
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    def put_event(
        self, record: FileRecord, operation: str, correlation_id: str, audit_ttl_days: int = 365
    ) -> None:
        """Append an immutable event record to the audit trail."""
        now = _now_iso()
        unique_suffix = uuid.uuid4().hex[:8]
        sk = f"{EVENT_PREFIX}{now}#{operation}#{unique_suffix}"
        item = record.to_dynamo_item(sk=sk)
        item["operation"] = operation
        item["correlation_id"] = correlation_id
        item["current_state"] = record.current_state
        item["date"] = _today_str()
        item["ttl"] = _ttl_epoch(audit_ttl_days)
        self._table.put_item(Item=item)
        logger.debug(
            "put_event",
            extra={"sha256": record.sha256_hash[:16], "operation": operation},
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    def get_current_state(self, sha256_hash: str) -> FileRecord | None:
        """Return the current state record for a file, or None if not found."""
        response = self._table.get_item(Key={"PK": f"{FILE_PREFIX}{sha256_hash}", "SK": CURRENT})
        item = response.get("Item")
        if not item:
            return None
        return _item_to_record(item)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    def list_by_state(self, state: str) -> list[FileRecord]:
        """Return all files in a given state (uses state-index GSI)."""
        items: list[dict[str, Any]] = []
        kwargs: dict[str, Any] = {
            "IndexName": "state-index",
            "KeyConditionExpression": Key("current_state").eq(state),
        }
        while True:
            response = self._table.query(**kwargs)
            items.extend(response.get("Items", []))
            if "LastEvaluatedKey" not in response:
                break
            kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]
        return [_item_to_record(item) for item in items]

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    def list_events_for_file(self, sha256_hash: str) -> list[dict[str, Any]]:
        """Return all event records for a file, sorted by timestamp."""
        items: list[dict[str, Any]] = []
        kwargs: dict[str, Any] = {
            "KeyConditionExpression": (
                Key("PK").eq(f"{FILE_PREFIX}{sha256_hash}") & Key("SK").begins_with(EVENT_PREFIX)
            ),
        }
        while True:
            response = self._table.query(**kwargs)
            items.extend(response.get("Items", []))
            if "LastEvaluatedKey" not in response:
                break
            kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]
        return items

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    def list_events_by_date(self, date_str: str) -> list[dict[str, Any]]:
        """Return all events for a given date YYYY-MM-DD (uses date-index GSI)."""
        items: list[dict[str, Any]] = []
        kwargs: dict[str, Any] = {
            "IndexName": "date-index",
            "KeyConditionExpression": Key("date").eq(date_str),
        }
        while True:
            response = self._table.query(**kwargs)
            items.extend(response.get("Items", []))
            if "LastEvaluatedKey" not in response:
                break
            kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]
        return items

    def summary(self) -> dict[str, Any]:
        """Return aggregate counts for the dashboard."""
        encrypted = self.list_by_state(ENCRYPTED)
        decrypted = self.list_by_state(DECRYPTED)
        last_activity = max(
            (r.last_updated for r in encrypted + decrypted),
            default="—",
        )
        return {
            "total": len(encrypted) + len(decrypted),
            "encrypted": len(encrypted),
            "decrypted": len(decrypted),
            "last_activity": last_activity,
        }


def _item_to_record(item: dict[str, Any]) -> FileRecord:
    """Convert a raw DynamoDB item to a FileRecord."""
    return FileRecord(
        sha256_hash=item.get("sha256_hash", ""),
        file_name=item.get("file_name", ""),
        current_state=item.get("current_state", ""),
        s3_key=item.get("s3_key", ""),
        kms_key_id=item.get("kms_key_id", ""),
        encryption_context=dict(item.get("encryption_context", {})),
        algorithm=item.get("algorithm", ""),
        message_id=item.get("message_id", ""),
        file_size_bytes=int(item.get("file_size_bytes", 0)),
        tags=dict(item.get("tags", {})),
        s3_version_id=item.get("s3_version_id", ""),
        encrypted_at=item.get("encrypted_at", ""),
        decrypted_at=item.get("decrypted_at", ""),
        last_updated=item.get("last_updated", ""),
        ttl=int(item.get("ttl", 0)),
    )
