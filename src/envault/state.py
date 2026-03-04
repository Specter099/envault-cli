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
from botocore.exceptions import ClientError
from tenacity import retry, retry_if_not_exception_type, stop_after_attempt, wait_exponential

from envault.config import boto_config
from envault.exceptions import StateConflictError

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
        self._dynamodb = boto3.resource("dynamodb", region_name=region, config=boto_config)
        self._table = self._dynamodb.Table(table_name)

    def _paginate_query(self, max_items: int = 0, **query_kwargs: Any) -> list[dict[str, Any]]:
        """Execute a DynamoDB Query, following LastEvaluatedKey until exhausted.

        Args:
            max_items: Maximum items to return. 0 means no limit.
        """
        items: list[dict[str, Any]] = []
        while True:
            response = self._table.query(**query_kwargs)
            items.extend(response.get("Items", []))
            if max_items and len(items) >= max_items:
                return items[:max_items]
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                break
            query_kwargs["ExclusiveStartKey"] = last_key
        return items

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_not_exception_type(StateConflictError),
    )
    def put_current_state(
        self, record: FileRecord, expected_last_updated: str | None = None
    ) -> None:
        """Upsert the current state record for a file (PK=FILE#hash, SK=CURRENT).

        Args:
            record: The file record to write.
            expected_last_updated: If provided, uses optimistic locking — the write
                only succeeds if the existing record's last_updated matches. If None
                and no record exists yet, uses attribute_not_exists to prevent
                clobbering an existing record.
        """
        record.last_updated = _now_iso()
        item = record.to_dynamo_item(sk=CURRENT)
        # Add GSI keys
        item["current_state"] = record.current_state
        item["date"] = _today_str()

        put_kwargs: dict[str, Any] = {"Item": item}

        if expected_last_updated is not None:
            put_kwargs["ConditionExpression"] = "last_updated = :expected"
            put_kwargs["ExpressionAttributeValues"] = {":expected": expected_last_updated}
        else:
            put_kwargs["ConditionExpression"] = "attribute_not_exists(PK)"

        try:
            self._table.put_item(**put_kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise StateConflictError(
                    f"Concurrent modification detected for {record.sha256_hash[:16]}... "
                    f"(expected last_updated={expected_last_updated!r}). "
                    "Another process may have modified this record."
                ) from exc
            raise

        logger.debug(
            "put_current_state",
            extra={"sha256": record.sha256_hash[:16], "state": record.current_state},
        )

    def put_event(
        self, record: FileRecord, operation: str, correlation_id: str, audit_ttl_days: int = 365
    ) -> None:
        """Append an immutable event record to the audit trail."""
        now = _now_iso()
        unique_suffix = uuid.uuid4().hex[:8]
        self._put_event_inner(record, operation, correlation_id, audit_ttl_days, now, unique_suffix)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    def _put_event_inner(
        self,
        record: FileRecord,
        operation: str,
        correlation_id: str,
        audit_ttl_days: int,
        now: str,
        unique_suffix: str,
    ) -> None:
        """Inner retry loop for put_event -- uses a fixed SK across retries."""
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
    def list_by_state(self, state: str, max_items: int = 0) -> list[FileRecord]:
        """Return all files in a given state (uses state-index GSI).

        Args:
            state: The state to filter by (e.g. ENCRYPTED, DECRYPTED).
            max_items: Maximum items to return. 0 means no limit.
        """
        items = self._paginate_query(
            max_items=max_items,
            IndexName="state-index",
            KeyConditionExpression=Key("current_state").eq(state),
        )
        return [_item_to_record(item) for item in items]

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    def list_events_for_file(self, sha256_hash: str) -> list[dict[str, Any]]:
        """Return all event records for a file, sorted by timestamp."""
        return self._paginate_query(
            KeyConditionExpression=(
                Key("PK").eq(f"{FILE_PREFIX}{sha256_hash}") & Key("SK").begins_with(EVENT_PREFIX)
            )
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    def list_events_by_date(self, date_str: str) -> list[dict[str, Any]]:
        """Return EVENT records for a given date YYYY-MM-DD (uses date-index GSI).

        CURRENT-state records also carry a 'date' attribute but are excluded by
        filtering on SK beginning with EVENT_PREFIX.
        """
        from boto3.dynamodb.conditions import Attr

        return self._paginate_query(
            IndexName="date-index",
            KeyConditionExpression=Key("date").eq(date_str),
            FilterExpression=Attr("SK").begins_with(EVENT_PREFIX),
        )

    def _count_by_state(self, state: str) -> int:
        """Return count of records in a given state using Select=COUNT (no data transfer)."""
        count = 0
        query_kwargs: dict[str, Any] = {
            "IndexName": "state-index",
            "KeyConditionExpression": Key("current_state").eq(state),
            "Select": "COUNT",
        }
        while True:
            response = self._table.query(**query_kwargs)
            count += response.get("Count", 0)
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                break
            query_kwargs["ExclusiveStartKey"] = last_key
        return count

    def summary(self) -> dict[str, Any]:
        """Return aggregate counts for the dashboard."""
        encrypted_count = self._count_by_state(ENCRYPTED)
        decrypted_count = self._count_by_state(DECRYPTED)
        return {
            "total": encrypted_count + decrypted_count,
            "encrypted": encrypted_count,
            "decrypted": decrypted_count,
            "last_activity": "\u2014",
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
