"""DynamoDB state store — single-table design with current state + append-only event log.

**What the audit trail can and cannot prove.** Events are written with
``attribute_not_exists(SK)``, which stops envault from overwriting an event by
accident (a retried write, an SK collision). It does not stop a principal that
holds ``dynamodb:PutItem`` on the table, which every envault user needs: such a
principal can write the same item without the condition, rewriting an event's
operation, principal, timestamp or expiry: a ``ttl`` in the past makes
DynamoDB's TTL process delete the event. The
``principal_arn`` on an event is reported by the client that wrote it, not
verified by DynamoDB. Treat this table as a convenient index of activity. The
authoritative record of who used which key and object is CloudTrail: KMS events
(``Decrypt``, ``GenerateDataKey``), plus DynamoDB and S3 data events where those
are enabled.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import boto3
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

from envault.config import boto_config
from envault.exceptions import MalformedRecordError, StateConflictError
from envault.fileid import ID_SCHEME_HMAC_SHA256, ID_SCHEME_SHA256
from envault.retry import aws_retry

logger = logging.getLogger(__name__)

# Record type constants
CURRENT = "CURRENT"
EVENT_PREFIX = "EVENT#"
FILE_PREFIX = "FILE#"

# States
ENCRYPTED = "ENCRYPTED"
DECRYPTED = "DECRYPTED"

# How a record's S3 key was chosen, which decides how the key is validated.
#: envault's own keys, which embed the file identifier.
S3_KEY_CONTENT_ADDRESSED = "content-addressed"
#: Keys written by the legacy shell workflow's ``aws s3 sync`` (records
#: imported by ``envault migrate``), validated by their layout instead.
S3_KEY_LEGACY_SYNC = "legacy-sync"


@dataclass
class FileRecord:
    """Represents the state of a file tracked by envault.

    ``file_id`` is the record's identifier and DynamoDB key (``FILE#<file_id>``)
    under its ``id_scheme`` (see :mod:`envault.fileid`): a keyed
    ``hmac-sha256-v1`` identifier with the ARN of the key that made it, or,
    for rows written before keyed identifiers, the plaintext's SHA-256. There
    is no field for a content hash as such, so nothing can put one into a
    keyed row: :meth:`to_dynamo_item` stores the identifier under the
    attribute its scheme uses, and only a legacy row gets ``sha256_hash``.
    ``id_scheme`` has no default; whoever builds a record says which it is.
    """

    file_id: str
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
    last_updated: str = ""
    #: :data:`S3_KEY_CONTENT_ADDRESSED` or :data:`S3_KEY_LEGACY_SYNC`. Rows
    #: written before this attribute existed are content-addressed.
    s3_key_scheme: str = S3_KEY_CONTENT_ADDRESSED
    #: :data:`~envault.fileid.ID_SCHEME_HMAC_SHA256` or
    #: :data:`~envault.fileid.ID_SCHEME_SHA256` (rows without ``id_scheme``).
    id_scheme: str = field(kw_only=True)
    #: ARN of the HMAC key that made a keyed identifier ("" for legacy rows).
    id_key_arn: str = field(default="", kw_only=True)

    def to_dynamo_item(self, sk: str) -> dict[str, Any]:
        """Serialize to a DynamoDB item dict.

        Raises:
            ValueError: The identifier scheme is unknown, or a keyed record
                lacks the ARN of its identifier key. No such row is written.
        """
        now = _now_iso()
        if not self.last_updated:
            self.last_updated = now
        attributes = asdict(self)
        for name in ("file_id", "id_scheme", "id_key_arn"):
            del attributes[name]
        item: dict[str, Any] = {
            "PK": f"{FILE_PREFIX}{self.file_id}",
            "SK": sk,
            **_identifier_attributes(self),
            **attributes,
        }
        return item


def _identifier_attributes(record: FileRecord) -> dict[str, str]:
    """How a row stores its identifier: by scheme, and never a content hash in a keyed row."""
    if record.id_scheme == ID_SCHEME_SHA256:
        # Rows of the legacy scheme keep the layout older clients wrote and read.
        return {"sha256_hash": record.file_id}
    if record.id_scheme == ID_SCHEME_HMAC_SHA256:
        if not record.id_key_arn:
            raise ValueError("a keyed record needs the ARN of the key that made its identifier")
        return {
            "file_id": record.file_id,
            "id_scheme": record.id_scheme,
            "id_key_arn": record.id_key_arn,
        }
    raise ValueError(
        f"refusing to write a record of unknown identifier scheme {record.id_scheme!r}"
    )


def item_id_scheme(item: Mapping[str, Any]) -> str:
    """The identifier scheme of a CURRENT or EVENT item: no ``id_scheme`` means legacy."""
    return str(item.get("id_scheme") or ID_SCHEME_SHA256)


def item_file_id(item: Mapping[str, Any]) -> str:
    """The identifier a CURRENT or EVENT item carries, whichever scheme wrote it."""
    attribute = "sha256_hash" if item_id_scheme(item) == ID_SCHEME_SHA256 else "file_id"
    return str(item.get(attribute, ""))


def _now_iso() -> str:
    # Microseconds (not seconds) so last_updated can serve as a CAS token:
    # two writers in the same wall-clock second must not share a token.
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _today_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _ttl_epoch(days: int) -> int:
    return int(time.time()) + days * 86400


class StateStore:
    """DynamoDB-backed state store for envault file records.

    Table design:
      PK: FILE#{file_id}  (see envault.fileid: keyed, or the SHA-256 on legacy rows)
      SK: CURRENT  (current operational state, upserted)
          EVENT#{iso_timestamp}#{operation}  (immutable audit trail)

    GSIs:
      state-index: PK=current_state, SK=encrypted_at  (CURRENT rows only)
      date-index:  PK=date, SK=last_updated          (EVENT rows only)

    "Immutable" and "append-only" describe what envault itself does. Anyone with
    write access to the table can change or delete any row, events included.
    CloudTrail is the authoritative trail (see the module docstring).
    """

    def __init__(self, table_name: str, region: str = "us-east-1") -> None:
        dynamodb = boto3.resource("dynamodb", region_name=region, config=boto_config)
        self._table = dynamodb.Table(table_name)

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

    def put_current_state(
        self, record: FileRecord, expected_last_updated: str | None = None
    ) -> None:
        """Upsert the current state record for a file (PK=FILE#file_id, SK=CURRENT).

        Sets ``record.last_updated`` to a fresh microsecond timestamp, which is
        the record's compare-and-swap token for the next writer.

        Retries are idempotent. The token is generated once, before the first
        attempt, so a retry re-sends the identical item. A write can land while
        its reply is lost (a read timeout). The retry's condition then fails
        because our own write is already there. In that case a consistent read
        finds exactly the item we sent, and the call succeeds instead of
        reporting a conflict that never happened.

        Args:
            record: The file record to write.
            expected_last_updated: If provided, uses optimistic locking — the write
                only succeeds if the existing record's last_updated matches. If None
                and no record exists yet, uses attribute_not_exists to prevent
                clobbering an existing record.

        Raises:
            StateConflictError: If the condition fails and the stored item is not
                the one this call wrote.
        """
        record.last_updated = _now_iso()
        item = record.to_dynamo_item(sk=CURRENT)
        self._put_current_item(item, expected_last_updated)
        logger.debug(
            "put_current_state",
            extra={"file_id": record.file_id[:16], "state": record.current_state},
        )

    @aws_retry(never=(StateConflictError,))
    def _put_current_item(self, item: dict[str, Any], expected_last_updated: str | None) -> None:
        """Conditional PutItem of a fully built CURRENT item (retry loop of put_current_state)."""
        put_kwargs: dict[str, Any] = {"Item": item}
        if expected_last_updated is not None:
            put_kwargs["ConditionExpression"] = "last_updated = :expected"
            put_kwargs["ExpressionAttributeValues"] = {":expected": expected_last_updated}
        else:
            put_kwargs["ConditionExpression"] = "attribute_not_exists(PK)"

        try:
            self._table.put_item(**put_kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise
            if self._stored_item_equals(item):
                logger.debug(
                    "conditional write already applied by an earlier attempt",
                    extra={"last_updated": item["last_updated"]},
                )
                return
            raise StateConflictError(
                f"Concurrent modification detected for "
                f"{str(item['PK']).removeprefix(FILE_PREFIX)[:16]}... "
                f"(expected last_updated={expected_last_updated!r}). "
                "Another process may have modified this record."
            ) from exc

    def _stored_item_equals(self, item: dict[str, Any]) -> bool:
        """True if a strongly consistent read returns exactly ``item``.

        The whole item is compared, not only its ``last_updated`` token: two
        writers that drew the same microsecond must not mistake each other's
        write for their own. DynamoDB returns numbers as Decimal, which compares
        equal to the int that was written.
        """
        response = self._table.get_item(
            Key={"PK": item["PK"], "SK": item["SK"]}, ConsistentRead=True
        )
        return bool(response.get("Item") == item)

    def put_event(
        self,
        record: FileRecord,
        operation: str,
        correlation_id: str,
        audit_ttl_days: int = 365,
        principal_arn: str = "",
    ) -> None:
        """Append an event record to the audit trail.

        The write is conditional on the SK being new, so envault never replaces
        an existing event. That guards against accidents, not against a table
        writer: anyone with ``dynamodb:PutItem`` can rewrite or forge events,
        including ``principal_arn``. CloudTrail is the authoritative trail.

        Args:
            record: The file the event concerns.
            operation: ENCRYPT, DECRYPT, ACCESS, ROTATE_KEY.
            correlation_id: Groups events from a single invocation.
            audit_ttl_days: Retention before DynamoDB TTL expires the event.
            principal_arn: The AWS identity performing the operation, as this
                client resolved it (see :func:`envault.identity.caller_arn`).
                Without this the trail records what happened but not who did
                it. DynamoDB stores whatever the writer sends, so this
                attributes honest clients only.
        """
        now = _now_iso()
        unique_suffix = uuid.uuid4().hex[:8]
        self._put_event_inner(
            record, operation, correlation_id, audit_ttl_days, now, unique_suffix, principal_arn
        )

    @aws_retry()
    def _put_event_inner(
        self,
        record: FileRecord,
        operation: str,
        correlation_id: str,
        audit_ttl_days: int,
        now: str,
        unique_suffix: str,
        principal_arn: str = "",
    ) -> None:
        """Inner retry loop for put_event -- uses a fixed SK across retries."""
        sk = f"{EVENT_PREFIX}{now}#{operation}#{unique_suffix}"
        item = record.to_dynamo_item(sk=sk)
        item["operation"] = operation
        item["correlation_id"] = correlation_id
        item["principal_arn"] = principal_arn
        # Stored under a different name so events stay out of the sparse
        # state-index: otherwise every state/filename lookup, rotate-key and
        # dashboard query reads (and pays for) the entire audit history.
        item["record_state"] = item.pop("current_state")
        item["date"] = _today_str()
        item["ttl"] = _ttl_epoch(audit_ttl_days)
        try:
            # Append-only at envault's own write path: a retry or an SK collision
            # can never replace an existing event. This is a client-side
            # condition. A principal holding PutItem can still overwrite the
            # item by writing it without the condition (r08), so it prevents
            # accidents, not tampering; CloudTrail is the authoritative trail.
            self._table.put_item(Item=item, ConditionExpression="attribute_not_exists(SK)")
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                # The SK carries a random suffix, so a collision means this exact
                # write already landed and tenacity is retrying a call that in
                # fact succeeded. Treat as done rather than failing the command.
                logger.debug("event already recorded, skipping duplicate write", extra={"sk": sk})
                return
            raise
        logger.debug(
            "put_event",
            extra={"file_id": record.file_id[:16], "operation": operation},
        )

    @aws_retry()
    def get_current_state(self, file_id: str) -> FileRecord | None:
        """Return the current state record stored under ``file_id``, or None if not found.

        Raises:
            MalformedRecordError: The row stored there is not shaped like a record.
        """
        response = self._table.get_item(Key={"PK": f"{FILE_PREFIX}{file_id}", "SK": CURRENT})
        item = response.get("Item")
        if not item:
            return None
        return _item_to_record(item)

    @aws_retry()
    def has_current_state(self, file_id: str) -> bool:
        """True if a current state record is stored under ``file_id``, whatever it holds.

        Only the key is read back, and nothing is parsed or checked.
        """
        response = self._table.get_item(
            Key={"PK": f"{FILE_PREFIX}{file_id}", "SK": CURRENT}, ProjectionExpression="PK"
        )
        return "Item" in response

    @aws_retry()
    def list_by_state(
        self,
        state: str,
        max_items: int = 0,
        *,
        on_malformed: Callable[[MalformedRecordError], None] | None = None,
    ) -> list[FileRecord]:
        """Return all files in a given state (uses state-index GSI).

        A malformed row (see :func:`_item_to_record`) is left out of the list
        and handed to ``on_malformed``; without one it is logged as a warning.
        One bad row never hides the others.

        Args:
            state: The state to filter by (e.g. ENCRYPTED, DECRYPTED).
            max_items: Maximum rows to read. 0 means no limit. Malformed rows
                count towards it.
            on_malformed: Called with the error for each malformed row.
        """
        items = self._paginate_query(
            max_items=max_items,
            IndexName="state-index",
            KeyConditionExpression=Key("current_state").eq(state),
            FilterExpression=Attr("SK").eq(CURRENT),
        )
        return _well_formed_records(items, on_malformed)

    @aws_retry()
    def list_by_file_name(
        self,
        file_name: str,
        state: str,
        *,
        on_malformed: Callable[[MalformedRecordError], None] | None = None,
    ) -> list[FileRecord]:
        """Return CURRENT records matching a file_name in a given state.

        Results are sorted by encrypted_at descending (newest first).
        Uses state-index GSI with FilterExpression on file_name and SK.
        Malformed rows are left out and reported as :meth:`list_by_state` does.
        """
        items = self._paginate_query(
            IndexName="state-index",
            KeyConditionExpression=Key("current_state").eq(state),
            FilterExpression=Attr("SK").eq(CURRENT) & Attr("file_name").eq(file_name),
        )
        records = _well_formed_records(items, on_malformed)
        records.sort(key=lambda r: r.encrypted_at, reverse=True)
        return records

    @aws_retry()
    def list_events_for_file(self, file_id: str) -> list[dict[str, Any]]:
        """Return all event records stored under ``file_id``, sorted by timestamp."""
        return self._paginate_query(
            KeyConditionExpression=(
                Key("PK").eq(f"{FILE_PREFIX}{file_id}") & Key("SK").begins_with(EVENT_PREFIX)
            )
        )

    @aws_retry()
    def list_events_by_date(self, date_str: str) -> list[dict[str, Any]]:
        """Return EVENT records for a given date YYYY-MM-DD (uses date-index GSI).

        CURRENT-state records also carry a 'date' attribute but are excluded by
        filtering on SK beginning with EVENT_PREFIX.
        """
        return self._paginate_query(
            IndexName="date-index",
            KeyConditionExpression=Key("date").eq(date_str),
            FilterExpression=Attr("SK").begins_with(EVENT_PREFIX),
        )

    def list_events_between(
        self, start: date, end: date, *, max_days: int | None = None
    ) -> list[dict[str, Any]]:
        """Return EVENT records dated ``start`` through ``end`` (inclusive), oldest first.

        Days are UTC calendar days, the same ``date`` attribute
        :meth:`put_event` writes. The date-index is partitioned by day, so this
        runs one paginated query per day (via :meth:`list_events_by_date`, each
        with its own retries). A transient failure on day 40 does not restart
        the whole range. Results are sorted by SK, whose second component is
        the event's ISO-8601 timestamp, so the order is chronological across
        days and files.

        Args:
            start: First day to include.
            end: Last day to include.
            max_days: If given, refuse ranges longer than this many days instead
                of issuing that many queries.

        Raises:
            TypeError: If ``start`` or ``end`` is a ``datetime`` rather than a ``date``.
            ValueError: If ``start`` is after ``end``, or the range is longer
                than ``max_days``.
        """
        for bound in (start, end):
            if isinstance(bound, datetime) or not isinstance(bound, date):
                raise TypeError(
                    f"list_events_between takes datetime.date values (UTC days), got {bound!r}"
                )
        if start > end:
            raise ValueError(f"start {start.isoformat()} is after end {end.isoformat()}")
        days = (end - start).days + 1
        if max_days is not None and days > max_days:
            raise ValueError(f"range of {days} days exceeds max_days={max_days}")

        events: list[dict[str, Any]] = []
        for offset in range(days):
            events.extend(self.list_events_by_date((start + timedelta(days=offset)).isoformat()))
        events.sort(key=lambda event: str(event.get("SK", "")))
        return events

    def _state_stats(self, state: str) -> tuple[int, str]:
        """Return (count, latest last_updated) of CURRENT records in a state.

        One paginated pass that projects only the timestamp. Filtering happens
        after DynamoDB's Limit is applied, so a ``Limit=1`` query here would
        return nothing whenever the first index entry is a legacy EVENT row.
        """
        count = 0
        latest = ""
        query_kwargs: dict[str, Any] = {
            "IndexName": "state-index",
            "KeyConditionExpression": Key("current_state").eq(state),
            "FilterExpression": Attr("SK").eq(CURRENT),
            "ProjectionExpression": "last_updated",
        }
        while True:
            response = self._table.query(**query_kwargs)
            for item in response.get("Items", []):
                count += 1
                latest = max(latest, str(item.get("last_updated", "")))
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                break
            query_kwargs["ExclusiveStartKey"] = last_key
        return count, latest

    def summary(self) -> dict[str, Any]:
        """Return aggregate counts and last activity timestamp for the dashboard."""
        encrypted_count, encrypted_latest = self._state_stats(ENCRYPTED)
        decrypted_count, decrypted_latest = self._state_stats(DECRYPTED)
        last_activity = max(encrypted_latest, decrypted_latest) or "\u2014"

        return {
            "total": encrypted_count + decrypted_count,
            "encrypted": encrypted_count,
            "decrypted": decrypted_count,
            "last_activity": last_activity,
        }


#: Attributes a CURRENT row holds as strings, whenever it has them.
_STRING_ATTRIBUTES = (
    "sha256_hash",
    "file_id",
    "id_scheme",
    "id_key_arn",
    "file_name",
    "current_state",
    "s3_key",
    "s3_key_scheme",
    "s3_version_id",
    "kms_key_id",
    "algorithm",
    "message_id",
    "encrypted_at",
    "last_updated",
)
#: Attributes a CURRENT row holds as maps of strings to strings.
_STRING_MAP_ATTRIBUTES = ("encryption_context", "tags")


def _kind(value: object) -> str:
    return "null" if value is None else f"a {type(value).__name__}"


def _is_string_map(value: object) -> bool:
    return isinstance(value, dict) and all(
        isinstance(key, str) and isinstance(inner, str) for key, inner in value.items()
    )


def _is_byte_count(value: object) -> bool:
    """A whole, non-negative number: an int, or the Decimal DynamoDB returns for one."""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value >= 0
    return (
        isinstance(value, Decimal)
        and value.is_finite()
        and value == value.to_integral_value()
        and value >= 0
    )


def _malformed_attributes(item: Mapping[str, Any]) -> list[str]:
    """What is wrong with the types of a CURRENT row's attributes ([] if nothing).

    Absent attributes are fine (rows from older versions lack some); present
    ones must have the type envault writes. Values are never quoted.
    """
    problems = [
        f"{name} is {_kind(item[name])}, not a string"
        for name in _STRING_ATTRIBUTES
        if name in item and not isinstance(item[name], str)
    ]
    problems += [
        f"{name} is not a map of strings"
        for name in _STRING_MAP_ATTRIBUTES
        if name in item and not _is_string_map(item[name])
    ]
    if "file_size_bytes" in item and not _is_byte_count(item["file_size_bytes"]):
        problems.append("file_size_bytes is not a whole number of bytes")
    return problems


def _well_formed_records(
    items: Iterable[dict[str, Any]],
    on_malformed: Callable[[MalformedRecordError], None] | None,
) -> list[FileRecord]:
    """The rows that parse; each malformed one goes to ``on_malformed`` (default: logged)."""
    records: list[FileRecord] = []
    for item in items:
        try:
            records.append(_item_to_record(item))
        except MalformedRecordError as exc:
            if on_malformed is None:
                logger.warning("Skipping a malformed record: %s", exc)
            else:
                on_malformed(exc)
    return records


def _item_to_record(item: dict[str, Any]) -> FileRecord:
    """Convert a raw DynamoDB item to a FileRecord, in either identifier layout.

    An unknown ``id_scheme`` is kept as it is, so that whoever uses the
    record can refuse it; it is never read as legacy.

    Raises:
        MalformedRecordError: An attribute has a type envault never writes
            (anyone with write access to the table can put one there). Such a
            row is never coerced into a record.
    """
    problems = _malformed_attributes(item)
    if problems:
        raise MalformedRecordError(str(item.get("PK", "")).removeprefix(FILE_PREFIX), problems)
    scheme = item_id_scheme(item)
    return FileRecord(
        file_id=item_file_id(item),
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
        last_updated=item.get("last_updated", ""),
        s3_key_scheme=item.get("s3_key_scheme", S3_KEY_CONTENT_ADDRESSED),
        id_scheme=scheme,
        id_key_arn=str(item.get("id_key_arn", "")) if scheme != ID_SCHEME_SHA256 else "",
    )
