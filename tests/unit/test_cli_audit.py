"""`envault audit` and `envault dashboard` through the CLI (M3 and the coverage gap)."""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import date
from unittest.mock import patch

import boto3
import pytest
from botocore.exceptions import ClientError
from click.testing import CliRunner, Result
from moto import mock_aws

from envault import cli as cli_mod
from envault import state as state_mod
from envault.cli import main
from envault.fileid import ID_SCHEME_SHA256
from envault.state import DECRYPTED, ENCRYPTED, FileRecord, StateStore

TABLE = "envault-test-state"
REGION = "us-east-1"
ENV = {
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",  # noqa: S105  # pragma: allowlist secret
    "AWS_DEFAULT_REGION": REGION,
    "ENVAULT_TABLE": TABLE,
    "ENVAULT_REGION": REGION,
    "COLUMNS": "250",
}
SHA_A = "a" * 64
SHA_B = "b" * 64


def _create_table() -> None:
    boto3.client("dynamodb", region_name=REGION).create_table(
        TableName=TABLE,
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[
            {"AttributeName": n, "AttributeType": "S"}
            for n in ("PK", "SK", "current_state", "encrypted_at", "date", "last_updated")
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


def _record(sha: str, name: str, state: str = ENCRYPTED) -> FileRecord:
    return FileRecord(
        id_scheme=ID_SCHEME_SHA256,
        file_id=sha,
        file_name=name,
        current_state=state,
        s3_key=f"encrypted/{sha[:2]}/{sha}/{name}.encrypted",
        kms_key_id="alias/k",
        encryption_context={},
        algorithm="AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384",
        message_id="m",
        file_size_bytes=1,
        encrypted_at="2026-11-01T00:00:00+00:00",
        last_updated="2026-11-01T00:00:00+00:00",
    )


def _event_on(store: StateStore, record: FileRecord, day: str, operation: str) -> None:
    """Write an event dated ``day`` (UTC), with a matching SK timestamp."""
    with (
        patch.object(state_mod, "_today_str", return_value=day),
        patch.object(state_mod, "_now_iso", return_value=f"{day}T12:00:00.000000+00:00"),
    ):
        store.put_event(
            record,
            operation=operation,
            correlation_id=f"corr-{day}",
            principal_arn="arn:aws:iam::123456789012:user/alice",
        )


@pytest.fixture
def three_days() -> Iterator[StateStore]:
    """Events on 2026-11-01 (ENCRYPT), 11-05 (ACCESS), 11-09 (DECRYPT), written out of order."""
    with mock_aws():
        _create_table()
        store = StateStore(table_name=TABLE, region=REGION)
        record = _record(SHA_A, "db.env")
        store.put_current_state(record)
        _event_on(store, record, "2026-11-09", "DECRYPT")
        _event_on(store, record, "2026-11-01", "ENCRYPT")
        _event_on(store, record, "2026-11-05", "ACCESS")
        yield store


def _audit(*args: str) -> Result:
    return CliRunner().invoke(main, ["audit", *args], env=ENV)


def _ops(result: Result) -> list[str]:
    """Operations in the order the table lists them."""
    return re.findall(r"\b(ENCRYPT|ACCESS|DECRYPT|ROTATE_KEY)\b", result.output)


def test_audit_since_includes_later_days(three_days: StateStore) -> None:
    """--since is the first day of a range, not the only day shown (M3)."""
    with patch.object(cli_mod, "_utc_today", return_value=date(2026, 11, 15)):
        all_three = _audit("--since", "2026-11-01")
        later_two = _audit("--since", "2026-11-02")

    assert all_three.exit_code == 0, all_three.output
    assert _ops(all_three) == ["ENCRYPT", "ACCESS", "DECRYPT"]
    assert later_two.exit_code == 0, later_two.output
    assert _ops(later_two) == ["ACCESS", "DECRYPT"]


def test_audit_until_bounds_range(three_days: StateStore) -> None:
    result = _audit("--since", "2026-11-01", "--until", "2026-11-05")

    assert result.exit_code == 0, result.output
    assert _ops(result) == ["ENCRYPT", "ACCESS"]


def test_audit_single_day_range(three_days: StateStore) -> None:
    result = _audit("--since", "2026-11-05", "--until", "2026-11-05")

    assert result.exit_code == 0, result.output
    assert _ops(result) == ["ACCESS"]


def test_audit_since_after_until_is_usage_error(three_days: StateStore) -> None:
    result = _audit("--since", "2026-11-09", "--until", "2026-11-01")

    assert result.exit_code == 2
    assert "after --until" in result.output


def test_audit_until_defaults_to_today_utc(three_days: StateStore) -> None:
    with patch.object(cli_mod, "_utc_today", return_value=date(2026, 11, 7)):
        result = _audit("--since", "2026-11-01")
        future = _audit("--since", "2026-11-08")

    assert _ops(result) == ["ENCRYPT", "ACCESS"]
    assert future.exit_code == 2
    assert "today" in future.output


def test_audit_refuses_ranges_longer_than_a_year(three_days: StateStore) -> None:
    """One query per day: an unbounded range would be thousands of queries."""
    result = _audit("--since", "2020-01-01", "--until", "2026-11-15")

    assert result.exit_code == 2
    assert "366" in result.output


def test_audit_until_needs_since(three_days: StateStore) -> None:
    result = _audit("--until", "2026-11-05")

    assert result.exit_code == 2
    assert "--since" in result.output


def test_audit_invalid_date_is_rejected(three_days: StateStore) -> None:
    result = _audit("--since", "2026-13-01")

    assert result.exit_code != 0
    assert "Invalid date" in result.output


def test_audit_by_file_lists_its_events_oldest_first(three_days: StateStore) -> None:
    result = _audit("--file", SHA_A)

    assert result.exit_code == 0, result.output
    assert _ops(result) == ["ENCRYPT", "ACCESS", "DECRYPT"]
    assert "db.env" in result.output
    assert "user/alice" in result.output  # principal, trimmed to its identity part
    assert "corr-202" in result.output  # correlation id, first 8 characters


def test_audit_by_file_honours_the_date_range(three_days: StateStore) -> None:
    """--file with --since/--until shows that file's events in the range only."""
    result = _audit("--file", SHA_A, "--since", "2026-11-02", "--until", "2026-11-06")

    assert result.exit_code == 0, result.output
    assert _ops(result) == ["ACCESS"]


def test_audit_requires_file_or_since(three_days: StateStore) -> None:
    result = _audit()

    assert result.exit_code == 1
    assert "Provide --file or --since" in result.output


def test_audit_reports_no_events(three_days: StateStore) -> None:
    result = _audit("--since", "2026-11-10", "--until", "2026-11-12")

    assert result.exit_code == 0, result.output
    assert "No events found" in result.output


def test_audit_aws_error_is_friendly(three_days: StateStore) -> None:
    denied = ClientError({"Error": {"Code": "AccessDeniedException", "Message": "nope"}}, "Query")
    with patch.object(StateStore, "list_events_by_date", side_effect=denied):
        result = _audit("--since", "2026-11-01", "--until", "2026-11-02")

    assert result.exit_code == 1
    assert "AWS error" in result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------


@mock_aws
def test_dashboard_counts_files_by_state_and_shows_last_activity() -> None:
    _create_table()
    store = StateStore(table_name=TABLE, region=REGION)
    for sha, name, current in ((SHA_A, "a.env", ENCRYPTED), ("c" * 64, "c.env", ENCRYPTED)):
        store.put_current_state(_record(sha, name, current))
    legacy = _record(SHA_B, "b.env", DECRYPTED)
    store.put_current_state(legacy)  # written last: the most recent activity
    _event_on(store, legacy, "2026-11-05", "ACCESS")  # events are not tracked files

    result = CliRunner().invoke(main, ["dashboard"], env=ENV)

    assert result.exit_code == 0, result.output
    lines = {line.split(":", 1)[0].strip(): line for line in result.output.splitlines()}
    assert lines["Total tracked files"].split()[-1] == "3"
    assert lines["Currently encrypted"].split()[-1] == "2"
    assert lines["Currently decrypted"].split()[-1] == "1"
    assert legacy.last_updated in result.output


@mock_aws
def test_dashboard_on_an_empty_table() -> None:
    _create_table()

    result = CliRunner().invoke(main, ["dashboard"], env=ENV)

    assert result.exit_code == 0, result.output
    assert "Total tracked files:" in result.output
    lines = {line.split(":", 1)[0].strip(): line for line in result.output.splitlines()}
    assert lines["Total tracked files"].split()[-1] == "0"
    assert lines["Last activity"].split()[-1] == "—"
