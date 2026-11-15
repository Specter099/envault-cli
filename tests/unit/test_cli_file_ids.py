"""File identifiers through the CLI (M6), with real crypto against moto.

The SHA-256 of a file's plaintext was its public identifier: the DynamoDB key,
part of the S3 key, a value in the KMS encryption context (which CloudTrail
logs), and in console and log output. For a short or guessable file that hash
is the content (r20 recovered a 6-digit PIN from an S3 key in 0.28 s). New
records are named by ``file_id = HMAC-SHA-256(ID key, SHA-256(plaintext))``
instead, computed by KMS GenerateMac, and nothing envault writes or prints for
them carries the raw hash.

Records written before (rows without ``id_scheme``, identified by the raw
SHA-256) must keep working. ``_legacy_record`` stores one exactly as envault
did then, attribute for attribute, without going through today's code.
"""

from __future__ import annotations

import base64
import hashlib
import io
import logging
import pathlib
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any
from unittest.mock import patch

import boto3
import botocore.client
import pytest
from botocore.exceptions import ClientError
from click.testing import CliRunner, Result
from moto import mock_aws

from envault import cli as cli_mod
from envault import identity
from envault.cli import main
from envault.crypto import decrypt_to_stream, encrypt_file
from envault.state import ENCRYPTED, StateStore

from ._id_key import ID_KEY_ALIAS, create_id_key, file_id_of

TABLE = "envault-test-state"
BUCKET = "envault-test-bucket"
ALIAS = "alias/envault-test"
NEW_ALIAS = "alias/new-key"
REGION = "us-east-1"

#: A low-entropy secret: its SHA-256 can be inverted by trying a million PINs.
PIN = b"493017\n"
OTHER = b"DATABASE_URL=postgres://app@db.internal/app\n"
ACCOUNT = "123456789012"  # moto's account
FOREIGN_KEY_ARN = "arn:aws:kms:us-east-1:444455556666:key/1234abcd-12ab-34cd-56ef-1234567890ab"


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


@pytest.fixture(autouse=True)
def _clear_identity_cache() -> Iterator[None]:
    identity.reset_cache()
    yield
    identity.reset_cache()


@pytest.fixture
def env() -> Iterator[dict[str, str]]:
    with mock_aws():
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
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket=BUCKET)
        s3.put_bucket_versioning(Bucket=BUCKET, VersioningConfiguration={"Status": "Enabled"})
        kms = boto3.client("kms", region_name=REGION)
        for alias in (ALIAS, NEW_ALIAS):
            kms.create_alias(AliasName=alias, TargetKeyId=kms.create_key()["KeyMetadata"]["KeyId"])
        create_id_key()
        account = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
        yield {
            "AWS_ACCESS_KEY_ID": "testing",
            "AWS_SECRET_ACCESS_KEY": "testing",  # noqa: S105
            "AWS_DEFAULT_REGION": REGION,
            "ENVAULT_KEY_ID": ALIAS,
            "ENVAULT_BUCKET": BUCKET,
            "ENVAULT_TABLE": TABLE,
            "ENVAULT_REGION": REGION,
            "ENVAULT_ALLOWED_ACCOUNT_IDS": str(account),
            "ENVAULT_ID_KEY_ID": ID_KEY_ALIAS,
            "COLUMNS": "250",
        }


def _run(env: dict[str, str], *args: str) -> Result:
    return CliRunner().invoke(main, list(args), env=env)


class _Exec:
    """Stands in for os.execvpe and records the environment the child would get."""

    def __init__(self) -> None:
        self.env: dict[str, str] | None = None

    def __call__(self, file: str, argv: list[str], env: dict[str, str]) -> None:
        self.env = dict(env)


def _exec(env: dict[str, str], identifier: str) -> tuple[Result, _Exec]:
    rec = _Exec()
    with patch("os.execvpe", rec):
        result = _run(env, "exec", "-s", f"{identifier}=SECRET", "--", "/bin/true")
    return result, rec


def _table() -> Any:
    return boto3.resource("dynamodb", region_name=REGION).Table(TABLE)


def _current(pk_id: str) -> dict[str, Any]:
    return dict(_table().get_item(Key={"PK": f"FILE#{pk_id}", "SK": "CURRENT"})["Item"])


# ---------------------------------------------------------------------------
# Records as envault wrote them before keyed identifiers
# ---------------------------------------------------------------------------


def _legacy_record(
    content: bytes, name: str, tmp_path: pathlib.Path, *, per_upload_key: bool = True
) -> dict[str, Any]:
    """Store ``content`` exactly as envault did before keyed identifiers; return the row.

    Ciphertext under the legacy encryption context (which names the raw
    SHA-256), at a key embedding that SHA-256, and a CURRENT row plus an
    ENCRYPT event in the attribute layout ``FileRecord.to_dynamo_item`` wrote
    then: ``sha256_hash``, no ``id_scheme``. ``per_upload_key=False`` gives the
    key format used before per-upload keys (M7).
    """
    sha = _sha256(content)
    work = tmp_path / f"legacy-{sha[:12]}"
    work.mkdir()
    (work / "plain").write_bytes(content)
    context = {
        "purpose": "envault-backup",
        "sha256": sha,
        "file_name": name,
        "kms_key_alias": ALIAS,
    }
    result = encrypt_file(work / "plain", ALIAS, context, work / "cipher", REGION)
    base = pathlib.PurePosixPath(name).name
    s3_key = (
        f"encrypted/{sha[:2]}/{sha}/{result.message_id}/{base}.encrypted"
        if per_upload_key
        else f"encrypted/{sha[:2]}/{sha}/{base}.encrypted"
    )
    put = boto3.client("s3", region_name=REGION).put_object(
        Bucket=BUCKET, Key=s3_key, Body=(work / "cipher").read_bytes()
    )
    for path in work.iterdir():
        path.unlink()
    work.rmdir()

    now = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    row = {
        "PK": f"FILE#{sha}",
        "SK": "CURRENT",
        "sha256_hash": sha,
        "file_name": name,
        "current_state": "ENCRYPTED",
        "s3_key": s3_key,
        "kms_key_id": ALIAS,
        "encryption_context": context,
        "algorithm": result.algorithm,
        "message_id": result.message_id,
        "file_size_bytes": len(content),
        "tags": {},
        "s3_version_id": put["VersionId"],
        "encrypted_at": now,
        "last_updated": now,
        "s3_key_scheme": "content-addressed",
    }
    _table().put_item(Item=row)
    event = {k: v for k, v in row.items() if k != "current_state"}
    event.update(
        SK=f"EVENT#{now}#ENCRYPT#0000beef",
        record_state="ENCRYPTED",
        operation="ENCRYPT",
        correlation_id="legacy-run",
        principal_arn="arn:aws:iam::123456789012:user/legacy",
        date=now[:10],
        ttl=int(time.time()) + 86400,
    )
    _table().put_item(Item=event)
    return row


def _substitute_ciphertext(row: dict[str, Any], donor: dict[str, Any]) -> None:
    """Point ``row`` (keeping its own identifier) at ``donor``'s ciphertext and context.

    The donor's object is copied to a key shaped for ``row``'s identifier, so
    every attribute check passes: only the content check can catch it.
    """
    pk_id = str(row["PK"]).removeprefix("FILE#")
    s3 = boto3.client("s3", region_name=REGION)
    body = s3.get_object(Bucket=BUCKET, Key=donor["s3_key"], VersionId=donor["s3_version_id"])
    forged_key = f"encrypted/{pk_id[:2]}/{pk_id}/{donor['message_id']}/forged.encrypted"
    put = s3.put_object(Bucket=BUCKET, Key=forged_key, Body=body["Body"].read())
    _table().put_item(
        Item={
            **row,
            "s3_key": forged_key,
            "s3_version_id": put["VersionId"],
            "message_id": donor["message_id"],
            "encryption_context": donor["encryption_context"],
        }
    )


# ---------------------------------------------------------------------------
# The plaintext's own hash never reaches a message (either scheme)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", ["decrypt", "exec"])
def test_checksum_mismatch_output_names_no_plaintext_hash(
    env: dict[str, str], tmp_path: pathlib.Path, command: str
) -> None:
    """A legacy record pointed at the PIN's ciphertext: refused, and the PIN's hash unsaid."""
    victim = _legacy_record(OTHER, "db.env", tmp_path)
    donor = _legacy_record(PIN, "pin.txt", tmp_path)
    _substitute_ciphertext(victim, donor)
    out = tmp_path / "out.txt"

    if command == "decrypt":
        result = _run(env, "decrypt", _sha256(OTHER), "-o", str(out))
        assert not out.exists()
    else:
        result, rec = _exec(env, _sha256(OTHER))
        assert rec.env is None, "the command must not run"

    assert result.exit_code == 1, result.output
    assert "checksum mismatch" in result.output.lower()
    assert _sha256(PIN)[:16] not in result.output


def test_encrypt_of_a_file_modified_while_encrypting_names_no_hash(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    (tmp_path / "pin.txt").write_bytes(PIN)
    real = cli_mod.encrypt_fd
    changed = b"493018\n"

    def encrypt_changed_file(fd: int, **kwargs: Any) -> Any:
        result = real(fd, **kwargs)
        result.sha256_hash = _sha256(changed)
        return result

    with patch.object(cli_mod, "encrypt_fd", encrypt_changed_file):
        result = _run(env, "encrypt", str(tmp_path / "pin.txt"))

    assert result.exit_code == 1, result.output
    assert "modified during encryption" in result.output
    for content in (PIN, changed):
        assert _sha256(content)[:16] not in result.output


# ---------------------------------------------------------------------------
# Helpers for the keyed scheme
# ---------------------------------------------------------------------------


def _spellings(content: bytes) -> list[str]:
    """How the plaintext's SHA-256 could show: full hex, the 16-character prefix, base64."""
    digest = hashlib.sha256(content)
    hexdigest = digest.hexdigest()
    return [hexdigest, hexdigest[:16], base64.b64encode(digest.digest()).decode()]


def _assert_not_exposed(content: bytes, where: str, *texts: object) -> None:
    for text in texts:
        for spelling in _spellings(content):
            assert spelling not in str(text), f"{where} carries the plaintext's SHA-256"


def _strings(value: Any) -> Iterator[str]:
    """Every key and value inside an item, a context or a tag set."""
    if isinstance(value, dict):
        for key, inner in value.items():
            yield str(key)
            yield from _strings(inner)
    elif isinstance(value, list | tuple | set):
        for inner in value:
            yield from _strings(inner)
    else:
        yield str(value)


@contextmanager
def _fresh_process_logging() -> Iterator[None]:
    """Let main() set logging up as in a new process (basicConfig needs a bare root)."""
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    saved_levels = {n: logging.getLogger(n).level for n in ("envault", "botocore")}
    for handler in saved_handlers:
        root.removeHandler(handler)
    try:
        yield
    finally:
        for handler in root.handlers[:]:
            root.removeHandler(handler)
        for handler in saved_handlers:
            root.addHandler(handler)
        root.setLevel(saved_level)
        for name, level in saved_levels.items():
            logging.getLogger(name).setLevel(level)


class _Records(logging.Handler):
    """Every record envault's own loggers emit, with all its attributes."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@contextmanager
def _aws_calls() -> Iterator[list[tuple[str, str, dict[str, Any]]]]:
    """Record every AWS API call: (service, operation, parameters)."""
    calls: list[tuple[str, str, dict[str, Any]]] = []
    real = botocore.client.BaseClient._make_api_call

    def call(self: Any, operation: str, params: dict[str, Any]) -> Any:
        calls.append((self.meta.service_model.service_name, operation, dict(params)))
        return real(self, operation, params)

    with patch.object(botocore.client.BaseClient, "_make_api_call", call):
        yield calls


def _failing(operation: str, error: Exception, times: int = 1_000_000) -> Any:
    """Make the next ``times`` calls of ``operation`` raise ``error``."""
    real = botocore.client.BaseClient._make_api_call
    left = [times]

    def call(self: Any, op: str, params: dict[str, Any]) -> Any:
        if op == operation and left[0] > 0:
            left[0] -= 1
            raise error
        return real(self, op, params)

    return patch.object(botocore.client.BaseClient, "_make_api_call", call)


def _client_error(code: str, operation: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": f"simulated {code}"}}, operation)


def _encrypt(env: dict[str, str], tmp_path: pathlib.Path, name: str, content: bytes) -> str:
    """Encrypt ``content`` as ``name`` through the CLI; return its keyed identifier."""
    source = tmp_path / "src" / name
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(content)
    result = _run(env, "encrypt", str(source))
    assert result.exit_code == 0, result.output
    source.unlink()
    return file_id_of(content)


def _without_id_key(env: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in env.items() if k != "ENVAULT_ID_KEY_ID"}


# ---------------------------------------------------------------------------
# M6 acceptance: a new record never exposes sha256(plaintext)
# ---------------------------------------------------------------------------


def test_a_new_record_never_exposes_the_plaintexts_sha256(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    """S3 keys, object metadata and tags, the encryption context, every attribute of the
    CURRENT and EVENT rows, console output, -v logs and every DynamoDB/S3 request."""
    (tmp_path / "pin.txt").write_bytes(PIN)
    file_id = file_id_of(PIN)
    outputs: list[str] = []
    collected = _Records()
    envault_logger = logging.getLogger("envault")
    envault_logger.addHandler(collected)
    try:
        with _aws_calls() as calls:
            for args in (
                ("-v", "encrypt", str(tmp_path / "pin.txt")),
                ("-v", "encrypt", str(tmp_path / "pin.txt")),  # already ENCRYPTED
                ("-v", "decrypt", "pin.txt", "-o", str(tmp_path / "out.txt")),
                ("-v", "status"),
                ("-v", "status", "--file", file_id),
                ("-v", "audit", "--file", file_id),
                ("-v", "dashboard"),
                ("-v", "rotate-key", "--new-key-id", NEW_ALIAS, "--dry-run"),
                ("-v", "rotate-key", "--new-key-id", NEW_ALIAS),
                ("-v", "decrypt", file_id, "-o", str(tmp_path / "again.txt")),
            ):
                with _fresh_process_logging():
                    result = CliRunner().invoke(main, list(args), env=env)
                assert result.exit_code == 0, (args, result.output)
                outputs += [result.stdout, result.stderr]
            rec = _Exec()
            with _fresh_process_logging(), patch("os.execvpe", rec):
                ran = CliRunner().invoke(
                    main, ["-v", "exec", "-s", "pin.txt=PIN", "--", "/bin/true"], env=env
                )
            assert ran.exit_code == 0, ran.output
            outputs += [ran.stdout, ran.stderr]
    finally:
        envault_logger.removeHandler(collected)

    assert (tmp_path / "out.txt").read_bytes() == PIN
    assert rec.env is not None and rec.env["PIN"] == PIN.decode().rstrip("\n")
    assert "already ENCRYPTED" in "".join(outputs)
    assert '"name": "envault.' in "".join(outputs), "-v must still log"

    # The record is keyed, and is the only one.
    rows = _table().scan()["Items"]
    current = [r for r in rows if r["SK"] == "CURRENT"]
    assert [r["PK"] for r in current] == [f"FILE#{file_id}"]
    assert current[0]["id_scheme"] == "hmac-sha256-v1"
    assert current[0]["id_key_arn"].startswith(f"arn:aws:kms:{REGION}:{ACCOUNT}:key/")
    assert {r["operation"] for r in rows if r["SK"] != "CURRENT"} >= {
        "ENCRYPT",
        "DECRYPT",
        "ACCESS",
        "ROTATE_KEY",
    }
    for row in rows:  # CURRENT and every EVENT, every attribute
        assert "sha256_hash" not in row
        _assert_not_exposed(PIN, f"DynamoDB row {row['SK']}", *_strings(row))

    s3 = boto3.client("s3", region_name=REGION)
    versions = s3.list_object_versions(Bucket=BUCKET)["Versions"]
    assert len(versions) == 2  # the first upload and the rotated one
    for version in versions:
        key, version_id = version["Key"], version["VersionId"]
        assert key.startswith(f"encrypted/{file_id[:2]}/{file_id}/")
        head = s3.head_object(Bucket=BUCKET, Key=key, VersionId=version_id)
        tags = s3.get_object_tagging(Bucket=BUCKET, Key=key, VersionId=version_id)["TagSet"]
        body = s3.get_object(Bucket=BUCKET, Key=key, VersionId=version_id)["Body"].read()
        # The context KMS saw (and CloudTrail records): what the ciphertext header binds.
        context = decrypt_to_stream(
            io.BytesIO(body), io.BytesIO(), region=REGION, allowed_account_ids=[ACCOUNT]
        ).encryption_context
        assert context["file_id"] == file_id
        assert "sha256" not in context
        _assert_not_exposed(
            PIN, "S3 object", key, *_strings(head.get("Metadata", {})), *_strings(tags)
        )
        _assert_not_exposed(PIN, "encryption context", *_strings(context))

    for text in outputs:
        _assert_not_exposed(PIN, "console or -v stderr", text)
    assert collected.records
    for record in collected.records:
        _assert_not_exposed(
            PIN, f"log record {record.name}", record.getMessage(), *vars(record).values()
        )
    # Not even a lookup: DynamoDB and S3 data events never see the hash.
    for service, operation, params in calls:
        if service in ("dynamodb", "s3"):
            _assert_not_exposed(PIN, f"{service} {operation} request", *_strings(params))


# ---------------------------------------------------------------------------
# Legacy records (identified by the raw SHA-256) keep working
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("per_upload_key", [True, False], ids=["per-upload-key", "pre-m7-key"])
def test_legacy_record_decrypts_by_name_and_by_its_sha256(
    env: dict[str, str], tmp_path: pathlib.Path, per_upload_key: bool
) -> None:
    _legacy_record(OTHER, "db.env", tmp_path, per_upload_key=per_upload_key)
    sha = _sha256(OTHER)

    by_name = _run(env, "decrypt", "db.env", "-o", str(tmp_path / "by-name"))
    by_sha = _run(env, "decrypt", sha, "-o", str(tmp_path / "by-sha"))
    without_id_key = _run(_without_id_key(env), "decrypt", sha, "-o", str(tmp_path / "plain"))

    for result, out in ((by_name, "by-name"), (by_sha, "by-sha"), (without_id_key, "plain")):
        assert result.exit_code == 0, result.output
        assert (tmp_path / out).read_bytes() == OTHER
    events = StateStore(TABLE, REGION).list_events_for_file(sha)
    decrypts = [e for e in events if e["operation"] == "DECRYPT"]
    assert len(decrypts) == 3
    for event in decrypts:  # a legacy record's events keep the legacy layout
        assert event["sha256_hash"] == sha
        assert "id_scheme" not in event


def test_legacy_record_through_exec(env: dict[str, str], tmp_path: pathlib.Path) -> None:
    _legacy_record(OTHER, "db.env", tmp_path)

    for identifier in ("db.env", _sha256(OTHER)):
        result, rec = _exec(env, identifier)
        assert result.exit_code == 0, result.output
        assert rec.env is not None
        assert rec.env["SECRET"] == OTHER.decode().rstrip("\n")


def test_legacy_record_in_status_audit_and_dashboard(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    _legacy_record(OTHER, "db.env", tmp_path)
    sha = _sha256(OTHER)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    listing = _run(env, "status")
    one = _run(env, "status", "--file", sha)
    by_file = _run(env, "audit", "--file", sha)
    by_day = _run(env, "audit", "--since", today)
    dashboard = _run(env, "dashboard")

    for result in (listing, one, by_file, by_day, dashboard):
        assert result.exit_code == 0, result.output
    for result in (listing, one):
        assert "db.env" in result.output
        assert sha[:16] in result.output  # a legacy identifier is the hash: shown as before
    for result in (by_file, by_day):
        assert "ENCRYPT" in result.output
        assert sha[:16] in result.output
    assert "Total tracked files:" in dashboard.output
    assert "1" in dashboard.output


def test_rotate_key_keeps_a_legacy_record_legacy(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    """No automatic upgrade: same identifier, same layout, legacy context."""
    _legacy_record(OTHER, "db.env", tmp_path)
    sha = _sha256(OTHER)

    result = _run(env, "rotate-key", "--new-key-id", NEW_ALIAS)

    assert result.exit_code == 0, result.output
    row = _current(sha)
    assert row["sha256_hash"] == sha
    assert not {"id_scheme", "file_id", "id_key_arn"} & set(row)
    assert row["kms_key_id"] == NEW_ALIAS
    assert row["encryption_context"]["sha256"] == sha
    assert "file_id" not in row["encryption_context"]
    assert row["s3_key"].startswith(f"encrypted/{sha[:2]}/{sha}/{row['message_id']}/")
    [rotation] = [
        e
        for e in StateStore(TABLE, REGION).list_events_for_file(sha)
        if e["operation"] == "ROTATE_KEY"
    ]
    assert rotation["sha256_hash"] == sha
    decrypted = _run(env, "decrypt", sha, "-o", str(tmp_path / "out"))
    assert decrypted.exit_code == 0, decrypted.output
    assert (tmp_path / "out").read_bytes() == OTHER


def test_rotate_key_keeps_a_keyed_record_keyed(env: dict[str, str], tmp_path: pathlib.Path) -> None:
    file_id = _encrypt(env, tmp_path, "pin.txt", PIN)
    before = _current(file_id)

    result = _run(env, "rotate-key", "--new-key-id", NEW_ALIAS)

    assert result.exit_code == 0, result.output
    after = _current(file_id)
    assert after["file_id"] == before["file_id"] == file_id
    assert after["id_scheme"] == before["id_scheme"] == "hmac-sha256-v1"
    assert after["id_key_arn"] == before["id_key_arn"]
    assert "sha256_hash" not in after
    assert after["kms_key_id"] == NEW_ALIAS
    assert after["encryption_context"]["file_id"] == file_id
    assert "sha256" not in after["encryption_context"]
    assert after["s3_key"].startswith(f"encrypted/{file_id[:2]}/{file_id}/{after['message_id']}/")
    decrypted = _run(env, "decrypt", "pin.txt", "-o", str(tmp_path / "out"))
    assert decrypted.exit_code == 0, decrypted.output
    assert (tmp_path / "out").read_bytes() == PIN


def test_a_legacy_row_still_gets_the_row_check(env: dict[str, str], tmp_path: pathlib.Path) -> None:
    """M5 for legacy rows: another row's attributes under this hash are refused."""
    victim = _legacy_record(OTHER, "a.env", tmp_path)
    donor = _legacy_record(PIN, "b.env", tmp_path)
    _table().put_item(Item={**donor, "PK": victim["PK"]})
    out = tmp_path / "out"

    result = _run(env, "decrypt", _sha256(OTHER), "-o", str(out))

    assert result.exit_code == 1, result.output
    assert "different file" in result.output
    assert not out.exists()


def test_reencrypting_a_file_with_only_a_legacy_record_creates_a_keyed_one(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    """encrypt deduplicates on the keyed identifier only: it never asks about FILE#<sha256>."""
    _legacy_record(PIN, "pin.txt", tmp_path)
    (tmp_path / "pin.txt").write_bytes(PIN)

    with _aws_calls() as calls:
        result = _run(env, "encrypt", str(tmp_path / "pin.txt"))

    assert result.exit_code == 0, result.output
    records = {r.file_id: r for r in StateStore(TABLE, REGION).list_by_state(ENCRYPTED)}
    assert set(records) == {_sha256(PIN), file_id_of(PIN)}
    assert records[file_id_of(PIN)].id_scheme == "hmac-sha256-v1"
    assert records[_sha256(PIN)].id_scheme == "sha256"
    for service, operation, params in calls:
        if service in ("dynamodb", "s3"):
            _assert_not_exposed(PIN, f"{service} {operation} request", *_strings(params))


# ---------------------------------------------------------------------------
# Looking a file up by the SHA-256 of its content
# ---------------------------------------------------------------------------


def _lookup(env: dict[str, str], tmp_path: pathlib.Path, command: str, value: str) -> Result:
    if command == "decrypt":
        return _run(env, "decrypt", value, "-o", str(tmp_path / "out.txt"))
    if command == "exec":
        result, _ = _exec(env, value)
        return result
    if command == "status":
        return _run(env, "status", "--file", value)
    return _run(env, "audit", "--file", value)


@pytest.mark.parametrize("command", ["decrypt", "exec", "status", "audit"])
def test_lookup_by_the_sha256_of_the_content(
    env: dict[str, str], tmp_path: pathlib.Path, command: str
) -> None:
    file_id = _encrypt(env, tmp_path, "pin.txt", PIN)

    if command == "exec":
        result, rec = _exec(env, _sha256(PIN))
        assert rec.env is not None and rec.env["SECRET"] == PIN.decode().rstrip("\n")
    else:
        result = _lookup(env, tmp_path, command, _sha256(PIN))

    assert result.exit_code == 0, result.output
    if command == "decrypt":
        assert (tmp_path / "out.txt").read_bytes() == PIN
    if command in ("status", "audit"):
        assert file_id[:16] in result.output
    if command == "audit":
        assert "ENCRYPT" in result.output
    _assert_not_exposed(PIN, f"{command} output", result.output)  # never echoed back


@pytest.mark.parametrize("command", ["decrypt", "exec", "status", "audit"])
def test_lookup_by_sha256_without_the_id_key_says_how(
    env: dict[str, str], tmp_path: pathlib.Path, command: str
) -> None:
    _encrypt(env, tmp_path, "pin.txt", PIN)

    result = _lookup(_without_id_key(env), tmp_path, command, _sha256(PIN))

    assert result.exit_code == (0 if command == "audit" else 1), result.output
    assert "ENVAULT_ID_KEY_ID" in result.output
    assert not (tmp_path / "out.txt").exists()


def test_lookup_by_sha256_also_checks_the_content_against_it(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    pin_id = _encrypt(env, tmp_path, "pin.txt", PIN)
    other_id = _encrypt(env, tmp_path, "db.env", OTHER)
    _substitute_ciphertext(_current(pin_id), _current(other_id))
    out = tmp_path / "out.txt"

    result = _run(env, "decrypt", _sha256(PIN), "-o", str(out))

    assert result.exit_code == 1, result.output
    assert "checksum mismatch" in result.output.lower()
    assert not out.exists()
    _assert_not_exposed(PIN, "decrypt output", result.output)
    _assert_not_exposed(OTHER, "decrypt output", result.output)


# ---------------------------------------------------------------------------
# Keyed records are verified before anything is delivered
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("how", ["decrypt", "exec-secret", "exec-file", "rotate-key"])
def test_a_keyed_record_pointed_at_other_content_is_refused(
    env: dict[str, str], tmp_path: pathlib.Path, how: str
) -> None:
    """Row and S3 key say pin.txt, the ciphertext is db.env's: VerifyMac catches it."""
    pin_id = _encrypt(env, tmp_path, "pin.txt", PIN)
    other_id = _encrypt(env, tmp_path, "db.env", OTHER)
    _substitute_ciphertext(_current(pin_id), _current(other_id))
    substituted = _current(pin_id)
    out = tmp_path / "out.txt"
    rec = _Exec()

    if how == "decrypt":
        result = _run(env, "decrypt", "pin.txt", "-o", str(out))
    elif how.startswith("exec"):
        flag = "-s" if how == "exec-secret" else "-f"
        with patch("os.execvpe", rec):
            result = _run(env, "exec", flag, "pin.txt=SECRET", "--", "/bin/true")
    else:
        result = _run(env, "rotate-key", "--new-key-id", NEW_ALIAS)

    assert result.exit_code == 1, result.output
    assert "checksum mismatch" in result.output.lower()
    assert not out.exists()
    assert rec.env is None, "the command must not run"
    if how == "rotate-key":
        assert "Rotation incomplete" in result.output
        assert _current(pin_id) == substituted  # not re-encrypted, not repointed
        assert _current(other_id)["kms_key_id"] == NEW_ALIAS  # the honest record rotated
    for content in (PIN, OTHER):
        _assert_not_exposed(content, f"{how} output", result.output)
    accesses = StateStore(TABLE, REGION).list_events_for_file(pin_id)
    assert not [e for e in accesses if e["operation"] in ("DECRYPT", "ACCESS")]


def test_a_keyed_row_describing_another_file_is_refused(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    """M5 for keyed rows: row db.env's attributes copied under pin.txt's identifier."""
    pin_id = _encrypt(env, tmp_path, "pin.txt", PIN)
    other_id = _encrypt(env, tmp_path, "db.env", OTHER)
    _table().put_item(Item={**_current(other_id), "PK": f"FILE#{pin_id}"})
    out = tmp_path / "out.txt"

    by_id = _run(env, "decrypt", pin_id, "-o", str(out))
    by_sha = _run(env, "decrypt", _sha256(PIN), "-o", str(out))

    for result in (by_id, by_sha):
        assert result.exit_code == 1, result.output
        assert "different file" in result.output
        _assert_not_exposed(PIN, "decrypt output", result.output)
    assert not out.exists()


@pytest.mark.parametrize("key_arn", [FOREIGN_KEY_ARN, "alias/envault-id", ""])
@pytest.mark.parametrize("command", ["decrypt", "exec", "rotate-key"])
def test_a_record_naming_an_untrusted_identifier_key_is_refused_before_any_kms_call(
    env: dict[str, str], tmp_path: pathlib.Path, key_arn: str, command: str
) -> None:
    file_id = _encrypt(env, tmp_path, "pin.txt", PIN)
    _table().update_item(
        Key={"PK": f"FILE#{file_id}", "SK": "CURRENT"},
        UpdateExpression="SET id_key_arn = :a",
        ExpressionAttributeValues={":a": key_arn},
    )
    rec = _Exec()

    with _aws_calls() as calls, patch("os.execvpe", rec):
        if command == "decrypt":
            result = _run(env, "decrypt", "pin.txt", "-o", str(tmp_path / "out.txt"))
        elif command == "exec":
            result = _run(env, "exec", "-s", "pin.txt=SECRET", "--", "/bin/true")
        else:
            result = _run(env, "rotate-key", "--new-key-id", NEW_ALIAS)

    assert result.exit_code == 1, result.output
    assert "identifier key" in result.output
    assert rec.env is None
    assert not (tmp_path / "out.txt").exists()
    kms_calls = {op for service, op, _ in calls if service == "kms"}
    assert not kms_calls & {"Decrypt", "VerifyMac", "GenerateMac"}, kms_calls
    assert "GetObject" not in {op for service, op, _ in calls if service == "s3"}


# ---------------------------------------------------------------------------
# KMS failures on MAC calls: availability or permission, never integrity
# ---------------------------------------------------------------------------


def test_verify_mac_access_denied_is_a_kms_error_and_nothing_is_delivered(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    file_id = _encrypt(env, tmp_path, "pin.txt", PIN)
    out = tmp_path / "out.txt"

    with _failing("VerifyMac", _client_error("AccessDeniedException", "VerifyMac")):
        result = _run(env, "decrypt", "pin.txt", "-o", str(out))

    assert result.exit_code == 1, result.output
    assert "KMS error" in result.output
    assert "kms:VerifyMac" in result.output
    assert "tamper" not in result.output.lower()
    assert "checksum" not in result.output.lower()
    assert not out.exists()
    assert list(tmp_path.glob(".out.txt*")) == []
    events = StateStore(TABLE, REGION).list_events_for_file(file_id)
    assert not [e for e in events if e["operation"] == "DECRYPT"]


def test_verify_mac_throttling_is_retried(
    env: dict[str, str], tmp_path: pathlib.Path, no_retry_sleep: list[float]
) -> None:
    _encrypt(env, tmp_path, "pin.txt", PIN)

    with _failing("VerifyMac", _client_error("ThrottlingException", "VerifyMac"), times=1):
        result = _run(env, "decrypt", "pin.txt", "-o", str(tmp_path / "out.txt"))

    assert result.exit_code == 0, result.output
    assert (tmp_path / "out.txt").read_bytes() == PIN
    assert no_retry_sleep == [1]


def test_generate_mac_failure_is_a_per_file_kms_error_on_encrypt(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    batch = tmp_path / "batch"
    batch.mkdir()
    (batch / "a.txt").write_bytes(PIN)
    (batch / "b.txt").write_bytes(OTHER)

    with _failing("GenerateMac", _client_error("AccessDeniedException", "GenerateMac")):
        result = _run(env, "encrypt", str(batch))

    assert result.exit_code == 1, result.output
    assert result.output.count("✗") == 2
    assert "kms:GenerateMac" in result.output
    assert "2 file(s) failed to encrypt" in result.output
    assert _table().scan()["Items"] == []
    assert "Versions" not in boto3.client("s3", region_name=REGION).list_object_versions(
        Bucket=BUCKET
    )


# ---------------------------------------------------------------------------
# encrypt and migrate need the ID key: no fallback to raw-SHA-256 identifiers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [None, ""], ids=["unset", "empty"])
def test_encrypt_without_the_id_key_is_a_usage_error(
    env: dict[str, str], tmp_path: pathlib.Path, value: str | None
) -> None:
    (tmp_path / "pin.txt").write_bytes(PIN)
    environment = _without_id_key(env) if value is None else {**env, "ENVAULT_ID_KEY_ID": value}

    result = _run(environment, "encrypt", str(tmp_path / "pin.txt"))

    assert result.exit_code == 2, result.output
    assert "--id-key-id" in result.output
    assert "ENVAULT_ID_KEY_ID" in result.output
    assert _table().scan()["Items"] == []
    assert "Versions" not in boto3.client("s3", region_name=REGION).list_object_versions(
        Bucket=BUCKET
    )


def test_migrate_without_the_id_key_is_a_usage_error(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    (tmp_path / "code").mkdir()
    metadata = tmp_path / "code" / "output.json"
    metadata.write_text("{}\n")

    result = _run(_without_id_key(env), "migrate", str(metadata))

    assert result.exit_code == 2, result.output
    assert "--id-key-id" in result.output
    assert "ENVAULT_ID_KEY_ID" in result.output
    assert _table().scan()["Items"] == []


def test_the_id_key_option_names_the_key(env: dict[str, str], tmp_path: pathlib.Path) -> None:
    """--id-key-id works like the variable, and takes an ARN as well as an alias."""
    arn = boto3.client("kms", region_name=REGION).describe_key(KeyId=ID_KEY_ALIAS)["KeyMetadata"][
        "Arn"
    ]
    (tmp_path / "pin.txt").write_bytes(PIN)

    result = _run(_without_id_key(env), "encrypt", "--id-key-id", arn, str(tmp_path / "pin.txt"))

    assert result.exit_code == 0, result.output
    row = _current(file_id_of(PIN))
    assert row["id_key_arn"] == arn


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------


def test_status_and_audit_label_the_identifier_column_id(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    file_id = _encrypt(env, tmp_path, "pin.txt", PIN)

    listing = _run(env, "status")
    events = _run(env, "audit", "--file", file_id)

    for result in (listing, events):
        assert result.exit_code == 0, result.output
        assert "ID (16)" in result.output
        assert "SHA256" not in result.output
        assert file_id[:16] in result.output
