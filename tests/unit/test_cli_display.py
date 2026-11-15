"""Untrusted strings never reach the terminal as control sequences (L5).

File names, tags, timestamps, principals and S3 keys come from DynamoDB (which
anyone with table write access can edit) or from the filesystem. Printed raw, an
ESC sequence in one of them can retitle the terminal, clear the screen or move
the cursor to forge output; bidi overrides and zero-width characters make one
name look like another. Every such value is shown with those characters as
visible escapes.

The console is a real Rich console forced into terminal mode, writing to a
buffer: that is what an operator's terminal receives.
"""

from __future__ import annotations

import io
import pathlib
import re
import sys
from collections.abc import Iterator
from datetime import datetime, timezone
from unittest.mock import patch

import boto3
import pytest
from click.testing import CliRunner
from moto import mock_aws
from rich.console import Console

from envault import cli as cli_mod
from envault import identity
from envault.cli import main
from envault.fileid import ID_SCHEME_SHA256
from envault.state import ENCRYPTED, FileRecord, StateStore

from ._id_key import ID_KEY_ALIAS, create_id_key

TABLE = "envault-test-state"
BUCKET = "envault-test-bucket"
ALIAS = "alias/envault-test"
REGION = "us-east-1"

# OSC 0 (set window title), BEL, CSI 2J (clear screen), CSI H (cursor home),
# U+202E RIGHT-TO-LEFT OVERRIDE, U+200B ZERO WIDTH SPACE.
EVIL = "report\x1b]0;PWNED-TITLE\x07\x1b[2J\x1b[1;1H‮​.txt"
RAW_SEQUENCES = ("\x1b]0;", "\x1b[2J", "\x1b[1;1H", "\x07", "‮", "​")
VISIBLE = "report\\x1b]0;PWNED-TITLE\\x07\\x1b[2J\\x1b[1;1H\\u202e\\u200b.txt"


@pytest.fixture(autouse=True)
def _clear_identity_cache() -> Iterator[None]:
    identity.reset_cache()
    yield
    identity.reset_cache()


@pytest.fixture
def terminal() -> Iterator[io.StringIO]:
    """Swap the CLI's console for a forced-terminal one writing to a buffer."""
    buf = io.StringIO()
    with patch.object(cli_mod, "console", Console(file=buf, force_terminal=True, width=400)):
        yield buf


def _assert_neutralised(output: str) -> str:
    """Check the raw output, then return it without Rich's own SGR styling.

    Rich's highlighter wraps brackets and digits of the visible escapes in its
    colour codes, so content checks run on the text with those removed. The
    injected sequences are checked first, on the raw output.
    """
    for seq in RAW_SEQUENCES:
        assert seq not in output, f"raw {seq!r} reached the terminal"
    return re.sub(r"\x1b\[[0-9;]*m", "", output)


# ---------------------------------------------------------------------------
# _display itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "shown"),
    [
        ("\x1b[2J", "\\x1b[2J"),  # C0 ESC (the "[" is also markup-escaped below)
        ("a\x07b", "a\\x07b"),  # BEL
        ("a\x9bb", "a\\x9bb"),  # C1 CSI
        ("a\x7fb", "a\\x7fb"),  # DEL
        ("a\nb\tc\rd", "a\\nb\\tc\\rd"),
        ("a‮b", "a\\u202eb"),  # bidi override (Cf)
        ("a​b", "a\\u200bb"),  # zero-width space (Cf)
        ("a﻿b", "a\\ufeffb"),  # BOM / zero-width no-break space (Cf)
        ("a b", "a\\u2028b"),  # line separator (Zl)
        ("a\udcffb", "a\\udcffb"),  # lone surrogate from an undecodable file name
        ("a\U000e0041b", "a\\U000e0041b"),  # tag character (Cf, astral)
    ],
)
def test_display_makes_control_and_format_characters_visible(raw: str, shown: str) -> None:
    buf = io.StringIO()
    Console(file=buf, force_terminal=False, width=200).print(cli_mod._display(raw))
    assert buf.getvalue().rstrip("\n") == shown


def test_display_keeps_ordinary_text_and_escapes_markup() -> None:
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=200, emoji=False)
    console.print(cli_mod._display("résumé 日本 [bold]x[/bold] :skull: 50% C:\\temp"))
    assert buf.getvalue().rstrip("\n") == "résumé 日本 [bold]x[/bold] :skull: 50% C:\\temp"


def test_display_accepts_non_strings() -> None:
    assert cli_mod._display(42) == "42"
    assert cli_mod._display(None) == "None"


def test_cli_console_does_not_render_emoji_codes_from_names() -> None:
    """`:skull:` in a stored name must print as typed, not as an emoji."""
    assert cli_mod.console._emoji is False


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def _provision() -> str:
    ddb = boto3.client("dynamodb", region_name=REGION)
    ddb.create_table(
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
    key_id = kms.create_key(Description="envault-test")["KeyMetadata"]["KeyId"]
    kms.create_alias(AliasName=ALIAS, TargetKeyId=key_id)
    kms.create_alias(
        AliasName="alias/new-key", TargetKeyId=kms.create_key()["KeyMetadata"]["KeyId"]
    )
    create_id_key()
    return str(boto3.client("sts", region_name=REGION).get_caller_identity()["Account"])


def _env(account: str) -> dict[str, str]:
    return {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",  # noqa: S105
        "AWS_DEFAULT_REGION": REGION,
        "ENVAULT_KEY_ID": ALIAS,
        "ENVAULT_BUCKET": BUCKET,
        "ENVAULT_TABLE": TABLE,
        "ENVAULT_REGION": REGION,
        "ENVAULT_ALLOWED_ACCOUNT_IDS": account,
        "ENVAULT_ID_KEY_ID": ID_KEY_ALIAS,
    }


def _seed_row(file_name: str = EVIL) -> FileRecord:
    """A CURRENT row and one event, every free-text attribute carrying escapes."""
    sha = "c" * 64
    record = FileRecord(
        id_scheme=ID_SCHEME_SHA256,
        file_id=sha,
        file_name=file_name,
        current_state=ENCRYPTED,
        s3_key=f"encrypted/{sha[:2]}/{sha}/report.txt.encrypted",
        kms_key_id=ALIAS,
        encryption_context={},
        algorithm="AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384",
        message_id="m",
        file_size_bytes=1,
        tags={"team\x1b[2J": "ops\x1b]0;PWNED-TITLE\x07"},
        encrypted_at="2026-11-01T00:00:00+00:00\x1b[1;1H",
    )
    store = StateStore(table_name=TABLE, region=REGION)
    store.put_current_state(record)
    store.put_event(
        record,
        operation="ACCESS",
        correlation_id="corr\x1b]0;PWNED-TITLE\x07",
        principal_arn="arn:aws:iam::123456789012:user/\x1b[2Jmallory‮",
    )
    return record


@mock_aws
def test_status_strips_control_characters(terminal: io.StringIO) -> None:
    env = _env(_provision())
    _seed_row()

    result = CliRunner().invoke(main, ["status"], env=env)

    assert result.exit_code == 0, terminal.getvalue()
    out = _assert_neutralised(terminal.getvalue())
    assert "\\x1b]0;PWNED-TITLE" in out
    assert "team\\x1b[2J=ops\\x1b]0;PWNED-TITLE\\x07" in out


@mock_aws
def test_audit_strips_control_characters(terminal: io.StringIO) -> None:
    env = _env(_provision())
    record = _seed_row()

    by_file = CliRunner().invoke(main, ["audit", "--file", record.file_id], env=env)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")  # the event's date
    by_date = CliRunner().invoke(main, ["audit", "--since", today], env=env)

    assert by_file.exit_code == 0, terminal.getvalue()
    assert by_date.exit_code == 0, terminal.getvalue()
    out = _assert_neutralised(terminal.getvalue())
    assert out.count("\\x1b]0;PWNED-TITLE") >= 2  # the file name in both tables
    assert "\\x1b[2Jmallory\\u202e" in out  # the principal


@mock_aws
def test_decrypt_messages_strip_control_characters(
    terminal: io.StringIO, tmp_path: pathlib.Path
) -> None:
    """Success and failure messages of decrypt name the file without its escapes."""
    env = _env(_provision())
    src = tmp_path / "in"
    src.mkdir()
    (src / EVIL).write_bytes(b"payload\n")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    runner = CliRunner()
    assert runner.invoke(main, ["encrypt", str(src / EVIL)], env=env).exit_code == 0

    ok = runner.invoke(main, ["decrypt", EVIL, "-o", str(out_dir)], env=env)
    assert ok.exit_code == 0, terminal.getvalue()

    # Now make the record disagree with its ciphertext: the mismatch report names the file.
    store = StateStore(table_name=TABLE, region=REGION)
    record = store.list_by_state(ENCRYPTED)[0]
    table = boto3.resource("dynamodb", region_name=REGION).Table(TABLE)
    table.update_item(
        Key={"PK": f"FILE#{record.file_id}", "SK": "CURRENT"},
        UpdateExpression="SET encryption_context.purpose = :p",
        ExpressionAttributeValues={":p": "tampered"},
    )
    bad = runner.invoke(main, ["decrypt", EVIL, "-o", str(tmp_path / "again"), "--force"], env=env)
    missing = runner.invoke(main, ["decrypt", EVIL + "-missing"], env=env)

    assert bad.exit_code == 1
    assert missing.exit_code == 1
    out = _assert_neutralised(terminal.getvalue())
    assert out.count(VISIBLE) >= 2


@mock_aws
def test_decrypt_never_creates_an_output_file_named_with_control_characters(
    tmp_path: pathlib.Path,
) -> None:
    """The output name derives from a stored name: escapes must not reach the filesystem."""
    env = _env(_provision())
    src = tmp_path / "in"
    src.mkdir()
    (src / EVIL).write_bytes(b"payload\n")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    runner = CliRunner()
    assert runner.invoke(main, ["encrypt", str(src / EVIL)], env=env).exit_code == 0

    result = runner.invoke(main, ["decrypt", EVIL, "-o", str(out_dir)], env=env)

    assert result.exit_code == 0, result.output
    [written] = list(out_dir.iterdir())
    assert written.read_bytes() == b"payload\n"
    assert written.name.startswith("decrypted_")


@mock_aws
def test_encrypt_messages_strip_control_characters(
    terminal: io.StringIO, tmp_path: pathlib.Path
) -> None:
    env = _env(_provision())
    (tmp_path / EVIL).write_bytes(b"payload\n")
    runner = CliRunner()

    first = runner.invoke(main, ["encrypt", str(tmp_path / EVIL)], env=env)
    again = runner.invoke(main, ["encrypt", str(tmp_path / EVIL)], env=env)  # already ENCRYPTED

    assert first.exit_code == 0, terminal.getvalue()
    assert again.exit_code == 0, terminal.getvalue()
    out = _assert_neutralised(terminal.getvalue())
    assert out.count("\\x1b]0;PWNED-TITLE") >= 2


@mock_aws
def test_rotate_key_dry_run_strips_control_characters(terminal: io.StringIO) -> None:
    env = _env(_provision())
    _seed_row()

    result = CliRunner().invoke(
        main, ["rotate-key", "--new-key-id", "alias/new-key", "--dry-run"], env=env
    )

    assert result.exit_code == 0, terminal.getvalue()
    out = _assert_neutralised(terminal.getvalue())
    assert VISIBLE in out


@mock_aws
def test_exec_messages_strip_control_characters(terminal: io.StringIO) -> None:
    env = _env(_provision())

    with patch("os.execvpe") as execvpe:
        result = CliRunner().invoke(main, ["exec", "-s", f"{EVIL}=VAR", "--", "true"], env=env)

    assert result.exit_code == 1
    assert not execvpe.called
    _assert_neutralised(terminal.getvalue())


def test_usage_error_hint_keeps_its_line_break(terminal: io.StringIO) -> None:
    """Only the user-supplied parts of a usage error are escaped, not envault's layout."""
    hook = sys.unraisablehook
    try:
        with patch("sys.argv", ["envault", "decrypt"]), pytest.raises(SystemExit) as exc_info:
            cli_mod.cli()
    finally:
        sys.unraisablehook = hook
    assert exc_info.value.code == 2
    out = _assert_neutralised(terminal.getvalue())
    assert "\\n" not in out
    # Click derives the program name from how Python was started; check the layout.
    assert "\n  Run '" in out
    assert "envault decrypt --help' for usage info." in out
