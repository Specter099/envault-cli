"""envault CLI — Click-based command-line interface."""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click
from botocore.exceptions import BotoCoreError, ClientError
from rich.console import Console
from rich.markup import escape
from rich.progress import track
from rich.table import Table

from envault.config import Config
from envault.crypto import decrypt_file, decrypt_to_stream, encrypt_file
from envault.exceptions import (
    AlreadyEncryptedError,
    ChecksumMismatchError,
    ConfigurationError,
    EncryptionContextMismatchError,
    EnvaultError,
    MigrationError,
    StateConflictError,
)
from envault.fileutils import best_effort_delete as _best_effort_delete
from envault.identity import caller_arn
from envault.isolation import CredentialFd, harden_process, wipe
from envault.s3 import S3Store
from envault.state import DECRYPTED, ENCRYPTED, FileRecord, StateStore

console = Console()
logger = logging.getLogger(__name__)


def _setup_logging(verbose: bool) -> None:
    from pythonjsonlogger.json import JsonFormatter

    handler = logging.StreamHandler(sys.stderr)
    fmt = JsonFormatter("%(asctime)s %(name)s %(levelname)s %(message)s")  # type: ignore[no-untyped-call,unused-ignore]
    handler.setFormatter(fmt)
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, handlers=[handler])


@click.group(invoke_without_command=True)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose JSON logging to stderr.")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """envault — client-side envelope encryption with AWS KMS + DynamoDB state tracking."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    _setup_logging(verbose)
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# Descriptive hints for required positional arguments, keyed by argument name.
_ARG_HINTS: dict[str, str] = {
    "IDENTIFIER": "a SHA256 hash or filename",
    "INPUT_PATH": "a file or directory to encrypt",
    "FROM_PATH": "the path to output.json (NDJSON format)",
}


def _friendly_message(e: click.UsageError) -> str:
    """Rewrite Click's generic error into a descriptive, human-readable message."""
    msg = e.format_message()
    # "Missing argument 'IDENTIFIER'." → descriptive version
    m = re.match(r"Missing argument '(\w+)'\.", msg)
    if m:
        arg = m.group(1)
        desc = _ARG_HINTS.get(arg, arg)
        cmd = e.ctx.info_name if e.ctx else "command"
        return f"The {cmd} command requires {desc}."
    return msg


def cli() -> None:
    """Entrypoint that wraps Click with human-readable error formatting."""
    try:
        main(standalone_mode=False)
    except click.UsageError as e:
        hint = ""
        if e.ctx:
            hint = f"\n  Run '{e.ctx.command_path} --help' for usage info."
        console.print(f"{escape(_friendly_message(e))}{escape(hint)}")
        sys.exit(2)
    except click.Abort:
        console.print("[yellow]Aborted.[/yellow]")
        sys.exit(1)


# ---------------------------------------------------------------------------
# encrypt
# ---------------------------------------------------------------------------


@main.command()
@click.argument("input_path", type=click.Path(exists=True, path_type=Path))
@click.option("--key-id", envvar="ENVAULT_KEY_ID", required=True, help="KMS key alias.")
@click.option("--bucket", envvar="ENVAULT_BUCKET", required=True, help="S3 bucket name.")
@click.option("--table", envvar="ENVAULT_TABLE", required=True, help="DynamoDB table name.")
@click.option("--tag", "-t", multiple=True, metavar="KEY=VALUE", help="File tags (repeatable).")
@click.option("--force", is_flag=True, help="Re-encrypt even if already ENCRYPTED.")
@click.option("--region", envvar="ENVAULT_REGION", default="us-east-1", show_default=True)
@click.pass_context
def encrypt(
    ctx: click.Context,
    input_path: Path,
    key_id: str,
    bucket: str,
    table: str,
    tag: tuple[str, ...],
    force: bool,
    region: str,
) -> None:
    """Encrypt a file or directory and store state in DynamoDB.

    INPUT_PATH can be a single file or a directory (processed recursively).
    """
    config = Config(key_id=key_id, bucket=bucket, table_name=table, region=region)
    tags = _parse_tags(tag)
    store = StateStore(table_name=table, region=region)
    s3 = S3Store(bucket=bucket, region=region, kms_key_id=key_id)
    correlation_id = str(uuid.uuid4())

    files = _collect_files(input_path)
    if not files:
        console.print(f"[yellow]No files found in {escape(str(input_path))}[/yellow]")
        return

    errors = 0
    for file_path in track(files, description="Encrypting..."):
        try:
            file_correlation_id = f"{correlation_id}/{uuid.uuid4()}"
            _encrypt_one(file_path, config, tags, store, s3, file_correlation_id, force)
        except AlreadyEncryptedError:
            console.print(
                f"[yellow]⏭[/yellow] {escape(file_path.name)} already ENCRYPTED "
                "(use --force to re-encrypt)"
            )
        except (EnvaultError, ClientError, BotoCoreError) as exc:
            console.print(f"[red]✗[/red] {escape(file_path.name)}: {escape(str(exc))}")
            logger.exception("Failed to encrypt %s", file_path)
            errors += 1

    if errors:
        console.print(f"\n[red]{errors} file(s) failed to encrypt.[/red]")
        sys.exit(1)


def _encrypt_one(
    file_path: Path,
    config: Config,
    tags: dict[str, str],
    store: StateStore,
    s3: S3Store,
    correlation_id: str,
    force: bool,
) -> None:
    from envault.crypto import sha256_file

    sha256 = sha256_file(file_path)

    existing = store.get_current_state(sha256)
    if existing and existing.current_state == ENCRYPTED and not force:
        raise AlreadyEncryptedError(sha256_hash=sha256, file_name=file_path.name)

    _fd, _tmp = tempfile.mkstemp(suffix=".encrypted", prefix="envault_enc_")
    os.close(_fd)
    tmp_encrypted = Path(_tmp)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    # enc_context uses the pre-read hash; it will be validated against result.sha256_hash below
    enc_context = config.build_encryption_context(sha256, file_path.name)

    try:
        result = encrypt_file(
            input_path=file_path,
            key_id=config.key_id,
            encryption_context=enc_context,
            output_path=tmp_encrypted,
            region=config.region,
        )

        if sha256 != result.sha256_hash:
            raise EnvaultError(
                f"File {file_path.name!r} was modified during encryption "
                f"(pre-read hash {sha256[:16]}… != encrypted hash {result.sha256_hash[:16]}…). "
                "Aborting to avoid storing mismatched metadata."
            )

        s3_key = s3.s3_key_for_file(sha256_hash=result.sha256_hash, file_name=file_path.name)
        version_id = s3.upload_file(local_path=tmp_encrypted, s3_key=s3_key)
    finally:
        tmp_encrypted.unlink(missing_ok=True)

    record = FileRecord(
        sha256_hash=result.sha256_hash,
        file_name=file_path.name,
        current_state=ENCRYPTED,
        s3_key=s3_key,
        s3_version_id=version_id,
        kms_key_id=config.key_id,
        encryption_context=enc_context,
        algorithm=result.algorithm,
        message_id=result.message_id,
        file_size_bytes=result.file_size_bytes,
        tags=tags,
        encrypted_at=now,
        last_updated=now,
    )
    try:
        store.put_current_state(
            record,
            expected_last_updated=existing.last_updated if existing else None,
        )
        store.put_event(
            record,
            operation="ENCRYPT",
            correlation_id=correlation_id,
            audit_ttl_days=config.audit_ttl_days,
            principal_arn=caller_arn(config.region),
        )
    except Exception:
        logger.error(
            "State write failed after S3 upload. Manual recovery may be needed.",
            extra={
                "sha256": sha256,
                "s3_key": s3_key,
                "s3_version_id": version_id,
                "bucket": config.bucket,
                "file_name": file_path.name,
            },
        )
        raise
    console.print(
        f"[green]✓[/green] {escape(file_path.name)} → s3://{escape(config.bucket)}/{escape(s3_key)}"
    )


# ---------------------------------------------------------------------------
# decrypt
# ---------------------------------------------------------------------------


@main.command()
@click.argument("identifier")
@click.option(
    "--output", "-o", type=click.Path(path_type=Path), default=Path("."), show_default=True
)
@click.option("--table", envvar="ENVAULT_TABLE", required=True)
@click.option("--bucket", envvar="ENVAULT_BUCKET", required=True)
@click.option("--region", envvar="ENVAULT_REGION", default="us-east-1")
@click.option(
    "--version",
    "version",
    type=int,
    default=1,
    show_default=True,
    help="Which version to decrypt when multiple exist (1=most recent).",
)
@click.option(
    "--allowed-account-ids",
    envvar="ENVAULT_ALLOWED_ACCOUNT_IDS",
    default="",
    help="Comma-separated AWS account IDs to trust for decryption.",
)
@click.pass_context
def decrypt(
    ctx: click.Context,
    identifier: str,
    output: Path,
    table: str,
    bucket: str,
    region: str,
    version: int,
    allowed_account_ids: str,
) -> None:
    """Decrypt a file by SHA256 hash or filename.

    IDENTIFIER is a 64-char SHA256 hash or the original filename.
    When a filename matches multiple versions, use --version N to pick one.
    """
    store = StateStore(table_name=table, region=region)
    s3 = S3Store(bucket=bucket, region=region)
    correlation_id = str(uuid.uuid4())
    account_ids = _validate_account_ids(allowed_account_ids)

    record = _resolve_identifier(identifier, version, store)
    sha256_hash = record.sha256_hash

    _fd, _tmp = tempfile.mkstemp(suffix=".encrypted", prefix="envault_dl_")
    os.close(_fd)
    tmp_encrypted = Path(_tmp)
    safe_name = Path(record.file_name).name
    if not safe_name or safe_name.startswith("."):
        safe_name = f"decrypted_{sha256_hash[:16]}"
    output_path = (output if output.is_dir() else output.parent) / safe_name

    try:
        s3.download_file(
            s3_key=record.s3_key, local_path=tmp_encrypted, version_id=record.s3_version_id
        )

        decrypt_file(
            input_path=tmp_encrypted,
            output_path=output_path,
            expected_sha256=sha256_hash,
            region=region,
            allowed_account_ids=account_ids or None,
            expected_context=record.encryption_context,
        )
    except EncryptionContextMismatchError:
        console.print(
            "[bold red]Decryption failed:[/bold red] encryption context mismatch.\n"
            "The ciphertext metadata does not match the record in DynamoDB.\n"
            "This could mean the encrypted file in S3 was replaced or corrupted.\n"
            "No plaintext was written.\n"
            f"  File: {escape(record.file_name)}  SHA256: {sha256_hash[:16]}..."
        )
        sys.exit(1)
    except ChecksumMismatchError as exc:
        console.print(
            "[bold red]Decryption failed:[/bold red] checksum mismatch.\n"
            f"Expected SHA256 {exc.expected[:16]}... but got {exc.actual[:16]}...\n"
            "The decrypted content does not match the original file.\n"
            "The encrypted data in S3 may have been corrupted or tampered with."
        )
        sys.exit(1)
    except ConfigurationError as exc:
        console.print(f"[bold red]Configuration error:[/bold red] {escape(str(exc))}")
        sys.exit(1)
    except (ClientError, BotoCoreError) as exc:
        error_msg = str(exc)
        if isinstance(exc, ClientError):
            error_msg = exc.response.get("Error", {}).get("Message", str(exc))
        console.print(
            f"[bold red]AWS error during decryption:[/bold red] {escape(error_msg)}\n"
            f"  File: {escape(record.file_name)}  S3: {escape(record.s3_key)}"
        )
        sys.exit(1)
    except EnvaultError as exc:
        console.print(f"[bold red]Decryption error:[/bold red] {escape(str(exc))}")
        sys.exit(1)
    finally:
        tmp_encrypted.unlink(missing_ok=True)

    # Reading a file does not change what is stored in S3, so current_state is
    # left alone — the ciphertext is still there and still encrypted. The read is
    # recorded as an event instead. This is what makes a file decryptable more
    # than once, keeps it visible to rotate-key, and avoids two concurrent reads
    # colliding on the CURRENT record's optimistic lock.
    try:
        store.put_event(
            record,
            operation="DECRYPT",
            correlation_id=correlation_id,
            principal_arn=caller_arn(region),
        )
    except (ClientError, BotoCoreError, EnvaultError) as exc:
        logger.error(
            "Audit event write failed after successful decryption.",
            extra={
                "sha256": sha256_hash,
                "output_path": str(output_path),
                "s3_key": record.s3_key,
            },
        )
        console.print(
            f"[green]✓[/green] Decrypted → {escape(str(output_path))}\n"
            f"[bold yellow]Warning:[/bold yellow] the access could not be recorded in the "
            f"audit trail: {escape(str(exc))}\n"
            "The plaintext was written but this read is missing from the audit log."
        )
        sys.exit(1)

    console.print(f"[green]✓[/green] Decrypted → {escape(str(output_path))}")


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


@main.command()
@click.option("--state", type=click.Choice(["encrypted", "decrypted", "all"]), default="all")
@click.option("--file", "sha256_hash", default=None, help="Hash of a specific file.")
@click.option("--table", envvar="ENVAULT_TABLE", required=True)
@click.option("--region", envvar="ENVAULT_REGION", default="us-east-1")
def status(state: str, sha256_hash: str | None, table: str, region: str) -> None:
    """Show current encryption state of files."""
    try:
        store = StateStore(table_name=table, region=region)

        if sha256_hash:
            _validate_sha256(sha256_hash)
            record = store.get_current_state(sha256_hash)
            if not record:
                console.print(f"[red]No record found for {sha256_hash[:16]}...[/red]")
                sys.exit(1)
            _print_records([record])
            return

        records = []
        if state in ("encrypted", "all"):
            records.extend(store.list_by_state(ENCRYPTED))
        if state in ("decrypted", "all"):
            records.extend(store.list_by_state(DECRYPTED))

        if not records:
            console.print("[yellow]No records found.[/yellow]")
            return
        _print_records(records)
    except (ClientError, BotoCoreError) as exc:
        msg = exc.response["Error"]["Message"] if isinstance(exc, ClientError) else str(exc)
        console.print(f"[bold red]AWS error:[/bold red] {escape(str(msg))}")
        sys.exit(1)
    except EnvaultError as exc:
        console.print(f"[bold red]Error:[/bold red] {escape(str(exc))}")
        sys.exit(1)


def _print_records(records: list[FileRecord]) -> None:
    t = Table(show_header=True, header_style="bold cyan")
    t.add_column("File", style="white")
    t.add_column("State")
    t.add_column("SHA256 (16)")
    t.add_column("Encrypted At")
    t.add_column("Tags")
    for r in sorted(records, key=lambda x: x.encrypted_at, reverse=True):
        state_color = "green" if r.current_state == ENCRYPTED else "yellow"
        tags_str = ", ".join(f"{k}={v}" for k, v in r.tags.items())
        # Escape everything that came back from DynamoDB: a file name containing
        # square brackets would otherwise be interpreted as Rich markup, which
        # both misrepresents the name and can raise MarkupError mid-table.
        t.add_row(
            escape(r.file_name),
            f"[{state_color}]{escape(r.current_state)}[/{state_color}]",
            escape(r.sha256_hash[:16]),
            escape(r.encrypted_at),
            escape(tags_str),
        )
    console.print(t)


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


@main.command()
@click.option("--file", "sha256_hash", default=None, help="Hash of a specific file.")
@click.option("--since", default=None, help="Date filter YYYY-MM-DD (uses date-index GSI).")
@click.option("--table", envvar="ENVAULT_TABLE", required=True)
@click.option("--region", envvar="ENVAULT_REGION", default="us-east-1")
def audit(sha256_hash: str | None, since: str | None, table: str, region: str) -> None:
    """Show the full event history."""
    try:
        store = StateStore(table_name=table, region=region)

        if sha256_hash:
            _validate_sha256(sha256_hash)
            events = store.list_events_for_file(sha256_hash)
        elif since:
            _validate_date(since)
            events = store.list_events_by_date(since)
        else:
            console.print("[yellow]Provide --file or --since.[/yellow]")
            sys.exit(1)

        if not events:
            console.print("[yellow]No events found.[/yellow]")
            return

        t = Table(show_header=True, header_style="bold cyan")
        t.add_column("Timestamp")
        t.add_column("Operation")
        t.add_column("File")
        t.add_column("SHA256 (16)")
        t.add_column("Principal")
        t.add_column("Correlation ID (8)")
        for e in events:
            sk: str = e.get("SK", "")
            parts = sk.split("#")
            ts = parts[1] if len(parts) > 1 else ""
            op = parts[2] if len(parts) > 2 else e.get("operation", "")
            t.add_row(
                escape(ts),
                escape(op),
                escape(str(e.get("file_name", ""))),
                escape(str(e.get("sha256_hash", ""))[:16]),
                escape(_short_principal(str(e.get("principal_arn", "")))),
                escape(str(e.get("correlation_id", ""))[:8]),
            )
        console.print(t)
    except (ClientError, BotoCoreError) as exc:
        msg = exc.response["Error"]["Message"] if isinstance(exc, ClientError) else str(exc)
        console.print(f"[bold red]AWS error:[/bold red] {escape(str(msg))}")
        sys.exit(1)
    except EnvaultError as exc:
        console.print(f"[bold red]Error:[/bold red] {escape(str(exc))}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------


@main.command()
@click.option("--table", envvar="ENVAULT_TABLE", required=True)
@click.option("--region", envvar="ENVAULT_REGION", default="us-east-1")
def dashboard(table: str, region: str) -> None:
    """Show a summary dashboard of all tracked files."""
    try:
        store = StateStore(table_name=table, region=region)
        summary = store.summary()

        console.print()
        console.print("[bold cyan]envault Dashboard[/bold cyan]")
        console.rule()

        t = Table.grid(padding=(0, 2))
        t.add_column(style="bold")
        t.add_column()
        t.add_row("Total tracked files:", str(summary["total"]))
        t.add_row("Currently encrypted:", f"[green]{summary['encrypted']}[/green]")
        t.add_row("Currently decrypted:", f"[yellow]{summary['decrypted']}[/yellow]")
        t.add_row("Last activity:", summary["last_activity"])
        console.print(t)
        console.print()
    except (ClientError, BotoCoreError) as exc:
        msg = exc.response["Error"]["Message"] if isinstance(exc, ClientError) else str(exc)
        console.print(f"[bold red]AWS error:[/bold red] {escape(str(msg))}")
        sys.exit(1)
    except EnvaultError as exc:
        console.print(f"[bold red]Error:[/bold red] {escape(str(exc))}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# migrate
# ---------------------------------------------------------------------------


@main.command()
@click.argument("from_path", type=click.Path(exists=True, path_type=Path))
@click.option("--table", envvar="ENVAULT_TABLE", required=True)
@click.option("--region", envvar="ENVAULT_REGION", default="us-east-1")
@click.option("--dry-run", is_flag=True, help="Parse without writing to DynamoDB.")
def migrate(from_path: Path, table: str, region: str, dry_run: bool) -> None:
    """Import existing output.json metadata into DynamoDB.

    FROM_PATH is the path to code/output.json (NDJSON format).
    """
    store = StateStore(table_name=table, region=region)
    imported = skipped = errors = 0

    lines = from_path.read_text().splitlines()
    for i, line in enumerate(track(lines, description="Migrating records..."), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            record = _parse_output_json_entry(entry)
            if record is None:
                skipped += 1
                continue
            if not dry_run:
                store.put_current_state(record)
                store.put_event(
                    record, operation="ENCRYPT", correlation_id="migrated-from-output-json"
                )
            imported += 1
        except StateConflictError:
            logger.info("Record already exists, skipping migration for line %d", i)
            skipped += 1
        except (json.JSONDecodeError, KeyError, ValueError, MigrationError) as exc:
            logger.warning("Failed to migrate record at line %d: %s", i, exc)
            errors += 1

    mode = "[dim](dry run)[/dim]" if dry_run else ""
    console.print(
        f"\n[green]Migrated {imported} records[/green], skipped {skipped}, errors {errors} {mode}"
    )


def _parse_output_json_entry(entry: dict[str, Any]) -> FileRecord | None:
    """Convert an output.json record to a FileRecord. Returns None if not an encrypt record."""
    if entry.get("mode") != "encrypt":
        return None

    header = entry.get("header", {})
    input_path = entry.get("input", "")
    if not input_path:
        return None

    plaintext_path = Path(input_path)
    if ".." in plaintext_path.parts:
        raise MigrationError(f"Path traversal not allowed in migration input: {input_path!r}")
    if plaintext_path.is_absolute():
        logger.warning("Absolute path in migration input: %s", input_path)

    file_name = S3Store._sanitize_filename(plaintext_path.name)
    algorithm = _extract_algorithm(header)
    message_id = _extract_message_id(header)
    kms_key_id = _extract_kms_key_id(header)
    enc_context = header.get("encryption_context", {})

    from envault.crypto import sha256_file

    if not plaintext_path.exists():
        logger.warning("Plaintext file not found for migration, skipping: %s", input_path)
        return None

    sha256_hash = sha256_file(plaintext_path)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    return FileRecord(
        sha256_hash=sha256_hash,
        file_name=file_name,
        current_state=ENCRYPTED,
        s3_key=f"encrypted/{sha256_hash[:2]}/{sha256_hash}/{file_name}.encrypted",
        s3_version_id="",
        kms_key_id=kms_key_id or "alias/s3_key",
        encryption_context=enc_context,
        algorithm=algorithm,
        message_id=message_id,
        file_size_bytes=plaintext_path.stat().st_size,
        tags={"source": "migrated"},
        encrypted_at=now,
        last_updated=now,
    )


def _extract_algorithm(header: dict[str, Any]) -> str:
    return str(header.get("algorithm", ""))


def _extract_message_id(header: dict[str, Any]) -> str:
    mid = header.get("message_id", "")
    if isinstance(mid, bytes):
        return mid.hex()
    return str(mid)


def _extract_kms_key_id(header: dict[str, Any]) -> str:
    edks = header.get("encrypted_data_keys", [])
    if edks:
        return str(edks[0].get("key_provider", {}).get("key_info", ""))
    return ""


# ---------------------------------------------------------------------------
# rotate-key
# ---------------------------------------------------------------------------


@main.command("rotate-key")
@click.option("--new-key-id", required=True, help="New KMS key alias or ARN.")
@click.option("--table", envvar="ENVAULT_TABLE", required=True)
@click.option("--bucket", envvar="ENVAULT_BUCKET", required=True)
@click.option("--region", envvar="ENVAULT_REGION", default="us-east-1")
@click.option("--dry-run", is_flag=True)
@click.option(
    "--allowed-account-ids",
    envvar="ENVAULT_ALLOWED_ACCOUNT_IDS",
    default="",
    help="Comma-separated AWS account IDs to trust for decryption.",
)
def rotate_key(
    new_key_id: str,
    table: str,
    bucket: str,
    region: str,
    dry_run: bool,
    allowed_account_ids: str,
) -> None:
    """Re-encrypt all ENCRYPTED files under a new KMS key.

    Downloads each file, decrypts with the original key, re-encrypts with the new key,
    uploads back to S3, and updates DynamoDB state.
    """
    store = StateStore(table_name=table, region=region)
    s3 = S3Store(bucket=bucket, region=region, kms_key_id=new_key_id)
    correlation_id = str(uuid.uuid4())
    account_ids = _validate_account_ids(allowed_account_ids)

    # Every tracked file still has ciphertext in S3 regardless of the state
    # recorded against it, so rotation must cover them all. Records written by
    # earlier versions were flipped to DECRYPTED on first read; skipping those
    # would silently leave the most-accessed files under the old key.
    records = store.list_by_state(ENCRYPTED)
    seen = {r.sha256_hash for r in records}
    legacy = [r for r in store.list_by_state(DECRYPTED) if r.sha256_hash not in seen]
    if legacy:
        console.print(
            f"[dim]Including {len(legacy)} record(s) marked DECRYPTED by an earlier "
            "version — their ciphertext is still in S3 and still needs rotating.[/dim]"
        )
    records.extend(legacy)

    if not records:
        console.print("[yellow]No tracked files found.[/yellow]")
        return

    console.print(f"Found {len(records)} files to rotate.")
    if dry_run:
        console.print("[dim]Dry run — no changes will be made.[/dim]")
        for r in records:
            console.print(f"  Would rotate: {escape(r.file_name)} ({r.sha256_hash[:16]}...)")
        return

    console.print(
        "[dim yellow]Note: Temporary plaintext is overwritten with zeros before deletion, "
        "but secure erasure is not guaranteed on copy-on-write filesystems (APFS, Btrfs, "
        "ZFS) or SSDs with wear-levelling.[/dim yellow]"
    )

    # Reuses the same context builder as encrypt so the two can never drift —
    # a divergent context here would make future decrypts fail verification.
    new_key_config = Config(key_id=new_key_id, bucket=bucket, table_name=table, region=region)

    rotated = errors = 0
    for record in track(records, description="Rotating keys..."):
        tmp_dl: Path | None = None
        tmp_pt: Path | None = None
        tmp_enc: Path | None = None
        try:
            _fd_dl, _tmp_dl = tempfile.mkstemp(suffix=".encrypted", prefix="envault_dl_")
            os.close(_fd_dl)
            tmp_dl = Path(_tmp_dl)
            _fd_pt, _tmp_pt = tempfile.mkstemp(prefix="envault_pt_")
            os.fchmod(_fd_pt, 0o600)
            os.close(_fd_pt)
            tmp_pt = Path(_tmp_pt)
            _fd_enc, _tmp_enc = tempfile.mkstemp(suffix=".encrypted", prefix="envault_enc_")
            os.close(_fd_enc)
            tmp_enc = Path(_tmp_enc)

            s3.download_file(record.s3_key, tmp_dl, record.s3_version_id)
            decrypt_file(
                tmp_dl,
                tmp_pt,
                expected_sha256=record.sha256_hash,
                region=region,
                allowed_account_ids=account_ids or None,
                expected_context=record.encryption_context,
            )
            tmp_dl.unlink(missing_ok=True)

            new_ctx = new_key_config.build_encryption_context(record.sha256_hash, record.file_name)
            new_result = encrypt_file(tmp_pt, new_key_id, new_ctx, tmp_enc, region)
            _best_effort_delete(tmp_pt)

            new_version_id = s3.upload_file(tmp_enc, record.s3_key)

            original_last_updated = record.last_updated
            old_kms_key = record.kms_key_id
            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            record.kms_key_id = new_key_id
            record.encryption_context = new_ctx
            record.algorithm = new_result.algorithm
            record.message_id = new_result.message_id
            record.s3_version_id = new_version_id
            record.last_updated = now
            # Legacy records land back in ENCRYPTED: the ciphertext is present,
            # which is what the field is supposed to describe.
            record.current_state = ENCRYPTED
            try:
                store.put_current_state(record, expected_last_updated=original_last_updated)
                store.put_event(
                    record,
                    operation="ROTATE_KEY",
                    correlation_id=correlation_id,
                    principal_arn=caller_arn(region),
                )
            except Exception:
                logger.error(
                    "State write failed after S3 re-upload during key rotation.",
                    extra={
                        "sha256": record.sha256_hash,
                        "s3_key": record.s3_key,
                        "s3_version_id": new_version_id,
                        "old_kms_key": old_kms_key,
                        "new_kms_key": new_key_id,
                        "correlation_id": correlation_id,
                    },
                )
                raise
            rotated += 1
        except (EnvaultError, ClientError, BotoCoreError, OSError) as exc:
            console.print(
                f"[red]Error rotating {escape(record.file_name)}: {escape(str(exc))}[/red]"
            )
            errors += 1
        finally:
            if tmp_dl is not None:
                tmp_dl.unlink(missing_ok=True)
            if tmp_pt is not None:
                _best_effort_delete(tmp_pt)
            if tmp_enc is not None:
                tmp_enc.unlink(missing_ok=True)

    console.print(f"\n[green]Rotated {rotated} files[/green], {errors} errors.")
    if errors:
        # A partially-rotated corpus means some files are still readable with the
        # old key. Exiting 0 here would report an incomplete rotation as success.
        console.print(
            f"[bold red]Rotation incomplete:[/bold red] {errors} file(s) are still "
            "encrypted under the previous key."
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# exec
# ---------------------------------------------------------------------------

_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Retained when --clean-env strips the inherited environment. Enough for a
# program to find its interpreter and render output; nothing that carries
# ambient credentials.
_MINIMAL_ENV_KEYS = ("PATH", "HOME", "LANG", "LC_ALL", "TERM", "TZ", "USER")


class _BufferSink:
    """Collects decrypted bytes into a wipeable buffer.

    ``bytearray`` rather than ``BytesIO`` so the accumulated plaintext can be
    overwritten afterwards. The per-chunk ``bytes`` handed over by the SDK are
    immutable and cannot be wiped — see :func:`envault.isolation.wipe`.
    """

    def __init__(self) -> None:
        self.buf = bytearray()

    def write(self, data: bytes) -> int:
        self.buf += data
        return len(data)


@main.command("exec", context_settings={"ignore_unknown_options": True})
@click.option(
    "--secret",
    "-s",
    "env_specs",
    multiple=True,
    metavar="IDENTIFIER=VAR",
    help="Expose a secret as environment variable VAR (repeatable).",
)
@click.option(
    "--file",
    "-f",
    "file_specs",
    multiple=True,
    metavar="IDENTIFIER=VAR",
    help="Expose a secret as a readable path in $VAR, backed by an anonymous fd (repeatable).",
)
@click.option("--table", envvar="ENVAULT_TABLE", required=True)
@click.option("--bucket", envvar="ENVAULT_BUCKET", required=True)
@click.option("--region", envvar="ENVAULT_REGION", default="us-east-1")
@click.option(
    "--allowed-account-ids",
    envvar="ENVAULT_ALLOWED_ACCOUNT_IDS",
    default="",
    help="Comma-separated AWS account IDs to trust for decryption.",
)
@click.option(
    "--clean-env",
    is_flag=True,
    help="Start the command from a minimal environment instead of inheriting this one.",
)
@click.argument("command", nargs=-1, type=click.UNPROCESSED)
def exec_(
    env_specs: tuple[str, ...],
    file_specs: tuple[str, ...],
    table: str,
    bucket: str,
    region: str,
    allowed_account_ids: str,
    clean_env: bool,
    command: tuple[str, ...],
) -> None:
    """Run a command with secrets supplied in memory, never on disk.

    \b
      envault exec -s db.env=DATABASE_URL -- ./server
      envault exec -f server.pem=TLS_CERT -- curl --cert {TLS_CERT} https://api

    ``--secret`` places the plaintext in the child's environment. ``--file``
    writes it to an anonymous file descriptor and puts a readable path in $VAR,
    for programs that insist on a file — certificates, keystores, kubeconfigs.
    A ``{VAR}`` token anywhere in COMMAND is replaced with that path.

    Nothing is written to the filesystem in either mode. Access is recorded in
    the audit trail *before* the command starts, and if that write fails the
    command does not run — an unlogged secret read is treated as a failure, not
    a warning.
    """
    # Before any plaintext exists in this address space.
    hardening = harden_process()
    if hardening.degraded:
        logger.warning("process hardening incomplete", extra={"degraded": hardening.degraded})

    if not command:
        raise click.UsageError("No command given. Usage: envault exec -s NAME=VAR -- COMMAND")
    if not env_specs and not file_specs:
        raise click.UsageError("Provide at least one --secret or --file.")

    account_ids = _validate_account_ids(allowed_account_ids)
    store = StateStore(table_name=table, region=region)
    s3 = S3Store(bucket=bucket, region=region)
    correlation_id = str(uuid.uuid4())

    env_pairs = [_parse_secret_spec(spec, "--secret") for spec in env_specs]
    file_pairs = [_parse_secret_spec(spec, "--file") for spec in file_specs]
    _reject_duplicate_targets(env_pairs + file_pairs)

    child_env: dict[str, str] = (
        {k: os.environ[k] for k in _MINIMAL_ENV_KEYS if k in os.environ}
        if clean_env
        else dict(os.environ)
    )

    creds: list[CredentialFd] = []
    sinks: list[_BufferSink] = []
    accessed: list[FileRecord] = []
    try:
        for identifier, var in env_pairs:
            record = _resolve_identifier(identifier, 1, store)
            sink = _BufferSink()
            sinks.append(sink)
            _stream_secret(record, sink, s3, region, account_ids)
            child_env[var] = _decode_secret(sink.buf, identifier)
            accessed.append(record)

        for identifier, var in file_pairs:
            record = _resolve_identifier(identifier, 1, store)
            cred = CredentialFd(var)
            creds.append(cred)
            with cred.writer() as out:
                _stream_secret(record, out, s3, region, account_ids)
            # Sealed only after the checksum and encryption context verified.
            cred.seal()
            child_env[var] = cred.child_path
            accessed.append(record)
            if cred.backing != "memfd":
                console.print(
                    "[yellow]Note:[/yellow] anonymous memory files are unavailable on this "
                    "platform; the credential is in an unlinked temp file instead. It has no "
                    "path, but may be backed by disk storage."
                )

        # Fail closed: no audit record, no secret. This runs before the command
        # so a crashing child still leaves the access logged.
        principal = caller_arn(region)
        for record in accessed:
            store.put_event(
                record,
                operation="ACCESS",
                correlation_id=correlation_id,
                principal_arn=principal,
            )
    except EncryptionContextMismatchError:
        _close_all(creds, sinks)
        console.print(
            "[bold red]Refusing to run:[/bold red] encryption context mismatch.\n"
            "A ciphertext in S3 does not match its record in DynamoDB."
        )
        sys.exit(1)
    except ChecksumMismatchError as exc:
        _close_all(creds, sinks)
        console.print(
            "[bold red]Refusing to run:[/bold red] checksum mismatch "
            f"(expected {exc.expected[:16]}..., got {exc.actual[:16]}...).\n"
            "The encrypted data may have been corrupted or tampered with."
        )
        sys.exit(1)
    except (EnvaultError, ClientError, BotoCoreError) as exc:
        _close_all(creds, sinks)
        msg = exc.response["Error"]["Message"] if isinstance(exc, ClientError) else str(exc)
        console.print(
            f"[bold red]Refusing to run:[/bold red] {escape(str(msg))}\n"
            "No command was started and no secrets were delivered."
        )
        sys.exit(1)

    argv = _substitute_paths(list(command), child_env, [var for _, var in file_pairs])

    # Wipe what we can before handing over. The env values themselves are
    # immutable strings destined for the child, and execve replaces this address
    # space wholesale — which disposes of every plaintext copy CPython made
    # along the way far more thoroughly than anything we could do here.
    for sink in sinks:
        wipe(sink.buf)
    sys.stdout.flush()
    sys.stderr.flush()

    try:
        # No shell, deliberately: argv is passed through untouched so a secret or
        # filename can never be reinterpreted as shell syntax. execve (rather
        # than fork) also replaces this address space, discarding every plaintext
        # copy CPython made while decrypting.
        os.execvpe(argv[0], argv, child_env)  # noqa: S606
    except OSError as exc:
        _close_all(creds, [])
        console.print(f"[bold red]Could not run {escape(argv[0])}:[/bold red] {escape(str(exc))}")
        sys.exit(127)


def _close_all(creds: list[CredentialFd], sinks: list[_BufferSink]) -> None:
    for cred in creds:
        cred.close()
    for sink in sinks:
        wipe(sink.buf)


def _stream_secret(
    record: FileRecord,
    out: Any,
    s3: S3Store,
    region: str,
    account_ids: list[str],
) -> None:
    """Fetch a record's ciphertext and decrypt it into ``out``, verifying first."""
    ciphertext = s3.download_to_memory(record.s3_key, record.s3_version_id)
    decrypt_to_stream(
        ciphertext,
        out,
        expected_sha256=record.sha256_hash,
        expected_context=record.encryption_context,
        region=region,
        allowed_account_ids=account_ids,
    )


def _decode_secret(buf: bytearray, identifier: str) -> str:
    """Decode a secret for the environment, dropping one trailing newline.

    Secrets stored as files almost always end in a newline that the original
    author did not intend as part of the value; carrying it into an environment
    variable breaks connection strings and tokens in ways that are tedious to
    debug. Exactly one is removed, so a deliberate blank line survives.
    """
    try:
        value = bytes(buf).decode("utf-8")
    except UnicodeDecodeError:
        raise click.UsageError(
            f"Secret {identifier!r} is not valid UTF-8 and cannot be an environment "
            "variable. Use --file to expose it as a file descriptor instead."
        ) from None
    if value.endswith("\n"):
        value = value[:-1]
    if "\x00" in value:
        raise click.UsageError(
            f"Secret {identifier!r} contains a NUL byte and cannot be an environment "
            "variable. Use --file instead."
        )
    return value


def _parse_secret_spec(spec: str, flag: str) -> tuple[str, str]:
    """Parse an IDENTIFIER=VAR pair, validating the target variable name."""
    identifier, sep, var = spec.partition("=")
    if not sep or not identifier or not var:
        raise click.UsageError(f"{flag} expects IDENTIFIER=VAR, got {spec!r}.")
    if not _ENV_NAME_RE.match(var):
        raise click.UsageError(
            f"{flag} target {var!r} is not a valid environment variable name "
            "(letters, digits, underscore; must not start with a digit)."
        )
    return identifier, var


def _reject_duplicate_targets(pairs: list[tuple[str, str]]) -> None:
    """Refuse to silently drop a secret because two specs share a target name."""
    seen: set[str] = set()
    for _, var in pairs:
        if var in seen:
            raise click.UsageError(f"Duplicate target variable {var!r} in --secret/--file.")
        seen.add(var)


def _substitute_paths(argv: list[str], env: dict[str, str], file_vars: list[str]) -> list[str]:
    """Replace ``{VAR}`` tokens in the command with the credential's fd path."""
    for var in file_vars:
        token = "{" + var + "}"
        path = env[var]
        argv = [arg.replace(token, path) for arg in argv]
    return argv


def _short_principal(arn: str) -> str:
    """Trim an ARN to its identity portion for table display."""
    if not arn:
        return "—"
    return arn.rsplit(":", 1)[-1] if ":" in arn else arn


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_TAG_KEY_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")
_TAG_VALUE_MAX_LEN = 256


def _validate_sha256(value: str) -> str:
    """Validate a SHA256 hash string. Exit with error if invalid."""
    if not _SHA256_RE.fullmatch(value):
        console.print(
            f"[red]Invalid SHA256 hash: {escape(repr(value))}. "
            "Expected 64 lowercase hexadecimal characters.[/red]"
        )
        sys.exit(1)
    return value


def _is_sha256(value: str) -> bool:
    """Return True if value looks like a full 64-char hex SHA256 hash."""
    return bool(_SHA256_RE.fullmatch(value))


def _validate_date(value: str) -> str:
    """Validate a YYYY-MM-DD date string."""
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        console.print(
            f"[red]Invalid date: {escape(repr(value))}. Expected format: YYYY-MM-DD.[/red]"
        )
        sys.exit(1)
    return value


def _resolve_identifier(
    identifier: str,
    version: int,
    store: StateStore,
) -> FileRecord:
    """Resolve an identifier (SHA256 or filename) to a FileRecord.

    For SHA256: direct lookup via get_current_state().
    For filename: query by file_name, return Nth most recent version.
    Exits with error if not found or version out of range.
    """
    if _is_sha256(identifier):
        record = store.get_current_state(identifier)
        if not record:
            console.print(f"[red]No record found for hash {escape(identifier[:16])}...[/red]")
            sys.exit(1)
        return record

    # Filename lookup
    records = store.list_by_file_name(identifier, ENCRYPTED)
    if not records:
        console.print(f"[red]No encrypted files found with name {escape(repr(identifier))}.[/red]")
        sys.exit(1)

    if version < 1 or version > len(records):
        console.print(
            f"[red]Version {version} out of range. "
            f"Found {len(records)} version(s) of"
            f" {escape(repr(identifier))}.[/red]"
        )
        sys.exit(1)

    if len(records) > 1:
        selected = records[version - 1]
        label = "most recent" if version == 1 else f"version {version}"
        console.print(
            f"[dim]{len(records)} versions found. "
            f"Decrypting {label} "
            f"({selected.encrypted_at}). "
            f"Use --version N to pick another.[/dim]"
        )

    return records[version - 1]


_ACCOUNT_ID_RE = re.compile(r"^[0-9]{12}$")


def _validate_account_ids(raw: str) -> list[str]:
    """Parse and validate comma-separated AWS account IDs. Exit with error if invalid."""
    account_ids = [a.strip() for a in raw.split(",") if a.strip()]
    if not account_ids:
        console.print(
            "[bold red]Error:[/bold red] ENVAULT_ALLOWED_ACCOUNT_IDS is required.\n"
            "Set it to a comma-separated list of AWS account IDs trusted to encrypt data."
        )
        sys.exit(1)
    for account_id in account_ids:
        if not _ACCOUNT_ID_RE.fullmatch(account_id):
            console.print(
                f"[red]Invalid AWS account ID: {escape(repr(account_id))}. Must be 12 digits.[/red]"
            )
            sys.exit(1)
    return account_ids


def _collect_files(path: Path) -> list[Path]:
    if path.is_symlink():
        return []
    if path.is_file():
        return [path]
    return [p for p in path.rglob("*") if p.is_file() and not p.is_symlink()]


def _parse_tags(tag_strs: tuple[str, ...]) -> dict[str, str]:
    tags: dict[str, str] = {}
    for t in tag_strs:
        if "=" not in t:
            console.print(
                f"[yellow]Ignoring invalid tag '{escape(t)}' (expected KEY=VALUE)[/yellow]"
            )
            continue
        k, _, v = t.partition("=")
        k = k.strip()
        v = v.strip()
        if not _TAG_KEY_RE.match(k):
            raise click.UsageError(
                f"Invalid tag key {k!r}: must be 1–64 characters, "
                "alphanumeric, underscore, or hyphen only."
            )
        if len(v) > _TAG_VALUE_MAX_LEN:
            raise click.UsageError(f"Tag value for {k!r} exceeds {_TAG_VALUE_MAX_LEN} characters.")
        tags[k] = v
    return tags
