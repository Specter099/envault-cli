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
from rich.progress import track
from rich.table import Table

from envault.config import Config
from envault.crypto import decrypt_file, encrypt_file
from envault.exceptions import (
    AlreadyEncryptedError,
    ChecksumMismatchError,
    ConfigurationError,
    EncryptionContextMismatchError,
    EnvaultError,
    MigrationError,
    StateConflictError,
)
from envault.s3 import S3Store
from envault.state import DECRYPTED, ENCRYPTED, FileRecord, StateStore

console = Console()
logger = logging.getLogger(__name__)


def _setup_logging(verbose: bool) -> None:
    from pythonjsonlogger.jsonlogger import (  # type: ignore[attr-defined,unused-ignore]
        JsonFormatter,
    )

    handler = logging.StreamHandler(sys.stderr)
    fmt = JsonFormatter("%(asctime)s %(name)s %(levelname)s %(message)s")  # type: ignore[no-untyped-call,unused-ignore]
    handler.setFormatter(fmt)
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, handlers=[handler])


def _load_config() -> Config:
    try:
        return Config.from_env()
    except ConfigurationError as e:
        console.print(f"[bold red]Configuration error:[/bold red] {e}")
        sys.exit(1)


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
        console.print(f"{_friendly_message(e)}{hint}")
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
        console.print(f"[yellow]No files found in {input_path}[/yellow]")
        return

    errors = 0
    for file_path in track(files, description="Encrypting..."):
        try:
            _encrypt_one(file_path, config, tags, store, s3, correlation_id, force)
        except AlreadyEncryptedError:
            console.print(
                f"[yellow]⏭[/yellow] {file_path.name} already ENCRYPTED (use --force to re-encrypt)"
            )
        except (EnvaultError, ClientError, BotoCoreError) as exc:
            console.print(f"[red]✗[/red] {file_path.name}: {exc}")
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
    console.print(f"[green]✓[/green] {file_path.name} → s3://{config.bucket}/{s3_key}")


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
    if record.current_state != ENCRYPTED:
        console.print(f"[yellow]File is in state {record.current_state}, not ENCRYPTED.[/yellow]")
        sys.exit(1)

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

        result = decrypt_file(
            input_path=tmp_encrypted,
            output_path=output_path,
            expected_sha256=sha256_hash,
            region=region,
            allowed_account_ids=account_ids or None,
        )

        _verify_encryption_context(
            expected=record.encryption_context, actual=result.encryption_context
        )
    except EncryptionContextMismatchError:
        output_path.unlink(missing_ok=True)
        console.print(
            "[bold red]Decryption failed:[/bold red] encryption context mismatch.\n"
            "The ciphertext metadata does not match the record in DynamoDB.\n"
            "This could mean the encrypted file in S3 was replaced or corrupted.\n"
            f"  File: {record.file_name}  SHA256: {sha256_hash[:16]}..."
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
        console.print(f"[bold red]Configuration error:[/bold red] {exc}")
        sys.exit(1)
    except (ClientError, BotoCoreError) as exc:
        error_msg = str(exc)
        if isinstance(exc, ClientError):
            error_msg = exc.response.get("Error", {}).get("Message", str(exc))
        console.print(
            f"[bold red]AWS error during decryption:[/bold red] {error_msg}\n"
            f"  File: {record.file_name}  S3: {record.s3_key}"
        )
        sys.exit(1)
    except EnvaultError as exc:
        console.print(f"[bold red]Decryption error:[/bold red] {exc}")
        sys.exit(1)
    finally:
        tmp_encrypted.unlink(missing_ok=True)

    original_last_updated = record.last_updated
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    record.current_state = DECRYPTED
    record.decrypted_at = now
    record.last_updated = now
    try:
        store.put_current_state(record, expected_last_updated=original_last_updated)
        store.put_event(record, operation="DECRYPT", correlation_id=correlation_id)
    except Exception:
        logger.error(
            "State write failed after successful decryption. "
            "File was decrypted to disk but state was not updated.",
            extra={
                "sha256": sha256_hash,
                "output_path": str(output_path),
                "s3_key": record.s3_key,
            },
        )
        raise

    console.print(f"[green]✓[/green] Decrypted → {output_path}")


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
        console.print(f"[bold red]AWS error:[/bold red] {msg}")
        sys.exit(1)
    except EnvaultError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
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
        t.add_row(
            r.file_name,
            f"[{state_color}]{r.current_state}[/{state_color}]",
            r.sha256_hash[:16],
            r.encrypted_at,
            tags_str,
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
        t.add_column("Correlation ID (8)")
        for e in events:
            sk: str = e.get("SK", "")
            parts = sk.split("#")
            ts = parts[1] if len(parts) > 1 else ""
            op = parts[2] if len(parts) > 2 else e.get("operation", "")
            t.add_row(
                ts,
                op,
                e.get("file_name", ""),
                e.get("sha256_hash", "")[:16],
                e.get("correlation_id", "")[:8],
            )
        console.print(t)
    except (ClientError, BotoCoreError) as exc:
        msg = exc.response["Error"]["Message"] if isinstance(exc, ClientError) else str(exc)
        console.print(f"[bold red]AWS error:[/bold red] {msg}")
        sys.exit(1)
    except EnvaultError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
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
        console.print(f"[bold red]AWS error:[/bold red] {msg}")
        sys.exit(1)
    except EnvaultError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
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
    file_name = Path(input_path).name if input_path else "unknown"
    algorithm = _extract_algorithm(header)
    message_id = _extract_message_id(header)
    kms_key_id = _extract_kms_key_id(header)
    enc_context = header.get("encryption_context", {})

    from envault.crypto import sha256_file

    plaintext_path = Path(input_path)
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
        file_size_bytes=0,
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

    records = store.list_by_state(ENCRYPTED)
    if not records:
        console.print("[yellow]No ENCRYPTED files found.[/yellow]")
        return

    console.print(f"Found {len(records)} ENCRYPTED files to rotate.")
    if dry_run:
        console.print("[dim]Dry run — no changes will be made.[/dim]")
        for r in records:
            console.print(f"  Would rotate: {r.file_name} ({r.sha256_hash[:16]}...)")
        return

    rotated = errors = 0
    for record in track(records, description="Rotating keys..."):
        tmp_dl = tmp_pt = tmp_enc = None
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
            dec_result = decrypt_file(
                tmp_dl,
                tmp_pt,
                expected_sha256=record.sha256_hash,
                region=region,
                allowed_account_ids=account_ids or None,
            )
            tmp_dl.unlink(missing_ok=True)

            _verify_encryption_context(
                expected=record.encryption_context, actual=dec_result.encryption_context
            )

            new_ctx = {
                "purpose": "envault-backup",
                "sha256": record.sha256_hash,
                "file_name": record.file_name,
                "kms_key_alias": new_key_id,
            }
            new_result = encrypt_file(tmp_pt, new_key_id, new_ctx, tmp_enc, region)
            _best_effort_delete(tmp_pt)

            new_version_id = s3.upload_file(tmp_enc, record.s3_key)

            original_last_updated = record.last_updated
            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            record.kms_key_id = new_key_id
            record.encryption_context = new_ctx
            record.algorithm = new_result.algorithm
            record.message_id = new_result.message_id
            record.s3_version_id = new_version_id
            record.last_updated = now
            try:
                store.put_current_state(record, expected_last_updated=original_last_updated)
                store.put_event(record, operation="ROTATE_KEY", correlation_id=correlation_id)
            except Exception:
                logger.error(
                    "State write failed after S3 re-upload during key rotation.",
                    extra={
                        "sha256": record.sha256_hash,
                        "s3_key": record.s3_key,
                        "s3_version_id": new_version_id,
                        "old_kms_key": record.kms_key_id,
                        "new_kms_key": new_key_id,
                        "correlation_id": correlation_id,
                    },
                )
                raise
            rotated += 1
        except (EnvaultError, ClientError, BotoCoreError) as exc:
            console.print(f"[red]Error rotating {record.file_name}: {exc}[/red]")
            errors += 1
        finally:
            if tmp_dl is not None:
                tmp_dl.unlink(missing_ok=True)
            if tmp_pt is not None:
                _best_effort_delete(tmp_pt)
            if tmp_enc is not None:
                tmp_enc.unlink(missing_ok=True)

    console.print(f"\n[green]Rotated {rotated} files[/green], {errors} errors.")


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
            f"[red]Invalid SHA256 hash: {value!r}. "
            "Expected 64 lowercase hexadecimal characters.[/red]"
        )
        sys.exit(1)
    return value


def _is_sha256(value: str) -> bool:
    """Return True if value looks like a full 64-char hex SHA256 hash."""
    return bool(_SHA256_RE.fullmatch(value))


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
            console.print(f"[red]No record found for hash {identifier[:16]}...[/red]")
            sys.exit(1)
        return record

    # Filename lookup
    records = store.list_by_file_name(identifier, ENCRYPTED)
    if not records:
        console.print(f"[red]No encrypted files found with name {identifier!r}.[/red]")
        sys.exit(1)

    if version < 1 or version > len(records):
        console.print(
            f"[red]Version {version} out of range. "
            f"Found {len(records)} version(s) of"
            f" {identifier!r}.[/red]"
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


_ACCOUNT_ID_RE = re.compile(r"\d{12}")


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
            console.print(f"[red]Invalid AWS account ID: {account_id!r}. Must be 12 digits.[/red]")
            sys.exit(1)
    return account_ids


def _verify_encryption_context(expected: dict[str, str], actual: dict[str, str]) -> None:
    """Verify that all expected encryption context keys exist in the actual context.

    The AWS Encryption SDK may add extra keys (e.g. ``aws-crypto-public-key``)
    to the ciphertext header when using algorithms with key commitment.  These
    SDK-managed keys are legitimate and should be ignored.  We only check that
    every application-level key stored in DynamoDB is present and matches.

    Raises:
        EncryptionContextMismatchError: If any expected key is missing or has a
            different value in the actual context.
    """
    mismatched: dict[str, tuple[str, str | None]] = {}
    for key, expected_value in expected.items():
        actual_value = actual.get(key)
        if actual_value != expected_value:
            mismatched[key] = (expected_value, actual_value)
    if mismatched:
        raise EncryptionContextMismatchError(expected=expected, actual=actual)


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
            console.print(f"[yellow]Ignoring invalid tag '{t}' (expected KEY=VALUE)[/yellow]")
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


def _best_effort_delete(path: Path) -> None:
    """Overwrite a file with zeros then unlink it (best-effort).

    Attempts to reduce plaintext exposure on disk after decryption or key
    rotation. This is NOT a guarantee of secure deletion — copy-on-write
    filesystems (APFS, Btrfs, ZFS), SSD wear-levelling, and journaling
    filesystems may retain copies of the original data.

    Does nothing if the file does not exist.
    """
    try:
        size = path.stat().st_size
        chunk = b"\x00" * min(65536, size)
        with path.open("r+b") as f:
            remaining = size
            while remaining > 0:
                to_write = min(len(chunk), remaining)
                f.write(chunk[:to_write])
                remaining -= to_write
            f.flush()
            os.fsync(f.fileno())
    except FileNotFoundError:
        return
    except OSError as exc:
        logger.warning("Best-effort overwrite failed for %s: %s", path, exc)
    path.unlink(missing_ok=True)
