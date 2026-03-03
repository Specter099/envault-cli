"""envault CLI — Click-based command-line interface."""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.progress import track
from rich.table import Table

from envault.config import Config
from envault.crypto import decrypt_file, encrypt_file
from envault.exceptions import AlreadyEncryptedError, ConfigurationError
from envault.s3 import S3Store
from envault.state import DECRYPTED, ENCRYPTED, FileRecord, StateStore

console = Console()
logger = logging.getLogger(__name__)


def _setup_logging(verbose: bool) -> None:
    import pythonjsonlogger.jsonlogger as jsonlogger

    handler = logging.StreamHandler(sys.stderr)
    fmt = jsonlogger.JsonFormatter("%(asctime)s %(name)s %(levelname)s %(message)s")  # type: ignore[attr-defined]
    handler.setFormatter(fmt)
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, handlers=[handler])


def _load_config() -> Config:
    try:
        return Config.from_env()
    except ConfigurationError as e:
        console.print(f"[bold red]Configuration error:[/bold red] {e}")
        sys.exit(1)


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose JSON logging to stderr.")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """envault — client-side envelope encryption with AWS KMS + DynamoDB state tracking."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    _setup_logging(verbose)


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
    s3 = S3Store(bucket=bucket, region=region)
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
        except Exception as exc:
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
    s3_key = s3.s3_key_for_file(file_path.name)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    try:
        result = encrypt_file(
            input_path=file_path,
            key_id=config.key_id,
            encryption_context=config.encryption_context,
            output_path=tmp_encrypted,
            region=config.region,
        )

        version_id = s3.upload_file(local_path=tmp_encrypted, s3_key=s3_key)
    finally:
        tmp_encrypted.unlink(missing_ok=True)

    record = FileRecord(
        sha256_hash=sha256,
        file_name=file_path.name,
        current_state=ENCRYPTED,
        s3_key=s3_key,
        s3_version_id=version_id,
        kms_key_id=config.key_id,
        encryption_context=config.encryption_context,
        algorithm=result.algorithm,
        message_id=result.message_id,
        file_size_bytes=result.file_size_bytes,
        tags=tags,
        encrypted_at=now,
        last_updated=now,
    )
    store.put_current_state(record)
    store.put_event(
        record,
        operation="ENCRYPT",
        correlation_id=correlation_id,
        audit_ttl_days=config.audit_ttl_days,
    )
    console.print(f"[green]✓[/green] {file_path.name} → s3://{config.bucket}/{s3_key}")


# ---------------------------------------------------------------------------
# decrypt
# ---------------------------------------------------------------------------


@main.command()
@click.argument("sha256_hash")
@click.option(
    "--output", "-o", type=click.Path(path_type=Path), default=Path("."), show_default=True
)
@click.option("--table", envvar="ENVAULT_TABLE", required=True)
@click.option("--bucket", envvar="ENVAULT_BUCKET", required=True)
@click.option("--region", envvar="ENVAULT_REGION", default="us-east-1")
@click.pass_context
def decrypt(
    ctx: click.Context,
    sha256_hash: str,
    output: Path,
    table: str,
    bucket: str,
    region: str,
) -> None:
    """Decrypt a file by its SHA256 hash.

    SHA256_HASH is the hash of the original plaintext file (shown by envault status).
    """
    store = StateStore(table_name=table, region=region)
    s3 = S3Store(bucket=bucket, region=region)
    correlation_id = str(uuid.uuid4())

    record = store.get_current_state(sha256_hash)
    if not record:
        console.print(f"[red]No record found for hash {sha256_hash[:16]}...[/red]")
        sys.exit(1)
    if record.current_state != ENCRYPTED:
        console.print(f"[yellow]File is in state {record.current_state}, not ENCRYPTED.[/yellow]")
        sys.exit(1)

    _fd, _tmp = tempfile.mkstemp(suffix=".encrypted", prefix="envault_dl_")
    os.close(_fd)
    tmp_encrypted = Path(_tmp)
    output_path = (output if output.is_dir() else output.parent) / record.file_name

    try:
        s3.download_file(
            s3_key=record.s3_key, local_path=tmp_encrypted, version_id=record.s3_version_id
        )

        decrypt_file(
            input_path=tmp_encrypted,
            output_path=output_path,
            expected_sha256=sha256_hash,
            region=region,
        )
    finally:
        tmp_encrypted.unlink(missing_ok=True)

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    record.current_state = DECRYPTED
    record.decrypted_at = now
    record.last_updated = now
    store.put_current_state(record)
    store.put_event(record, operation="DECRYPT", correlation_id=correlation_id)

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
    store = StateStore(table_name=table, region=region)

    if sha256_hash:
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
    store = StateStore(table_name=table, region=region)

    if sha256_hash:
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


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------


@main.command()
@click.option("--table", envvar="ENVAULT_TABLE", required=True)
@click.option("--region", envvar="ENVAULT_REGION", default="us-east-1")
def dashboard(table: str, region: str) -> None:
    """Show a summary dashboard of all tracked files."""
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
        except Exception as exc:
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
        logger.warning(
            "Plaintext file not found for migration, skipping: %s", input_path
        )
        return None

    sha256_hash = sha256_file(plaintext_path)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    return FileRecord(
        sha256_hash=sha256_hash,
        file_name=file_name,
        current_state=ENCRYPTED,
        s3_key=f"encrypted/{file_name}.encrypted",
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
def rotate_key(new_key_id: str, table: str, bucket: str, region: str, dry_run: bool) -> None:
    """Re-encrypt all ENCRYPTED files under a new KMS key.

    Downloads each file, decrypts with the original key, re-encrypts with the new key,
    uploads back to S3, and updates DynamoDB state.
    """
    store = StateStore(table_name=table, region=region)
    s3 = S3Store(bucket=bucket, region=region)
    correlation_id = str(uuid.uuid4())

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
        try:
            _fd_dl, _tmp_dl = tempfile.mkstemp(suffix=".encrypted", prefix="envault_dl_")
            os.close(_fd_dl)
            tmp_dl = Path(_tmp_dl)
            _fd_pt, _tmp_pt = tempfile.mkstemp(prefix="envault_pt_")
            os.close(_fd_pt)
            tmp_pt = Path(_tmp_pt)
            _fd_enc, _tmp_enc = tempfile.mkstemp(suffix=".encrypted", prefix="envault_enc_")
            os.close(_fd_enc)
            tmp_enc = Path(_tmp_enc)

            s3.download_file(record.s3_key, tmp_dl, record.s3_version_id)
            decrypt_file(tmp_dl, tmp_pt, expected_sha256=record.sha256_hash, region=region)

            new_result = encrypt_file(
                tmp_pt, new_key_id, record.encryption_context, tmp_enc, region
            )
            _secure_delete(tmp_pt)

            new_version_id = s3.upload_file(tmp_enc, record.s3_key)

            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            record.kms_key_id = new_key_id
            record.algorithm = new_result.algorithm
            record.message_id = new_result.message_id
            record.s3_version_id = new_version_id
            record.last_updated = now
            store.put_current_state(record)
            store.put_event(record, operation="ROTATE_KEY", correlation_id=correlation_id)
            rotated += 1
        except Exception as exc:
            console.print(f"[red]Error rotating {record.file_name}: {exc}[/red]")
            errors += 1
        finally:
            tmp_dl.unlink(missing_ok=True)
            tmp_pt.unlink(missing_ok=True)
            tmp_enc.unlink(missing_ok=True)

    console.print(f"\n[green]Rotated {rotated} files[/green], {errors} errors.")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _collect_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    return [p for p in path.rglob("*") if p.is_file()]


def _parse_tags(tag_strs: tuple[str, ...]) -> dict[str, str]:
    tags: dict[str, str] = {}
    for t in tag_strs:
        if "=" not in t:
            console.print(f"[yellow]Ignoring invalid tag '{t}' (expected KEY=VALUE)[/yellow]")
            continue
        k, _, v = t.partition("=")
        tags[k.strip()] = v.strip()
    return tags


def _secure_delete(path: Path) -> None:
    """Overwrite a file with zeros then unlink it.

    Prevents plaintext recovery from disk after decryption or key rotation.
    Does nothing if the file does not exist.
    """
    try:
        size = path.stat().st_size
        with path.open("r+b") as f:
            f.write(b"\x00" * size)
            f.flush()
            os.fsync(f.fileno())
    except FileNotFoundError:
        return
    except OSError:
        pass
    path.unlink(missing_ok=True)
