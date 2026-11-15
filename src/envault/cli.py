"""envault CLI — Click-based command-line interface."""

from __future__ import annotations

import glob
import json
import logging
import os
import re
import shutil
import signal
import stat
import sys
import tempfile
import unicodedata
import uuid
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path, PurePosixPath
from types import FrameType
from typing import Any, ClassVar

import boto3
import click
from botocore.exceptions import BotoCoreError, ClientError
from rich.console import Console
from rich.markup import escape
from rich.progress import track
from rich.table import Table

from envault.config import Config, boto_config
from envault.crypto import (
    decrypt_file,
    decrypt_to_stream,
    encrypt_fd,
    encrypt_file,
    sha256_fd,
    sha256_file,
)
from envault.exceptions import (
    AlreadyEncryptedError,
    ChecksumMismatchError,
    ConfigurationError,
    EncryptionContextMismatchError,
    EnvaultError,
    KMSError,
    MigrationError,
    StateConflictError,
)
from envault.fileutils import best_effort_delete as _best_effort_delete
from envault.fileutils import open_regular_nofollow
from envault.identity import caller_arn
from envault.isolation import CredentialFd, harden_process, wipe
from envault.s3 import S3Store, assert_s3_key_matches_hash
from envault.state import DECRYPTED, ENCRYPTED, FileRecord, StateStore

# emoji=False: a stored name like ":skull:" must print as typed.
console = Console(emoji=False)
logger = logging.getLogger(__name__)


# Characters a terminal acts on or renders invisibly: C0/C1 controls and DEL
# (Cc), format characters such as bidi overrides and zero-width spaces (Cf),
# lone surrogates from undecodable file names (Cs), line/paragraph separators.
_UNSAFE_DISPLAY_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
_NAMED_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _visible_escape(ch: str) -> str:
    named = _NAMED_ESCAPES.get(ch)
    if named:
        return named
    code = ord(ch)
    if code <= 0xFF:
        return f"\\x{code:02x}"
    if code <= 0xFFFF:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


def _has_unsafe_characters(text: str) -> bool:
    return any(unicodedata.category(ch) in _UNSAFE_DISPLAY_CATEGORIES for ch in text)


def _display(value: object) -> str:
    """Render an untrusted value for console markup: visible escapes, no markup.

    File names, tags, timestamps, principals and S3 keys come from DynamoDB
    (anyone with table write access can edit them), from the filesystem, or from
    error messages that embed those. Printed raw, an ESC sequence among them can
    retitle the terminal, clear it or forge output, and a bidi override can make
    one name read as another. Such characters are shown as Python-style escapes
    (``\\x1b``, ``\\u202e``), then Rich markup is escaped. Use this for every
    value envault did not write itself.
    """
    text = str(value)
    if _has_unsafe_characters(text):
        text = "".join(
            _visible_escape(ch) if unicodedata.category(ch) in _UNSAFE_DISPLAY_CATEGORIES else ch
            for ch in text
        )
    return escape(text)


def _is_logger(name: str, family: str) -> bool:
    return name == family or name.startswith(family + ".")


class _StderrLogPolicy(logging.Filter):
    """Decide which log records envault's stderr handler writes.

    envault's own loggers pass at whatever level they are set to (DEBUG under
    ``-v``). Every other logger passes at WARNING and above only, whatever
    level it was given: botocore logs signed request headers (the session
    token) and response bodies (the plaintext data key KMS returns) at DEBUG,
    so ``-v`` must never reach them. The Encryption SDK's records are dropped
    unless ``-v`` is set: it logs a traceback at ERROR for every KMS failure
    and "Error on closing" for every abandoned decrypt, and envault reports
    those failures itself, in one line.
    """

    def __init__(self, verbose: bool) -> None:
        super().__init__()
        self.verbose = verbose

    def filter(self, record: logging.LogRecord) -> bool:
        if _is_logger(record.name, "envault"):
            return True
        if record.levelno < logging.WARNING:
            return False
        if _is_logger(record.name, "aws_encryption_sdk"):
            return self.verbose
        return True


def _setup_logging(verbose: bool) -> None:
    from pythonjsonlogger.json import JsonFormatter

    handler = logging.StreamHandler(sys.stderr)
    fmt = JsonFormatter("%(asctime)s %(name)s %(levelname)s %(message)s")  # type: ignore[no-untyped-call,unused-ignore]
    handler.setFormatter(fmt)
    handler.addFilter(_StderrLogPolicy(verbose))
    # The root logger stays at WARNING under -v: only envault's own loggers
    # become verbose. The handler's filter enforces the same rule for loggers
    # that set their own level.
    logging.basicConfig(level=logging.WARNING, handlers=[handler])
    logging.getLogger("envault").setLevel(logging.DEBUG if verbose else logging.NOTSET)


def _sdk_finalizer_noise_filter(
    previous: Callable[[Any], object],
) -> Callable[[Any], None]:
    """Wrap a ``sys.unraisablehook`` so it drops the Encryption SDK's finalizer errors.

    An SDK stream abandoned mid-message (any failed decrypt) raises again from
    its finalizer ("Footer not read"), which Python prints to stderr as
    "Exception ignored in ..." with a traceback, at garbage collection or at
    interpreter exit. The SDK itself treats errors from closing as safe to
    ignore, and envault has already reported the failure. Everything else goes
    to ``previous``.
    """
    from aws_encryption_sdk.exceptions import AWSEncryptionSDKClientError

    def hook(unraisable: Any) -> None:
        source = type(unraisable.object).__module__
        if isinstance(unraisable.exc_value, AWSEncryptionSDKClientError) and _is_logger(
            source, "aws_encryption_sdk"
        ):
            logger.debug(
                "Discarded an Encryption SDK error raised while finalizing an abandoned stream: %s",
                unraisable.exc_value,
            )
            return
        previous(unraisable)

    return hook


@click.group(invoke_without_command=True)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose JSON logging to stderr.")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """envault — client-side envelope encryption with AWS KMS + DynamoDB state tracking."""
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


# ---------------------------------------------------------------------------
# Signals and temporary files
#
# SIGTERM and SIGHUP end a process without running Python's cleanup, which
# left decrypted plaintext in the output directory (decrypt) and in /dev/shm
# (rotate-key). The console entry point turns them into SystemExit(128 +
# signum), and SIGINT into KeyboardInterrupt as usual, so every ``finally``
# runs. After the first of these signals, the next one is ignored: the process
# is already on its way out, and a second Ctrl-C must not cut the overwrite of
# plaintext short. A third ends the process at once, in case something holds
# it up. Signals are deferred (held, then acted on), never blocked with a
# signal mask, which the command `exec` starts would inherit.
# ---------------------------------------------------------------------------

#: Stop signals ignored during shutdown before the next one ends the process.
_SIGNALS_IGNORED_WHILE_STOPPING = 1


class _SignalState:
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.stopping: int | None = None  # the signal being acted on
        self.pending: int | None = None  # received inside a deferred section
        self.deferring = 0
        self.ignored = 0


_signals = _SignalState()


def _stop_exception(signum: int) -> BaseException:
    if signum == signal.SIGINT:
        return KeyboardInterrupt()
    return SystemExit(128 + signum)


def _on_stop_signal(signum: int, frame: FrameType | None) -> None:
    """Handler for SIGTERM, SIGHUP and SIGINT once the entry point installed it."""
    if _signals.stopping is not None:
        _signals.ignored += 1
        if _signals.ignored > _SIGNALS_IGNORED_WHILE_STOPPING:
            # The operator insists: end now, cleanup or not.
            signal.signal(signum, signal.SIG_DFL)
            os.kill(os.getpid(), signum)
        return
    if _signals.deferring:
        if _signals.pending is None:
            _signals.pending = signum
        return
    _signals.stopping = signum
    raise _stop_exception(signum)


@contextmanager
def _signals_deferred() -> Iterator[None]:
    """Hold stop signals until the block ends, then act on the first one received.

    For short critical sections: creating a temporary file and recording it,
    and destroying temporary files.
    """
    _signals.deferring += 1
    try:
        yield
    finally:
        _signals.deferring -= 1
        signum = _signals.pending
        if not _signals.deferring and signum is not None:
            _signals.pending = None
            if _signals.stopping is None:
                _signals.stopping = signum
                raise _stop_exception(signum)


def _install_signal_handlers() -> Callable[[], None]:
    """Route SIGTERM, SIGHUP and SIGINT to :func:`_on_stop_signal`; return an undo.

    Only signals at their default disposition are taken over. One the parent
    chose to ignore (``nohup`` ignores SIGHUP) stays ignored, for envault and
    for the command ``exec`` starts. Call from the main thread.
    """
    _signals.reset()
    previous: dict[int, Any] = {}
    for name in ("SIGTERM", "SIGHUP", "SIGINT"):
        signum = getattr(signal, name, None)
        if signum is None:
            continue
        default = signal.default_int_handler if name == "SIGINT" else signal.SIG_DFL
        if signal.getsignal(signum) != default:
            continue
        previous[signum] = signal.signal(signum, _on_stop_signal)

    def restore() -> None:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        _signals.reset()

    return restore


def _default_signals_for_child() -> dict[int, Any]:
    """Reset SIGPIPE and SIGXFSZ, which Python ignores, before exec (as subprocess does).

    Ignored dispositions survive execve: without this, the command `exec`
    starts would see EPIPE instead of being stopped by SIGPIPE. Returns the
    previous handlers, to put back if the exec fails.
    """
    previous: dict[int, Any] = {}
    for name in ("SIGPIPE", "SIGXFSZ"):
        signum = getattr(signal, name, None)
        if signum is not None:
            previous[signum] = signal.signal(signum, signal.SIG_DFL)
    return previous


def _destroy(path: Path, plaintext: bool) -> None:
    """Remove a temporary file, and the files other code derives from its name."""
    try:
        if plaintext:
            _best_effort_delete(path)
            # decrypt_file streams into a hidden sibling and renames it over
            # ``path`` only once verified.
            for part in path.parent.glob(f".{glob.escape(path.name)}.*.part"):
                _best_effort_delete(part)
        else:
            path.unlink(missing_ok=True)
            # s3transfer downloads into a sibling named after the destination.
            for partial in path.parent.glob(f"{glob.escape(path.name)}.*"):
                partial.unlink(missing_ok=True)
    except OSError as exc:
        logger.warning("Could not remove temporary file %s: %s", path, exc)


def _destroy_dir(directory: Path) -> None:
    """Overwrite and remove every file in a private scratch directory, then the directory."""
    try:
        entries = list(directory.iterdir())
    except OSError:
        entries = []
    for entry in entries:
        _best_effort_delete(entry)
    shutil.rmtree(directory, ignore_errors=True)


class _Scratch:
    """Temporary files a command creates, destroyed when it ends, however it ends.

    A path is recorded inside the same signal-deferred section that creates it,
    so no signal can strand a file between the two, and destruction cannot be
    interrupted. Plaintext files are zero-overwritten before removal (best
    effort; see :func:`envault.fileutils.best_effort_delete`), as are the
    hidden ``.<name>.*.part`` files decrypt_file writes next to them. Whatever
    a command's own cleanup did not reach is swept by the console entry point
    on its way out (:meth:`cleanup_all`).
    """

    _live: ClassVar[list[_Scratch]] = []

    def __init__(self) -> None:
        self._files: list[tuple[Path, bool]] = []
        self._dirs: list[Path] = []

    def __enter__(self) -> _Scratch:
        _Scratch._live.append(self)
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.cleanup()

    def file(
        self,
        *,
        prefix: str,
        suffix: str = "",
        directory: Path | None = None,
        plaintext: bool = False,
    ) -> Path:
        """Create an empty 0600 temporary file that is destroyed with the scratch."""
        with _signals_deferred():
            fd, name = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=directory)
            path = Path(name)
            self._files.append((path, plaintext))
            os.close(fd)
        return path

    def adopt(self, path: Path, *, plaintext: bool) -> None:
        """Destroy ``path`` with the scratch if it exists then (other code creates it)."""
        with _signals_deferred():
            self._files.append((path, plaintext))

    def ram_dir(self) -> Path | None:
        """A private RAM-backed directory destroyed with the scratch, if there is one."""
        with _signals_deferred():
            path = _private_ram_dir()
            if path is not None:
                self._dirs.append(path)
        return path

    def discard(self, *paths: Path | None) -> None:
        """Destroy these files now rather than when the command ends."""
        with _signals_deferred():
            for entry in [e for e in self._files if e[0] in paths]:
                self._files.remove(entry)
                _destroy(*entry)

    def cleanup(self) -> None:
        with _signals_deferred():
            while self._files:
                _destroy(*self._files.pop())
            while self._dirs:
                _destroy_dir(self._dirs.pop())
            if self in _Scratch._live:
                _Scratch._live.remove(self)

    @classmethod
    def cleanup_all(cls) -> None:
        with _signals_deferred():
            for scratch in list(cls._live):
                scratch.cleanup()


def cli() -> None:
    """Entrypoint that wraps Click with human-readable error formatting."""
    sys.unraisablehook = _sdk_finalizer_noise_filter(sys.unraisablehook)
    restore_signals = _install_signal_handlers()
    try:
        main(standalone_mode=False)
    except click.UsageError as e:
        hint = ""
        if e.ctx:
            hint = f"\n  Run '{_display(e.ctx.command_path)} --help' for usage info."
        console.print(f"{_display(_friendly_message(e))}{hint}")
        sys.exit(2)
    except click.Abort:
        console.print("[yellow]Aborted.[/yellow]")
        sys.exit(1)
    finally:
        try:
            _Scratch.cleanup_all()
        finally:
            restore_signals()


# Every command that writes an audit event takes this, so ENVAULT_AUDIT_TTL_DAYS
# applies to ENCRYPT, DECRYPT, ACCESS, and ROTATE_KEY events alike.
_audit_ttl_option = click.option(
    "--audit-ttl-days",
    envvar="ENVAULT_AUDIT_TTL_DAYS",
    type=click.IntRange(min=1),
    default=365,
    show_default=True,
    help="Days to retain audit events before DynamoDB TTL expires them.",
)


@contextmanager
def _exit_on_error(headline: str = "Error") -> Iterator[None]:
    """Turn AWS and envault errors into a one-line message and exit status 1."""
    try:
        yield
    except (ClientError, BotoCoreError) as exc:
        _report_error("AWS error", exc)
        sys.exit(1)
    except EnvaultError as exc:
        _report_error(headline, exc)
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
@_audit_ttl_option
def encrypt(
    input_path: Path,
    key_id: str,
    bucket: str,
    table: str,
    tag: tuple[str, ...],
    force: bool,
    region: str,
    audit_ttl_days: int,
) -> None:
    """Encrypt a file or directory and store state in DynamoDB.

    INPUT_PATH can be a single file or a directory (processed recursively).
    """
    config = Config(key_id=key_id, bucket=bucket, region=region, audit_ttl_days=audit_ttl_days)
    tags = _parse_tags(tag)
    store = StateStore(table_name=table, region=region)
    s3 = S3Store(bucket=bucket, region=region, kms_key_id=key_id)
    correlation_id = str(uuid.uuid4())

    files = _collect_files(input_path)
    if not files:
        console.print(f"[yellow]No files found in {_display(str(input_path))}[/yellow]")
        return

    errors = 0
    for item in track(files, description="Encrypting..."):
        try:
            file_correlation_id = f"{correlation_id}/{uuid.uuid4()}"
            _encrypt_one(item, config, tags, store, s3, file_correlation_id, force)
        except AlreadyEncryptedError:
            console.print(
                f"[yellow]⏭[/yellow] {_display(item.name)} already ENCRYPTED "
                "(use --force to re-encrypt)"
            )
        except (EnvaultError, ClientError, BotoCoreError, OSError) as exc:
            console.print(f"[red]✗[/red] {_display(item.name)}: {_display(_error_message(exc))}")
            # The ✗ line is the report; the traceback is for -v only.
            logger.debug("Failed to encrypt %s", item.path, exc_info=True)
            errors += 1

    if errors:
        console.print(f"\n[red]{errors} file(s) failed to encrypt.[/red]")
        sys.exit(1)


def _encrypt_one(
    item: _CollectedFile,
    config: Config,
    tags: dict[str, str],
    store: StateStore,
    s3: S3Store,
    correlation_id: str,
    force: bool,
) -> None:
    # One descriptor for the dedup hash and the encryption, opened without
    # following a symlink and only if it is still the inode collected: a path
    # swapped since the walk is refused, and a swap after this open changes
    # nothing that is read.
    fd = open_regular_nofollow(item.path, expected=item.identity)
    try:
        _encrypt_fd(fd, item, config, tags, store, s3, correlation_id, force)
    finally:
        os.close(fd)


def _encrypt_fd(
    fd: int,
    item: _CollectedFile,
    config: Config,
    tags: dict[str, str],
    store: StateStore,
    s3: S3Store,
    correlation_id: str,
    force: bool,
) -> None:
    name = item.name
    sha256 = sha256_fd(fd)

    existing = store.get_current_state(sha256)
    if existing and existing.current_state == ENCRYPTED and not force:
        raise AlreadyEncryptedError(sha256_hash=sha256, file_name=name)

    # Microseconds: versions of one name are ordered by this, and two files
    # encrypted within the same second must not tie.
    now = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    # enc_context uses the pre-read hash; it will be validated against result.sha256_hash below
    enc_context = config.build_encryption_context(sha256, name)

    with _Scratch() as scratch:
        tmp_encrypted = scratch.file(prefix="envault_enc_", suffix=".encrypted")
        result = encrypt_fd(
            fd,
            key_id=config.key_id,
            encryption_context=enc_context,
            output_path=tmp_encrypted,
            region=config.region,
        )

        if sha256 != result.sha256_hash:
            raise EnvaultError(
                f"File {name!r} was modified during encryption "
                f"(pre-read hash {_id_prefix(sha256)}… != encrypted hash "
                f"{_id_prefix(result.sha256_hash)}…). "
                "Aborting to avoid storing mismatched metadata."
            )

        # A key of its own for every upload (it embeds the message id), written
        # only if nothing is there: no upload can make the version another
        # record pins noncurrent. The name part is the stored name's basename.
        s3_key = s3.s3_key_for_file(
            sha256_hash=result.sha256_hash, file_name=name, message_id=result.message_id
        )
        version_id = s3.upload_file(local_path=tmp_encrypted, s3_key=s3_key, if_none_match=True)

    record = FileRecord(
        sha256_hash=result.sha256_hash,
        file_name=name,
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
    except Exception:
        # Typically a concurrent encrypt of the same content won the
        # conditional write. Its record pins its own key, untouched by ours.
        logger.error(
            "State write failed after S3 upload. The uploaded object is an orphan: no "
            "record points to it, and it can be deleted.",
            extra={
                "sha256": sha256,
                "s3_key": s3_key,
                "s3_version_id": version_id,
                "bucket": config.bucket,
                "file_name": name,
            },
        )
        raise
    try:
        store.put_event(
            record,
            operation="ENCRYPT",
            correlation_id=correlation_id,
            audit_ttl_days=config.audit_ttl_days,
            principal_arn=caller_arn(config.region),
        )
    except Exception:
        logger.error(
            "The file was encrypted and its record written, but its ENCRYPT audit event "
            "could not be recorded.",
            extra={"s3_key": s3_key, "bucket": config.bucket, "file_name": name},
        )
        raise
    console.print(
        f"[green]✓[/green] {_display(name)} → s3://{_display(config.bucket)}/{_display(s3_key)}"
    )


# ---------------------------------------------------------------------------
# decrypt
# ---------------------------------------------------------------------------


@main.command()
@click.argument("identifier")
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default=Path("."),
    show_default=True,
    help="Existing directory (file keeps its original name) or the output file path.",
)
@click.option("--force", is_flag=True, help="Overwrite the output file if it already exists.")
@click.option("--table", envvar="ENVAULT_TABLE", required=True)
@click.option("--bucket", envvar="ENVAULT_BUCKET", required=True)
@click.option("--region", envvar="ENVAULT_REGION", default="us-east-1")
@click.option(
    "--version",
    "version",
    type=click.IntRange(min=1),
    default=None,
    help="When several files are stored under the same name, which one: "
    "1 = most recent (the default), 2 = the one before, and so on.",
)
@click.option(
    "--allowed-account-ids",
    envvar="ENVAULT_ALLOWED_ACCOUNT_IDS",
    default="",
    help="Comma-separated AWS account IDs to trust for decryption.",
)
@click.option(
    "--latest",
    is_flag=True,
    help="Allow download when the record has no S3 VersionId (migrated files).",
)
@_audit_ttl_option
def decrypt(
    identifier: str,
    output: Path,
    force: bool,
    table: str,
    bucket: str,
    region: str,
    version: int | None,
    allowed_account_ids: str,
    latest: bool,
    audit_ttl_days: int,
) -> None:
    """Decrypt a file by SHA256 hash or stored name.

    IDENTIFIER is a 64-char SHA256 hash or the name the file was stored under:
    its path relative to the directory given to encrypt (prod/db.env), or its
    basename when that is unambiguous. When several files are stored under the
    same name, use --version N to pick one.
    """
    store = StateStore(table_name=table, region=region)
    s3 = S3Store(bucket=bucket, region=region)
    correlation_id = str(uuid.uuid4())
    account_ids = _validate_account_ids(allowed_account_ids)

    with _exit_on_error("Decryption error"):
        selection = _resolve_identifier(identifier, store, version=version)
        record = selection.record
        _check_record(record)
    sha256_hash = record.sha256_hash

    if output.is_dir():
        safe_name = Path(record.file_name).name
        # The name comes from DynamoDB: no hidden files, no control or
        # invisible characters in a name the operator's tools will print.
        if not safe_name or safe_name.startswith(".") or _has_unsafe_characters(safe_name):
            safe_name = _fallback_output_name(record)
        output_path = output / safe_name
    else:
        output_path = output

    # Refuse before creating temps so a no-op collision leaves no residue.
    if output_path.exists() and not force:
        console.print(
            f"[red]Refusing to overwrite {_display(str(output_path))}. "
            "Pass --force to replace the existing file.[/red]"
        )
        sys.exit(1)

    try:
        version_id = _s3_version_id(record, latest)
    except EnvaultError as exc:
        console.print(f"[bold red]Decryption error:[/bold red] {_display(exc)}")
        sys.exit(1)

    # Verified plaintext waits here, hidden, until the read is on the audit trail.
    staging = output_path.with_name(f".{output_path.name}.{uuid.uuid4().hex[:8]}.verified")

    # The scratch destroys the downloaded ciphertext, any partial or verified
    # plaintext (not the published file: a hard link, it is only unlinked) and
    # their derivatives, on every exit: errors, exits and signals alike.
    with _Scratch() as scratch:
        try:
            scratch.adopt(staging, plaintext=True)
            tmp_encrypted = scratch.file(prefix="envault_dl_", suffix=".encrypted")
            s3.download_file(
                s3_key=record.s3_key,
                local_path=tmp_encrypted,
                version_id=version_id,
                allow_latest=latest,
            )
            decrypt_file(
                input_path=tmp_encrypted,
                output_path=staging,
                expected_sha256=selection.expected_sha256,
                region=region,
                allowed_account_ids=account_ids,
                expected_context=record.encryption_context,
            )

            # Fail closed, like exec: reading a file does not change what is stored
            # in S3, so current_state is left alone and the read is recorded as an
            # event — before the plaintext becomes visible at its final path. If the
            # event cannot be written the plaintext is destroyed, never delivered.
            try:
                store.put_event(
                    record,
                    operation="DECRYPT",
                    correlation_id=correlation_id,
                    audit_ttl_days=audit_ttl_days,
                    principal_arn=caller_arn(region),
                )
            except (ClientError, BotoCoreError, EnvaultError) as exc:
                logger.error(
                    "Audit event write failed; decrypted plaintext discarded.",
                    extra={"sha256": sha256_hash, "s3_key": record.s3_key},
                )
                console.print(
                    "[bold red]Refusing to write plaintext:[/bold red] the access could not be "
                    f"recorded in the audit trail: {_display(exc)}"
                )
                sys.exit(1)

            _publish(staging, output_path, overwrite=force)
        except EncryptionContextMismatchError:
            console.print(
                "[bold red]Decryption failed:[/bold red] encryption context mismatch.\n"
                "The ciphertext metadata does not match the record in DynamoDB.\n"
                "This could mean the encrypted file in S3 was replaced or corrupted.\n"
                "No plaintext was written.\n"
                f"  File: {_display(record.file_name)}  SHA256: {_id_prefix(sha256_hash)}..."
            )
            sys.exit(1)
        except ChecksumMismatchError as exc:
            console.print(
                "[bold red]Decryption failed:[/bold red] checksum mismatch.\n"
                f"Expected SHA256 {_id_prefix(exc.expected)}... "
                f"but got {_id_prefix(exc.actual)}...\n"
                "The decrypted content does not match the original file.\n"
                "The encrypted data in S3 may have been corrupted or tampered with."
            )
            sys.exit(1)
        except ConfigurationError as exc:
            console.print(f"[bold red]Configuration error:[/bold red] {_display(exc)}")
            sys.exit(1)
        except KMSError as exc:
            # Availability or permission, never a statement about the ciphertext.
            _report_error("KMS error", exc)
            sys.exit(1)
        except (ClientError, BotoCoreError) as exc:
            error_msg = str(exc)
            if isinstance(exc, ClientError):
                error_msg = exc.response.get("Error", {}).get("Message", str(exc))
            console.print(
                f"[bold red]AWS error during decryption:[/bold red] {_display(error_msg)}\n"
                f"  File: {_display(record.file_name)}  S3: {_display(record.s3_key)}"
            )
            sys.exit(1)
        except (EnvaultError, OSError) as exc:
            console.print(f"[bold red]Decryption error:[/bold red] {_display(exc)}")
            sys.exit(1)

    console.print(f"[green]✓[/green] Decrypted → {_display(str(output_path))}")


def _publish(src: Path, dst: Path, *, overwrite: bool) -> None:
    """Move ``src`` to ``dst``; without ``overwrite``, never replace an existing file.

    ``os.link`` fails atomically if ``dst`` exists, closing the race between the
    up-front existence check and this point.
    """
    if overwrite:
        os.replace(src, dst)
        return
    try:
        os.link(src, dst)
    except FileExistsError:
        raise EnvaultError(f"{dst} appeared while decrypting; not overwriting it.") from None
    except OSError:
        # Filesystem without hard links (FAT, some network mounts): fall back
        # to check-then-rename, which is racy but still refuses a known file.
        if dst.exists():
            raise EnvaultError(f"{dst} appeared while decrypting; not overwriting it.") from None
        os.replace(src, dst)
        return
    src.unlink()


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
    with _exit_on_error():
        store = StateStore(table_name=table, region=region)

        if sha256_hash:
            _validate_sha256(sha256_hash)
            record = store.get_current_state(sha256_hash)
            if not record:
                console.print(f"[red]No record found for {_id_prefix(sha256_hash)}...[/red]")
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
        # Escape everything that came back from DynamoDB: a file name containing
        # square brackets would otherwise be interpreted as Rich markup, which
        # both misrepresents the name and can raise MarkupError mid-table.
        t.add_row(
            _display(r.file_name),
            f"[{state_color}]{_display(r.current_state)}[/{state_color}]",
            _id_prefix(r.sha256_hash),
            _display(r.encrypted_at),
            _display(tags_str),
        )
    console.print(t)


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


# One date-index query per day: a range is bounded so a typo cannot turn one
# command into thousands of queries. Audit events expire after
# ENVAULT_AUDIT_TTL_DAYS (365 by default) anyway.
_AUDIT_MAX_DAYS = 366


def _utc_today() -> date:
    """Today's date in UTC, the calendar the audit trail's ``date`` attribute uses."""
    return datetime.now(timezone.utc).date()


@main.command()
@click.option("--file", "sha256_hash", default=None, help="Hash of a specific file.")
@click.option(
    "--since",
    default=None,
    help="First day to show, YYYY-MM-DD (UTC, inclusive).",
)
@click.option(
    "--until",
    default=None,
    help="Last day to show, YYYY-MM-DD (UTC, inclusive). Default: today. Needs --since.",
)
@click.option("--table", envvar="ENVAULT_TABLE", required=True)
@click.option("--region", envvar="ENVAULT_REGION", default="us-east-1")
def audit(
    sha256_hash: str | None, since: str | None, until: str | None, table: str, region: str
) -> None:
    """Show the audit trail, oldest event first.

    --file shows one file's events; --since/--until limit them to a range of
    UTC days. Without --file, every event in the range is shown (--since is
    then required). A range may span at most 366 days.
    """
    with _exit_on_error():
        window = _audit_window(since, until)
        store = StateStore(table_name=table, region=region)

        if sha256_hash:
            _validate_sha256(sha256_hash)
            events = store.list_events_for_file(sha256_hash)
            if window is not None:
                first, last = (day.isoformat() for day in window)
                events = [e for e in events if first <= str(e.get("date", "")) <= last]
        elif window is not None:
            events = store.list_events_between(*window, max_days=_AUDIT_MAX_DAYS)
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
                _display(ts),
                _display(op),
                _display(str(e.get("file_name", ""))),
                _id_prefix(e.get("sha256_hash", "")),
                _display(_short_principal(str(e.get("principal_arn", "")))),
                _display(str(e.get("correlation_id", ""))[:8]),
            )
        console.print(t)


def _audit_window(since: str | None, until: str | None) -> tuple[date, date] | None:
    """Validate --since/--until into an inclusive range of UTC days, or None."""
    if since is None:
        if until is not None:
            raise click.UsageError("--until needs --since.")
        return None
    first = _parse_day(since)
    last = _parse_day(until) if until is not None else _utc_today()
    if first > last:
        bound = f"--until {last.isoformat()}" + (" (today, UTC)" if until is None else "")
        raise click.UsageError(f"--since {first.isoformat()} is after {bound}.")
    span = (last - first).days + 1
    if span > _AUDIT_MAX_DAYS:
        raise click.UsageError(
            f"--since/--until span {span} days; audit reads one day at a time and "
            f"accepts at most {_AUDIT_MAX_DAYS}. Narrow the range."
        )
    return first, last


def _parse_day(value: str) -> date:
    """Parse a YYYY-MM-DD option value (exits with a message if malformed)."""
    return datetime.strptime(_validate_date(value), "%Y-%m-%d").date()


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------


@main.command()
@click.option("--table", envvar="ENVAULT_TABLE", required=True)
@click.option("--region", envvar="ENVAULT_REGION", default="us-east-1")
def dashboard(table: str, region: str) -> None:
    """Show a summary dashboard of all tracked files."""
    with _exit_on_error():
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
        t.add_row("Last activity:", _display(summary["last_activity"]))
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
@_audit_ttl_option
def migrate(from_path: Path, table: str, region: str, dry_run: bool, audit_ttl_days: int) -> None:
    """Import existing output.json metadata into DynamoDB.

    FROM_PATH is the path to code/output.json (NDJSON format).
    """
    store = StateStore(table_name=table, region=region)
    imported = skipped = errors = 0
    import_root = from_path.parent.resolve()

    lines = from_path.read_text().splitlines()
    for i, line in enumerate(track(lines, description="Migrating records..."), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            if not isinstance(entry, dict):
                raise MigrationError(
                    f"Expected a JSON object at line {i}, got {type(entry).__name__}"
                )
            record = _parse_output_json_entry(entry, import_root=import_root)
            if record is None:
                skipped += 1
                continue
            if not dry_run:
                store.put_current_state(record)
                store.put_event(
                    record,
                    operation="ENCRYPT",
                    correlation_id="migrated-from-output-json",
                    audit_ttl_days=audit_ttl_days,
                    principal_arn=caller_arn(region),
                )
            imported += 1
        except StateConflictError:
            logger.info("Record already exists, skipping migration for line %d", i)
            skipped += 1
        except (
            json.JSONDecodeError,
            KeyError,
            ValueError,
            TypeError,
            AttributeError,
            MigrationError,
        ) as exc:
            logger.warning("Failed to migrate record at line %d: %s", i, exc)
            errors += 1

    mode = "[dim](dry run)[/dim]" if dry_run else ""
    console.print(
        f"\n[green]Migrated {imported} records[/green], skipped {skipped}, errors {errors} {mode}"
    )


def _parse_output_json_entry(
    entry: dict[str, Any], *, import_root: Path | None = None
) -> FileRecord | None:
    """Convert an output.json record to a FileRecord. Returns None if not an encrypt record."""
    if entry.get("mode") != "encrypt":
        return None

    header = entry.get("header", {}) or {}
    if not isinstance(header, dict):
        raise MigrationError("header must be a JSON object")
    input_path = entry.get("input", "")
    if not input_path:
        return None

    plaintext_path = _confine_migration_path(input_path, import_root)

    file_name = S3Store._sanitize_filename(plaintext_path.name)
    algorithm = _extract_algorithm(header)
    message_id = _extract_message_id(header)
    kms_key_id = _extract_kms_key_id(header)
    enc_context = header.get("encryption_context", {}) or {}
    if not isinstance(enc_context, dict):
        raise MigrationError("encryption_context must be a JSON object")

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
    if not isinstance(edks, list) or not edks:
        return ""
    first = edks[0]
    if not isinstance(first, dict):
        return ""
    provider = first.get("key_provider", {})
    if not isinstance(provider, dict):
        return ""
    return str(provider.get("key_info", ""))


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
@click.option(
    "--latest",
    is_flag=True,
    help="Allow download when a record has no S3 VersionId (migrated files).",
)
@_audit_ttl_option
def rotate_key(
    new_key_id: str,
    table: str,
    bucket: str,
    region: str,
    dry_run: bool,
    allowed_account_ids: str,
    latest: bool,
    audit_ttl_days: int,
) -> None:
    """Re-encrypt all ENCRYPTED files under a new KMS key.

    Downloads each file, decrypts with the original key, re-encrypts with the new key,
    uploads back to S3, and updates DynamoDB state.
    """
    store = StateStore(table_name=table, region=region)
    s3 = S3Store(bucket=bucket, region=region, kms_key_id=new_key_id)
    correlation_id = str(uuid.uuid4())
    account_ids = _validate_account_ids(allowed_account_ids)

    if not dry_run:
        _preflight_kms_key(new_key_id, region)

    # Every tracked file still has ciphertext in S3 regardless of the state
    # recorded against it, so rotation must cover them all. Records written by
    # earlier versions were flipped to DECRYPTED on first read; skipping those
    # would silently leave the most-accessed files under the old key.
    with _exit_on_error():
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
            console.print(
                f"  Would rotate: {_display(r.file_name)} ({_id_prefix(r.sha256_hash)}...)"
            )
        return

    # Plaintext copies live in a private RAM directory where there is one; the
    # scratch destroys them, and the directory, however rotation ends.
    with _Scratch() as scratch:
        _rotate_records(
            records,
            scratch,
            store=store,
            s3=s3,
            new_key_id=new_key_id,
            bucket=bucket,
            region=region,
            account_ids=account_ids,
            latest=latest,
            audit_ttl_days=audit_ttl_days,
            correlation_id=correlation_id,
        )


def _rotate_records(
    records: list[FileRecord],
    scratch: _Scratch,
    *,
    store: StateStore,
    s3: S3Store,
    new_key_id: str,
    bucket: str,
    region: str,
    account_ids: list[str],
    latest: bool,
    audit_ttl_days: int,
    correlation_id: str,
) -> None:
    shm_dir = scratch.ram_dir()
    if shm_dir is None:
        console.print(
            "[dim yellow]Note: no RAM-backed filesystem available; temporary plaintext is "
            "written to disk and overwritten with zeros before deletion, but secure erasure "
            "is not guaranteed on copy-on-write filesystems (APFS, Btrfs, ZFS) or SSDs with "
            "wear-levelling.[/dim yellow]"
        )

    # Reuses the same context builder as encrypt so the two can never drift —
    # a divergent context here would make future decrypts fail verification.
    new_key_config = Config(key_id=new_key_id, bucket=bucket, region=region)

    rotated = errors = 0
    for record in track(records, description="Rotating keys..."):
        tmp_dl: Path | None = None
        tmp_pt: Path | None = None
        tmp_enc: Path | None = None
        try:
            tmp_dl = scratch.file(prefix="envault_dl_", suffix=".encrypted")
            tmp_pt = scratch.file(
                prefix="envault_pt_",
                directory=_plaintext_dir(shm_dir, record.file_size_bytes),
                plaintext=True,
            )
            tmp_enc = scratch.file(prefix="envault_enc_", suffix=".encrypted")

            _check_record(record)
            s3.download_file(
                record.s3_key,
                tmp_dl,
                _s3_version_id(record, latest),
                allow_latest=latest,
            )
            decrypt_file(
                tmp_dl,
                tmp_pt,
                expected_sha256=record.sha256_hash,
                region=region,
                allowed_account_ids=account_ids,
                expected_context=record.encryption_context,
            )
            scratch.discard(tmp_dl)

            new_ctx = new_key_config.build_encryption_context(record.sha256_hash, record.file_name)
            new_result = encrypt_file(tmp_pt, new_key_id, new_ctx, tmp_enc, region)
            scratch.discard(tmp_pt)

            # The new ciphertext gets a key of its own; the object the record
            # pinned so far is left exactly as it is (and stays readable with
            # the old key until that key is disabled).
            new_s3_key = s3.s3_key_for_file(
                record.sha256_hash, record.file_name, message_id=new_result.message_id
            )
            new_version_id = s3.upload_file(tmp_enc, new_s3_key, if_none_match=True)

            original_last_updated = record.last_updated
            old_kms_key = record.kms_key_id
            old_s3_key = record.s3_key
            now = datetime.now(timezone.utc).isoformat(timespec="microseconds")
            record.kms_key_id = new_key_id
            record.encryption_context = new_ctx
            record.algorithm = new_result.algorithm
            record.message_id = new_result.message_id
            record.s3_key = new_s3_key
            record.s3_version_id = new_version_id
            record.last_updated = now
            # Legacy records land back in ENCRYPTED: the ciphertext is present,
            # which is what the field is supposed to describe.
            record.current_state = ENCRYPTED
            try:
                store.put_current_state(record, expected_last_updated=original_last_updated)
            except Exception:
                logger.error(
                    "State write failed after S3 re-upload during key rotation. The new "
                    "object is an orphan: the record still points to the old, intact one, "
                    "and the orphan can be deleted.",
                    extra={
                        "sha256": record.sha256_hash,
                        "s3_key": new_s3_key,
                        "s3_version_id": new_version_id,
                        "old_s3_key": old_s3_key,
                        "old_kms_key": old_kms_key,
                        "new_kms_key": new_key_id,
                        "correlation_id": correlation_id,
                    },
                )
                raise
            try:
                store.put_event(
                    record,
                    operation="ROTATE_KEY",
                    correlation_id=correlation_id,
                    audit_ttl_days=audit_ttl_days,
                    principal_arn=caller_arn(region),
                )
            except Exception:
                logger.error(
                    "The file was rotated and its record updated, but its ROTATE_KEY audit "
                    "event could not be recorded.",
                    extra={
                        "s3_key": new_s3_key,
                        "old_kms_key": old_kms_key,
                        "new_kms_key": new_key_id,
                        "correlation_id": correlation_id,
                    },
                )
                raise
            rotated += 1
        except (EnvaultError, ClientError, BotoCoreError, OSError) as exc:
            console.print(
                f"[red]Error rotating {_display(record.file_name)}: {_display(exc)}[/red]"
            )
            errors += 1
        finally:
            scratch.discard(tmp_dl, tmp_pt, tmp_enc)

    console.print(f"\n[green]Rotated {rotated} files[/green], {errors} errors.")
    if errors:
        # A partially-rotated corpus means some files are still readable with the
        # old key. Exiting 0 here would report an incomplete rotation as success.
        console.print(
            f"[bold red]Rotation incomplete:[/bold red] {errors} file(s) are still "
            "encrypted under the previous key."
        )
        sys.exit(1)


def _private_ram_dir() -> Path | None:
    """Create a 0700 scratch directory on a RAM-backed filesystem, if there is one.

    Plaintext written here never reaches persistent storage (it can still be
    swapped, like any process memory). Returns None where /dev/shm is absent.
    """
    shm = Path("/dev/shm")  # noqa: S108 — the point is RAM backing, not a shared name
    if not shm.is_dir():
        return None
    try:
        return Path(tempfile.mkdtemp(prefix="envault_rot_", dir=shm))
    except OSError:
        return None


def _plaintext_dir(shm_dir: Path | None, size: int) -> Path | None:
    """Use the RAM directory unless the file would take more than half its free space."""
    if shm_dir is not None and size * 2 < shutil.disk_usage(shm_dir).free:
        return shm_dir
    return None


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


# Option parsing stops at the first argument that is not an envault option:
# everything from COMMAND on belongs to the child, so `aws s3 ls --region x`
# or `psql -f schema.sql` reach it intact with or without `--`.
@main.command(
    "exec",
    context_settings={"ignore_unknown_options": True, "allow_interspersed_args": False},
)
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
@click.option(
    "--latest",
    is_flag=True,
    help="Allow download when a record has no S3 VersionId (migrated files).",
)
@_audit_ttl_option
@click.argument("command", nargs=-1, type=click.UNPROCESSED)
def exec_(
    env_specs: tuple[str, ...],
    file_specs: tuple[str, ...],
    table: str,
    bucket: str,
    region: str,
    allowed_account_ids: str,
    clean_env: bool,
    latest: bool,
    audit_ttl_days: int,
    command: tuple[str, ...],
) -> None:
    """Run a command with secrets supplied in memory, never on disk.

    \b
      envault exec -s db.env=DATABASE_URL -- ./server
      envault exec -f server.pem=TLS_CERT -- curl --cert {TLS_CERT} https://api

    envault's options go before COMMAND. Everything from COMMAND on is passed
    to it unchanged, including options such as ``--region`` or ``-f``, so the
    ``--`` separator is optional.

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
    if command[0].startswith("-"):
        # An unknown option before COMMAND would otherwise become the program.
        raise click.UsageError(
            f"No such option: {command[0]}. envault's options go before COMMAND."
        )
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
    if not clean_env and any(key.startswith("AWS_") for key in child_env):
        console.print(
            "[yellow]Warning:[/yellow] the child will inherit AWS credentials from this "
            "environment. Pass --clean-env to start it from a minimal environment."
        )

    creds: list[CredentialFd] = []
    sinks: list[_BufferSink] = []
    accessed: list[FileRecord] = []
    try:
        for identifier, var in env_pairs:
            selection = _resolve_identifier(identifier, store, newest_only=True)
            sink = _BufferSink()
            sinks.append(sink)
            _stream_secret(selection, sink, s3, region, account_ids, allow_latest=latest)
            child_env[var] = _decode_secret(sink.buf, identifier)
            accessed.append(selection.record)

        for identifier, var in file_pairs:
            selection = _resolve_identifier(identifier, store, newest_only=True)
            cred = CredentialFd(var)
            creds.append(cred)
            with cred.writer() as out:
                _stream_secret(selection, out, s3, region, account_ids, allow_latest=latest)
            # Sealed only after the checksum and encryption context verified.
            cred.seal()
            child_env[var] = cred.child_path
            accessed.append(selection.record)
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
                audit_ttl_days=audit_ttl_days,
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
            f"(expected {_id_prefix(exc.expected)}..., got {_id_prefix(exc.actual)}...).\n"
            "The encrypted data may have been corrupted or tampered with."
        )
        sys.exit(1)
    except (EnvaultError, ClientError, BotoCoreError, OSError) as exc:
        _close_all(creds, sinks)
        _report_error("Refusing to run", exc)
        console.print("No command was started and no secrets were delivered.")
        sys.exit(1)
    except click.UsageError:
        # Non-UTF-8 / NUL secrets raise here after plaintext is already in sinks.
        _close_all(creds, sinks)
        raise
    except BaseException:
        # Interrupted (a signal): nothing is handed over; wipe what we hold.
        _close_all(creds, sinks)
        raise

    argv = _substitute_paths(list(command), child_env, [var for _, var in file_pairs])

    # Wipe what we can before handing over. The env values themselves are
    # immutable strings destined for the child, and execve replaces this address
    # space wholesale — which disposes of every plaintext copy CPython made
    # along the way far more thoroughly than anything we could do here.
    for sink in sinks:
        wipe(sink.buf)
    sys.stdout.flush()
    sys.stderr.flush()

    # execve resets envault's own signal handlers to their defaults in the child
    # (and keeps a SIGHUP the parent ignored, ignored); nothing is blocked.
    previous_handlers = _default_signals_for_child()
    try:
        # No shell, deliberately: argv is passed through untouched so a secret or
        # filename can never be reinterpreted as shell syntax. execve (rather
        # than fork) also replaces this address space, discarding every plaintext
        # copy CPython made while decrypting.
        os.execvpe(argv[0], argv, child_env)  # noqa: S606
    except OSError as exc:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        _close_all(creds, [])
        console.print(f"[bold red]Could not run {_display(argv[0])}:[/bold red] {_display(exc)}")
        sys.exit(127)


def _close_all(creds: list[CredentialFd], sinks: list[_BufferSink]) -> None:
    for cred in creds:
        cred.close()
    for sink in sinks:
        wipe(sink.buf)


def _stream_secret(
    selection: _Selection,
    out: Any,
    s3: S3Store,
    region: str,
    account_ids: list[str],
    *,
    allow_latest: bool = False,
) -> None:
    """Fetch a record's ciphertext and decrypt it into ``out``, verifying first."""
    record = selection.record
    _check_record(record)
    ciphertext = s3.download_to_memory(
        record.s3_key,
        _s3_version_id(record, allow_latest),
        allow_latest=allow_latest,
    )
    decrypt_to_stream(
        ciphertext,
        out,
        expected_sha256=selection.expected_sha256,
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


_TAG_KEY_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")
_TAG_VALUE_MAX_LEN = 256


def _s3_version_id(record: FileRecord, allow_latest: bool) -> str:
    """Return the stored VersionId, or empty if ``--latest`` was passed.

    An empty stored VersionId without ``--latest`` is a fail-closed error:
    fetching current would silently decrypt a different object if the key
    was overwritten after encryption (typical of migrated records).
    """
    if record.s3_version_id:
        return record.s3_version_id
    if allow_latest:
        return ""
    raise EnvaultError(
        "Refusing to download without an S3 VersionId. "
        "This record has an empty version id (typical of migrated files). "
        "Pass --latest to fetch the current object, or re-encrypt so a version is stored."
    )


def _preflight_kms_key(key_id: str, region: str) -> None:
    """Fail before any plaintext is written if the target CMK is unusable."""
    kms = boto3.client("kms", region_name=region, config=boto_config)
    try:
        metadata = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    except (ClientError, BotoCoreError) as exc:
        console.print(
            f"[bold red]Cannot use KMS key {_display(key_id)}:[/bold red] "
            f"{_display(_error_message(exc))}\n"
            "Rotation did not download or decrypt any files. Grant kms:DescribeKey "
            "(and GenerateDataKey) on the target key, or pass a key this principal can use."
        )
        sys.exit(1)
    state = str(metadata.get("KeyState", ""))
    if state != "Enabled":
        console.print(
            f"[bold red]Cannot use KMS key {_display(key_id)}:[/bold red] "
            f"key state is {_display(state) or 'unknown'}, not Enabled.\n"
            "Rotation did not download or decrypt any files."
        )
        sys.exit(1)


def _path_has_symlink_component(path: Path) -> bool:
    """True if any existing component of ``path`` is a symlink."""
    parts = path.parts
    if not parts:
        return False
    if path.is_absolute():
        current = Path(parts[0])
        rest = parts[1:]
    else:
        current = Path()
        rest = parts
    for part in rest:
        current = current / part
        try:
            if current.is_symlink():
                return True
        except OSError:
            return True
    return False


def _confine_migration_path(input_path: str, import_root: Path | None) -> Path:
    """Resolve a migration input path, rejecting traversal and per-component symlinks.

    ``import_root`` is required. Absolute paths are checked for lexical
    containment *before* any ``lstat``, so a poisoned output.json cannot
    cause the importer to touch files outside the import directory.
    """
    candidate = Path(input_path)
    if ".." in candidate.parts:
        raise MigrationError(f"Path traversal not allowed in migration input: {input_path!r}")
    if import_root is None:
        raise MigrationError(
            "import_root is required; refusing to hash an unconstrained migration path"
        )

    root = import_root.resolve()
    if candidate.is_absolute():
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise MigrationError(
                f"Path {input_path!r} is outside the import directory {str(root)!r}"
            ) from exc
        joined = candidate
    else:
        joined = root / candidate

    if _path_has_symlink_component(joined):
        raise MigrationError(f"Symlink not allowed in migration input: {input_path!r}")

    resolved = joined.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise MigrationError(
            f"Path {input_path!r} is outside the import directory {str(root)!r}"
        ) from exc
    return resolved


def _validate_date(value: str) -> str:
    """Validate a YYYY-MM-DD date string."""
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        console.print(
            f"[red]Invalid date: {_display(repr(value))}. Expected format: YYYY-MM-DD.[/red]"
        )
        sys.exit(1)
    return value


# ---------------------------------------------------------------------------
# File identifiers
#
# Everything the CLI does with a file identifier is in this section:
# recognising one on the command line, resolving IDENTIFIER (an identifier or
# a stored name) to a record, checking a record against the identifier it was
# looked up by and against its S3 key, and the short form shown to operators.
# Today the identifier is the SHA-256 of the plaintext; another scheme changes
# these helpers, not the commands.
# ---------------------------------------------------------------------------


_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _validate_sha256(value: str) -> str:
    """Validate a SHA256 hash string. Exit with error if invalid."""
    if not _is_sha256(value):
        console.print(
            f"[red]Invalid SHA256 hash: {_display(repr(value))}. "
            "Expected 64 lowercase hexadecimal characters.[/red]"
        )
        sys.exit(1)
    return value


def _is_sha256(value: str) -> bool:
    """Return True if value looks like a full 64-char hex SHA256 hash."""
    return bool(_SHA256_RE.fullmatch(value))


def _id_prefix(identifier: object) -> str:
    """Short form of a file identifier for messages and tables (first 16 characters).

    The one place that decides how identifiers are shown to the operator.
    Identifiers read from DynamoDB are untrusted, so the prefix is escaped.
    """
    return _display(str(identifier)[:16])


def _fallback_output_name(record: FileRecord) -> str:
    """Output file name when a record's stored name cannot be used as one."""
    return f"decrypted_{record.sha256_hash[:16]}"


def _check_record(record: FileRecord) -> None:
    """Refuse a row whose identifier or S3 key is not well formed.

    Rows come from DynamoDB, which any principal with write access can edit. The
    identifier ends up in the expected checksum and in file names, and the key
    decides which object is fetched.

    Raises:
        _IdentifierError: The identifier is not 64 lowercase hex characters.
        InvalidS3KeyError: The key is not this identifier's content-addressed path.
    """
    if not _is_sha256(record.sha256_hash):
        raise _IdentifierError(
            f"The record for {record.file_name!r} has a malformed identifier; refusing to use it."
        )
    assert_s3_key_matches_hash(record.s3_key, record.sha256_hash, message_id=record.message_id)


class _IdentifierError(EnvaultError):
    """IDENTIFIER matched no record, several, or a row that contradicts it.

    ``candidates`` are the records an operator can choose between, listed under
    the message; ``numbered`` lists them with their --version numbers.
    """

    def __init__(
        self, message: str, candidates: Sequence[FileRecord] = (), *, numbered: bool = False
    ) -> None:
        super().__init__(message)
        self.candidates = tuple(candidates)
        self.numbered = numbered


@dataclass(frozen=True)
class _Selection:
    """The record IDENTIFIER resolved to, and the identifier its plaintext must have."""

    record: FileRecord
    expected_sha256: str


def _resolve_identifier(
    identifier: str,
    store: StateStore,
    *,
    version: int | None = None,
    newest_only: bool = False,
) -> _Selection:
    """Resolve IDENTIFIER (an identifier or a stored file name) to one record.

    An identifier must find a row that says it is about that identifier, and
    the plaintext is then checked against the identifier the operator typed,
    never against what the row claims. Name lookups have no such anchor: they
    trust every principal that can write to the table.

    A name is matched exactly against stored names first. Only when nothing is
    stored under exactly that name, and the name has no directory part, do
    stored paths with that basename match (rows written before stored names
    became relative paths hold a bare basename). Matches spanning more than one
    stored name are ambiguous and refused. Several records under one exact name
    are versions, newest first by ``encrypted_at`` read as a time: --version
    picks one (default: the newest). If the newest two have the same
    timestamp, which one is newest is unknown: with ``newest_only`` (exec) or
    without an explicit ``version`` the lookup is refused.

    Raises:
        _IdentifierError: Nothing matches, the match is ambiguous, or the row
            stored under an identifier describes another file.
    """
    if _is_sha256(identifier):
        record = store.get_current_state(identifier)
        if record is None:
            raise _IdentifierError(f"No record found for hash {identifier[:16]}...")
        if record.sha256_hash != identifier:
            raise _IdentifierError(
                f"The record stored under {identifier[:16]}... describes a different file "
                f"({str(record.sha256_hash)[:16]}...). Refusing to use it: the state table "
                "may have been tampered with."
            )
        return _Selection(record, expected_sha256=identifier)

    candidates = _records_named(identifier, store)
    if not candidates:
        raise _IdentifierError(f"No encrypted files found with name {identifier!r}.")
    versions = _newest_first(candidates)
    if len({r.file_name for r in candidates}) > 1:
        raise _IdentifierError(
            f"The name {identifier!r} is ambiguous: it matches {len(versions)} files stored "
            "under different names. Use the full stored name or the identifier:",
            versions,
        )
    tie = len(versions) > 1 and _encrypted_at(versions[0]) == _encrypted_at(versions[1])
    if tie and (newest_only or version is None):
        how = "Use the identifier" if newest_only else "Pass --version N to choose one"
        raise _IdentifierError(
            f"The newest versions of {identifier!r} were encrypted at the same time, so "
            f"which one is current is unknown. {how}:",
            versions,
            numbered=not newest_only,
        )
    index = 1 if newest_only or version is None else version
    if index > len(versions):
        raise _IdentifierError(
            f"Version {index} out of range. Found {len(versions)} version(s) of {identifier!r}."
        )
    selected = versions[index - 1]
    if len(versions) > 1:
        label = "most recent" if index == 1 else f"version {index}"
        hint = "" if newest_only else " Use --version N to pick another."
        console.print(
            f"[dim]{len(versions)} versions found. Using {label} "
            f"({_display(selected.encrypted_at)}).{hint}[/dim]"
        )
    return _Selection(selected, expected_sha256=selected.sha256_hash)


def _records_named(name: str, store: StateStore) -> list[FileRecord]:
    """ENCRYPTED records stored under ``name``, else (bare names only) under that basename."""
    exact = store.list_by_file_name(name, ENCRYPTED)
    if exact or "/" in name:
        return exact
    return [r for r in store.list_by_state(ENCRYPTED) if PurePosixPath(r.file_name).name == name]


_UNKNOWN_TIME = datetime.min.replace(tzinfo=timezone.utc)


def _encrypted_at(record: FileRecord) -> datetime:
    """``encrypted_at`` as a time; rows predating microsecond timestamps compare correctly."""
    value = record.encrypted_at
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return _UNKNOWN_TIME
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _newest_first(records: Iterable[FileRecord]) -> list[FileRecord]:
    """Newest first by ``encrypted_at``; ties ordered by identifier, so --version N is stable."""
    return sorted(records, key=lambda r: (_encrypted_at(r), r.sha256_hash), reverse=True)


def _error_message(exc: BaseException) -> str:
    """One line for an error: AWS's own message for a ClientError, else the text."""
    if isinstance(exc, ClientError):
        return str(exc.response.get("Error", {}).get("Message") or exc)
    return str(exc)


def _report_error(headline: str, exc: BaseException) -> None:
    """Print ``headline: message``, plus the records to choose from for an identifier error."""
    console.print(f"[bold red]{headline}:[/bold red] {_display(_error_message(exc))}")
    if isinstance(exc, _IdentifierError):
        for number, record in enumerate(exc.candidates, start=1):
            label = f"--version {number}  " if exc.numbered else ""
            console.print(
                f"  {label}{_id_prefix(record.sha256_hash)}  {_display(record.file_name)}"
                f"  {_display(record.encrypted_at)}"
            )


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
                f"[red]Invalid AWS account ID: {_display(repr(account_id))}. "
                "Must be 12 digits.[/red]"
            )
            sys.exit(1)
    return account_ids


@dataclass(frozen=True)
class _CollectedFile:
    """A regular file selected for encryption, and the name it is stored under."""

    path: Path
    #: The file's path relative to the directory given to encrypt, with "/"
    #: separators (its basename when a single file was given). Two files with
    #: the same basename in different directories stay distinguishable.
    name: str
    #: ``(st_dev, st_ino)`` from ``lstat`` at collection time. Encryption opens
    #: the path only if it is still this inode.
    identity: tuple[int, int]


def _collect_files(path: Path) -> list[_CollectedFile]:
    """Regular files under ``path``, never following directory or file symlinks."""
    try:
        top = os.lstat(path)
    except OSError:
        return []
    if stat.S_ISREG(top.st_mode):
        return [_CollectedFile(path=path, name=path.name, identity=(top.st_dev, top.st_ino))]
    if not stat.S_ISDIR(top.st_mode):  # a symlink, FIFO, socket or device
        return []
    files: list[_CollectedFile] = []
    for root, dirnames, filenames in os.walk(path, followlinks=False):
        # os.walk(followlinks=False) still lists symlink directories; drop them
        # so we never encrypt a tree the operator did not intend to include.
        dirnames[:] = sorted(d for d in dirnames if not Path(root, d).is_symlink())
        for filename in sorted(filenames):
            candidate = Path(root) / filename
            try:
                st = os.lstat(candidate)
            except OSError:
                continue  # vanished during the walk
            if stat.S_ISREG(st.st_mode):
                files.append(
                    _CollectedFile(
                        path=candidate,
                        name=candidate.relative_to(path).as_posix(),
                        identity=(st.st_dev, st.st_ino),
                    )
                )
    return files


def _parse_tags(tag_strs: tuple[str, ...]) -> dict[str, str]:
    tags: dict[str, str] = {}
    for t in tag_strs:
        if "=" not in t:
            console.print(
                f"[yellow]Ignoring invalid tag '{_display(t)}' (expected KEY=VALUE)[/yellow]"
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
