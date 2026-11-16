"""envault CLI — Click-based command-line interface."""

from __future__ import annotations

import base64
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
)
from envault.exceptions import (
    AlreadyEncryptedError,
    ChecksumMismatchError,
    ConfigurationError,
    EncryptionContextMismatchError,
    EnvaultError,
    InvalidS3KeyError,
    KMSError,
    MalformedRecordError,
    MigrationError,
    StateConflictError,
)
from envault.fileid import (
    ID_SCHEME_HMAC_SHA256,
    ID_SCHEME_SHA256,
    ID_SCHEMES,
    FileIdVerifier,
    IdKey,
    check_id_key_arn,
    is_file_id,
    sha256_digest,
)
from envault.fileutils import best_effort_delete as _best_effort_delete
from envault.fileutils import open_regular_nofollow
from envault.identity import caller_arn
from envault.isolation import CredentialFd, harden_process, wipe
from envault.retry import aws_retry
from envault.s3 import (
    LEGACY_S3_PREFIX,
    S3Store,
    assert_legacy_s3_key,
    assert_s3_key_matches_hash,
)
from envault.state import (
    DECRYPTED,
    ENCRYPTED,
    S3_KEY_CONTENT_ADDRESSED,
    S3_KEY_LEGACY_SYNC,
    FileRecord,
    StateStore,
    item_file_id,
)

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
# it up, even inside a deferred section. Signals are deferred (held, then acted
# on), never blocked with a signal mask, which the command `exec` starts would
# inherit.
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
    """Handler for SIGTERM, SIGHUP and SIGINT once the entry point installed it.

    Every stop signal counts towards the third-signal escape, including those
    that arrive while a deferred section holds the first: a cleanup that hangs
    inside one must not make the process unkillable short of SIGKILL.
    """
    if _signals.stopping is not None or _signals.pending is not None:
        _signals.ignored += 1
        if _signals.ignored > _SIGNALS_IGNORED_WHILE_STOPPING:
            # The operator insists: end now, cleanup or not.
            signal.signal(signum, signal.SIG_DFL)
            os.kill(os.getpid(), signum)
        return
    if _signals.deferring:
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
        try:
            previous[signum] = signal.signal(signum, _on_stop_signal)
        except ValueError:  # not the main thread: leave signal handling alone
            break

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


# The HMAC key that names files (M6, see envault.fileid). encrypt and migrate
# cannot run without it: there is no fallback to naming files by the SHA-256 of
# their content. decrypt, exec, status and audit use it only to look a file up
# by that SHA-256: while it is set, 64 hex characters are mapped with it first,
# so a SHA-256 is never sent to DynamoDB. Reading a keyed record verifies it
# with the key the record names, configured or not.
_ID_KEY_HELP = (
    "KMS HMAC key (HMAC_256, GENERATE_VERIFY_MAC) that names files, as an alias, key ID "
    "or ARN, e.g. alias/envault-id from the envault stack."
)
_id_key_required_option = click.option(
    "--id-key-id",
    envvar="ENVAULT_ID_KEY_ID",
    default=None,
    metavar="KEY",
    help=f"{_ID_KEY_HELP} Required.",
)
_id_key_lookup_option = click.option(
    "--id-key-id",
    envvar="ENVAULT_ID_KEY_ID",
    default=None,
    metavar="KEY",
    help=f"{_ID_KEY_HELP} Optional: lets a file be looked up by the SHA-256 of its content. "
    "While it is set, 64 hex characters are first mapped through it (kms:GenerateMac), so a "
    "SHA-256 is never sent to DynamoDB.",
)


def _require_id_key(id_key_id: str | None, region: str) -> IdKey:
    """The configured identifier key; a usage error (exit 2) if there is none."""
    if not id_key_id:
        raise click.UsageError(
            "No key to name files with: pass --id-key-id or set ENVAULT_ID_KEY_ID to the KMS "
            "HMAC key that derives file identifiers (alias/envault-id in the envault stack). "
            "envault no longer names new files by the SHA-256 of their content."
        )
    return IdKey(id_key_id, region)


def _optional_id_key(id_key_id: str | None, region: str) -> IdKey | None:
    return IdKey(id_key_id, region) if id_key_id else None


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
@_id_key_required_option
@_audit_ttl_option
def encrypt(
    input_path: Path,
    key_id: str,
    bucket: str,
    table: str,
    tag: tuple[str, ...],
    force: bool,
    region: str,
    id_key_id: str | None,
    audit_ttl_days: int,
) -> None:
    """Encrypt a file or directory and store state in DynamoDB.

    INPUT_PATH can be a single file or a directory (processed recursively;
    symlinks are not followed). Each file is stored under its path relative to
    INPUT_PATH (prod/db.env), a single file under its name; decrypt and exec
    accept that name. Every upload goes to a new S3 key: no upload replaces an
    object a record points to.

    Each file is identified by an HMAC of its SHA-256 under the --id-key-id
    key (ENVAULT_ID_KEY_ID), which reveals nothing about its content; the
    SHA-256 itself is never stored, uploaded or printed.
    """
    id_key = _require_id_key(id_key_id, region)
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
            _encrypt_one(item, config, tags, store, s3, file_correlation_id, force, id_key)
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
    id_key: IdKey,
) -> None:
    # One descriptor for the dedup hash and the encryption, opened without
    # following a symlink and only if it is still the inode collected: a path
    # swapped since the walk is refused, and a swap after this open changes
    # nothing that is read.
    fd = open_regular_nofollow(item.path, expected=item.identity)
    try:
        _encrypt_fd(fd, item, config, tags, store, s3, correlation_id, force, id_key)
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
    id_key: IdKey,
) -> None:
    name = item.name
    # The SHA-256 never leaves this function: KMS turns its digest into the
    # file's identifier, and only that is stored, uploaded, logged or printed.
    sha256 = sha256_fd(fd)
    keyed = id_key.file_id(sha256_digest(sha256))
    file_id = keyed.file_id

    # Deduplicate on the keyed identifier only. Looking up FILE#<sha256> as
    # well would send the content hash to DynamoDB (and to CloudTrail data
    # events); a file known only by a legacy record gets a new, keyed one.
    existing = store.get_current_state(file_id)
    if existing and existing.current_state == ENCRYPTED and not force:
        raise AlreadyEncryptedError(file_id=file_id, file_name=name)

    # Microseconds: versions of one name are ordered by this, and two files
    # encrypted within the same second must not tie.
    now = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    # Built from the pre-read hash; the bytes encrypted are checked against it below.
    enc_context = config.build_encryption_context(file_id, name)

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
            # Neither hash is named: both are hashes of plaintext (M6).
            raise EnvaultError(
                f"File {name!r} was modified during encryption: the bytes encrypted are not "
                "the bytes hashed before. Aborting to avoid storing mismatched metadata."
            )

        # A key of its own for every upload (it embeds the message id), written
        # only if nothing is there: no upload can make the version another
        # record pins noncurrent. The name part is the stored name's basename.
        s3_key = s3.s3_key_for_file(file_id=file_id, file_name=name, message_id=result.message_id)
        version_id = s3.upload_file(local_path=tmp_encrypted, s3_key=s3_key, if_none_match=True)

    record = FileRecord(
        file_id=file_id,
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
        id_scheme=ID_SCHEME_HMAC_SHA256,
        id_key_arn=keyed.key_arn,
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
                "file_id": file_id,
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
    # Kept as typed: a trailing separator says "directory", and Path() drops it.
    type=click.Path(),
    default=".",
    show_default=True,
    help="Existing directory (file keeps its original name) or the output file path. "
    "A path ending in / must be an existing directory.",
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
@_id_key_lookup_option
@_audit_ttl_option
def decrypt(
    identifier: str,
    output: str,
    force: bool,
    table: str,
    bucket: str,
    region: str,
    version: int | None,
    allowed_account_ids: str,
    latest: bool,
    id_key_id: str | None,
    audit_ttl_days: int,
) -> None:
    """Decrypt a file by identifier, SHA-256 or stored name.

    \b
    IDENTIFIER is one of:
      - the file's identifier, 64 hex characters as `status` lists it;
      - the SHA-256 of its content, with --id-key-id / ENVAULT_ID_KEY_ID set
        (the content is then checked against that SHA-256 too);
      - the name it was stored under: its path relative to the directory given
        to encrypt (prod/db.env), or its basename when that is unambiguous.
    When several files are stored under the same name, use --version N to pick one.
    """
    destination = _output_destination(output)
    store = StateStore(table_name=table, region=region)
    s3 = S3Store(bucket=bucket, region=region)
    correlation_id = str(uuid.uuid4())
    account_ids = _validate_account_ids(allowed_account_ids)
    verifier = FileIdVerifier(region=region, allowed_account_ids=account_ids)

    with _exit_on_error("Decryption error"):
        selection = _resolve_identifier(
            identifier, store, version=version, id_key=_optional_id_key(id_key_id, region)
        )
        record = selection.record
        _check_record(record, region=region, allowed_account_ids=account_ids)

    if destination.is_dir():
        safe_name = Path(record.file_name).name
        # The name comes from DynamoDB: no hidden files, no control or
        # invisible characters in a name the operator's tools will print.
        if not safe_name or safe_name.startswith(".") or _has_unsafe_characters(safe_name):
            safe_name = _fallback_output_name(record)
        output_path = destination / safe_name
    else:
        output_path = destination

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
            # A keyed identifier is verified while the plaintext is still in a
            # hidden .part file: only plaintext that passed every check is ever
            # named ".verified", and the read is recorded before it is published.
            decrypt_file(
                input_path=tmp_encrypted,
                output_path=staging,
                expected_sha256=selection.expected_sha256,
                region=region,
                allowed_account_ids=account_ids,
                expected_context=record.encryption_context,
                verify_digest=_identity_check(selection, verifier),
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
                    extra={"file_id": record.file_id, "s3_key": record.s3_key},
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
                f"  File: {_display(record.file_name)}  ID: {_id_prefix(record.file_id)}..."
            )
            sys.exit(1)
        except ChecksumMismatchError:
            # Named by the identifier it should have had, never by the hash of
            # what was decrypted (M6): for a short file that hash is the content.
            console.print(
                "[bold red]Decryption failed:[/bold red] checksum mismatch.\n"
                "The decrypted content is not the file this record identifies "
                f"({_id_prefix(selection.expected_file_id)}...). No plaintext was written.\n"
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


def _output_destination(raw: str) -> Path:
    """decrypt's -o value as a path. Written as a directory, it must be one.

    ``Path("out/")`` is ``Path("out")``: without this check a missing
    directory became a file of that name (and ``a/b/`` a file ``b`` in a new
    directory ``a``).

    Raises:
        click.UsageError: ``raw`` ends with a path separator and is not an
            existing directory (exit 2, before anything is read).
    """
    separators = tuple(sep for sep in (os.sep, os.altsep) if sep)
    if raw.endswith(separators) and not Path(raw).is_dir():
        raise click.UsageError(
            f"--output {raw!r} ends with {raw[-1]!r} but is not an existing directory. "
            "Create the directory first, or leave out the trailing separator to write "
            "to a file of that name."
        )
    return Path(raw)


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
@click.option(
    "--file",
    "identifier",
    default=None,
    help="A file's identifier, as status lists it, or the SHA-256 of its content "
    "(with --id-key-id).",
)
@click.option("--table", envvar="ENVAULT_TABLE", required=True)
@click.option("--region", envvar="ENVAULT_REGION", default="us-east-1")
@_id_key_lookup_option
def status(
    state: str, identifier: str | None, table: str, region: str, id_key_id: str | None
) -> None:
    """Show current encryption state of files.

    A malformed record (an attribute of a type envault never writes) is left
    out of the listing with a warning; --file refuses one (exit 1).
    """
    with _exit_on_error():
        store = StateStore(table_name=table, region=region)

        if identifier:
            _validate_identifier(identifier)
            selection = _record_by_id(identifier, store, _optional_id_key(id_key_id, region))
            _print_records([selection.record])
            return

        records = []
        malformed: list[MalformedRecordError] = []
        if state in ("encrypted", "all"):
            records.extend(store.list_by_state(ENCRYPTED, on_malformed=malformed.append))
        if state in ("decrypted", "all"):
            records.extend(store.list_by_state(DECRYPTED, on_malformed=malformed.append))
        for problem in malformed:
            console.print(f"[yellow]Warning:[/yellow] {_display(problem)}")

        if not records:
            if not malformed:
                console.print("[yellow]No records found.[/yellow]")
            return
        _print_records(records)


def _print_records(records: list[FileRecord]) -> None:
    t = Table(show_header=True, header_style="bold cyan")
    t.add_column("File", style="white")
    t.add_column("State")
    t.add_column("ID (16)")
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
            _id_prefix(r.file_id),
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
@click.option(
    "--file",
    "identifier",
    default=None,
    help="A file's identifier, as status lists it, or the SHA-256 of its content "
    "(with --id-key-id).",
)
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
@_id_key_lookup_option
def audit(
    identifier: str | None,
    since: str | None,
    until: str | None,
    table: str,
    region: str,
    id_key_id: str | None,
) -> None:
    """Show the audit trail, oldest event first.

    --file shows one file's events; --since/--until limit them to a range of
    UTC days. Without --file, every event in the range is shown (--since is
    then required). A range may span at most 366 days.
    """
    with _exit_on_error():
        window = _audit_window(since, until)
        store = StateStore(table_name=table, region=region)

        if identifier:
            _validate_identifier(identifier)
            events = _events_by_id(identifier, store, _optional_id_key(id_key_id, region))
            if window is not None:
                first, last = (day.isoformat() for day in window)
                events = [e for e in events if first <= str(e.get("date", "")) <= last]
        elif window is not None:
            events = store.list_events_between(*window, max_days=_AUDIT_MAX_DAYS)
        else:
            console.print("[yellow]Provide --file or --since.[/yellow]")
            sys.exit(1)

        if not events:
            hint = f" {_SHA256_LOOKUP_HINT}" if identifier and not id_key_id else ""
            console.print(f"[yellow]No events found.{_display(hint)}[/yellow]")
            return

        t = Table(show_header=True, header_style="bold cyan")
        t.add_column("Timestamp")
        t.add_column("Operation")
        t.add_column("File")
        t.add_column("ID (16)")
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
                _id_prefix(item_file_id(e)),
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


# KMS key ARNs as the Encryption SDK records them for a KMS data key.
_KMS_KEY_ARN_RE = re.compile(
    r"arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/"
    r"(?:mrk-[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
)


@main.command()
@click.argument("from_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--table", envvar="ENVAULT_TABLE", required=True)
@click.option("--region", envvar="ENVAULT_REGION", default="us-east-1")
@click.option(
    "--plaintext-root",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Directory the legacy workflow encrypted (its INPUT_DIR). "
    "Default: the encrypt/ directory next to FROM_PATH's directory.",
)
@click.option(
    "--ciphertext-root",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Directory aws-encryption-cli wrote ciphertext to, which `aws s3 sync` uploaded "
    "under encrypted/ (its OUTPUT_DIR). Default: the encrypted/ directory next to "
    "FROM_PATH's directory.",
)
@click.option(
    "--bucket",
    envvar="ENVAULT_BUCKET",
    default=None,
    help="Bucket the legacy workflow synced to. Each object must exist there; its current "
    "VersionId is pinned, so decrypt needs no --latest.",
)
@click.option("--dry-run", is_flag=True, help="Parse and verify without writing to DynamoDB.")
@_id_key_required_option
@_audit_ttl_option
def migrate(
    from_path: Path,
    table: str,
    region: str,
    plaintext_root: Path | None,
    ciphertext_root: Path | None,
    bucket: str | None,
    dry_run: bool,
    id_key_id: str | None,
    audit_ttl_days: int,
) -> None:
    """Import the legacy shell workflow's metadata into DynamoDB.

    FROM_PATH is the file aws-encryption-cli wrote with --metadata-output
    (code/output.json): one JSON record per encrypted file, with absolute
    paths. Each record becomes an ENCRYPTED record named by the keyed
    identifier of its plaintext (an HMAC of its SHA-256 under --id-key-id),
    which is why the plaintext must still be in the plaintext root.
    It points at the object `aws s3 sync ../encrypted s3://$S3_BUCKET/encrypted`
    uploaded: encrypted/<path relative to the ciphertext root>. Paths outside
    the two roots, and symlinks inside them, are refused.

    Exits 1 if any record could not be migrated.
    """
    id_key = _require_id_key(id_key_id, region)
    base = Path(os.path.abspath(from_path)).parent
    roots = _LegacyRoots(
        base=base,
        plaintext=_LegacyRoot.of("plaintext", plaintext_root or base.parent / "encrypt"),
        ciphertext=_LegacyRoot.of("ciphertext", ciphertext_root or base.parent / "encrypted"),
    )
    with _exit_on_error("Migration error"):
        try:
            text = from_path.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise MigrationError(f"Cannot read {str(from_path)!r} as UTF-8 text: {exc}") from None
    store = StateStore(table_name=table, region=region)
    pin = _pinned_version_lookup(bucket, region) if bucket else None
    entries = list(_metadata_lines(text))
    superseded = _superseded_lines(entries, base)

    imported = skipped = errors = 0
    imported_from: dict[str, int] = {}  # identifier -> line it was imported from
    for lineno, item in track(entries, description="Migrating records..."):
        try:
            if isinstance(item, MigrationError):
                raise item
            if lineno in superseded:
                console.print(
                    f"[dim]line {lineno}: skipped, a later record describes the same file[/dim]"
                )
                skipped += 1
                continue
            record = _parse_output_json_entry(item, roots=roots, id_key=id_key)
            if record is None:  # a decrypt record, or anything else that is not an encryption
                skipped += 1
                continue
            if record.file_id in imported_from:
                console.print(
                    f"[dim]line {lineno}: skipped, same content as line "
                    f"{imported_from[record.file_id]}[/dim]"
                )
                skipped += 1
                continue
            if pin is not None:
                record.s3_version_id = pin(record.s3_key)
            if not dry_run:
                store.put_current_state(record)
                store.put_event(
                    record,
                    operation="ENCRYPT",
                    correlation_id="migrated-from-output-json",
                    audit_ttl_days=audit_ttl_days,
                    principal_arn=caller_arn(region),
                )
            imported_from[record.file_id] = lineno
            imported += 1
            console.print(
                f"[green]✓[/green] {_display(record.file_name)} → {_display(record.s3_key)}"
            )
        except StateConflictError:
            console.print(f"[dim]line {lineno}: skipped, already in the state table[/dim]")
            skipped += 1
        except (EnvaultError, ClientError, BotoCoreError, OSError) as exc:
            console.print(f"[red]✗[/red] line {lineno}: {_display(_error_message(exc))}")
            logger.debug("Failed to migrate line %d", lineno, exc_info=True)
            errors += 1

    mode = "[dim](dry run)[/dim]" if dry_run else ""
    console.print(
        f"\n[green]Migrated {imported} records[/green], skipped {skipped}, errors {errors} {mode}"
    )
    if errors:
        sys.exit(1)


@dataclass(frozen=True)
class _LegacyRoot:
    """A directory of the legacy workflow, in both spellings a recorded path may use.

    aws-encryption-cli records ``os.path.abspath`` of each path: lexical, on top
    of the physical working directory. The root as given (made absolute) and
    its realpath cover both, without touching any recorded path.
    """

    label: str
    path: Path
    real: Path

    @classmethod
    def of(cls, label: str, path: Path) -> _LegacyRoot:
        absolute = Path(os.path.abspath(path))
        return cls(label=label, path=absolute, real=Path(os.path.realpath(absolute)))

    def relative(self, raw: object, *, field: str, base: Path) -> PurePosixPath:
        """``raw`` as a path strictly inside this root, decided lexically (no filesystem access).

        A relative path is taken relative to ``base`` (the metadata file's
        directory, the legacy scripts' working directory).
        """
        if not isinstance(raw, str) or not raw:
            raise MigrationError(f"the record has no {field!r} path")
        if "\x00" in raw:
            raise MigrationError(f"{field!r} contains a NUL character")
        candidate = Path(raw)
        traversal = ".." in candidate.parts
        if candidate.is_absolute():
            if traversal:
                raise MigrationError(f"Path traversal not allowed in {field!r}: {raw!r}")
            lexical = Path(os.path.normpath(candidate))
        else:
            lexical = Path(os.path.normpath(base / candidate))
        for root in (self.path, self.real):
            try:
                inside = lexical.relative_to(root)
            except ValueError:
                continue
            if inside.parts:
                return PurePosixPath(*inside.parts)
        prefix = "Path traversal not allowed: " if traversal else ""
        raise MigrationError(
            f"{prefix}{field} {raw!r} is outside the {self.label} root {str(self.path)!r}"
        )


@dataclass(frozen=True)
class _LegacyRoots:
    base: Path  # the metadata file's directory: the legacy scripts ran from here
    plaintext: _LegacyRoot
    ciphertext: _LegacyRoot


def _metadata_lines(text: str) -> Iterator[tuple[int, dict[str, Any] | MigrationError]]:
    """Each non-empty line as a JSON object, or the reason it is not one."""
    for lineno, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            yield lineno, MigrationError(f"not valid JSON ({exc.msg})")
            continue
        if isinstance(entry, dict):
            yield lineno, entry
        else:
            yield lineno, MigrationError(f"expected a JSON object, got {type(entry).__name__}")


def _superseded_lines(
    entries: list[tuple[int, dict[str, Any] | MigrationError]], base: Path
) -> set[int]:
    """Encrypt records followed by a later record for the same ciphertext file.

    aws-encryption-cli appends to its metadata file, and each run's `aws s3
    sync` replaced the object: only the newest record describes it.
    """
    outputs: dict[int, str] = {}
    for lineno, entry in entries:
        if isinstance(entry, dict) and entry.get("mode") == "encrypt":
            output = entry.get("output")
            if isinstance(output, str) and output and "\x00" not in output:
                outputs[lineno] = os.path.normpath(os.path.join(base, output))
    newest = {output: lineno for lineno, output in outputs.items()}
    return {lineno for lineno, output in outputs.items() if newest[output] != lineno}


def _parse_output_json_entry(
    entry: dict[str, Any], *, roots: _LegacyRoots, id_key: IdKey
) -> FileRecord | None:
    """Turn one aws-encryption-cli metadata record into a FileRecord.

    Returns None for records that are not encryptions. Everything is checked
    before the filesystem is touched: the header, then both paths lexically
    against their roots. Only then is the plaintext opened (no symlink on the
    way, regular file only) and hashed; ``id_key`` turns the hash into the
    record's keyed identifier.

    Raises:
        MigrationError: The record cannot be migrated; the message says why.
        InvalidS3KeyError: The ciphertext path does not make a valid legacy key.
        KMSError: KMS could not compute the identifier.
    """
    if entry.get("mode") != "encrypt":
        return None
    header = entry.get("header")
    if not isinstance(header, dict):
        raise MigrationError("the record has no header object")
    algorithm, message_id, key_arn, context = _legacy_header(header)
    plain_rel = roots.plaintext.relative(entry.get("input"), field="input", base=roots.base)
    cipher_rel = roots.ciphertext.relative(entry.get("output"), field="output", base=roots.base)
    s3_key = LEGACY_S3_PREFIX + cipher_rel.as_posix()
    assert_legacy_s3_key(s3_key)

    fd = _open_legacy_plaintext(roots.plaintext, plain_rel, str(entry.get("input")))
    try:
        sha256 = sha256_fd(fd)
        size = os.fstat(fd).st_size
    finally:
        os.close(fd)
    keyed = id_key.file_id(sha256_digest(sha256))
    now = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    return FileRecord(
        file_id=keyed.file_id,
        file_name=plain_rel.as_posix(),
        current_state=ENCRYPTED,
        s3_key=s3_key,
        s3_version_id="",
        kms_key_id=key_arn,
        encryption_context=context,
        algorithm=algorithm,
        message_id=message_id,
        file_size_bytes=size,
        tags={"source": "migrated"},
        encrypted_at=now,
        last_updated=now,
        s3_key_scheme=S3_KEY_LEGACY_SYNC,
        id_scheme=ID_SCHEME_HMAC_SHA256,
        id_key_arn=keyed.key_arn,
    )


def _legacy_header(header: dict[str, Any]) -> tuple[str, str, str, dict[str, str]]:
    """(algorithm, message id as hex, KMS key ARN, encryption context) of a metadata header.

    aws-encryption-cli base64-encodes the message id and the key provider's id
    and info. Messages envault would refuse to decrypt (non-committing suites,
    several encrypted data keys, non-KMS keys) are refused here already.
    """
    algorithm = header.get("algorithm")
    if not isinstance(algorithm, str) or not algorithm:
        raise MigrationError("the header names no algorithm suite")
    if "COMMIT_KEY" not in algorithm:
        raise MigrationError(
            f"algorithm suite {algorithm} is not key-committing, and envault refuses to "
            "decrypt such messages; re-encrypt the file with `envault encrypt`"
        )
    edks = header.get("encrypted_data_keys")
    if not isinstance(edks, list) or len(edks) != 1 or not isinstance(edks[0], dict):
        count = len(edks) if isinstance(edks, list) else 0
        raise MigrationError(
            f"the message has {count} encrypted data keys; envault decrypts messages with "
            "exactly one"
        )
    provider = edks[0].get("key_provider")
    if not isinstance(provider, dict):
        raise MigrationError("the encrypted data key names no key provider")
    provider_id = _decoded_text(provider.get("provider_id"), plain=lambda v: v == "aws-kms")
    if provider_id != "aws-kms":
        raise MigrationError(f"the data key's provider is {provider_id!r}, not aws-kms")
    key_arn = _decoded_text(
        provider.get("key_info"), plain=lambda v: bool(_KMS_KEY_ARN_RE.fullmatch(v))
    )
    if not _KMS_KEY_ARN_RE.fullmatch(key_arn):
        raise MigrationError(f"key_info is not a KMS key ARN: {key_arn!r}")
    raw_id = header.get("message_id")
    try:
        message_id = base64.b64decode(str(raw_id), validate=True).hex()
    except ValueError:
        message_id = ""
    if not raw_id or not message_id:
        raise MigrationError("the header's message_id is missing or not base64")
    context = header.get("encryption_context") or {}
    if not isinstance(context, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in context.items()
    ):
        raise MigrationError("encryption_context must be a JSON object of strings")
    # aws-crypto-* keys are the SDK's own (the message's signing key); envault
    # verifies the application's context.
    return (
        algorithm,
        message_id,
        key_arn,
        {k: v for k, v in context.items() if not k.startswith("aws-crypto-")},
    )


def _decoded_text(value: object, *, plain: Callable[[str], bool]) -> str:
    """A header field aws-encryption-cli stores base64-encoded ("" if it is neither form).

    A value that already passes ``plain`` is taken as is, for metadata written
    by other tools.
    """
    if not isinstance(value, str):
        return ""
    if plain(value):
        return value
    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return ""


def _open_legacy_plaintext(root: _LegacyRoot, rel: PurePosixPath, raw: str) -> int:
    """Open the plaintext ``rel`` below ``root`` for hashing, refusing any symlink on the way."""
    current = root.real
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            raise MigrationError(f"Symlink not allowed in migration input: {raw!r}")
    if not current.resolve().is_relative_to(root.real):
        raise MigrationError(f"input {raw!r} resolves outside the plaintext root")
    try:
        return open_regular_nofollow(current)
    except FileNotFoundError:
        raise MigrationError(
            f"plaintext {raw!r} not found: its checksum cannot be computed, so the record "
            "cannot be migrated"
        ) from None


def _pinned_version_lookup(bucket: str, region: str) -> Callable[[str], str]:
    """A function returning the current VersionId of a legacy object ("" if unversioned)."""
    client = boto3.client("s3", region_name=region, config=boto_config)

    @aws_retry(never=(EnvaultError,))
    def current_version(s3_key: str) -> str:
        try:
            response = client.head_object(Bucket=bucket, Key=s3_key)
        except ClientError as exc:
            if str(exc.response.get("Error", {}).get("Code", "")) in {"404", "NoSuchKey"}:
                raise MigrationError(
                    f"s3://{bucket}/{s3_key} does not exist: the legacy sync never uploaded "
                    "it, or it was removed"
                ) from None
            raise
        return str(response.get("VersionId") or "")

    return current_version


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
    uploads back to S3, and updates DynamoDB state. Each record keeps its
    identifier and its identifier scheme: a keyed record is verified with the
    key it names before it is re-encrypted; a legacy record (identified by
    its SHA-256) stays legacy.

    A malformed record (an attribute of a type envault never writes) cannot
    be rotated: it is reported with a ✗, the others are rotated, and the
    command exits 1, with --dry-run too.
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
    malformed: list[MalformedRecordError] = []
    with _exit_on_error():
        records = store.list_by_state(ENCRYPTED, on_malformed=malformed.append)
        seen = {r.file_id for r in records}
        legacy = [
            r
            for r in store.list_by_state(DECRYPTED, on_malformed=malformed.append)
            if r.file_id not in seen
        ]
    if legacy:
        console.print(
            f"[dim]Including {len(legacy)} record(s) marked DECRYPTED by an earlier "
            "version — their ciphertext is still in S3 and still needs rotating.[/dim]"
        )
    records.extend(legacy)

    if not records and not malformed:
        console.print("[yellow]No tracked files found.[/yellow]")
        return

    console.print(f"Found {len(records)} files to rotate.")
    for problem in malformed:
        console.print(f"[red]✗[/red] {_display(problem)}")
    if dry_run:
        console.print("[dim]Dry run — no changes will be made.[/dim]")
        for r in records:
            console.print(f"  Would rotate: {_display(r.file_name)} ({_id_prefix(r.file_id)}...)")
        if malformed:
            console.print(
                f"[bold red]Rotation would be incomplete:[/bold red] {len(malformed)} "
                "malformed record(s) cannot be rotated."
            )
            sys.exit(1)
        return

    rotated = 0
    if records:
        # Plaintext copies live in a private RAM directory where there is one;
        # the scratch destroys them, and the directory, however rotation ends.
        with _Scratch() as scratch:
            rotated = _rotate_records(
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

    errors = len(records) - rotated + len(malformed)
    console.print(f"\n[green]Rotated {rotated} files[/green], {errors} errors.")
    if errors:
        # A partially-rotated corpus means some files are still readable with the
        # old key. Exiting 0 here would report an incomplete rotation as success.
        console.print(
            f"[bold red]Rotation incomplete:[/bold red] {errors} file(s) are still "
            "encrypted under the previous key."
        )
        sys.exit(1)


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
) -> int:
    """Rotate each record, reporting each failure on its own line; return how many rotated."""
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
    verifier = FileIdVerifier(region=region, allowed_account_ids=account_ids)

    rotated = 0
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

            _check_record(record, region=region, allowed_account_ids=account_ids)
            s3.download_file(
                record.s3_key,
                tmp_dl,
                _s3_version_id(record, latest),
                allow_latest=latest,
            )
            selection = _Selection(record, expected_file_id=record.file_id)
            # Verified (keyed records: VerifyMac) before the plaintext reaches
            # tmp_pt, and so before anything is re-encrypted under the record's
            # identifier.
            decrypted = decrypt_file(
                tmp_dl,
                tmp_pt,
                expected_sha256=selection.expected_sha256,
                region=region,
                allowed_account_ids=account_ids,
                expected_context=record.encryption_context,
                verify_digest=_identity_check(selection, verifier),
            )
            scratch.discard(tmp_dl)

            # The record keeps its identifier and scheme; the context names it
            # the way that scheme always has.
            new_ctx = new_key_config.build_encryption_context(
                record.file_id, record.file_name, legacy=record.id_scheme == ID_SCHEME_SHA256
            )
            new_result = encrypt_file(tmp_pt, new_key_id, new_ctx, tmp_enc, region)
            scratch.discard(tmp_pt)
            if new_result.sha256_hash != decrypted.sha256_hash:
                raise EnvaultError(
                    f"The temporary plaintext of {record.file_name!r} changed between decryption "
                    "and re-encryption; not rotating it."
                )

            # The new ciphertext gets a key of its own; the object the record
            # pinned so far is left exactly as it is (and stays readable with
            # the old key until that key is disabled).
            new_s3_key = s3.s3_key_for_file(
                record.file_id, record.file_name, message_id=new_result.message_id
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
            record.s3_key_scheme = S3_KEY_CONTENT_ADDRESSED
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
                        "file_id": record.file_id,
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
        finally:
            scratch.discard(tmp_dl, tmp_pt, tmp_enc)
    return rotated


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
@_id_key_lookup_option
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
    id_key_id: str | None,
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

    IDENTIFIER is what decrypt takes: a file's identifier, the SHA-256 of its
    content (with ENVAULT_ID_KEY_ID set), or its stored name.

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
    id_key = _optional_id_key(id_key_id, region)
    verifier = FileIdVerifier(region=region, allowed_account_ids=account_ids)

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
    # The secret being fetched, for messages: (target variable, selection).
    checking: tuple[str, _Selection] | None = None
    try:
        for identifier, var in env_pairs:
            selection = _resolve_identifier(identifier, store, newest_only=True, id_key=id_key)
            checking = (var, selection)
            sink = _BufferSink()
            sinks.append(sink)
            _stream_secret(selection, sink, s3, region, account_ids, verifier, allow_latest=latest)
            child_env[var] = _decode_secret(sink.buf, identifier)
            accessed.append(selection.record)

        for identifier, var in file_pairs:
            selection = _resolve_identifier(identifier, store, newest_only=True, id_key=id_key)
            checking = (var, selection)
            cred = CredentialFd(var)
            creds.append(cred)
            with cred.writer() as out:
                _stream_secret(
                    selection, out, s3, region, account_ids, verifier, allow_latest=latest
                )
            # Sealed only after the checksum, identifier and encryption context verified.
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
    except ChecksumMismatchError:
        _close_all(creds, sinks)
        # Named by the identifier it should have had, never by the hash of what
        # was decrypted (M6).
        which = (
            f"the secret for {_display(checking[0])} is not the file its record identifies "
            f"({_id_prefix(checking[1].expected_file_id)}...)"
            if checking
            else "a secret is not the file its record identifies"
        )
        console.print(
            f"[bold red]Refusing to run:[/bold red] checksum mismatch: {which}.\n"
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
    verifier: FileIdVerifier,
    *,
    allow_latest: bool = False,
) -> None:
    """Fetch a record's ciphertext and decrypt it into ``out``, verifying first.

    ``out`` holds unverified plaintext until this returns: the caller seals,
    decodes or hands it over only then.
    """
    record = selection.record
    _check_record(record, region=region, allowed_account_ids=account_ids)
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
        verify_digest=_identity_check(selection, verifier),
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
# recognising one on the command line, resolving IDENTIFIER (an identifier, the
# SHA-256 of a file's content, or a stored name) to a record, checking a record
# against the identifier it was looked up by, against its S3 key and its
# identifier key, verifying decrypted plaintext against a keyed identifier, and
# the short form shown to operators. The schemes themselves (keyed
# hmac-sha256-v1 for new records, the raw SHA-256 for legacy ones) live in
# envault.fileid.
# ---------------------------------------------------------------------------

#: Appended where a raw SHA-256 could have been meant but no ID key is configured.
_SHA256_LOOKUP_HINT = (
    "If it is the SHA-256 of a file's content, set ENVAULT_ID_KEY_ID (or pass --id-key-id) "
    "to look the file up by it."
)


def _validate_identifier(value: str) -> str:
    """Validate a file identifier (or SHA-256) given as an option. Exit with error if invalid."""
    if not is_file_id(value):
        console.print(
            f"[red]Invalid identifier: {_display(repr(value))}. Expected a file identifier or "
            "a SHA-256: 64 lowercase hexadecimal characters.[/red]"
        )
        sys.exit(1)
    return value


def _id_prefix(identifier: object) -> str:
    """Short form of a file identifier for messages and tables (first 16 characters).

    The one place that decides how identifiers are shown to the operator.
    Identifiers read from DynamoDB are untrusted, so the prefix is escaped.
    """
    return _display(str(identifier)[:16])


def _fallback_output_name(record: FileRecord) -> str:
    """Output file name when a record's stored name cannot be used as one."""
    return f"decrypted_{record.file_id[:16]}"


def _check_record(record: FileRecord, *, region: str, allowed_account_ids: Sequence[str]) -> None:
    """Refuse a row whose identifier, identifier key or S3 key is not acceptable.

    Rows come from DynamoDB, which any principal with write access can edit. The
    identifier ends up in the expected checksum and in file names, the
    identifier key is what KMS verifies a keyed identifier with, and the S3 key
    decides which object is fetched. Runs before any KMS call for the record.

    Raises:
        _IdentifierError: The identifier is not 64 lowercase hex characters, or
            its scheme is unknown.
        UntrustedIdKeyError: A keyed record's ``id_key_arn`` is not a KMS key
            ARN in the region's partition and a trusted account.
        InvalidS3KeyError: The key is not valid for the record's key scheme: this
            identifier's content-addressed path, or (migrated records) a key in
            the legacy-sync layout.
    """
    if not is_file_id(record.file_id):
        raise _IdentifierError(
            f"The record for {record.file_name!r} has a malformed identifier; refusing to use it."
        )
    if record.id_scheme not in ID_SCHEMES:
        raise _IdentifierError(
            f"The record for {record.file_name!r} uses identifier scheme {record.id_scheme!r}, "
            "which this version of envault does not know; refusing to use it."
        )
    if record.id_scheme == ID_SCHEME_HMAC_SHA256:
        # The same trust anchor as discovery decryption, before KMS is asked anything.
        check_id_key_arn(record.id_key_arn, region=region, allowed_account_ids=allowed_account_ids)
    if record.s3_key_scheme == S3_KEY_CONTENT_ADDRESSED:
        assert_s3_key_matches_hash(record.s3_key, record.file_id, message_id=record.message_id)
    elif record.s3_key_scheme == S3_KEY_LEGACY_SYNC:
        # Migrated records point where the legacy `aws s3 sync` put the object;
        # the key carries no identifier, so the plaintext's identifier check and
        # the encryption context are what bind the object to the record.
        assert_legacy_s3_key(record.s3_key)
    else:
        raise InvalidS3KeyError(
            f"Refusing to use S3 key {record.s3_key!r}: unknown key scheme "
            f"{record.s3_key_scheme!r}."
        )


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
    """The record IDENTIFIER resolved to, and what its plaintext must turn out to be."""

    record: FileRecord
    #: The identifier the plaintext must have under the record's scheme: the
    #: one the operator typed (or the keyed identifier of the SHA-256 they
    #: typed), or for a name lookup the record's own.
    expected_file_id: str
    #: A SHA-256 the operator typed and that was looked up through the ID
    #: key: the plaintext must also hash to it.
    typed_sha256: str | None = None

    @property
    def expected_sha256(self) -> str | None:
        """What the plaintext's SHA-256 must equal (checked by the crypto layer), if anything.

        For a legacy record the identifier is that SHA-256. For a keyed one it
        is only known when the operator typed it; the keyed identifier itself
        is checked by the check :func:`_identity_check` builds.
        """
        if self.record.id_scheme == ID_SCHEME_SHA256:
            return self.expected_file_id
        return self.typed_sha256


def _identity_check(
    selection: _Selection, verifier: FileIdVerifier
) -> Callable[[bytes], None] | None:
    """The check decrypted plaintext must pass to be the file a keyed record identifies.

    Passed to the crypto layer as ``verify_digest``, which calls it with the
    plaintext's raw SHA-256 digest after decryption into a hidden ``.part``
    file, a buffer or an unsealed memfd: before the plaintext is named,
    published, sealed, handed to a command or re-encrypted. For a keyed record
    KMS VerifyMac checks the expected identifier against that digest under the
    record's identifier key (already found trustworthy by
    :func:`_check_record`). A legacy record needs none (None): its identifier
    is the SHA-256 itself, which the crypto layer compares with
    :attr:`_Selection.expected_sha256` while decrypting.

    The check raises:
        FileIdMismatchError: The plaintext is not that file (an integrity failure).
        UntrustedIdKeyError: The record's identifier key is not trusted.
        KMSError: KMS could not answer (availability or permission).

    Raises:
        _IdentifierError: The record's identifier scheme is unknown
            (:func:`_check_record` refuses these first).
    """
    record = selection.record
    if record.id_scheme == ID_SCHEME_SHA256:
        return None
    if record.id_scheme != ID_SCHEME_HMAC_SHA256:
        raise _IdentifierError(
            f"The record for {record.file_name!r} uses unknown identifier scheme "
            f"{record.id_scheme!r}; refusing to deliver it."
        )
    expected_file_id = selection.expected_file_id
    key_arn = record.id_key_arn

    def check(digest: bytes) -> None:
        verifier.verify(expected_file_id, digest, key_arn=key_arn)

    return check


def _resolve_identifier(
    identifier: str,
    store: StateStore,
    *,
    version: int | None = None,
    newest_only: bool = False,
    id_key: IdKey | None = None,
) -> _Selection:
    """Resolve IDENTIFIER (an identifier, a SHA-256 or a stored file name) to one record.

    64 hex characters are looked up as described in :func:`_record_by_id`: the
    row found must say it is about that identifier, and the plaintext is
    checked against what the operator typed, never against what the row
    claims. Name lookups have no such anchor: they trust every principal that
    can write to the table.

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
        KMSError: The ID key could not map a SHA-256 to an identifier.
    """
    if is_file_id(identifier):
        return _record_by_id(identifier, store, id_key)

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
    return _Selection(selected, expected_file_id=selected.file_id)


def _record_by_id(identifier: str, store: StateStore, id_key: IdKey | None) -> _Selection:
    """The record for 64 hex characters: the SHA-256 of a file's content, or a file's identifier.

    With an ID key configured, the value is first taken as the SHA-256 of a
    file's content: KMS maps it to the keyed identifier (GenerateMac) and only
    that is looked up. A SHA-256 that names a keyed record therefore never
    reaches DynamoDB, nor the CloudTrail data events that record lookup keys.
    The row found must be keyed with the configured key, and the plaintext
    must hash to the SHA-256 typed as well as verify against the identifier.

    Only if nothing is stored under the mapped identifier is the value looked
    up as typed: a file's identifier, or the SHA-256 that names a legacy
    record. Without an ID key that is the only lookup. Either way the row must
    say it is about the identifier it is stored under (M5).

    Raises:
        _IdentifierError: No record, or a row that contradicts its key.
        MalformedRecordError: The row found is not shaped like a record.
        KMSError: The ID key could not map the value. The lookup stops there:
            looking the value up as typed instead would send it to DynamoDB.
    """
    if id_key is not None:
        keyed = id_key.file_id(sha256_digest(identifier))
        record = store.get_current_state(keyed.file_id)
        if record is not None:
            _require_row_describes(record, keyed.file_id)
            if record.id_scheme != ID_SCHEME_HMAC_SHA256 or record.id_key_arn != keyed.key_arn:
                raise _IdentifierError(
                    f"The record stored under {keyed.file_id[:16]}... does not name the "
                    "configured identifier key. Refusing to use it: the state table may have "
                    "been tampered with."
                )
            return _Selection(record, expected_file_id=keyed.file_id, typed_sha256=identifier)
    record = store.get_current_state(identifier)
    if record is not None:
        _require_row_describes(record, identifier)
        return _Selection(record, expected_file_id=identifier)
    if id_key is None:
        raise _IdentifierError(f"No record found for {identifier[:16]}... {_SHA256_LOOKUP_HINT}")
    raise _IdentifierError(
        f"No record found for {identifier[:16]}..., neither as the SHA-256 of a file's content "
        "nor as a file identifier."
    )


def _require_row_describes(record: FileRecord, stored_under: str) -> None:
    """The row found under an identifier must be about that identifier (M5, either scheme)."""
    if record.file_id != stored_under:
        raise _IdentifierError(
            f"The record stored under {stored_under[:16]}... describes a different file "
            f"({str(record.file_id)[:16]}...). Refusing to use it: the state table "
            "may have been tampered with."
        )


def _events_by_id(identifier: str, store: StateStore, id_key: IdKey | None) -> list[dict[str, Any]]:
    """Audit events for 64 hex characters, found the way :func:`_record_by_id` finds a record.

    With an ID key the value is mapped first. It is looked up as typed only if
    nothing at all is stored under the mapped identifier: no events (they
    expire) and no record either, so a keyed file whose events have expired
    does not send the SHA-256 typed to DynamoDB.
    """
    if id_key is not None:
        file_id = id_key.file_id(sha256_digest(identifier)).file_id
        events = store.list_events_for_file(file_id)
        if events or store.has_current_state(file_id):
            return events
    return store.list_events_for_file(identifier)


def _records_named(name: str, store: StateStore) -> list[FileRecord]:
    """ENCRYPTED records stored under ``name``, else (bare names only) under that basename.

    A malformed row stored under exactly ``name`` is refused: which version is
    current cannot be told without it. The basename fallback reads every
    ENCRYPTED row and ignores malformed ones, so one bad row cannot break
    lookups of every other file.

    Raises:
        _IdentifierError: A row stored under exactly ``name`` is malformed.
    """
    malformed: list[MalformedRecordError] = []
    exact = store.list_by_file_name(name, ENCRYPTED, on_malformed=malformed.append)
    if malformed:
        raise _IdentifierError(
            f"The name {name!r} matches a malformed record. {malformed[0]}"
        ) from malformed[0]
    if exact or "/" in name:
        return exact
    return [
        r
        for r in store.list_by_state(ENCRYPTED, on_malformed=_ignore_malformed)
        if PurePosixPath(r.file_name).name == name
    ]


def _ignore_malformed(problem: MalformedRecordError) -> None:
    logger.debug("Name lookup ignores a malformed record: %s", problem)


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
    return sorted(records, key=lambda r: (_encrypted_at(r), r.file_id), reverse=True)


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
                f"  {label}{_id_prefix(record.file_id)}  {_display(record.file_name)}"
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
