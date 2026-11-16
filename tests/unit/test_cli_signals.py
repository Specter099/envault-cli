"""SIGTERM, SIGHUP and SIGINT stop envault without leaving plaintext behind (M2).

The console entry point turns SIGTERM and SIGHUP into SystemExit(128 + signum)
(SIGINT stays KeyboardInterrupt), so every ``finally`` runs. Temporary files
are registered as they are created and destroyed when the command ends,
however it ends; a second signal cannot interrupt that.

In-process tests drive the handlers directly; the real-process tests run the
``envault`` entry point in a fresh interpreter (moto in-process there too) and
signal it from outside, the way an operator or a supervisor would.
"""

from __future__ import annotations

import os
import pathlib
import select
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
from collections.abc import Iterator
from unittest.mock import patch

import boto3
import pytest
from click.testing import CliRunner, Result
from moto import mock_aws

from envault import cli as cli_mod
from envault import crypto as crypto_mod
from envault import identity
from envault.cli import main
from envault.state import ENCRYPTED, StateStore

from ._id_key import ID_KEY_ALIAS, TESTS_DIR, id_key_env

TABLE = "envault-test-state"
BUCKET = "envault-test-bucket"
ALIAS = "alias/envault-test"
NEW_ALIAS = "alias/new-key"
REGION = "us-east-1"
SHM = pathlib.Path("/dev/shm")  # noqa: S108
# Several frames and several 64 KiB read chunks, so a signal lands mid-stream.
BIG = b"PLAINTEXT-MARKER-" + b"y" * (1024 * 1024)

pytestmark = pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX signals")


@pytest.fixture(autouse=True)
def _clear_identity_cache() -> Iterator[None]:
    identity.reset_cache()
    yield
    identity.reset_cache()


@pytest.fixture
def handlers() -> Iterator[None]:
    """Install the CLI's signal handlers for one test, then put the old ones back.

    The handlers leave a signal the parent ignored alone, by design, and the
    test run may have inherited an ignored SIGHUP (``nohup pytest``). These
    tests are about the handlers, so SIGHUP starts at its default here.
    """
    previous_sighup = signal.signal(signal.SIGHUP, signal.SIG_DFL)
    restore = cli_mod._install_signal_handlers()
    try:
        yield
    finally:
        restore()
        signal.signal(signal.SIGHUP, previous_sighup)


def _signal_self(signum: int) -> None:
    os.kill(os.getpid(), signum)
    # The Python-level handler runs at the next bytecode boundary.
    for _ in range(100):
        time.sleep(0.001)


# ---------------------------------------------------------------------------
# The handlers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("signum", "code"), [(signal.SIGTERM, 143), (signal.SIGHUP, 129)])
def test_sigterm_and_sighup_become_system_exit(handlers: None, signum: int, code: int) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _signal_self(signum)
    assert exc_info.value.code == code


def test_sigint_stays_keyboard_interrupt(handlers: None) -> None:
    with pytest.raises(KeyboardInterrupt):
        _signal_self(signal.SIGINT)


@pytest.mark.parametrize("second", [signal.SIGTERM, signal.SIGINT, signal.SIGHUP])
def test_second_signal_does_not_interrupt_cleanup(handlers: None, second: int) -> None:
    cleaned: list[str] = []
    with pytest.raises(SystemExit) as exc_info:
        try:
            _signal_self(signal.SIGTERM)
        finally:
            _signal_self(second)  # an impatient second signal during cleanup
            cleaned.append("done")
    assert cleaned == ["done"]
    assert exc_info.value.code == 143


def test_third_signal_ends_the_process_at_once(tmp_path: pathlib.Path) -> None:
    """If cleanup ever hangs, the operator can still stop envault without SIGKILL."""
    script = tmp_path / "stuck.py"
    script.write_text(
        textwrap.dedent(
            """
            import os, signal, sys, time
            from envault.cli import _install_signal_handlers
            _install_signal_handlers()
            try:
                print("READY", flush=True)
                time.sleep(60)
            finally:
                print("CLEANING", flush=True)
                time.sleep(60)  # a cleanup that never finishes
            """
        )
    )
    proc = subprocess.Popen(  # noqa: S603
        [sys.executable, str(script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    assert proc.stdout is not None
    assert proc.stdout.readline().strip() == b"READY"
    proc.send_signal(signal.SIGTERM)  # starts the orderly shutdown
    assert proc.stdout.readline().strip() == b"CLEANING"
    proc.send_signal(signal.SIGTERM)  # ignored: cleanup is running
    time.sleep(0.3)
    assert proc.poll() is None
    proc.send_signal(signal.SIGTERM)  # the third ends it
    assert proc.wait(timeout=10) == -signal.SIGTERM
    proc.communicate()


def test_signal_during_deferred_section_is_delivered_after_it(handlers: None) -> None:
    steps: list[str] = []
    with pytest.raises(SystemExit) as exc_info:
        with cli_mod._signals_deferred():
            _signal_self(signal.SIGHUP)
            steps.append("finished the section")
        steps.append("never reached")
    assert steps == ["finished the section"]
    assert exc_info.value.code == 129


def test_handlers_leave_an_ignored_sighup_alone() -> None:
    """`nohup envault exec ...`: the child must still ignore SIGHUP."""
    previous = signal.signal(signal.SIGHUP, signal.SIG_IGN)
    try:
        restore = cli_mod._install_signal_handlers()
        try:
            assert signal.getsignal(signal.SIGHUP) == signal.SIG_IGN
            assert signal.getsignal(signal.SIGTERM) != signal.SIG_DFL
        finally:
            restore()
        assert signal.getsignal(signal.SIGTERM) == signal.SIG_DFL
    finally:
        signal.signal(signal.SIGHUP, previous)


# ---------------------------------------------------------------------------
# Commands interrupted in-process
# ---------------------------------------------------------------------------


@pytest.fixture
def private_tempdir(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> pathlib.Path:
    scratch = tmp_path / "tmp"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    return scratch


@pytest.fixture
def env(tmp_path: pathlib.Path) -> Iterator[dict[str, str]]:
    """Moto account with big.dat encrypted under ALIAS (and NEW_ALIAS available)."""
    with mock_aws():
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
        for alias in (ALIAS, NEW_ALIAS):
            kms.create_alias(AliasName=alias, TargetKeyId=kms.create_key()["KeyMetadata"]["KeyId"])
        account = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
        environment = {
            "AWS_ACCESS_KEY_ID": "testing",
            "AWS_SECRET_ACCESS_KEY": "testing",  # noqa: S105
            "AWS_DEFAULT_REGION": REGION,
            "ENVAULT_KEY_ID": ALIAS,
            "ENVAULT_BUCKET": BUCKET,
            "ENVAULT_TABLE": TABLE,
            "ENVAULT_REGION": REGION,
            "ENVAULT_ALLOWED_ACCOUNT_IDS": str(account),
            **id_key_env(),
        }
        (tmp_path / "big.dat").write_bytes(BIG)
        result = CliRunner().invoke(main, ["encrypt", str(tmp_path / "big.dat")], env=environment)
        assert result.exit_code == 0, result.output
        (tmp_path / "big.dat").unlink()
        yield environment


def _run(env: dict[str, str], *args: str) -> Result:
    return CliRunner().invoke(main, list(args), env=env)


def test_decrypt_interrupted_mid_stream_leaves_no_plaintext(
    env: dict[str, str],
    tmp_path: pathlib.Path,
    private_tempdir: pathlib.Path,
    handlers: None,
) -> None:
    """r06 (a): SIGTERM after the first plaintext chunk reached the hidden .part file."""
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    real_write = crypto_mod._WriteTracker.write

    def write_then_terminate(self, data):  # type: ignore[no-untyped-def]
        real_write(self, data)
        _signal_self(signal.SIGTERM)

    with patch.object(crypto_mod._WriteTracker, "write", write_then_terminate):
        result = _run(env, "decrypt", "big.dat", "-o", str(out_dir))

    assert isinstance(result.exception, SystemExit)
    assert result.exit_code == 143
    assert list(out_dir.iterdir()) == []  # no .part, no .verified, no output
    assert list(private_tempdir.iterdir()) == []


def test_decrypt_interrupted_while_publishing_keeps_no_extra_names(
    env: dict[str, str],
    tmp_path: pathlib.Path,
    private_tempdir: pathlib.Path,
    handlers: None,
) -> None:
    """SIGTERM right after the audit event: the staging copy is still destroyed."""
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    real_publish = cli_mod._publish

    def terminate_then_publish(src, dst, *, overwrite):  # type: ignore[no-untyped-def]
        _signal_self(signal.SIGTERM)
        real_publish(src, dst, overwrite=overwrite)

    with patch.object(cli_mod, "_publish", terminate_then_publish):
        result = _run(env, "decrypt", "big.dat", "-o", str(out_dir))

    assert result.exit_code == 143
    assert list(out_dir.iterdir()) == []
    assert list(private_tempdir.iterdir()) == []


def _rot_dirs() -> set[pathlib.Path]:
    return set(SHM.glob("envault_rot_*")) if SHM.is_dir() else set()


@pytest.mark.parametrize("stage", ["decrypting", "re-encrypting"])
def test_rotate_key_interrupted_mid_file_leaves_no_plaintext(
    env: dict[str, str],
    private_tempdir: pathlib.Path,
    handlers: None,
    stage: str,
) -> None:
    """r06 (c): SIGHUP while the plaintext copy exists; the RAM directory goes too."""
    before_dirs = _rot_dirs()
    [before] = StateStore(table_name=TABLE, region=REGION).list_by_state(ENCRYPTED)
    if stage == "decrypting":
        real_write = crypto_mod._WriteTracker.write

        def interrupt(self, data):  # type: ignore[no-untyped-def]
            real_write(self, data)
            _signal_self(signal.SIGHUP)

        target = patch.object(crypto_mod._WriteTracker, "write", interrupt)
    else:
        real_encrypt = cli_mod.encrypt_file

        def interrupt_encrypt(*args, **kwargs):  # type: ignore[no-untyped-def]
            _signal_self(signal.SIGHUP)  # the full plaintext copy exists now
            return real_encrypt(*args, **kwargs)

        target = patch.object(cli_mod, "encrypt_file", interrupt_encrypt)

    with target:
        result = _run(env, "rotate-key", "--new-key-id", NEW_ALIAS)

    assert result.exit_code == 129
    assert _rot_dirs() == before_dirs
    assert list(private_tempdir.iterdir()) == []
    [after] = StateStore(table_name=TABLE, region=REGION).list_by_state(ENCRYPTED)
    assert after == before


def test_rotate_key_removes_its_ram_directory_on_success(
    env: dict[str, str], private_tempdir: pathlib.Path
) -> None:
    before_dirs = _rot_dirs()

    result = _run(env, "rotate-key", "--new-key-id", NEW_ALIAS)

    assert result.exit_code == 0, result.output
    assert _rot_dirs() == before_dirs
    assert list(private_tempdir.iterdir()) == []


# ---------------------------------------------------------------------------
# Real processes, real signals
# ---------------------------------------------------------------------------

_CHILD = textwrap.dedent(
    """
    import os, signal, sys
    import boto3
    from moto import mock_aws
    from envault.cli import cli, main
    from unit._id_key import create_id_key, install_generate_mac_key_arn_fix

    # As envault would start from a shell, whatever the test run inherited
    # (nohup ignores SIGHUP); IGNORE_SIGHUP below ignores it on purpose.
    signal.signal(signal.SIGHUP, signal.SIG_DFL)
    install_generate_mac_key_arn_fix()
    with mock_aws():
        kms = boto3.client("kms", region_name="us-east-1")
        for alias in ("alias/envault-test", "alias/new-key"):
            kms.create_alias(AliasName=alias, TargetKeyId=kms.create_key()["KeyMetadata"]["KeyId"])
        create_id_key()
        ddb = boto3.client("dynamodb", region_name="us-east-1")
        ddb.create_table(
            TableName="envault-test-state", BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"} for n in
                ("PK", "SK", "current_state", "encrypted_at", "date", "last_updated")],
            KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"},
                       {"AttributeName": "SK", "KeyType": "RANGE"}],
            GlobalSecondaryIndexes=[
                {"IndexName": "state-index", "Projection": {"ProjectionType": "ALL"},
                 "KeySchema": [{"AttributeName": "current_state", "KeyType": "HASH"},
                               {"AttributeName": "encrypted_at", "KeyType": "RANGE"}]},
                {"IndexName": "date-index", "Projection": {"ProjectionType": "ALL"},
                 "KeySchema": [{"AttributeName": "date", "KeyType": "HASH"},
                               {"AttributeName": "last_updated", "KeyType": "RANGE"}]}])
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="envault-test-bucket")
        s3.put_bucket_versioning(Bucket="envault-test-bucket",
                                 VersioningConfiguration={"Status": "Enabled"})
        line = b"PLAINTEXT-MARKER-" + b"y" * 46 + b"\\n"
        with open("big.dat", "wb") as f:
            f.write(line * (int(os.environ["BIG_MB"]) * 1024 * 1024 // len(line)))
        try:
            main(["encrypt", "big.dat"], standalone_mode=False)
        except SystemExit:
            pass
        os.unlink("big.dat")
        print("READY", flush=True)
        if os.environ.get("IGNORE_SIGHUP"):
            signal.signal(signal.SIGHUP, signal.SIG_IGN)  # as nohup would
        sys.argv = ["envault", *sys.argv[1:]]
        cli()
    """
)


def _spawn(
    tmp_path: pathlib.Path, *args: str, extra: dict[str, str] | None = None
) -> subprocess.Popen[bytes]:
    script = tmp_path / "child.py"
    script.write_text(_CHILD)
    private_tmp = tmp_path / "tmp"
    private_tmp.mkdir(exist_ok=True)
    env = {
        **{k: v for k, v in os.environ.items() if not k.startswith(("AWS_", "ENVAULT_"))},
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_DEFAULT_REGION": REGION,
        "ENVAULT_KEY_ID": ALIAS,
        "ENVAULT_BUCKET": BUCKET,
        "ENVAULT_TABLE": TABLE,
        "ENVAULT_ALLOWED_ACCOUNT_IDS": "123456789012",
        "ENVAULT_ID_KEY_ID": ID_KEY_ALIAS,
        "PYTHONPATH": str(TESTS_DIR),
        "TMPDIR": str(private_tmp),
        "BIG_MB": "48",
        **(extra or {}),
    }
    proc = subprocess.Popen(  # noqa: S603
        [sys.executable, str(script), *args],
        cwd=tmp_path,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdout is not None
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        ready, _, _ = select.select([proc.stdout], [], [], max(0.0, deadline - time.monotonic()))
        line = proc.stdout.readline() if ready else b""
        if line.strip() == b"READY":
            break
        if not line:  # EOF or timeout
            proc.kill()
            proc.communicate()
            pytest.fail("child process did not get ready")
    return proc


def _wait_for(pattern_dir: pathlib.Path, glob: str, min_size: int, timeout: float = 60) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for path in pattern_dir.glob(glob):
            try:
                if path.stat().st_size >= min_size:
                    return True
            except OSError:
                pass
        time.sleep(0.005)
    return False


def _finish(proc: subprocess.Popen[bytes]) -> tuple[int, str]:
    _, err = proc.communicate(timeout=120)
    return proc.returncode, err.decode(errors="replace")


@pytest.mark.parametrize(("signum", "code"), [(signal.SIGTERM, 143), (signal.SIGINT, 1)])
def test_real_process_decrypt_signalled_mid_stream_leaves_nothing(
    tmp_path: pathlib.Path, signum: int, code: int
) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    proc = _spawn(tmp_path, "decrypt", "big.dat", "-o", str(out_dir))

    reached = _wait_for(out_dir, ".*.part", 4 * 1024 * 1024)
    proc.send_signal(signum)
    returncode, stderr = _finish(proc)

    assert reached, "decrypt finished before it could be interrupted"
    assert returncode == code, stderr
    assert list(out_dir.iterdir()) == [], "plaintext left in the output directory"
    assert list((tmp_path / "tmp").iterdir()) == []
    assert "Traceback" not in stderr


@pytest.mark.skipif(not SHM.is_dir(), reason="needs a RAM-backed /dev/shm")
def test_real_process_rotate_key_sighup_leaves_no_plaintext(tmp_path: pathlib.Path) -> None:
    before = _rot_dirs()
    proc = _spawn(tmp_path, "rotate-key", "--new-key-id", NEW_ALIAS)

    deadline = time.monotonic() + 60
    reached = False
    while not reached and time.monotonic() < deadline:
        for directory in _rot_dirs() - before:
            reached = reached or _wait_for(directory, "*", 4 * 1024 * 1024, timeout=0.01)
    proc.send_signal(signal.SIGHUP)
    returncode, stderr = _finish(proc)

    assert reached, "rotate-key finished before it could be interrupted"
    assert returncode == 129, stderr
    assert _rot_dirs() == before, "plaintext scratch directory left in /dev/shm"
    assert list((tmp_path / "tmp").iterdir()) == []


@pytest.mark.skipif(not pathlib.Path("/proc/self/status").exists(), reason="Linux /proc")
@pytest.mark.parametrize("parent_ignores_sighup", [False, True])
def test_exec_child_gets_default_signal_dispositions(
    tmp_path: pathlib.Path, parent_ignores_sighup: bool
) -> None:
    """The command `envault exec` starts inherits sane signal dispositions.

    execve resets the handlers envault installed; nothing is left blocked; a
    SIGHUP ignored by the parent (nohup) stays ignored; SIGPIPE, which Python
    ignores at start-up, is restored to its default as subprocess would.
    """
    # Small: exec holds ciphertext in memory (16 MiB cap).
    extra = {"BIG_MB": "1", **({"IGNORE_SIGHUP": "1"} if parent_ignores_sighup else {})}
    proc = _spawn(
        tmp_path, "exec", "-f", "big.dat=F", "--", "cat", "/proc/self/status", extra=extra
    )
    out, err = proc.communicate(timeout=120)

    assert proc.returncode == 0, err.decode(errors="replace")
    masks = {
        line.split(":")[0]: int(line.split()[1], 16)
        for line in out.decode().splitlines()
        if line.startswith(("SigBlk", "SigIgn", "SigCgt"))
    }
    assert set(masks) == {"SigBlk", "SigIgn", "SigCgt"}, out
    bit = {s: 1 << (s - 1) for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGPIPE)}
    for signum in bit:
        assert not masks["SigBlk"] & bit[signum], f"{signum} blocked in the child"
        assert not masks["SigCgt"] & bit[signum], f"{signum} still caught in the child"
    assert bool(masks["SigIgn"] & bit[signal.SIGHUP]) is parent_ignores_sighup
    assert not masks["SigIgn"] & bit[signal.SIGTERM]
    assert not masks["SigIgn"] & bit[signal.SIGPIPE]
