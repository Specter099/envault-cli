"""Tests for envault.fileutils: plaintext deletion and race-free opening."""

from __future__ import annotations

import fcntl
import os
import threading
from pathlib import Path

import pytest

from envault.fileutils import best_effort_delete

SECRET = b"the real secret content\n"


def _run_with_timeout(fn, timeout: float = 5.0) -> None:
    """Run ``fn`` in a thread; fail (instead of hanging the suite) if it blocks."""
    errors: list[BaseException] = []

    def target() -> None:
        try:
            fn()
        except BaseException as exc:  # noqa: BLE001 - reported to the test thread
            errors.append(exc)

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout)
    assert not thread.is_alive(), f"{getattr(fn, '__name__', fn)} blocked"
    if errors:
        raise errors[0]


# ---------------------------------------------------------------------------
# best_effort_delete (L3)
# ---------------------------------------------------------------------------


def test_best_effort_delete_does_not_zero_hardlinked_file(tmp_path: Path) -> None:
    """r07: interrupted between os.link(staging, dst) and staging.unlink().

    staging and the published file are one inode. Zeroing "staging" would zero
    the file the user was just given; only the extra name may go.
    """
    staging = tmp_path / ".out.txt.0123abcd.verified"
    staging.write_bytes(SECRET)
    published = tmp_path / "out.txt"
    os.link(staging, published)

    best_effort_delete(staging)

    assert not staging.exists()
    assert published.read_bytes() == SECRET


def test_best_effort_delete_zeroes_a_single_link_file(tmp_path: Path) -> None:
    plaintext = tmp_path / "pt"
    plaintext.write_bytes(SECRET)
    held = os.open(plaintext, os.O_RDONLY)  # observe the inode after the unlink
    try:
        best_effort_delete(plaintext)
        assert not plaintext.exists()
        assert os.pread(held, len(SECRET) + 16, 0) == b"\x00" * len(SECRET)
    finally:
        os.close(held)


def test_best_effort_delete_does_not_follow_a_symlink(tmp_path: Path) -> None:
    target = tmp_path / "victim"
    target.write_bytes(b"precious, not ours")
    link = tmp_path / "staging"
    link.symlink_to(target)

    best_effort_delete(link)

    assert target.read_bytes() == b"precious, not ours"
    assert not link.is_symlink()


def test_best_effort_delete_does_not_block_on_a_fifo(tmp_path: Path) -> None:
    fifo = tmp_path / "staging"
    os.mkfifo(fifo)
    _run_with_timeout(lambda: best_effort_delete(fifo))
    assert not fifo.exists()


def test_best_effort_delete_leaves_a_directory_alone(tmp_path: Path) -> None:
    directory = tmp_path / "staging"
    directory.mkdir()
    (directory / "inner").write_bytes(b"kept")

    best_effort_delete(directory)  # must not raise

    assert (directory / "inner").read_bytes() == b"kept"


def test_best_effort_delete_missing_file_is_a_noop(tmp_path: Path) -> None:
    best_effort_delete(tmp_path / "never-existed")


def test_best_effort_delete_unwritable_file_is_still_unlinked(tmp_path: Path) -> None:
    plaintext = tmp_path / "pt"
    plaintext.write_bytes(SECRET)
    plaintext.chmod(0o400)
    best_effort_delete(plaintext)
    assert not plaintext.exists()


# ---------------------------------------------------------------------------
# open_regular_nofollow (L4)
# ---------------------------------------------------------------------------


def _identity(path: Path) -> tuple[int, int]:
    st = os.lstat(path)
    return st.st_dev, st.st_ino


def test_open_regular_nofollow_opens_a_regular_file(tmp_path: Path) -> None:
    from envault.fileutils import open_regular_nofollow

    p = tmp_path / "notes.txt"
    p.write_bytes(SECRET)
    fd = open_regular_nofollow(p, expected=_identity(p))
    try:
        assert os.read(fd, 100) == SECRET
        assert not os.get_inheritable(fd), "must be O_CLOEXEC"
        assert not fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_NONBLOCK
        with pytest.raises(OSError):
            os.write(fd, b"x")  # read-only
    finally:
        os.close(fd)


def test_open_regular_nofollow_refuses_a_symlink(tmp_path: Path) -> None:
    from envault.exceptions import EnvaultError, UnsafeFileError
    from envault.fileutils import open_regular_nofollow

    target = tmp_path / "victim_private_key"
    target.write_bytes(b"-----BEGIN PRIVATE KEY-----\n")
    link = tmp_path / "notes.txt"
    link.symlink_to(target)
    with pytest.raises(UnsafeFileError, match="symbolic link") as exc_info:
        open_regular_nofollow(link)
    assert isinstance(exc_info.value, EnvaultError)


def test_open_regular_nofollow_detects_symlink_swap_after_collection(tmp_path: Path) -> None:
    """r12 R14: the entry is replaced by a symlink after the walk recorded it."""
    from envault.exceptions import UnsafeFileError
    from envault.fileutils import open_regular_nofollow

    private = tmp_path / "victim_private_key"
    private.write_bytes(b"-----BEGIN PRIVATE KEY-----\n")
    entry = tmp_path / "notes.txt"
    entry.write_bytes(b"harmless\n")
    collected = _identity(entry)

    entry.unlink()
    entry.symlink_to(private)

    with pytest.raises(UnsafeFileError):
        open_regular_nofollow(entry, expected=collected)


def test_open_regular_nofollow_detects_replaced_file(tmp_path: Path) -> None:
    from envault.exceptions import UnsafeFileError
    from envault.fileutils import open_regular_nofollow

    entry = tmp_path / "notes.txt"
    entry.write_bytes(b"harmless\n")
    collected = _identity(entry)
    replacement = tmp_path / "other"
    replacement.write_bytes(b"something else\n")
    os.replace(replacement, entry)  # same name, different inode

    with pytest.raises(UnsafeFileError, match="changed"):
        open_regular_nofollow(entry, expected=collected)


def test_open_regular_nofollow_refuses_a_directory(tmp_path: Path) -> None:
    from envault.exceptions import UnsafeFileError
    from envault.fileutils import open_regular_nofollow

    with pytest.raises(UnsafeFileError, match="not a regular file"):
        open_regular_nofollow(tmp_path)


def test_open_regular_nofollow_refuses_a_fifo_without_blocking(tmp_path: Path) -> None:
    from envault.exceptions import UnsafeFileError
    from envault.fileutils import open_regular_nofollow

    fifo = tmp_path / "notes.txt"
    os.mkfifo(fifo)

    def attempt() -> None:
        with pytest.raises(UnsafeFileError, match="not a regular file"):
            open_regular_nofollow(fifo)

    _run_with_timeout(attempt)


def test_open_regular_nofollow_missing_file_raises_file_not_found(tmp_path: Path) -> None:
    from envault.fileutils import open_regular_nofollow

    with pytest.raises(FileNotFoundError):
        open_regular_nofollow(tmp_path / "gone")


def test_open_regular_nofollow_message_escapes_control_characters(tmp_path: Path) -> None:
    from envault.exceptions import UnsafeFileError
    from envault.fileutils import open_regular_nofollow

    target = tmp_path / "t"
    target.write_bytes(b"x")
    evil = tmp_path / "report\x1b]0;PWNED\x07.txt"
    evil.symlink_to(target)
    with pytest.raises(UnsafeFileError) as exc_info:
        open_regular_nofollow(evil)
    assert "\x1b" not in str(exc_info.value)
