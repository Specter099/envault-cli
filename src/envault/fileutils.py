"""Shared filesystem helpers for envault."""

from __future__ import annotations

import errno
import fcntl
import logging
import os
import stat
from pathlib import Path

from envault.exceptions import UnsafeFileError

logger = logging.getLogger(__name__)

_ZEROS = b"\x00" * 65536


def best_effort_delete(path: Path) -> None:
    """Overwrite a file with zeros then unlink it (best-effort).

    Attempts to reduce plaintext exposure on disk after decryption or key
    rotation. This is NOT a guarantee of secure deletion — copy-on-write
    filesystems (APFS, Btrfs, ZFS), SSD wear-levelling, and journaling
    filesystems may retain copies of the original data.

    Only the inode behind *this name alone* is overwritten:

    * A regular file with other hard links is unlinked but not zeroed. Its
      content is still reachable under another name, which is not ours to
      destroy. This is exactly the state decrypt is in when it is interrupted
      between publishing the output (a hard link to the staging file) and
      removing the staging name.
    * A symbolic link is removed, never followed. The overwrite would land on
      whatever it points to.
    * FIFOs, sockets and devices are removed without being opened. Opening a
      FIFO for writing blocks until a reader appears.
    * A directory is left in place, with a warning.

    The file is opened with ``O_NOFOLLOW`` and re-checked with ``fstat`` (same
    inode, still a single link) before the first byte is written, so a swap
    between the check and the open is caught too. Never raises for a missing
    path; other failures are logged and the unlink is still attempted.
    """
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        logger.warning("Best-effort delete could not stat %s: %s", path, exc)
        return

    if stat.S_ISDIR(st.st_mode):
        logger.warning("Best-effort delete refused %s: it is a directory", path)
        return
    if stat.S_ISREG(st.st_mode):
        if st.st_nlink == 1:
            _zero_fill(path, st)
        else:
            logger.debug(
                "Not overwriting %s: %d other hard link(s) still name its content",
                path,
                st.st_nlink - 1,
            )
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.warning("Best-effort delete could not unlink %s: %s", path, exc)


def _is_sole_link_of(st: os.stat_result, expected: os.stat_result) -> bool:
    """Same regular inode as ``expected``, and this is still its only name."""
    return (
        stat.S_ISREG(st.st_mode)
        and (st.st_dev, st.st_ino) == (expected.st_dev, expected.st_ino)
        and st.st_nlink == 1
    )


def _zero_fill(path: Path, expected: os.stat_result) -> None:
    """Overwrite the regular, single-link file at ``path`` with zeros and fsync.

    The path is first opened read-only with ``O_NOFOLLOW | O_NONBLOCK``, so a
    symlink or FIFO swapped in since the ``lstat`` is refused before anything
    is opened for writing. The write handle must then be that same inode,
    still with a single link, or nothing is written at all.
    """
    try:
        probe = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        logger.warning("Best-effort overwrite failed for %s: %s", path, exc)
        return
    try:
        if not _is_sole_link_of(os.fstat(probe), expected):
            logger.warning("Best-effort overwrite skipped for %s: file changed underneath", path)
            return
        with path.open("r+b", buffering=0) as f:
            st = os.fstat(f.fileno())
            if not _is_sole_link_of(st, expected):
                logger.warning(
                    "Best-effort overwrite skipped for %s: file changed underneath", path
                )
                return
            remaining = st.st_size
            while remaining > 0:
                written = f.write(_ZEROS[: min(len(_ZEROS), remaining)])
                if not written:
                    raise OSError(errno.EIO, "short write while overwriting")
                remaining -= written
            os.fsync(f.fileno())
    except OSError as exc:
        logger.warning("Best-effort overwrite failed for %s: %s", path, exc)
    finally:
        os.close(probe)


def open_regular_nofollow(path: Path | str, expected: tuple[int, int] | None = None) -> int:
    """Open ``path`` read-only, only if it is a regular file and not a symlink.

    Use this to read a file chosen earlier (by a directory walk, say) without
    following whatever the path points to *now*. The flags are ``O_RDONLY |
    O_NOFOLLOW | O_CLOEXEC``, with ``O_NONBLOCK`` during the open so a FIFO
    swapped in cannot hang the process (it is cleared again before
    returning). The descriptor's ``fstat`` must be a regular file.

    Hash and encrypt from the returned descriptor
    (:func:`envault.crypto.sha256_fd`, :func:`envault.crypto.encrypt_fd`).
    Re-opening the path in between would reopen the race this closes.

    Args:
        path: File to open. A symlink in the *final* component is refused
            (``O_NOFOLLOW``); directory components are resolved normally.
        expected: ``(st_dev, st_ino)`` recorded from ``os.lstat`` when the
            file was selected. If given, the opened file must be that inode.

    Returns:
        A new file descriptor. The caller owns it and must ``os.close`` it.

    Raises:
        UnsafeFileError: ``path`` is a symlink, not a regular file, or not the
            ``expected`` inode.
        OSError: Any other open failure (``FileNotFoundError``, ``PermissionError``).
    """
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise UnsafeFileError(f"Refusing to read {os.fspath(path)!r}: it is a symbolic link.")
    if not stat.S_ISREG(st.st_mode):
        raise UnsafeFileError(f"Refusing to read {os.fspath(path)!r}: not a regular file.")
    if expected is not None and (st.st_dev, st.st_ino) != expected:
        raise UnsafeFileError(
            f"Refusing to read {os.fspath(path)!r}: the file changed after it was selected."
        )

    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise UnsafeFileError(
                f"Refusing to read {os.fspath(path)!r}: it is a symbolic link."
            ) from None
        raise
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise UnsafeFileError(f"Refusing to read {os.fspath(path)!r}: not a regular file.")
        identity = (opened.st_dev, opened.st_ino)
        if identity != (st.st_dev, st.st_ino) or (expected is not None and identity != expected):
            raise UnsafeFileError(
                f"Refusing to read {os.fspath(path)!r}: the file changed after it was selected."
            )
        fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) & ~os.O_NONBLOCK)
    except BaseException:
        os.close(fd)
        raise
    return fd
