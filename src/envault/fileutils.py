"""Shared filesystem helpers for envault."""

from __future__ import annotations

import errno
import logging
import os
from pathlib import Path

from envault.exceptions import EnvaultError

logger = logging.getLogger(__name__)


def open_nofollow(path: Path, flags: int, mode: int = 0o600) -> int:
    """Open ``path`` without following a final-component symlink.

    Raises:
        EnvaultError: If ``path`` is a symlink (``ELOOP``).
        OSError: Other open failures.
    """
    try:
        return os.open(str(path), flags | getattr(os, "O_NOFOLLOW", 0), mode)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise EnvaultError(
                f"Refusing to follow symlink: {path}. "
                "Ciphertext and plaintext must be regular files."
            ) from exc
        raise


def best_effort_delete(path: Path) -> None:
    """Overwrite a file with zeros then unlink it (best-effort).

    Attempts to reduce plaintext exposure on disk after decryption or key
    rotation. This is NOT a guarantee of secure deletion — copy-on-write
    filesystems (APFS, Btrfs, ZFS), SSD wear-levelling, and journaling
    filesystems may retain copies of the original data.

    Opens with ``O_NOFOLLOW`` so a swapped-in symlink cannot redirect the
    overwrite at another file. If the path is a symlink, the target is left
    untouched and only the symlink is unlinked.

    Does nothing if the file does not exist.
    """
    fd = -1
    try:
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(path), flags)
        size = os.fstat(fd).st_size
        chunk = b"\x00" * min(65536, max(size, 0))
        remaining = size
        while remaining > 0:
            to_write = min(len(chunk), remaining)
            written = os.write(fd, chunk[:to_write])
            remaining -= written
        os.fsync(fd)
    except FileNotFoundError:
        return
    except OSError as exc:
        logger.warning("Best-effort overwrite failed for %s: %s", path, exc)
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
    path.unlink(missing_ok=True)
