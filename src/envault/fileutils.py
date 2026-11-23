"""Shared filesystem helpers for envault."""

from __future__ import annotations

import errno
import logging
import os
from pathlib import Path

from envault.exceptions import EnvaultError

logger = logging.getLogger(__name__)


def _nofollow_flag() -> int:
    """Return ``O_NOFOLLOW``, or fail closed if this platform cannot refuse symlinks."""
    flag = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(flag, int):
        raise EnvaultError(
            "This platform cannot refuse symlinks (O_NOFOLLOW is unavailable). "
            "Refusing to open the file rather than follow a symlink."
        )
    return flag


def open_nofollow(path: Path, flags: int, mode: int = 0o600) -> int:
    """Open ``path`` without following a final-component symlink.

    Raises:
        EnvaultError: If ``path`` is a symlink (``ELOOP``), or if this
            platform cannot refuse symlinks.
        OSError: Other open failures.
    """
    try:
        return os.open(str(path), flags | _nofollow_flag(), mode)
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
        # Do not use open_nofollow here: ELOOP as EnvaultError would skip
        # unlink. Catch OSError, skip the overwrite, then unlink the path
        # (the symlink itself, not its target). If O_NOFOLLOW is missing,
        # skip the overwrite entirely rather than following a symlink.
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise OSError("O_NOFOLLOW unavailable; skipping overwrite")
        fd = os.open(str(path), os.O_RDWR | nofollow)
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
