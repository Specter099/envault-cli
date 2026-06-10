"""Shared filesystem helpers for envault."""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def best_effort_delete(path: Path) -> None:
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
