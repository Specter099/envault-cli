"""Process hardening and credential isolation primitives.

This module implements the first two rungs of envault's isolation ladder:

* **Rung 1 — same-uid processes on this host.** :func:`harden_process` disables
  the dumpable flag, core dumps, and (best effort) swapping, so another process
  running as the same user cannot ``ptrace`` envault or read its plaintext out
  of ``/proc/<pid>/mem`` while a secret is in flight.
* **Rung 2 — no filesystem path at all.** :class:`CredentialFd` holds credential
  material in an anonymous, sealed ``memfd`` that is exposed to a child process
  only through an inherited file descriptor. There is no name in any filesystem
  namespace to race, snapshot, back up, or forget to delete.

**What this does not do.** ``PR_SET_DUMPABLE`` is reset to 1 by ``execve`` for
non-setuid binaries, so it protects *this* process only — it cannot be inherited
by the command that :command:`envault exec` launches. A same-uid attacker can
still read that child's environment and its ``/proc/<pid>/fd`` entries. Nothing
here defends against root, and CPython cannot reliably zero plaintext it has
already copied. These primitives narrow the window; they do not close it.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import fcntl
import logging
import os
import resource
import sys
import tempfile
from dataclasses import dataclass, field
from types import TracebackType
from typing import BinaryIO

logger = logging.getLogger(__name__)

# <sys/prctl.h>
_PR_SET_DUMPABLE = 4

# <sys/mman.h>
_MCL_CURRENT = 1
_MCL_FUTURE = 2

# <linux/fcntl.h> — not exposed by Python's fcntl module on all versions.
_F_ADD_SEALS = 1033
_F_SEAL_SHRINK = 0x0002
_F_SEAL_GROW = 0x0004
_F_SEAL_WRITE = 0x0008

_IS_LINUX = sys.platform.startswith("linux")


def _libc() -> ctypes.CDLL | None:
    """Load libc for prctl/mlockall, or return None where unavailable."""
    global _LIBC_CACHE
    if _LIBC_CACHE is not _UNSET:
        return _LIBC_CACHE
    try:
        name = ctypes.util.find_library("c")
        _LIBC_CACHE = ctypes.CDLL(name or "libc.so.6", use_errno=True)
    except OSError as exc:  # pragma: no cover - platform dependent
        logger.debug("libc unavailable, process hardening degraded: %s", exc)
        _LIBC_CACHE = None
    return _LIBC_CACHE


_UNSET: object = object()
_LIBC_CACHE: ctypes.CDLL | None = _UNSET  # type: ignore[assignment]


@dataclass
class HardeningReport:
    """Which hardening steps actually took effect.

    Every step is best effort: a missing capability degrades protection but must
    never stop a legitimate decrypt, so callers inspect this instead of catching
    exceptions.
    """

    dumpable_disabled: bool = False
    core_dumps_disabled: bool = False
    memory_locked: bool = False
    degraded: list[str] = field(default_factory=list)

    @property
    def fully_applied(self) -> bool:
        return not self.degraded

    def summary(self) -> str:
        applied = []
        if self.dumpable_disabled:
            applied.append("ptrace/proc blocked")
        if self.core_dumps_disabled:
            applied.append("core dumps off")
        if self.memory_locked:
            applied.append("memory locked")
        return ", ".join(applied) if applied else "none"


def harden_process() -> HardeningReport:
    """Reduce this process's exposure before any plaintext exists in memory.

    Call once, as early as possible, and always before decryption. Safe to call
    more than once.

    Returns:
        A :class:`HardeningReport` describing what took effect. Steps that could
        not be applied are listed in ``degraded`` rather than raised.
    """
    report = HardeningReport()

    # Core dumps first: a dump written before the other steps land would contain
    # nothing sensitive yet, but ordering costs nothing and the guarantee is
    # cleaner.
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        report.core_dumps_disabled = True
    except (ValueError, OSError) as exc:
        report.degraded.append(f"core dumps still enabled ({exc})")

    libc = _libc()

    # PR_SET_DUMPABLE=0 re-owns /proc/<pid>/{mem,environ,maps} to root and makes
    # ptrace_may_access() deny same-uid attach. This is the single highest-value
    # step available to an unprivileged process.
    if libc is not None and _IS_LINUX:
        if libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) == 0:
            report.dumpable_disabled = True
        else:
            err = ctypes.get_errno()
            report.degraded.append(f"process remains ptrace-able (prctl errno {err})")
    else:
        report.degraded.append("process remains ptrace-able (prctl unavailable)")

    # Keep plaintext pages out of swap. Usually fails without CAP_IPC_LOCK or a
    # raised RLIMIT_MEMLOCK, which is expected and not worth warning about.
    if libc is not None:
        if libc.mlockall(_MCL_CURRENT | _MCL_FUTURE) == 0:
            report.memory_locked = True
        else:
            report.degraded.append("plaintext pages may reach swap (mlockall denied)")
    else:
        report.degraded.append("plaintext pages may reach swap (mlockall unavailable)")

    logger.debug("process hardening applied", extra={"applied": report.summary()})
    return report


def _open_anonymous(label: str) -> tuple[int, str]:
    """Open a file descriptor with no reachable filesystem path.

    On Linux this is a sealable ``memfd``: the bytes live in anonymous memory and
    have never had a name. Elsewhere it degrades to a temp file that is unlinked
    immediately, which removes the path but leaves the data on disk-backed
    storage until the descriptor closes.

    Returns:
        ``(fd, backing)`` where ``backing`` is ``"memfd"`` or ``"unlinked-tmp"``.
    """
    if _IS_LINUX and hasattr(os, "memfd_create"):
        flags = getattr(os, "MFD_CLOEXEC", 0x0001) | getattr(os, "MFD_ALLOW_SEALING", 0x0002)
        return os.memfd_create(f"envault:{label}", flags), "memfd"

    fd, path = tempfile.mkstemp(prefix="envault_cred_")
    os.unlink(path)
    os.set_inheritable(fd, False)
    return fd, "unlinked-tmp"


class CredentialFd:
    """Credential material held in an anonymous descriptor, not a file.

    The descriptor is handed to a child process by inheritance, and the child
    reaches the bytes through ``/proc/self/fd/N``. Nothing appears in any
    directory, so there is no path for another process to open, no cleanup that
    can fail, and no plaintext surviving a crash.

    Write the material, call :meth:`seal`, then pass :attr:`fd` to the child via
    ``subprocess``'s ``pass_fds`` and :attr:`child_path` as the location it
    should read. Sealing happens *after* the caller has verified the checksum
    and encryption context, so a child never observes unverified bytes.

    Use as a context manager; the descriptor closes on exit and the memory is
    released by the kernel.
    """

    def __init__(self, label: str) -> None:
        self._fd, self.backing = _open_anonymous(label)
        self._closed = False
        self._sealed = False

    @property
    def fd(self) -> int:
        if self._closed:
            raise ValueError("CredentialFd is closed")
        return self._fd

    @property
    def sealed(self) -> bool:
        return self._sealed

    @property
    def child_path(self) -> str:
        """Path the *child* uses to read this descriptor after inheriting it."""
        if _IS_LINUX:
            return f"/proc/self/fd/{self.fd}"
        return f"/dev/fd/{self.fd}"

    def writer(self) -> BinaryIO:
        """Return a buffered writer over the descriptor.

        Closing the returned object does not close the descriptor, so the
        credential survives for the child.
        """
        return os.fdopen(self.fd, "wb", closefd=False)

    def seal(self) -> None:
        """Make the content immutable and hand the descriptor to children.

        Sealing prevents the bytes from being altered after verification — by
        this process or anything it spawns. Also clears ``FD_CLOEXEC`` so the
        descriptor survives ``execve``.

        Seals are a Linux ``memfd`` feature; on other backends only the
        inheritance change applies.
        """
        if _IS_LINUX and self.backing == "memfd":
            try:
                fcntl.fcntl(self.fd, _F_ADD_SEALS, _F_SEAL_WRITE | _F_SEAL_SHRINK | _F_SEAL_GROW)
                self._sealed = True
            except OSError as exc:  # pragma: no cover - kernel dependent
                logger.debug("could not seal credential fd: %s", exc)
        os.set_inheritable(self.fd, True)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                os.close(self._fd)
            except OSError:  # pragma: no cover - already closed
                pass

    def __enter__(self) -> CredentialFd:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def wipe(buf: bytearray) -> None:
    """Overwrite a mutable buffer in place.

    Only meaningful for ``bytearray``. CPython copies ``bytes`` and ``str``
    freely and never guarantees an overwrite on free, so this narrows the window
    for material we control end to end and does nothing for anything the
    interpreter has already duplicated. Do not read more into it than that.
    """
    for i in range(len(buf)):
        buf[i] = 0
