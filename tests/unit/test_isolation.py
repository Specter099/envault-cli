"""Tests for process hardening and anonymous credential descriptors."""

from __future__ import annotations

import os
import resource
import sys

import pytest

from envault.isolation import CredentialFd, HardeningReport, harden_process, wipe

_LINUX = sys.platform.startswith("linux")


def test_harden_process_disables_core_dumps() -> None:
    harden_process()
    soft, _hard = resource.getrlimit(resource.RLIMIT_CORE)
    assert soft == 0


def test_harden_process_is_idempotent() -> None:
    """Called once per command, but must tolerate being called again."""
    first = harden_process()
    second = harden_process()
    assert first.core_dumps_disabled == second.core_dumps_disabled


def test_harden_process_never_raises_and_reports_degradation() -> None:
    """Missing capabilities must degrade the report, never fail the command."""
    report = harden_process()
    assert isinstance(report, HardeningReport)
    assert isinstance(report.degraded, list)
    assert isinstance(report.summary(), str)


@pytest.mark.skipif(not _LINUX, reason="PR_SET_DUMPABLE is Linux-only")
def test_harden_process_sets_dumpable_off() -> None:
    report = harden_process()
    assert report.dumpable_disabled, report.degraded


def test_credential_fd_roundtrip() -> None:
    with CredentialFd("test") as cred:
        with cred.writer() as out:
            out.write(b"super-secret-value")
        cred.seal()
        with open(cred.child_path, "rb") as fh:
            assert fh.read() == b"super-secret-value"


def test_credential_fd_has_no_filesystem_path(tmp_path) -> None:
    """The credential must not be reachable by name from any directory."""
    with CredentialFd("test") as cred:
        with cred.writer() as out:
            out.write(b"secret")
        cred.seal()
        # child_path is a descriptor reference, not a directory entry.
        assert cred.child_path.startswith(("/proc/self/fd/", "/dev/fd/"))
        assert not list(tmp_path.iterdir())


@pytest.mark.skipif(not _LINUX, reason="memfd sealing is Linux-only")
def test_credential_fd_uses_memfd_on_linux() -> None:
    with CredentialFd("test") as cred:
        assert cred.backing == "memfd"


@pytest.mark.skipif(not _LINUX, reason="memfd sealing is Linux-only")
def test_sealed_credential_cannot_be_modified() -> None:
    """Verified bytes must stay verified — nothing may rewrite them afterwards."""
    with CredentialFd("test") as cred:
        with cred.writer() as out:
            out.write(b"verified")
        cred.seal()
        assert cred.sealed
        with pytest.raises(OSError):
            os.pwrite(cred.fd, b"tampered", 0)


def test_credential_fd_is_inheritable_after_seal() -> None:
    """The child receives the credential by inheritance, so CLOEXEC must clear."""
    with CredentialFd("test") as cred:
        with cred.writer() as out:
            out.write(b"secret")
        cred.seal()
        assert os.get_inheritable(cred.fd)


def test_credential_fd_closes_and_rejects_use() -> None:
    cred = CredentialFd("test")
    fd = cred.fd
    cred.close()
    with pytest.raises(ValueError):
        _ = cred.fd
    with pytest.raises(OSError):
        os.fstat(fd)


def test_credential_fd_double_close_is_safe() -> None:
    cred = CredentialFd("test")
    cred.close()
    cred.close()


def test_wipe_zeroes_buffer() -> None:
    buf = bytearray(b"sensitive")
    wipe(buf)
    assert buf == bytearray(len(b"sensitive"))


def test_wipe_empty_buffer() -> None:
    buf = bytearray()
    wipe(buf)
    assert buf == bytearray()
