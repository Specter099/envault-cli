"""Unit tests for envault.crypto.

Covers:
  - sha256_file: pure-Python, no AWS needed
  - _HashingReader and result dataclasses
  - Full encrypt/decrypt round-trips against moto-mocked KMS (the
    aws-encryption-sdk only sends the DEK to KMS for wrapping, which moto
    supports — the AES-GCM enveloping happens client-side)
  - Failure-path hygiene: corrupted ciphertext, checksum mismatch, and
    explicit region handling
"""

from __future__ import annotations

import hashlib
import io
import os
import random
import tempfile
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import aws_encryption_sdk
import boto3
import botocore.client
import pytest
from aws_encryption_sdk import CommitmentPolicy, StrictAwsKmsMasterKeyProvider
from aws_encryption_sdk.identifiers import Algorithm
from botocore.exceptions import ClientError
from moto import mock_aws

from envault.crypto import (
    DecryptResult,
    EncryptResult,
    _HashingReader,
    decrypt_file,
    decrypt_to_stream,
    encrypt_file,
    sha256_file,
)
from envault.exceptions import ChecksumMismatchError, DecryptionError

KMS_KEY_ALIAS = "alias/envault-test"
REGION = "us-east-1"
MOTO_ACCOUNT_ID = "123456789012"


def test_sha256_file_correct_hash(tmp_path: Path) -> None:
    content = b"hello world\n"
    p = tmp_path / "test.txt"
    p.write_bytes(content)

    expected = hashlib.sha256(content).hexdigest()
    assert sha256_file(p) == expected


def test_sha256_file_empty(tmp_path: Path) -> None:
    p = tmp_path / "empty.txt"
    p.write_bytes(b"")
    expected = hashlib.sha256(b"").hexdigest()
    assert sha256_file(p) == expected


def test_sha256_file_large(tmp_path: Path) -> None:
    # Ensure chunked reading works correctly
    content = b"X" * (200 * 1024)  # 200 KB, forces multiple 65536-byte chunks
    p = tmp_path / "large.bin"
    p.write_bytes(content)
    expected = hashlib.sha256(content).hexdigest()
    assert sha256_file(p) == expected


def test_encrypt_result_dataclass() -> None:
    result = EncryptResult(
        sha256_hash="abc123",
        file_size_bytes=1024,
        algorithm="AES_256_GCM",
        message_id="msg-001",
        output_path=Path("/tmp/out.enc"),  # noqa: S108
    )
    assert result.sha256_hash == "abc123"
    assert result.file_size_bytes == 1024
    assert result.algorithm == "AES_256_GCM"
    assert result.message_id == "msg-001"
    assert result.output_path == Path("/tmp/out.enc")  # noqa: S108


def test_decrypt_result_dataclass() -> None:
    ctx = {"purpose": "envault-backup", "sha256": "def456"}
    result = DecryptResult(
        sha256_hash="def456",
        file_size_bytes=2048,
        output_path=Path("/tmp/out.txt"),  # noqa: S108
        encryption_context=ctx,
    )
    assert result.sha256_hash == "def456"
    assert result.file_size_bytes == 2048
    assert result.output_path == Path("/tmp/out.txt")  # noqa: S108
    assert result.encryption_context == ctx


def test_decrypt_file_requires_account_ids(tmp_path: Path) -> None:
    """decrypt_file must raise ConfigurationError when allowed_account_ids is empty."""

    from envault.exceptions import ConfigurationError

    dummy_input = tmp_path / "dummy.enc"
    dummy_input.write_bytes(b"fake ciphertext")
    dummy_output = tmp_path / "out.txt"

    with pytest.raises(ConfigurationError, match="allowed_account_ids"):
        decrypt_file(
            input_path=dummy_input,
            output_path=dummy_output,
            region="us-east-1",
            allowed_account_ids=[],
        )

    with pytest.raises(ConfigurationError, match="allowed_account_ids"):
        decrypt_file(
            input_path=dummy_input,
            output_path=dummy_output,
            region="us-east-1",
            allowed_account_ids=None,
        )


def test_checksum_mismatch_error_carries_only_what_was_expected() -> None:
    """The plaintext's own hash is not kept: for a short file it is as good as the content."""
    err = ChecksumMismatchError(expected="a" * 64)

    assert err.expected == "a" * 64
    assert not hasattr(err, "actual")
    assert "mismatch" in str(err).lower()


def _assert_hash_absent(digest: str, *texts: object) -> None:
    for text in texts:
        assert digest not in str(text)
        assert digest[:16] not in str(text)


@pytest.mark.parametrize("api", ["decrypt_file", "decrypt_to_stream"])
def test_checksum_mismatch_never_names_the_plaintext_hash(
    kms_key: str, tmp_path: Path, api: str
) -> None:
    """M6: a 6-digit PIN's SHA-256 is the PIN. No prefix of it may reach an error."""
    content = b"493017\n"
    actual = hashlib.sha256(content).hexdigest()
    plaintext = tmp_path / "pin.txt"
    plaintext.write_bytes(content)
    encrypted = tmp_path / "pin.enc"
    encrypt_file(plaintext, KMS_KEY_ALIAS, {"purpose": "envault-backup"}, encrypted, REGION)

    with pytest.raises(ChecksumMismatchError) as exc_info:
        if api == "decrypt_file":
            decrypt_file(
                encrypted,
                tmp_path / "out.txt",
                expected_sha256="0" * 64,
                region=REGION,
                allowed_account_ids=[MOTO_ACCOUNT_ID],
            )
        else:
            with encrypted.open("rb") as source:
                decrypt_to_stream(
                    source,
                    io.BytesIO(),
                    expected_sha256="0" * 64,
                    region=REGION,
                    allowed_account_ids=[MOTO_ACCOUNT_ID],
                )

    err = exc_info.value
    _assert_hash_absent(actual, err, repr(err), *vars(err).values(), *err.args)


def test_crypto_logs_never_carry_the_plaintext_hash(
    kms_key: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """M6: under -v envault's INFO records reach stderr with their extras as JSON fields."""
    import logging

    content = b"493017\n"
    digest = hashlib.sha256(content).hexdigest()
    plaintext = tmp_path / "pin.txt"
    plaintext.write_bytes(content)
    encrypted = tmp_path / "pin.enc"

    with caplog.at_level(logging.DEBUG, logger="envault"):
        result = encrypt_file(
            plaintext, KMS_KEY_ALIAS, {"purpose": "envault-backup"}, encrypted, REGION
        )
        decrypt_file(
            encrypted,
            tmp_path / "out.txt",
            expected_sha256=result.sha256_hash,
            region=REGION,
            allowed_account_ids=[MOTO_ACCOUNT_ID],
        )

    records = [r for r in caplog.records if r.name.startswith("envault")]
    assert records, "expected envault's own log records"
    for record in records:
        _assert_hash_absent(digest, record.getMessage(), *vars(record).values())


# ---------------------------------------------------------------------------
# _HashingReader tests
# ---------------------------------------------------------------------------


def test_hashing_reader_computes_sha256(tmp_path: Path) -> None:
    """_HashingReader must produce correct SHA256 after multiple reads."""
    content = b"hello world" * 100
    p = tmp_path / "data.bin"
    p.write_bytes(content)

    with p.open("rb") as f:
        reader = _HashingReader(f)
        chunks = []
        while True:
            chunk = reader.read(64)
            if not chunk:
                break
            chunks.append(chunk)

    assert b"".join(chunks) == content
    assert reader.hexdigest == hashlib.sha256(content).hexdigest()


def test_hashing_reader_empty_read(tmp_path: Path) -> None:
    """_HashingReader must handle empty files correctly."""
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")

    with p.open("rb") as f:
        reader = _HashingReader(f)
        data = reader.read()

    assert data == b""
    assert reader.hexdigest == hashlib.sha256(b"").hexdigest()


def test_hashing_reader_delegates_attributes(tmp_path: Path) -> None:
    """_HashingReader must delegate unknown attributes to the wrapped file."""
    p = tmp_path / "test.bin"
    p.write_bytes(b"some data")

    with p.open("rb") as f:
        reader = _HashingReader(f)
        # .name is a file attribute, not defined on _HashingReader
        assert reader.name == f.name
        # .seekable() is a method on the file object
        assert reader.seekable() == f.seekable()


# ---------------------------------------------------------------------------
# Round-trip tests against moto-mocked KMS
# ---------------------------------------------------------------------------


def _write_multiframe_plaintext(path: Path) -> bytes:
    """Write plaintext large enough to span multiple 64 KiB read chunks.

    This matters for the corruption test: a corrupted late frame must fail
    only after earlier chunks were already written to disk.
    """
    content = os.urandom(200 * 1024)
    path.write_bytes(content)
    return content


def test_roundtrip_encrypt_decrypt(kms_key: str, tmp_path: Path) -> None:
    """Encrypt then decrypt restores the exact content and encryption context."""
    plaintext = tmp_path / "secret.txt"
    content = _write_multiframe_plaintext(plaintext)
    encrypted = tmp_path / "secret.enc"
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    output = out_dir / "secret.txt"

    result = encrypt_file(
        input_path=plaintext,
        key_id=KMS_KEY_ALIAS,
        encryption_context={"purpose": "envault-backup", "file_name": "secret.txt"},
        output_path=encrypted,
        region=REGION,
    )
    assert result.sha256_hash == hashlib.sha256(content).hexdigest()
    assert result.file_size_bytes == len(content)

    dec = decrypt_file(
        input_path=encrypted,
        output_path=output,
        expected_sha256=result.sha256_hash,
        region=REGION,
        allowed_account_ids=[MOTO_ACCOUNT_ID],
    )
    assert output.read_bytes() == content
    assert dec.sha256_hash == result.sha256_hash
    assert dec.encryption_context["purpose"] == "envault-backup"
    assert dec.encryption_context["file_name"] == "secret.txt"


def test_decrypt_corrupted_ciphertext_raises_and_cleans_up(kms_key: str, tmp_path: Path) -> None:
    """A late-frame corruption surfaces as DecryptionError, is not retried,
    and leaves no partial plaintext in the destination directory."""
    plaintext = tmp_path / "secret.txt"
    _write_multiframe_plaintext(plaintext)
    encrypted = tmp_path / "secret.enc"
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    output = out_dir / "secret.txt"

    result = encrypt_file(
        input_path=plaintext,
        key_id=KMS_KEY_ALIAS,
        encryption_context={"purpose": "envault-backup"},
        output_path=encrypted,
        region=REGION,
    )

    data = bytearray(encrypted.read_bytes())
    data[int(len(data) * 0.9)] ^= 0xFF  # corrupt a late AES-GCM frame
    encrypted.write_bytes(bytes(data))

    with pytest.raises(DecryptionError):
        decrypt_file(
            input_path=encrypted,
            output_path=output,
            expected_sha256=result.sha256_hash,
            region=REGION,
            allowed_account_ids=[MOTO_ACCOUNT_ID],
        )

    assert not output.exists()
    assert list(out_dir.iterdir()) == []  # no partial or temp files left behind
    stats = decrypt_file.statistics
    assert stats["attempt_number"] == 1  # deterministic failure must not be retried


def test_decrypt_checksum_mismatch_leaves_no_output(kms_key: str, tmp_path: Path) -> None:
    """On checksum mismatch the plaintext never appears at output_path and no
    temp file remains in the destination directory."""
    plaintext = tmp_path / "secret.txt"
    _write_multiframe_plaintext(plaintext)
    encrypted = tmp_path / "secret.enc"
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    output = out_dir / "secret.txt"

    encrypt_file(
        input_path=plaintext,
        key_id=KMS_KEY_ALIAS,
        encryption_context={"purpose": "envault-backup"},
        output_path=encrypted,
        region=REGION,
    )

    with pytest.raises(ChecksumMismatchError):
        decrypt_file(
            input_path=encrypted,
            output_path=output,
            expected_sha256="0" * 64,
            region=REGION,
            allowed_account_ids=[MOTO_ACCOUNT_ID],
        )

    assert not output.exists()
    assert list(out_dir.iterdir()) == []
    stats = decrypt_file.statistics
    assert stats["attempt_number"] == 1


def test_encrypt_decrypt_respects_explicit_region(tmp_path: Path) -> None:
    """encrypt_file must resolve the key alias in the requested region, not
    the ambient AWS_DEFAULT_REGION (us-east-1 in the test environment)."""
    with mock_aws():
        kms = boto3.client("kms", region_name="us-west-2")
        key_id = kms.create_key(Description="west-only")["KeyMetadata"]["KeyId"]
        kms.create_alias(AliasName="alias/west-only", TargetKeyId=key_id)

        plaintext = tmp_path / "secret.txt"
        content = b"regional content\n" * 100
        plaintext.write_bytes(content)
        encrypted = tmp_path / "secret.enc"
        output = tmp_path / "out.txt"

        result = encrypt_file(
            input_path=plaintext,
            key_id="alias/west-only",
            encryption_context={"purpose": "envault-backup"},
            output_path=encrypted,
            region="us-west-2",
        )
        decrypt_file(
            input_path=encrypted,
            output_path=output,
            expected_sha256=result.sha256_hash,
            region="us-west-2",
            allowed_account_ids=[MOTO_ACCOUNT_ID],
        )
        assert output.read_bytes() == content


# ---------------------------------------------------------------------------
# Streaming decrypt: verification ordering
# ---------------------------------------------------------------------------


@mock_aws
def test_decrypt_to_stream_rejects_context_before_writing_plaintext():
    """A mismatched context must be caught before any plaintext reaches the sink."""
    import io

    from envault.crypto import decrypt_to_stream
    from envault.exceptions import EncryptionContextMismatchError

    kms = boto3.client("kms", region_name=REGION)
    key_id = kms.create_key(Description="stream-test")["KeyMetadata"]["KeyId"]
    account = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
    ctx = {"purpose": "envault-backup", "sha256": "a" * 64}

    ciphertext = io.BytesIO()
    plaintext = b"the actual secret bytes"
    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "in.txt"
        src.write_bytes(plaintext)
        out = Path(tmpdir) / "out.enc"
        encrypt_file(src, key_id, ctx, out, REGION)
        ciphertext = io.BytesIO(out.read_bytes())

    sink = io.BytesIO()
    with pytest.raises(EncryptionContextMismatchError):
        decrypt_to_stream(
            ciphertext,
            sink,
            expected_context={"purpose": "SOMETHING-ELSE"},
            region=REGION,
            allowed_account_ids=[account],
        )
    assert sink.getvalue() == b"", "plaintext must not be written on a context mismatch"


@mock_aws
def test_decrypt_to_stream_roundtrip():
    import io

    from envault.crypto import decrypt_to_stream

    kms = boto3.client("kms", region_name=REGION)
    key_id = kms.create_key(Description="stream-test")["KeyMetadata"]["KeyId"]
    account = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
    plaintext = b"round trip content"
    ctx = {"purpose": "envault-backup"}

    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "in.txt"
        src.write_bytes(plaintext)
        out = Path(tmpdir) / "out.enc"
        encrypt_file(src, key_id, ctx, out, REGION)
        ciphertext = io.BytesIO(out.read_bytes())

    sink = io.BytesIO()
    result = decrypt_to_stream(
        ciphertext,
        sink,
        expected_sha256=hashlib.sha256(plaintext).hexdigest(),
        expected_context=ctx,
        region=REGION,
        allowed_account_ids=[account],
    )
    assert sink.getvalue() == plaintext
    assert result.output_path is None


def test_partition_for_region():
    """Discovery filters must not silently exclude GovCloud or China partitions."""
    from envault.crypto import _partition_for_region

    assert _partition_for_region("us-east-1") == "aws"
    assert _partition_for_region("eu-west-2") == "aws"
    assert _partition_for_region("us-gov-west-1") == "aws-us-gov"
    assert _partition_for_region("cn-north-1") == "aws-cn"


def test_decrypt_missing_ciphertext_cleans_temp(tmp_path: Path) -> None:
    """If the ciphertext path cannot be opened, no .part file must remain."""
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    output = out_dir / "secret.txt"
    missing = tmp_path / "nope.enc"

    with pytest.raises(FileNotFoundError):
        decrypt_file(
            input_path=missing,
            output_path=output,
            allowed_account_ids=[MOTO_ACCOUNT_ID],
        )

    assert not output.exists()
    assert list(out_dir.iterdir()) == []


# ---------------------------------------------------------------------------
# Fault injection helpers
# ---------------------------------------------------------------------------

_REAL_API_CALL = botocore.client.BaseClient._make_api_call
PLAINTEXT_MARKER = b"PLAINTEXT-MARKER-must-never-appear-in-messages\n"


def _client_error(code: str, op: str, status: int = 400) -> ClientError:
    return ClientError(
        {
            "Error": {"Code": code, "Message": f"simulated {code}"},
            "ResponseMetadata": {"HTTPStatusCode": status},
        },
        op,
    )


@contextmanager
def _kms_faults(**plans: list[Exception | None]):
    """Make the n-th call of a KMS operation raise ``plans[op][n]`` (None = real call).

    Patches the same layer the review repros patch (BaseClient._make_api_call),
    so the Encryption SDK sees exactly what it would see from KMS. Yields a
    Counter of KMS calls per operation.
    """
    calls: Counter[str] = Counter()

    def patched(self, operation_name, api_params):
        if self.meta.service_model.service_name == "kms":
            calls[operation_name] += 1
            plan = plans.get(operation_name, [])
            index = calls[operation_name] - 1
            if index < len(plan) and plan[index] is not None:
                raise plan[index]
        return _REAL_API_CALL(self, operation_name, api_params)

    with patch.object(botocore.client.BaseClient, "_make_api_call", patched):
        yield calls


def _encrypt_marker(tmp_path: Path, content: bytes = PLAINTEXT_MARKER) -> tuple[Path, str]:
    plaintext = tmp_path / "secret.txt"
    plaintext.write_bytes(content)
    encrypted = tmp_path / "secret.enc"
    result = encrypt_file(
        plaintext, KMS_KEY_ALIAS, {"purpose": "envault-backup"}, encrypted, REGION
    )
    return encrypted, result.sha256_hash


def _assert_no_tampering_claim(message: str) -> None:
    lowered = message.lower()
    for word in ("tamper", "corrupt", "truncat"):
        assert word not in lowered, f"KMS failure described as {word!r}: {message}"


# ---------------------------------------------------------------------------
# M1: an interrupt during decrypt_file is never retried (r02 (b))
# ---------------------------------------------------------------------------


def test_decrypt_file_does_not_retry_keyboard_interrupt(
    kms_key: str, tmp_path: Path, no_retry_sleep: list[float]
) -> None:
    import envault.crypto as crypto

    encrypted, sha = _encrypt_marker(tmp_path)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    output = out_dir / "plain.txt"
    real = crypto.decrypt_to_stream
    seen = {"n": 0}

    def interrupted_once(*args, **kwargs):
        seen["n"] += 1
        if seen["n"] == 1:
            raise KeyboardInterrupt
        return real(*args, **kwargs)

    with patch.object(crypto, "decrypt_to_stream", interrupted_once):
        with pytest.raises(KeyboardInterrupt):
            decrypt_file(
                encrypted, output, expected_sha256=sha, allowed_account_ids=[MOTO_ACCOUNT_ID]
            )
    assert seen["n"] == 1
    assert not output.exists()
    assert list(out_dir.iterdir()) == [], "the .part file must be cleaned up"
    assert no_retry_sleep == []


# ---------------------------------------------------------------------------
# L1(d): KMS failures on decrypt are retried when transient, never called tampering
# ---------------------------------------------------------------------------


def test_decrypt_retries_kms_throttling(
    kms_key: str, tmp_path: Path, no_retry_sleep: list[float]
) -> None:
    """r11 (d): one throttled KMS Decrypt must not end the decrypt."""
    encrypted, sha = _encrypt_marker(tmp_path)
    output = tmp_path / "out.txt"
    with _kms_faults(Decrypt=[_client_error("ThrottlingException", "Decrypt")]) as calls:
        result = decrypt_file(
            encrypted, output, expected_sha256=sha, allowed_account_ids=[MOTO_ACCOUNT_ID]
        )
    assert output.read_bytes() == PLAINTEXT_MARKER
    assert result.sha256_hash == sha
    assert calls["Decrypt"] == 2
    assert no_retry_sleep == [1]


def test_decrypt_to_stream_retries_kms_throttling_before_writing(
    kms_key: str, tmp_path: Path, no_retry_sleep: list[float]
) -> None:
    encrypted, sha = _encrypt_marker(tmp_path)
    throttle = _client_error("ThrottlingException", "Decrypt")
    sink = io.BytesIO()
    with _kms_faults(Decrypt=[throttle, throttle]) as calls:
        decrypt_to_stream(
            io.BytesIO(encrypted.read_bytes()),
            sink,
            expected_sha256=sha,
            allowed_account_ids=[MOTO_ACCOUNT_ID],
        )
    assert sink.getvalue() == PLAINTEXT_MARKER
    assert calls["Decrypt"] == 3


def test_decrypt_kms_throttling_exhausted_is_a_transient_kms_error(
    kms_key: str, tmp_path: Path, no_retry_sleep: list[float]
) -> None:
    from envault.exceptions import EnvaultError, KMSError

    encrypted, sha = _encrypt_marker(tmp_path)
    throttle = _client_error("ThrottlingException", "Decrypt")
    sink = io.BytesIO()
    with _kms_faults(Decrypt=[throttle] * 3) as calls:
        with pytest.raises(KMSError) as exc_info:
            decrypt_to_stream(
                io.BytesIO(encrypted.read_bytes()), sink, allowed_account_ids=[MOTO_ACCOUNT_ID]
            )
    err = exc_info.value
    assert isinstance(err, EnvaultError)
    assert not isinstance(err, DecryptionError)
    assert err.operation == "Decrypt"
    assert err.error_code == "ThrottlingException"
    assert err.transient is True
    assert err.key_id.startswith("arn:aws:kms:us-east-1:123456789012:key/")
    assert "ThrottlingException" in str(err)
    _assert_no_tampering_claim(str(err))
    assert calls["Decrypt"] == 3
    assert sink.getvalue() == b""


def test_decrypt_kms_access_denied_message(
    kms_key: str, tmp_path: Path, no_retry_sleep: list[float]
) -> None:
    """A permission problem is not reported as tampering, and is not retried."""
    from envault.exceptions import KMSError

    encrypted, sha = _encrypt_marker(tmp_path)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    output = out_dir / "plain.txt"
    with _kms_faults(Decrypt=[_client_error("AccessDeniedException", "Decrypt")]) as calls:
        with pytest.raises(KMSError) as exc_info:
            decrypt_file(
                encrypted, output, expected_sha256=sha, allowed_account_ids=[MOTO_ACCOUNT_ID]
            )
    err = exc_info.value
    assert err.error_code == "AccessDeniedException"
    assert err.transient is False
    assert "AccessDeniedException" in str(err)
    assert "kms:Decrypt" in str(err)
    _assert_no_tampering_claim(str(err))
    assert PLAINTEXT_MARKER.decode().strip() not in str(err)
    assert calls["Decrypt"] == 1
    assert no_retry_sleep == []
    assert list(out_dir.iterdir()) == []


@pytest.mark.parametrize("code", ["DisabledException", "KMSInvalidStateException"])
def test_decrypt_kms_key_state_errors_are_not_tampering(
    code: str, kms_key: str, tmp_path: Path, no_retry_sleep: list[float]
) -> None:
    from envault.exceptions import KMSError

    encrypted, _sha = _encrypt_marker(tmp_path)
    with _kms_faults(Decrypt=[_client_error(code, "Decrypt")]) as calls:
        with pytest.raises(KMSError) as exc_info:
            decrypt_to_stream(
                io.BytesIO(encrypted.read_bytes()),
                io.BytesIO(),
                allowed_account_ids=[MOTO_ACCOUNT_ID],
            )
    assert exc_info.value.error_code == code
    assert exc_info.value.transient is False
    _assert_no_tampering_claim(str(exc_info.value))
    assert calls["Decrypt"] == 1


@pytest.mark.parametrize(
    "code",
    ["InvalidCiphertextException", "IncorrectKeyException", "InvalidKeyUsageException"],
)
def test_decrypt_kms_rejecting_the_data_key_is_an_integrity_failure(
    code: str, kms_key: str, tmp_path: Path, no_retry_sleep: list[float]
) -> None:
    """KMS saying the encrypted data key does not verify implicates the ciphertext."""
    encrypted, _sha = _encrypt_marker(tmp_path)
    with _kms_faults(Decrypt=[_client_error(code, "Decrypt")]) as calls:
        with pytest.raises(DecryptionError, match="tampered") as exc_info:
            decrypt_to_stream(
                io.BytesIO(encrypted.read_bytes()),
                io.BytesIO(),
                allowed_account_ids=[MOTO_ACCOUNT_ID],
            )
    assert code in str(exc_info.value)
    assert calls["Decrypt"] == 1
    assert no_retry_sleep == []


def test_decrypt_kms_not_found_names_both_explanations(
    kms_key: str, tmp_path: Path, no_retry_sleep: list[float]
) -> None:
    """A deleted key and a forged key ARN look identical; say so, keep the strong type."""
    encrypted, _sha = _encrypt_marker(tmp_path)
    with _kms_faults(Decrypt=[_client_error("NotFoundException", "Decrypt")]):
        with pytest.raises(DecryptionError) as exc_info:
            decrypt_to_stream(
                io.BytesIO(encrypted.read_bytes()),
                io.BytesIO(),
                allowed_account_ids=[MOTO_ACCOUNT_ID],
            )
    message = str(exc_info.value)
    assert "deleted" in message
    assert "tampered" in message


def test_decrypt_to_stream_does_not_retry_an_unseekable_source(
    kms_key: str, tmp_path: Path, no_retry_sleep: list[float]
) -> None:
    from envault.exceptions import KMSError

    encrypted, _sha = _encrypt_marker(tmp_path)

    class OneShot:
        """A stream that cannot be replayed (like an S3 response body)."""

        def __init__(self, data: bytes) -> None:
            self._buf = io.BytesIO(data)

        def read(self, size: int = -1) -> bytes:
            return self._buf.read(size)

        def seekable(self) -> bool:
            return False

    with _kms_faults(Decrypt=[_client_error("ThrottlingException", "Decrypt")]) as calls:
        with pytest.raises(KMSError):
            decrypt_to_stream(
                OneShot(encrypted.read_bytes()), io.BytesIO(), allowed_account_ids=[MOTO_ACCOUNT_ID]
            )
    assert calls["Decrypt"] == 1


def test_decrypt_to_stream_never_retries_after_plaintext_was_written(
    kms_key: str, tmp_path: Path, no_retry_sleep: list[float]
) -> None:
    """A transient error mid-stream must not replay into a sink that holds plaintext."""
    from botocore.exceptions import ReadTimeoutError

    plaintext = tmp_path / "big.bin"
    content = _write_multiframe_plaintext(plaintext)
    encrypted = tmp_path / "big.enc"
    encrypt_file(plaintext, KMS_KEY_ALIAS, {"purpose": "envault-backup"}, encrypted, REGION)
    data = encrypted.read_bytes()

    class FlakyAfter(io.BytesIO):
        """Seekable, but the connection 'drops' once 150 KB have been read."""

        def __init__(self, payload: bytes) -> None:
            super().__init__(payload)
            self.seeks = 0
            self.failed = False

        def seek(self, *args):  # type: ignore[override]
            self.seeks += 1
            return super().seek(*args)

        def read(self, size: int = -1) -> bytes:
            if not self.failed and self.tell() > 150 * 1024:
                self.failed = True
                raise ReadTimeoutError(endpoint_url="https://s3.us-east-1.amazonaws.com")
            return super().read(size)

    source = FlakyAfter(data)
    sink = io.BytesIO()
    with _kms_faults() as calls:
        with pytest.raises(ReadTimeoutError):
            decrypt_to_stream(source, sink, allowed_account_ids=[MOTO_ACCOUNT_ID])
    assert 0 < len(sink.getvalue()) < len(content), "plaintext had reached the sink"
    assert calls["Decrypt"] == 1, "no second attempt after plaintext was written"
    assert no_retry_sleep == []


def test_decrypt_to_stream_retry_transient_false_makes_one_attempt(
    kms_key: str, tmp_path: Path, no_retry_sleep: list[float]
) -> None:
    from envault.exceptions import KMSError

    encrypted, _sha = _encrypt_marker(tmp_path)
    with _kms_faults(Decrypt=[_client_error("ThrottlingException", "Decrypt")]) as calls:
        with pytest.raises(KMSError):
            decrypt_to_stream(
                io.BytesIO(encrypted.read_bytes()),
                io.BytesIO(),
                allowed_account_ids=[MOTO_ACCOUNT_ID],
                retry_transient=False,
            )
    assert calls["Decrypt"] == 1


# ---------------------------------------------------------------------------
# r15: properties that must stay true (regression guards)
# ---------------------------------------------------------------------------


def _r15_ciphertext(tmp_path: Path) -> tuple[bytes, bytes]:
    # Seeded, not secure: reproduces the r15 test vectors exactly.
    pt = bytes(random.Random(1).randrange(256) for _ in range(20000))  # noqa: S311
    src = tmp_path / "p"
    src.write_bytes(pt)
    ctx = {"purpose": "envault-backup", "sha256": "a" * 64, "file_name": "p"}
    encrypt_file(src, KMS_KEY_ALIAS, ctx, tmp_path / "c", REGION)
    return pt, (tmp_path / "c").read_bytes()


def test_decrypt_untrusted_account_makes_no_kms_calls(
    kms_key: str, tmp_path: Path, no_retry_sleep: list[float]
) -> None:
    _pt, ct = _r15_ciphertext(tmp_path)
    sink = io.BytesIO()
    with _kms_faults() as calls:
        with pytest.raises(DecryptionError, match="trusted account"):
            decrypt_to_stream(io.BytesIO(ct), sink, allowed_account_ids=["999999999999"])
    assert calls["Decrypt"] == 0
    assert sink.getvalue() == b""


def test_decrypt_wrong_partition_is_refused_without_kms_calls(
    kms_key: str, tmp_path: Path, no_retry_sleep: list[float]
) -> None:
    _pt, ct = _r15_ciphertext(tmp_path)
    with _kms_faults() as calls:
        with pytest.raises(DecryptionError):
            decrypt_to_stream(
                io.BytesIO(ct),
                io.BytesIO(),
                region="us-gov-west-1",
                allowed_account_ids=[MOTO_ACCOUNT_ID],
            )
    assert calls["Decrypt"] == 0


def test_decrypt_refuses_non_committing_algorithm_suite(
    kms_key: str, tmp_path: Path, no_retry_sleep: list[float]
) -> None:
    pt = b"legacy suite" * 100
    legacy = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
    )
    provider = StrictAwsKmsMasterKeyProvider(key_ids=[KMS_KEY_ALIAS], region_names=[REGION])
    old_ct, header = legacy.encrypt(
        source=pt,
        key_provider=provider,
        encryption_context={"purpose": "envault-backup"},
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    )
    assert not header.algorithm.is_committing()
    sink = io.BytesIO()
    with pytest.raises(DecryptionError):
        decrypt_to_stream(io.BytesIO(old_ct), sink, allowed_account_ids=[MOTO_ACCOUNT_ID])
    assert sink.getvalue() == b""


def test_decrypt_refuses_two_encrypted_data_keys(
    kms_key: str, tmp_path: Path, no_retry_sleep: list[float]
) -> None:
    kms = boto3.client("kms", region_name=REGION)
    first = kms.describe_key(KeyId=KMS_KEY_ALIAS)["KeyMetadata"]["Arn"]
    second = kms.create_key()["KeyMetadata"]["Arn"]
    two = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )
    ct, _ = two.encrypt(
        source=b"two keys" * 100,
        key_provider=StrictAwsKmsMasterKeyProvider(key_ids=[first, second]),
        encryption_context={"purpose": "envault-backup"},
    )
    with _kms_faults() as calls:
        with pytest.raises(DecryptionError):
            decrypt_to_stream(io.BytesIO(ct), io.BytesIO(), allowed_account_ids=[MOTO_ACCOUNT_ID])
    assert calls["Decrypt"] == 0


def test_decrypt_truncation_and_bitflip_sweep_all_raise_decryption_error(
    kms_key: str, tmp_path: Path, no_retry_sleep: list[float]
) -> None:
    """r15 #7/#8: every truncation, single-bit flip and garbage blob is a DecryptionError.

    In particular none becomes a KMSError (a softer message) or a retry: flips
    in the encrypted data key reach KMS, which rejects them.
    """
    pt, ct = _r15_ciphertext(tmp_path)
    rng = random.Random(7)  # noqa: S311 - seeded so the sweep is the r15 sweep
    cuts = sorted(
        {0, 1, 2, 10, 50, 100, 200, 400, 600, 800, len(ct) - 200, len(ct) - 103, len(ct) - 50}
        | {len(ct) - 1}
        | {rng.randrange(len(ct)) for _ in range(40)}
    )
    blobs = [ct[:cut] for cut in cuts]
    for _ in range(60):
        flipped = bytearray(ct)
        flipped[rng.randrange(len(flipped))] ^= 1 << rng.randrange(8)
        blobs.append(bytes(flipped))
    blobs += [b"", b"not an esdk message at all" * 10]

    outcomes: Counter[str] = Counter()
    for blob in blobs:
        sink = io.BytesIO()
        try:
            decrypt_to_stream(io.BytesIO(blob), sink, allowed_account_ids=[MOTO_ACCOUNT_ID])
            outcomes["DECRYPTED" if sink.getvalue() == pt else "DECRYPTED-WRONG"] += 1
        except DecryptionError:
            outcomes["DecryptionError"] += 1
        except Exception as exc:  # noqa: BLE001 - the point is to see every other type
            outcomes[type(exc).__name__] += 1
    assert outcomes == Counter({"DecryptionError": len(blobs)}), outcomes
    assert no_retry_sleep == [], "integrity failures must never be retried"


# ---------------------------------------------------------------------------
# L2: encrypt wraps Encryption SDK failures; deterministic KMS errors fail fast
# ---------------------------------------------------------------------------


def test_encrypt_wraps_kms_access_denied(
    kms_key: str, tmp_path: Path, no_retry_sleep: list[float]
) -> None:
    """r11 (a): a raw GenerateKeyError escaped the CLI after 3 s of retries."""
    from envault.exceptions import EnvaultError, KMSError

    plaintext = tmp_path / "secret.txt"
    plaintext.write_bytes(PLAINTEXT_MARKER)
    denied = _client_error("AccessDeniedException", "GenerateDataKey")
    with _kms_faults(GenerateDataKey=[denied] * 3) as calls:
        with pytest.raises(KMSError) as exc_info:
            encrypt_file(plaintext, KMS_KEY_ALIAS, {"p": "x"}, tmp_path / "out.enc", REGION)
    err = exc_info.value
    assert isinstance(err, EnvaultError)
    assert err.operation == "GenerateDataKey"
    assert err.error_code == "AccessDeniedException"
    assert err.transient is False
    assert KMS_KEY_ALIAS in str(err)
    assert "AccessDeniedException" in str(err)
    assert PLAINTEXT_MARKER.decode().strip() not in str(err)
    assert calls["GenerateDataKey"] == 1, "deterministic KMS errors must not be retried"
    assert no_retry_sleep == []


def test_encrypt_unknown_key_alias_fails_fast(
    kms_key: str, tmp_path: Path, no_retry_sleep: list[float]
) -> None:
    from envault.exceptions import KMSError

    plaintext = tmp_path / "secret.txt"
    plaintext.write_bytes(b"x")
    with _kms_faults() as calls:
        with pytest.raises(KMSError) as exc_info:
            encrypt_file(plaintext, "alias/does-not-exist", {}, tmp_path / "o", REGION)
    assert exc_info.value.error_code == "NotFoundException"
    assert calls["GenerateDataKey"] == 1


def test_encrypt_retries_kms_throttling(
    kms_key: str, tmp_path: Path, no_retry_sleep: list[float]
) -> None:
    plaintext = tmp_path / "secret.txt"
    content = _write_multiframe_plaintext(plaintext)
    throttle = _client_error("ThrottlingException", "GenerateDataKey")
    with _kms_faults(GenerateDataKey=[throttle]) as calls:
        result = encrypt_file(plaintext, KMS_KEY_ALIAS, {}, tmp_path / "out.enc", REGION)
    assert calls["GenerateDataKey"] == 2
    # The retry re-read the whole input from the start.
    assert result.sha256_hash == hashlib.sha256(content).hexdigest()
    assert result.file_size_bytes == len(content)


def test_encrypt_kms_throttling_exhausted_is_transient(
    kms_key: str, tmp_path: Path, no_retry_sleep: list[float]
) -> None:
    from envault.exceptions import KMSError

    plaintext = tmp_path / "secret.txt"
    plaintext.write_bytes(b"x")
    throttle = _client_error("ThrottlingException", "GenerateDataKey")
    with _kms_faults(GenerateDataKey=[throttle] * 3) as calls:
        with pytest.raises(KMSError) as exc_info:
            encrypt_file(plaintext, KMS_KEY_ALIAS, {}, tmp_path / "out.enc", REGION)
    assert exc_info.value.transient is True
    assert calls["GenerateDataKey"] == 3


def test_encrypt_wraps_non_kms_sdk_errors(tmp_path: Path, no_retry_sleep: list[float]) -> None:
    from envault.exceptions import EncryptionError, EnvaultError

    plaintext = tmp_path / "secret.txt"
    plaintext.write_bytes(PLAINTEXT_MARKER)
    with pytest.raises(EncryptionError) as exc_info:
        encrypt_file(plaintext, "", {}, tmp_path / "out.enc", REGION)
    assert isinstance(exc_info.value, EnvaultError)
    assert PLAINTEXT_MARKER.decode().strip() not in str(exc_info.value)
    assert no_retry_sleep == []


def test_sdk_kms_clients_make_one_http_attempt_per_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_retry_sleep: list[float]
) -> None:
    """KMS clients built by the Encryption SDK get boto_config too: 3 requests, not 6."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from envault.exceptions import KMSError

    hits = {"n": 0}

    class Always500(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            hits["n"] += 1
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Always500)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("AWS_ENDPOINT_URL_KMS", f"http://127.0.0.1:{server.server_port}")
    plaintext = tmp_path / "secret.txt"
    plaintext.write_bytes(b"x")
    try:
        with pytest.raises(KMSError) as exc_info:
            encrypt_file(plaintext, KMS_KEY_ALIAS, {}, tmp_path / "out.enc", REGION)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    assert exc_info.value.transient is True
    assert hits["n"] == 3


# ---------------------------------------------------------------------------
# L4: hash and encrypt from one descriptor
# ---------------------------------------------------------------------------


def test_sha256_fd_hashes_the_whole_file_from_offset_zero(tmp_path: Path) -> None:
    from envault.crypto import sha256_fd

    p = tmp_path / "data.bin"
    content = os.urandom(150 * 1024)
    p.write_bytes(content)
    fd = os.open(p, os.O_RDONLY)
    try:
        os.read(fd, 1000)  # move the offset; the hash must still cover everything
        assert sha256_fd(fd) == hashlib.sha256(content).hexdigest() == sha256_file(p)
        os.fstat(fd)  # still open: the caller owns it
    finally:
        os.close(fd)


def test_encrypt_fd_after_sha256_fd_encrypts_the_same_bytes(kms_key: str, tmp_path: Path) -> None:
    from envault.crypto import encrypt_fd, sha256_fd
    from envault.fileutils import open_regular_nofollow

    p = tmp_path / "notes.txt"
    content = _write_multiframe_plaintext(p)
    fd = open_regular_nofollow(p)
    try:
        digest = sha256_fd(fd)  # leaves the offset at end of file
        result = encrypt_fd(
            fd, KMS_KEY_ALIAS, {"purpose": "envault-backup"}, tmp_path / "c", REGION
        )
        os.fstat(fd)  # encrypt_fd must not close the caller's descriptor
    finally:
        os.close(fd)
    assert result.sha256_hash == digest == hashlib.sha256(content).hexdigest()
    assert result.file_size_bytes == len(content)
    out = tmp_path / "round.txt"
    decrypt_file(tmp_path / "c", out, expected_sha256=digest, allowed_account_ids=[MOTO_ACCOUNT_ID])
    assert out.read_bytes() == content


def test_encrypt_fd_reads_the_opened_file_not_the_current_path(
    kms_key: str, tmp_path: Path
) -> None:
    """r12 R14: a symlink swapped in after the open does not change what is encrypted."""
    from envault.crypto import encrypt_fd, sha256_fd
    from envault.fileutils import open_regular_nofollow

    private = tmp_path / "victim_private_key"
    private.write_bytes(b"-----BEGIN PRIVATE KEY----- not in the tree\n")
    entry = tmp_path / "notes.txt"
    entry.write_bytes(b"harmless\n")
    fd = open_regular_nofollow(entry)
    try:
        entry.unlink()
        entry.symlink_to(private)
        digest = sha256_fd(fd)
        result = encrypt_fd(fd, KMS_KEY_ALIAS, {}, tmp_path / "c", REGION)
    finally:
        os.close(fd)
    assert digest == result.sha256_hash == hashlib.sha256(b"harmless\n").hexdigest()


def test_encrypt_file_refuses_a_symlink(kms_key: str, tmp_path: Path) -> None:
    from envault.exceptions import UnsafeFileError

    target = tmp_path / "target"
    target.write_bytes(b"secret")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    with _kms_faults() as calls:
        with pytest.raises(UnsafeFileError):
            encrypt_file(link, KMS_KEY_ALIAS, {}, tmp_path / "c", REGION)
    assert calls["GenerateDataKey"] == 0
