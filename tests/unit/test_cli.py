from __future__ import annotations

import hashlib
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from envault.cli import _best_effort_delete, _parse_output_json_entry, _parse_tags, main


def _make_entry(input_path: str) -> dict:
    return {
        "mode": "encrypt",
        "input": input_path,
        "header": {
            "algorithm": "AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384",
            "message_id": "abcd1234",
            "encryption_context": {"purpose": "backup"},
            "encrypted_data_keys": [{"key_provider": {"key_info": "alias/envault"}}],
        },
    }


def test_parse_entry_uses_content_hash(tmp_path: Path):
    """_parse_output_json_entry must hash file CONTENT, not the path string."""
    plaintext = tmp_path / "secret.txt"
    content = b"sensitive data\n"
    plaintext.write_bytes(content)
    expected_hash = hashlib.sha256(content).hexdigest()

    entry = _make_entry(str(plaintext))
    record = _parse_output_json_entry(entry)

    assert record is not None
    assert record.sha256_hash == expected_hash


def test_parse_entry_skips_missing_file(tmp_path: Path):
    """_parse_output_json_entry returns None when the plaintext file doesn't exist."""
    entry = _make_entry("/nonexistent/path/file.txt")
    record = _parse_output_json_entry(entry)
    assert record is None


def test_parse_entry_skips_non_encrypt_mode():
    entry = {"mode": "decrypt", "input": "/some/file"}
    assert _parse_output_json_entry(entry) is None


def test_best_effort_delete_overwrites_before_removal(tmp_path: Path):
    """_best_effort_delete must zero-out file contents before unlinking."""
    p = tmp_path / "sensitive.bin"
    p.write_bytes(b"TOP SECRET DATA")
    assert p.exists()

    _best_effort_delete(p)

    assert not p.exists()


def test_best_effort_delete_missing_file_is_noop(tmp_path: Path):
    """_best_effort_delete on a non-existent path must not raise."""
    p = tmp_path / "does_not_exist"
    _best_effort_delete(p)  # should not raise


def test_best_effort_delete_zero_length_file(tmp_path: Path):
    p = tmp_path / "empty"
    p.write_bytes(b"")
    _best_effort_delete(p)
    assert not p.exists()


def test_best_effort_delete_logs_warning_on_oserror(tmp_path: Path, caplog):
    """_best_effort_delete must log a warning if overwrite fails with OSError."""
    import logging
    from unittest.mock import patch

    p = tmp_path / "readonly.bin"
    p.write_bytes(b"data")

    with (
        patch.object(Path, "open", side_effect=OSError("Permission denied")),
        caplog.at_level(logging.WARNING, logger="envault.cli"),
    ):
        _best_effort_delete(p)

    assert any("best-effort" in r.message.lower() for r in caplog.records)


def test_parse_tags_valid():
    result = _parse_tags(("project=finance", "env=prod"))
    assert result == {"project": "finance", "env": "prod"}


def test_parse_tags_invalid_key_raises():
    """Tag keys with special characters must raise UsageError."""
    with pytest.raises(click.UsageError, match="Invalid tag key"):
        _parse_tags(("bad key!=value",))


def test_parse_tags_key_too_long_raises():
    """Tag key longer than 64 chars must raise UsageError."""
    long_key = "k" * 65
    with pytest.raises(click.UsageError, match="Invalid tag key"):
        _parse_tags((f"{long_key}=value",))


def test_parse_tags_value_too_long_raises():
    """Tag value longer than 256 chars must raise UsageError."""
    long_val = "v" * 257
    with pytest.raises(click.UsageError, match="exceeds"):
        _parse_tags((f"key={long_val}",))


def test_parse_tags_empty_key_raises():
    with pytest.raises(click.UsageError, match="Invalid tag key"):
        _parse_tags(("=value",))


def test_decrypt_rejects_invalid_sha256_format():
    """decrypt must reject hash arguments that are not 64-char hex strings."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "decrypt",
            "not-a-valid-hash",
            "--table",
            "t",
            "--bucket",
            "b",
        ],
        env={
            "AWS_ACCESS_KEY_ID": "testing",
            "AWS_SECRET_ACCESS_KEY": "testing",
            "AWS_DEFAULT_REGION": "us-east-1",
        },
    )
    assert result.exit_code != 0
    assert "invalid" in result.output.lower() or "sha256" in result.output.lower()
