from __future__ import annotations

import hashlib
from pathlib import Path

from envault.cli import _parse_output_json_entry


def _make_entry(input_path: str) -> dict:
    return {
        "mode": "encrypt",
        "input": input_path,
        "header": {
            "algorithm": "AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384",
            "message_id": "abcd1234",
            "encryption_context": {"purpose": "backup"},
            "encrypted_data_keys": [
                {"key_provider": {"key_info": "alias/envault"}}
            ],
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
