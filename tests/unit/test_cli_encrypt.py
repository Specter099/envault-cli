"""`envault encrypt` end to end with real crypto against moto (L4, M7, L2)."""

from __future__ import annotations

import hashlib
import os
import pathlib
import tempfile
from collections.abc import Iterator
from unittest.mock import patch

import boto3
import pytest
from click.testing import CliRunner, Result
from moto import mock_aws

from envault import cli as cli_mod
from envault import identity
from envault.cli import main
from envault.state import ENCRYPTED, StateStore

TABLE = "envault-test-state"
BUCKET = "envault-test-bucket"
ALIAS = "alias/envault-test"
REGION = "us-east-1"

VICTIM = b"-----BEGIN PRIVATE KEY----- not in the tree being encrypted\n"
HARMLESS = b"harmless\n"


@pytest.fixture(autouse=True)
def _clear_identity_cache() -> Iterator[None]:
    identity.reset_cache()
    yield
    identity.reset_cache()


@pytest.fixture
def env() -> Iterator[dict[str, str]]:
    with mock_aws():
        ddb = boto3.client("dynamodb", region_name=REGION)
        ddb.create_table(
            TableName=TABLE,
            BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[
                {"AttributeName": n, "AttributeType": "S"}
                for n in ("PK", "SK", "current_state", "encrypted_at", "date", "last_updated")
            ],
            KeySchema=[
                {"AttributeName": "PK", "KeyType": "HASH"},
                {"AttributeName": "SK", "KeyType": "RANGE"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "state-index",
                    "KeySchema": [
                        {"AttributeName": "current_state", "KeyType": "HASH"},
                        {"AttributeName": "encrypted_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "date-index",
                    "KeySchema": [
                        {"AttributeName": "date", "KeyType": "HASH"},
                        {"AttributeName": "last_updated", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
        )
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket=BUCKET)
        s3.put_bucket_versioning(Bucket=BUCKET, VersioningConfiguration={"Status": "Enabled"})
        kms = boto3.client("kms", region_name=REGION)
        kms.create_alias(AliasName=ALIAS, TargetKeyId=kms.create_key()["KeyMetadata"]["KeyId"])
        account = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
        yield {
            "AWS_ACCESS_KEY_ID": "testing",
            "AWS_SECRET_ACCESS_KEY": "testing",  # noqa: S105
            "AWS_DEFAULT_REGION": REGION,
            "ENVAULT_KEY_ID": ALIAS,
            "ENVAULT_BUCKET": BUCKET,
            "ENVAULT_TABLE": TABLE,
            "ENVAULT_REGION": REGION,
            "ENVAULT_ALLOWED_ACCOUNT_IDS": str(account),
            "COLUMNS": "250",
        }


def _run(env: dict[str, str], *args: str) -> Result:
    return CliRunner().invoke(main, list(args), env=env)


def _records() -> list[object]:
    return list(StateStore(table_name=TABLE, region=REGION).list_by_state(ENCRYPTED))


def _objects() -> list[dict[str, object]]:
    listing = boto3.client("s3", region_name=REGION).list_object_versions(Bucket=BUCKET)
    return list(listing.get("Versions", []))


# ---------------------------------------------------------------------------
# L4: the file encrypted is the file collected
# ---------------------------------------------------------------------------


@pytest.fixture
def tree(tmp_path: pathlib.Path) -> pathlib.Path:
    (tmp_path / "victim_private_key").write_bytes(VICTIM)
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "notes.txt").write_bytes(HARMLESS)
    return shared


def _swap_after_collection(swap):  # type: ignore[no-untyped-def]
    """Run the real _collect_files, then let another user change the tree."""
    real = cli_mod._collect_files

    def collect_then_swap(path: pathlib.Path):  # type: ignore[no-untyped-def]
        files = real(path)
        swap()
        return files

    return patch.object(cli_mod, "_collect_files", collect_then_swap)


def test_encrypt_refuses_symlink_swapped_after_collection(
    env: dict[str, str], tree: pathlib.Path
) -> None:
    """r12 R14: notes.txt became a symlink to a file outside the tree."""
    notes = tree / "notes.txt"

    def swap() -> None:
        notes.unlink()
        notes.symlink_to(tree.parent / "victim_private_key")

    with _swap_after_collection(swap):
        result = _run(env, "encrypt", str(tree))

    assert result.exit_code == 1, result.output
    assert "✗ notes.txt" in result.output
    assert _records() == []
    assert _objects() == []


def test_encrypt_refuses_file_replaced_after_collection(
    env: dict[str, str], tree: pathlib.Path
) -> None:
    """A different regular file (new inode) at the collected path is not the collected file."""
    notes = tree / "notes.txt"

    def swap() -> None:
        replacement = tree / ".replacement"
        replacement.write_bytes(VICTIM)
        os.replace(replacement, notes)

    with _swap_after_collection(swap):
        result = _run(env, "encrypt", str(tree))

    assert result.exit_code == 1, result.output
    assert "changed after it was selected" in result.output
    assert _records() == []
    assert _objects() == []


def test_encrypt_hashes_and_encrypts_one_open_file(env: dict[str, str], tree: pathlib.Path) -> None:
    """A swap between hashing and encrypting cannot change what is encrypted.

    Both read the descriptor opened once, so the record describes the bytes
    that were hashed even though the path now names other content.
    """
    notes = tree / "notes.txt"
    real_sha256_fd = cli_mod.sha256_fd

    def hash_then_swap(fd: int) -> str:
        digest = real_sha256_fd(fd)
        replacement = tree / ".replacement"
        replacement.write_bytes(VICTIM)
        os.replace(replacement, notes)
        return digest

    with patch.object(cli_mod, "sha256_fd", hash_then_swap):
        result = _run(env, "encrypt", str(tree))

    assert result.exit_code == 0, result.output
    [record] = _records()
    assert record.sha256_hash == hashlib.sha256(HARMLESS).hexdigest()  # type: ignore[attr-defined]
    out = tree.parent / "out.txt"
    decrypted = _run(env, "decrypt", "notes.txt", "-o", str(out))
    assert decrypted.exit_code == 0, decrypted.output
    assert out.read_bytes() == HARMLESS


def test_collect_files_records_each_files_identity(tree: pathlib.Path) -> None:
    (tree / "sub").mkdir()
    (tree / "sub" / "deep.txt").write_bytes(b"x")
    os.mkfifo(tree / "a.fifo")

    collected = {item.name: item for item in cli_mod._collect_files(tree)}

    assert set(collected) == {"notes.txt", "sub/deep.txt"}  # the FIFO is not a regular file
    for item in collected.values():
        st = os.lstat(item.path)
        assert item.identity == (st.st_dev, st.st_ino)


# ---------------------------------------------------------------------------
# Hermetic temp-file cleanup (the shared temp dir is not inspected)
# ---------------------------------------------------------------------------


@pytest.fixture
def private_tempdir(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> pathlib.Path:
    """Point tempfile at a directory only this test uses."""
    scratch = tmp_path / "tmp"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    return scratch


def test_encrypt_temp_file_cleanup_on_failure(
    env: dict[str, str], tree: pathlib.Path, private_tempdir: pathlib.Path
) -> None:
    """The temporary ciphertext is removed when encryption fails."""
    from envault.exceptions import EncryptionError

    with patch.object(cli_mod, "encrypt_fd", side_effect=EncryptionError("boom")):
        result = _run(env, "encrypt", str(tree))

    assert result.exit_code == 1
    assert "boom" in result.output
    assert list(private_tempdir.iterdir()) == []


def test_encrypt_temp_file_cleanup_on_success(
    env: dict[str, str], tree: pathlib.Path, private_tempdir: pathlib.Path
) -> None:
    result = _run(env, "encrypt", str(tree))

    assert result.exit_code == 0, result.output
    assert list(private_tempdir.iterdir()) == []
