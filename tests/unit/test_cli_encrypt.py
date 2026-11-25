"""`envault encrypt` end to end with real crypto against moto (L4, M7, L2)."""

from __future__ import annotations

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

from ._id_key import file_id_of, id_key_env

TABLE = "envault-test-state"
BUCKET = "envault-test-bucket"
ALIAS = "alias/envault-test"
REGION = "us-east-1"

# pragma: allowlist nextline secret
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
            "AWS_SECRET_ACCESS_KEY": "testing",  # noqa: S105  # pragma: allowlist secret
            "AWS_DEFAULT_REGION": REGION,
            "ENVAULT_KEY_ID": ALIAS,
            "ENVAULT_BUCKET": BUCKET,
            "ENVAULT_TABLE": TABLE,
            "ENVAULT_REGION": REGION,
            "ENVAULT_ALLOWED_ACCOUNT_IDS": str(account),
            "COLUMNS": "250",
            **id_key_env(),
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

    def collect_then_swap(path: pathlib.Path, *args):  # type: ignore[no-untyped-def]
        files = real(path, *args)
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
    assert record.file_id == file_id_of(HARMLESS)  # type: ignore[attr-defined]
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


# ---------------------------------------------------------------------------
# M7: one never-reused key per upload, written with If-None-Match
# ---------------------------------------------------------------------------


def _versions_at(key: str) -> list[dict[str, object]]:
    return [v for v in _objects() if v["Key"] == key]


def test_encrypt_uploads_to_a_per_upload_key(env: dict[str, str], tree: pathlib.Path) -> None:
    calls: list[dict[str, object]] = []
    real_upload = cli_mod.S3Store.upload_file

    def spy(self, local_path, s3_key, **kwargs):  # type: ignore[no-untyped-def]
        calls.append({"s3_key": s3_key, **kwargs})
        return real_upload(self, local_path, s3_key, **kwargs)

    with patch.object(cli_mod.S3Store, "upload_file", spy):
        result = _run(env, "encrypt", str(tree))

    assert result.exit_code == 0, result.output
    [record] = _records()
    sha, message_id = record.file_id, record.message_id  # type: ignore[attr-defined]
    assert record.s3_key == f"encrypted/{sha[:2]}/{sha}/{message_id}/notes.txt.encrypted"  # type: ignore[attr-defined]
    assert calls == [{"s3_key": record.s3_key, "if_none_match": True}]  # type: ignore[attr-defined]


def test_lost_encrypt_race_does_not_pin_noncurrent_version(
    env: dict[str, str], tree: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    """r09 R10: two pipelines encrypt the same file at once.

    The second read "no record" before the first wrote one. It still uploads
    (to its own key) and then loses the conditional state write. The record
    must keep pinning a version that is the current one at its key.
    """
    import logging

    first = _run(env, "encrypt", str(tree))
    assert first.exit_code == 0, first.output
    with (
        patch.object(StateStore, "get_current_state", return_value=None),
        caplog.at_level(logging.ERROR, logger="envault.cli"),
    ):
        second = _run(env, "encrypt", str(tree))

    assert second.exit_code == 1
    assert "✗ notes.txt" in second.output
    [record] = _records()
    [pinned] = _versions_at(record.s3_key)  # type: ignore[attr-defined]
    assert pinned["VersionId"] == record.s3_version_id  # type: ignore[attr-defined]
    assert pinned["IsLatest"] is True
    # The loser's object went to its own key: an orphan, logged for clean-up.
    [orphan_key] = {str(v["Key"]) for v in _objects()} - {record.s3_key}  # type: ignore[attr-defined]
    logged = [r for r in caplog.records if "orphan" in r.getMessage()]
    assert logged and logged[0].__dict__["s3_key"] == orphan_key


def test_encrypt_force_writes_a_new_key_and_keeps_the_old_object(
    env: dict[str, str], tree: pathlib.Path
) -> None:
    assert _run(env, "encrypt", str(tree)).exit_code == 0
    [before] = _records()
    [old_version] = _versions_at(before.s3_key)  # type: ignore[attr-defined]

    result = _run(env, "encrypt", "--force", str(tree))

    assert result.exit_code == 0, result.output
    [after] = _records()
    assert after.s3_key != before.s3_key  # type: ignore[attr-defined]
    assert _versions_at(before.s3_key) == [old_version]  # type: ignore[attr-defined]
    [new_version] = _versions_at(after.s3_key)  # type: ignore[attr-defined]
    assert new_version["VersionId"] == after.s3_version_id  # type: ignore[attr-defined]
    out = tree.parent / "out.txt"
    assert _run(env, "decrypt", "notes.txt", "-o", str(out)).exit_code == 0
    assert out.read_bytes() == HARMLESS


# ---------------------------------------------------------------------------
# N8: symbolic links are refused out loud, never skipped in silence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("target", ["file", "directory"])
def test_encrypt_refuses_symlink_input_path(
    env: dict[str, str], tmp_path: pathlib.Path, target: str
) -> None:
    """Kubernetes secret mounts are symlinks: such a path stored nothing, and exited 0."""
    if target == "file":
        real = tmp_path / "secret.env"
        real.write_bytes(HARMLESS)
    else:
        real = tmp_path / "secrets"
        real.mkdir()
        (real / "a.env").write_bytes(HARMLESS)
    link = tmp_path / "link"
    link.symlink_to(real)

    result = _run(env, "encrypt", str(link))

    assert result.exit_code == 1, result.output
    assert "symbolic link" in result.output
    assert os.path.realpath(link) in result.output  # what to pass instead
    assert _records() == []
    assert _objects() == []


def test_encrypt_refuses_an_input_path_that_is_not_a_file_or_directory(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)

    result = _run(env, "encrypt", str(fifo))

    assert result.exit_code == 1, result.output
    assert "not a regular file or a directory" in result.output
    assert _records() == []


def test_encrypt_reports_what_it_skips_in_a_directory(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    tree = tmp_path / "tree"
    (tree / "sub").mkdir(parents=True)
    (tree / "real.env").write_bytes(HARMLESS)
    (tree / "sub" / "link.env").symlink_to(tmp_path / "victim")
    (tmp_path / "victim").write_bytes(VICTIM)
    (tree / "linkdir").symlink_to(tmp_path)
    os.mkfifo(tree / "pipe")

    result = _run(env, "encrypt", str(tree))

    assert result.exit_code == 0, result.output
    for name, reason in (
        ("sub/link.env", "symbolic link"),
        ("linkdir", "symbolic link"),
        ("pipe", "not a regular file"),
    ):
        [line] = [line for line in result.output.splitlines() if name in line]
        assert reason in line, line
    assert [r.file_name for r in _records()] == ["real.env"]  # type: ignore[attr-defined]


def test_encrypt_of_a_directory_with_only_symlinks_exits_1(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tmp_path / "victim").write_bytes(VICTIM)
    (tree / "link.env").symlink_to(tmp_path / "victim")

    result = _run(env, "encrypt", str(tree))

    assert result.exit_code == 1, result.output
    assert "link.env" in result.output
    assert "Nothing to encrypt" in result.output
    assert _records() == []
    assert _objects() == []


def test_encrypt_of_an_empty_directory_finds_nothing_and_exits_0(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    (tmp_path / "empty").mkdir()

    result = _run(env, "encrypt", str(tmp_path / "empty"))

    assert result.exit_code == 0, result.output
    assert "No files found" in result.output
