"""`envault decrypt` end to end with real crypto against moto (L3 and coverage gaps).

The older decrypt CLI tests replace decrypt_file with a fake that ignores the
expected checksum; these run the Encryption SDK for real.
"""

from __future__ import annotations

import hashlib
import pathlib
import stat
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
from envault.exceptions import DecryptionError
from envault.state import ENCRYPTED, StateStore

from ._id_key import id_key_env

TABLE = "envault-test-state"
BUCKET = "envault-test-bucket"
ALIAS = "alias/envault-test"
REGION = "us-east-1"
SECRET = b"the real secret content\n" * 1000


@pytest.fixture(autouse=True)
def _clear_identity_cache() -> Iterator[None]:
    identity.reset_cache()
    yield
    identity.reset_cache()


@pytest.fixture
def private_tempdir(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> pathlib.Path:
    """Point tempfile at a directory only this test uses (never the shared temp dir)."""
    scratch = tmp_path / "tmp"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    return scratch


@pytest.fixture
def env(tmp_path: pathlib.Path) -> Iterator[dict[str, str]]:
    """Moto account with s.txt encrypted (and its plaintext removed)."""
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
        environment = {
            "AWS_ACCESS_KEY_ID": "testing",
            "AWS_SECRET_ACCESS_KEY": "testing",  # noqa: S105
            "AWS_DEFAULT_REGION": REGION,
            "ENVAULT_KEY_ID": ALIAS,
            "ENVAULT_BUCKET": BUCKET,
            "ENVAULT_TABLE": TABLE,
            "ENVAULT_REGION": REGION,
            "ENVAULT_ALLOWED_ACCOUNT_IDS": str(account),
            "COLUMNS": "250",
            **id_key_env(),
        }
        source = tmp_path / "s.txt"
        source.write_bytes(SECRET)
        result = CliRunner().invoke(main, ["encrypt", str(source)], env=environment)
        assert result.exit_code == 0, result.output
        source.unlink()
        yield environment


def _run(env: dict[str, str], *args: str) -> Result:
    return CliRunner().invoke(main, list(args), env=env)


def test_decrypt_command_end_to_end_real_crypto(
    env: dict[str, str], tmp_path: pathlib.Path, private_tempdir: pathlib.Path
) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    sha = hashlib.sha256(SECRET).hexdigest()

    by_name = _run(env, "decrypt", "s.txt", "-o", str(out_dir))
    by_hash = _run(env, "decrypt", sha, "-o", str(tmp_path / "by-hash.txt"))

    assert by_name.exit_code == 0, by_name.output
    assert by_hash.exit_code == 0, by_hash.output
    published = out_dir / "s.txt"
    assert published.read_bytes() == SECRET
    assert (tmp_path / "by-hash.txt").read_bytes() == SECRET
    assert stat.S_IMODE(published.stat().st_mode) == 0o600
    assert sorted(p.name for p in out_dir.iterdir()) == ["s.txt"]  # no staging copy
    assert list(private_tempdir.iterdir()) == []  # no downloaded ciphertext
    store = StateStore(table_name=TABLE, region=REGION)
    events = [e for e in store.list_events_for_file(sha) if e["operation"] == "DECRYPT"]
    assert len(events) == 2
    # Reading does not consume: the record still says ENCRYPTED.
    [record] = store.list_by_state(ENCRYPTED)
    assert record.file_id == sha


def test_publish_interrupted_between_link_and_unlink_keeps_output(
    env: dict[str, str], tmp_path: pathlib.Path
) -> None:
    """r07 (L3): an interrupt after the output was linked must not zero it.

    _publish hard-links the verified staging file to the output path, then
    unlinks the staging name. Interrupted in between, cleanup sees the staging
    name with a second link and must remove only that name.
    """
    out = tmp_path / "out.txt"
    real_unlink = pathlib.Path.unlink

    def unlink_interrupted(self: pathlib.Path, *args: object, **kwargs: object) -> None:
        if self.name.endswith(".verified"):  # the src.unlink() right after os.link()
            raise KeyboardInterrupt
        real_unlink(self, *args, **kwargs)  # type: ignore[arg-type]

    with patch.object(pathlib.Path, "unlink", unlink_interrupted):
        result = _run(env, "decrypt", "s.txt", "-o", str(out))

    assert result.exit_code != 0  # interrupted
    assert out.read_bytes() == SECRET, "the published file was overwritten"
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".out.txt")] == []


def test_decrypt_temp_file_cleanup_on_failure(
    env: dict[str, str], tmp_path: pathlib.Path, private_tempdir: pathlib.Path
) -> None:
    """The downloaded ciphertext and any partial plaintext are removed when decrypt fails."""
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    with patch.object(cli_mod, "decrypt_file", side_effect=DecryptionError("boom")):
        result = _run(env, "decrypt", "s.txt", "-o", str(out_dir))

    assert result.exit_code == 1
    assert "boom" in result.output
    assert list(private_tempdir.iterdir()) == []
    assert list(out_dir.iterdir()) == []


def test_decrypt_of_tampered_ciphertext_leaves_nothing(
    env: dict[str, str], tmp_path: pathlib.Path, private_tempdir: pathlib.Path
) -> None:
    """A real integrity failure halfway through the stream: no plaintext anywhere."""
    store = StateStore(table_name=TABLE, region=REGION)
    [record] = store.list_by_state(ENCRYPTED)
    s3 = boto3.client("s3", region_name=REGION)
    body = bytearray(s3.get_object(Bucket=BUCKET, Key=record.s3_key)["Body"].read())
    body[len(body) // 2] ^= 0x01
    put = s3.put_object(Bucket=BUCKET, Key=record.s3_key, Body=bytes(body))
    boto3.resource("dynamodb", region_name=REGION).Table(TABLE).update_item(
        Key={"PK": f"FILE#{record.file_id}", "SK": "CURRENT"},
        UpdateExpression="SET s3_version_id = :v",
        ExpressionAttributeValues={":v": put["VersionId"]},
    )
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    result = _run(env, "decrypt", "s.txt", "-o", str(out_dir))

    assert result.exit_code == 1
    assert "Failed to decrypt" in result.output
    assert list(out_dir.iterdir()) == []
    assert list(private_tempdir.iterdir()) == []
    events = store.list_events_for_file(record.file_id)
    assert not [e for e in events if e["operation"] == "DECRYPT"]
