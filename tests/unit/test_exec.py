"""End-to-end tests for `envault exec` — real crypto against moto-backed AWS.

These exercise the actual encryption SDK rather than a mocked ``decrypt_file``,
because the properties under test (plaintext never reaching disk, verification
happening before delivery, audit written before the command runs) live in the
interaction between the layers, not in any one of them.
"""

from __future__ import annotations

import os
import pathlib
from unittest.mock import patch

import boto3
import pytest
from botocore.exceptions import ClientError
from click.testing import CliRunner
from moto import mock_aws

from envault import identity
from envault.cli import main
from envault.state import StateStore

TABLE_NAME = "envault-test-state"
BUCKET_NAME = "envault-test-bucket"
KEY_ALIAS = "alias/envault-test"
REGION = "us-east-1"

SECRET_VALUE = b"postgres://user:hunter2@db.internal:5432/app\n"


def _provision() -> str:
    """Create the table, bucket and key. Returns the moto account ID."""
    ddb = boto3.client("dynamodb", region_name=REGION)
    ddb.create_table(
        TableName=TABLE_NAME,
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
    s3.create_bucket(Bucket=BUCKET_NAME)
    s3.put_bucket_versioning(Bucket=BUCKET_NAME, VersioningConfiguration={"Status": "Enabled"})
    kms = boto3.client("kms", region_name=REGION)
    key_id = kms.create_key(Description="envault-test")["KeyMetadata"]["KeyId"]
    kms.create_alias(AliasName=KEY_ALIAS, TargetKeyId=key_id)
    return boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]


@pytest.fixture(autouse=True)
def _clear_identity_cache():
    identity.reset_cache()
    yield
    identity.reset_cache()


def _env(account: str) -> dict[str, str]:
    return {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",  # noqa: S105
        "AWS_DEFAULT_REGION": REGION,
        "ENVAULT_KEY_ID": KEY_ALIAS,
        "ENVAULT_BUCKET": BUCKET_NAME,
        "ENVAULT_TABLE": TABLE_NAME,
        "ENVAULT_REGION": REGION,
        "ENVAULT_ALLOWED_ACCOUNT_IDS": account,
    }


class _ExecRecorder:
    """Stands in for os.execvpe, capturing what the child would have received."""

    def __init__(self, read_files: tuple[str, ...] = ()) -> None:
        self.called = False
        self.argv: list[str] = []
        self.env: dict[str, str] = {}
        self.file_contents: dict[str, bytes] = {}
        self._read_files = read_files

    def __call__(self, file: str, argv: list[str], env: dict[str, str]) -> None:
        self.called = True
        self.argv = list(argv)
        self.env = dict(env)
        # Read through the inherited descriptor exactly as the child would.
        for var in self._read_files:
            with open(env[var], "rb") as fh:
                self.file_contents[var] = fh.read()


def _seed_secret(runner: CliRunner, env: dict[str, str], name: str = "db.env") -> None:
    pathlib.Path(name).write_bytes(SECRET_VALUE)
    result = runner.invoke(main, ["encrypt", name], env=env, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    os.unlink(name)


@mock_aws
def test_exec_injects_secret_into_environment() -> None:
    account = _provision()
    env = _env(account)
    runner = CliRunner()
    with runner.isolated_filesystem():
        _seed_secret(runner, env)
        rec = _ExecRecorder()
        with patch("os.execvpe", rec):
            result = runner.invoke(
                main,
                ["exec", "-s", "db.env=DATABASE_URL", "--", "/bin/true"],
                env=env,
                catch_exceptions=False,
            )
        assert rec.called, result.output
        # Trailing newline from the file is not part of the value.
        assert rec.env["DATABASE_URL"] == SECRET_VALUE.decode().rstrip("\n")
        assert rec.argv == ["/bin/true"]


@mock_aws
def test_exec_never_writes_plaintext_to_disk() -> None:
    account = _provision()
    env = _env(account)
    runner = CliRunner()
    with runner.isolated_filesystem() as cwd:
        _seed_secret(runner, env)
        rec = _ExecRecorder()
        with patch("os.execvpe", rec):
            runner.invoke(
                main,
                ["exec", "-s", "db.env=DATABASE_URL", "--", "/bin/true"],
                env=env,
                catch_exceptions=False,
            )
        assert rec.called
        on_disk = [p for p in pathlib.Path(cwd).rglob("*") if p.is_file()]
        for path in on_disk:
            assert SECRET_VALUE.strip() not in path.read_bytes()


@mock_aws
def test_exec_file_mode_exposes_readable_fd_path() -> None:
    account = _provision()
    env = _env(account)
    runner = CliRunner()
    with runner.isolated_filesystem():
        _seed_secret(runner, env, "server.pem")
        rec = _ExecRecorder(read_files=("TLS_CERT",))
        with patch("os.execvpe", rec):
            result = runner.invoke(
                main,
                ["exec", "-f", "server.pem=TLS_CERT", "--", "/bin/true"],
                env=env,
                catch_exceptions=False,
            )
        assert rec.called, result.output
        assert rec.file_contents["TLS_CERT"] == SECRET_VALUE
        assert rec.env["TLS_CERT"].startswith(("/proc/self/fd/", "/dev/fd/"))


@mock_aws
def test_exec_substitutes_path_token_in_argv() -> None:
    account = _provision()
    env = _env(account)
    runner = CliRunner()
    with runner.isolated_filesystem():
        _seed_secret(runner, env, "server.pem")
        rec = _ExecRecorder()
        with patch("os.execvpe", rec):
            runner.invoke(
                main,
                ["exec", "-f", "server.pem=TLS_CERT", "--", "curl", "--cert", "{TLS_CERT}"],
                env=env,
                catch_exceptions=False,
            )
        assert rec.called
        assert rec.argv[2] == rec.env["TLS_CERT"]
        assert "{TLS_CERT}" not in rec.argv


@mock_aws
def test_exec_is_repeatable() -> None:
    """C-1 regression: reading a secret must not make it unreadable."""
    account = _provision()
    env = _env(account)
    runner = CliRunner()
    with runner.isolated_filesystem():
        _seed_secret(runner, env)
        for _ in range(3):
            rec = _ExecRecorder()
            with patch("os.execvpe", rec):
                result = runner.invoke(
                    main,
                    ["exec", "-s", "db.env=DATABASE_URL", "--", "/bin/true"],
                    env=env,
                    catch_exceptions=False,
                )
            assert rec.called, result.output


@mock_aws
def test_exec_records_access_with_principal() -> None:
    account = _provision()
    env = _env(account)
    runner = CliRunner()
    with runner.isolated_filesystem():
        _seed_secret(runner, env)
        with patch("os.execvpe", _ExecRecorder()):
            runner.invoke(
                main,
                ["exec", "-s", "db.env=DATABASE_URL", "--", "/bin/true"],
                env=env,
                catch_exceptions=False,
            )
        store = StateStore(table_name=TABLE_NAME, region=REGION)
        records = store.list_by_state("ENCRYPTED")
        events = store.list_events_for_file(records[0].sha256_hash)
        access = [e for e in events if e.get("operation") == "ACCESS"]
        assert len(access) == 1
        assert access[0]["principal_arn"].startswith("arn:aws:")


@mock_aws
def test_exec_refuses_to_run_when_audit_write_fails() -> None:
    """Fail closed: an unloggable read must not deliver the secret."""
    account = _provision()
    env = _env(account)
    runner = CliRunner()
    with runner.isolated_filesystem():
        _seed_secret(runner, env)
        rec = _ExecRecorder()
        throttled = ClientError(
            {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "throttled"}},
            "PutItem",
        )
        with (
            patch("os.execvpe", rec),
            patch.object(StateStore, "put_event", side_effect=throttled),
        ):
            result = runner.invoke(
                main, ["exec", "-s", "db.env=DATABASE_URL", "--", "/bin/true"], env=env
            )
        assert not rec.called, "the command must not run without an audit record"
        assert result.exit_code != 0
        # A clean refusal, not a traceback: the handler also performs the
        # credential-fd cleanup that an escaping exception would skip.
        assert result.exception is None or isinstance(result.exception, SystemExit), (
            f"expected a clean exit, got {result.exception!r}"
        )
        assert "Refusing to run" in result.output


@mock_aws
def test_exec_refuses_on_checksum_mismatch() -> None:
    """A ciphertext whose plaintext no longer matches its record must not run."""
    account = _provision()
    env = _env(account)
    runner = CliRunner()
    with runner.isolated_filesystem():
        _seed_secret(runner, env)
        store = StateStore(table_name=TABLE_NAME, region=REGION)
        record = store.list_by_state("ENCRYPTED")[0]
        table = boto3.resource("dynamodb", region_name=REGION).Table(TABLE_NAME)
        table.update_item(
            Key={"PK": f"FILE#{record.sha256_hash}", "SK": "CURRENT"},
            UpdateExpression="SET sha256_hash = :h",
            ExpressionAttributeValues={":h": "b" * 64},
        )
        rec = _ExecRecorder()
        with patch("os.execvpe", rec):
            result = runner.invoke(
                main, ["exec", "-s", "db.env=DATABASE_URL", "--", "/bin/true"], env=env
            )
        assert not rec.called
        assert result.exit_code != 0
        assert "checksum" in result.output.lower()


@mock_aws
def test_exec_refuses_on_encryption_context_mismatch() -> None:
    account = _provision()
    env = _env(account)
    runner = CliRunner()
    with runner.isolated_filesystem():
        _seed_secret(runner, env)
        store = StateStore(table_name=TABLE_NAME, region=REGION)
        record = store.list_by_state("ENCRYPTED")[0]
        table = boto3.resource("dynamodb", region_name=REGION).Table(TABLE_NAME)
        tampered = dict(record.encryption_context)
        tampered["purpose"] = "not-what-was-encrypted"
        table.update_item(
            Key={"PK": f"FILE#{record.sha256_hash}", "SK": "CURRENT"},
            UpdateExpression="SET encryption_context = :c",
            ExpressionAttributeValues={":c": tampered},
        )
        rec = _ExecRecorder()
        with patch("os.execvpe", rec):
            result = runner.invoke(
                main, ["exec", "-s", "db.env=DATABASE_URL", "--", "/bin/true"], env=env
            )
        assert not rec.called
        assert result.exit_code != 0
        assert "encryption context" in result.output.lower()


@mock_aws
def test_exec_clean_env_drops_inherited_variables() -> None:
    account = _provision()
    env = {**_env(account), "SOME_AMBIENT_TOKEN": "leaky"}
    runner = CliRunner()
    with runner.isolated_filesystem():
        _seed_secret(runner, env)
        rec = _ExecRecorder()
        with patch("os.execvpe", rec):
            runner.invoke(
                main,
                ["exec", "--clean-env", "-s", "db.env=DATABASE_URL", "--", "/bin/true"],
                env=env,
                catch_exceptions=False,
            )
        assert rec.called
        assert "SOME_AMBIENT_TOKEN" not in rec.env
        assert "AWS_SECRET_ACCESS_KEY" not in rec.env
        assert rec.env["DATABASE_URL"]


@mock_aws
def test_exec_warns_when_inheriting_aws_credentials() -> None:
    account = _provision()
    env = _env(account)
    runner = CliRunner()
    with runner.isolated_filesystem():
        _seed_secret(runner, env)
        rec = _ExecRecorder()
        with patch("os.execvpe", rec):
            result = runner.invoke(
                main, ["exec", "-s", "db.env=DATABASE_URL", "--", "/bin/true"], env=env
            )
        assert rec.called, result.output
        assert "clean-env" in result.output.lower()


@mock_aws
def test_exec_rejects_binary_secret_for_env() -> None:
    account = _provision()
    env = _env(account)
    runner = CliRunner()
    with runner.isolated_filesystem():
        pathlib.Path("blob.bin").write_bytes(b"\xff\xfe\x00binary")
        runner.invoke(main, ["encrypt", "blob.bin"], env=env, catch_exceptions=False)
        rec = _ExecRecorder()
        with patch("os.execvpe", rec):
            result = runner.invoke(
                main, ["exec", "-s", "blob.bin=BLOB", "--", "/bin/true"], env=env
            )
        assert not rec.called
        assert result.exit_code != 0


@mock_aws
def test_exec_binary_secret_works_in_file_mode() -> None:
    """What --secret rejects, --file must still deliver byte-for-byte."""
    account = _provision()
    env = _env(account)
    payload = b"\xff\xfe\x00binary"
    runner = CliRunner()
    with runner.isolated_filesystem():
        pathlib.Path("blob.bin").write_bytes(payload)
        runner.invoke(main, ["encrypt", "blob.bin"], env=env, catch_exceptions=False)
        rec = _ExecRecorder(read_files=("BLOB",))
        with patch("os.execvpe", rec):
            result = runner.invoke(
                main, ["exec", "-f", "blob.bin=BLOB", "--", "/bin/true"], env=env
            )
        assert rec.called, result.output
        assert rec.file_contents["BLOB"] == payload


@pytest.mark.parametrize(
    "args",
    [
        ["exec", "-s", "db.env=DATABASE_URL"],  # no command
        ["exec", "--", "/bin/true"],  # no secrets
        ["exec", "-s", "db.env", "--", "/bin/true"],  # malformed spec
        ["exec", "-s", "db.env=2BAD", "--", "/bin/true"],  # invalid env name
        ["exec", "-s", "a=X", "-s", "b=X", "--", "/bin/true"],  # duplicate target
    ],
)
@mock_aws
def test_exec_usage_errors(args: list[str]) -> None:
    account = _provision()
    runner = CliRunner()
    rec = _ExecRecorder()
    with patch("os.execvpe", rec):
        result = runner.invoke(main, args, env=_env(account))
    assert not rec.called
    assert result.exit_code != 0


@mock_aws
def test_exec_file_mode_survives_markup_in_secret_name() -> None:
    """A file name carrying Rich markup must not break the exec path."""
    account = _provision()
    env = _env(account)
    runner = CliRunner()
    with runner.isolated_filesystem():
        _seed_secret(runner, env, "[bold]cert.pem")
        rec = _ExecRecorder(read_files=("TLS_CERT",))
        with patch("os.execvpe", rec):
            result = runner.invoke(
                main,
                ["exec", "-f", "[bold]cert.pem=TLS_CERT", "--", "/bin/true"],
                env=env,
                catch_exceptions=False,
            )
        assert rec.called, result.output
        assert rec.file_contents["TLS_CERT"] == SECRET_VALUE
