"""What `envault` writes to stderr through logging, with and without --verbose (H1).

botocore logs request headers (including the session token) and response bodies
(including the plaintext data key KMS returns) at DEBUG. `-v` must raise envault's
own verbosity without ever lowering a third-party logger's threshold.

Each test runs the CLI with logging as a fresh process has it (no root handlers),
so the CLI's own ``logging.basicConfig`` takes effect and its handler writes to
the CliRunner's stderr; the original handlers are restored afterwards.
"""

from __future__ import annotations

import logging
import os
import pathlib
import subprocess
import sys
import textwrap
from collections.abc import Iterator
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch

import boto3
import botocore.client
import pytest
from botocore.exceptions import ClientError
from click.testing import CliRunner, Result
from moto import mock_aws

from envault import cli as cli_mod
from envault import identity
from envault.cli import main

from ._id_key import ID_KEY_ALIAS, TESTS_DIR, create_id_key

TABLE = "envault-test-state"
BUCKET = "envault-test-bucket"
ALIAS = "alias/envault-test"
REGION = "us-east-1"
SESSION_TOKEN = "FAKE-SESSION-TOKEN-0123456789abcdef"  # noqa: S105  # pragma: allowlist secret
SECRET = b"postgres://app:correct-horse-battery@db.internal:5432/prod\n"  # pragma: allowlist secret

_TOUCHED_LOGGERS = ("envault", "aws_encryption_sdk", "botocore", "urllib3")


@pytest.fixture(autouse=True)
def _clear_identity_cache() -> Iterator[None]:
    identity.reset_cache()
    yield
    identity.reset_cache()


@contextmanager
def _fresh_process_logging() -> Iterator[None]:
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    saved_levels = {name: logging.getLogger(name).level for name in _TOUCHED_LOGGERS}
    for handler in saved_handlers:
        root.removeHandler(handler)
    try:
        yield
    finally:
        for handler in root.handlers[:]:
            root.removeHandler(handler)
        for handler in saved_handlers:
            root.addHandler(handler)
        root.setLevel(saved_level)
        for name, level in saved_levels.items():
            logging.getLogger(name).setLevel(level)


def _provision() -> str:
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
    key_id = kms.create_key(Description="envault-test")["KeyMetadata"]["KeyId"]
    kms.create_alias(AliasName=ALIAS, TargetKeyId=key_id)
    create_id_key()
    return str(boto3.client("sts", region_name=REGION).get_caller_identity()["Account"])


def _env(account: str, **extra: str) -> dict[str, str]:
    return {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",  # noqa: S105  # pragma: allowlist secret
        "AWS_DEFAULT_REGION": REGION,
        "ENVAULT_KEY_ID": ALIAS,
        "ENVAULT_BUCKET": BUCKET,
        "ENVAULT_TABLE": TABLE,
        "ENVAULT_REGION": REGION,
        "ENVAULT_ALLOWED_ACCOUNT_IDS": account,
        "ENVAULT_ID_KEY_ID": ID_KEY_ALIAS,
        **extra,
    }


def _invoke(args: list[str], env: dict[str, str]) -> Result:
    """Run the CLI as a fresh process would, returning stdout and stderr separately."""
    with _fresh_process_logging():
        return CliRunner().invoke(main, args, env=env)


def _assert_no_secret_material(stderr: str) -> None:
    # botocore.parsers logs KMS response bodies, which carry the data key
    # under "Plaintext"; botocore.auth/endpoint log the signed headers.
    assert "Plaintext" not in stderr, "KMS data key written to the log"
    assert SESSION_TOKEN not in stderr, "session token written to the log"
    assert SECRET.strip().decode() not in stderr, "secret value written to the log"
    assert "botocore" not in stderr


@mock_aws
def test_verbose_logging_never_emits_kms_plaintext(tmp_path: pathlib.Path) -> None:
    """-v encrypt: the GenerateDataKey response body (data key) never reaches stderr."""
    env = _env(_provision(), AWS_SESSION_TOKEN=SESSION_TOKEN)
    secret = tmp_path / "db.env"
    secret.write_bytes(SECRET)

    result = _invoke(["-v", "encrypt", str(secret)], env)

    assert result.exit_code == 0, result.output
    _assert_no_secret_material(result.stderr)
    # -v still does its job: envault's own debug/info records are there.
    assert '"name": "envault.' in result.stderr


@mock_aws
@pytest.mark.parametrize("command", ["decrypt", "exec"])
def test_verbose_decrypt_and_exec_never_emit_kms_plaintext_or_session_token(
    tmp_path: pathlib.Path, command: str
) -> None:
    """-v on the read paths: neither the Decrypt response nor the signed headers are logged."""
    env = _env(_provision(), AWS_SESSION_TOKEN=SESSION_TOKEN)
    secret = tmp_path / "db.env"
    secret.write_bytes(SECRET)
    assert _invoke(["encrypt", str(secret)], env).exit_code == 0

    if command == "decrypt":
        args = ["-v", "decrypt", "db.env", "-o", str(tmp_path / "out.env")]
    else:
        args = ["-v", "exec", "-s", "db.env=DATABASE_URL", "--", "/bin/true"]
    with patch("os.execvpe", lambda *a, **k: None):
        result = _invoke(args, env)

    assert result.exit_code == 0, result.output
    _assert_no_secret_material(result.stderr)
    assert '"name": "envault.' in result.stderr


@mock_aws
def test_verbose_logging_holds_even_if_botocore_logger_is_lowered(tmp_path: pathlib.Path) -> None:
    """The handler, not only the root level, keeps third-party DEBUG records out.

    A library (or a sitecustomize) that sets botocore's own logger to DEBUG must
    not be enough to put wire logs on envault's stderr.
    """
    env = _env(_provision())
    secret = tmp_path / "db.env"
    secret.write_bytes(SECRET)
    with _fresh_process_logging():
        logging.getLogger("botocore").setLevel(logging.DEBUG)
        result = CliRunner().invoke(main, ["-v", "encrypt", str(secret)], env=env)

    assert result.exit_code == 0, result.output
    _assert_no_secret_material(result.stderr)


@mock_aws
def test_quiet_run_writes_no_envault_debug_records(tmp_path: pathlib.Path) -> None:
    env = _env(_provision())
    secret = tmp_path / "db.env"
    secret.write_bytes(SECRET)

    result = _invoke(["encrypt", str(secret)], env)

    assert result.exit_code == 0, result.output
    assert result.stderr == ""


def _fail(op_name: str, code: str):  # type: ignore[no-untyped-def]
    real = botocore.client.BaseClient._make_api_call

    def patched(self, op, kwargs):  # type: ignore[no-untyped-def]
        if op == op_name:
            raise ClientError({"Error": {"Code": code, "Message": f"simulated {code}"}}, op)
        return real(self, op, kwargs)

    return patched


@mock_aws
def test_sdk_error_tracebacks_stay_off_stderr_without_verbose(tmp_path: pathlib.Path) -> None:
    """The Encryption SDK logs a traceback for every KMS failure; envault reports it itself."""
    env = _env(_provision())
    secret = tmp_path / "db.env"
    secret.write_bytes(SECRET)

    with patch.object(
        botocore.client.BaseClient,
        "_make_api_call",
        _fail("GenerateDataKey", "AccessDeniedException"),
    ):
        quiet = _invoke(["encrypt", str(secret)], env)
        verbose = _invoke(["-v", "encrypt", str(secret)], env)

    assert quiet.exit_code == 1
    assert "AccessDeniedException" in quiet.stdout  # the one-line ✗ report
    assert "aws_encryption_sdk" not in quiet.stderr
    assert "Traceback" not in quiet.stderr
    # Under -v the SDK's own error records are shown, for diagnosis.
    assert verbose.exit_code == 1
    assert "aws_encryption_sdk" in verbose.stderr


@mock_aws
def test_envault_warnings_still_reach_stderr_without_verbose(tmp_path: pathlib.Path) -> None:
    """Quietening third parties must not hide envault's own warnings."""
    env = _env(_provision())
    secret = tmp_path / "db.env"
    secret.write_bytes(SECRET)
    assert _invoke(["encrypt", str(secret)], env).exit_code == 0
    identity.reset_cache()  # encrypt resolved and cached the caller already

    sts_down = _fail("GetCallerIdentity", "AccessDenied")
    with patch.object(botocore.client.BaseClient, "_make_api_call", sts_down):
        result = _invoke(["decrypt", "db.env", "-o", str(tmp_path / "out.env")], env)

    assert result.exit_code == 0, result.output
    assert "Could not resolve caller identity" in result.stderr
    assert '"levelname": "WARNING"' in result.stderr


def test_sdk_finalizer_noise_hook_drops_only_sdk_stream_errors() -> None:
    """An abandoned SDK decrypt stream raises "Footer not read" from its finalizer.

    Python prints that as "Exception ignored in ..." with a traceback. The hook
    installed by the console entry point drops exactly that and passes anything
    else to the previous hook.
    """
    from aws_encryption_sdk.exceptions import SerializationError

    seen: list[object] = []
    hook = cli_mod._sdk_finalizer_noise_filter(seen.append)
    sdk_stream = type("StreamDecryptor", (), {"__module__": "aws_encryption_sdk.streaming_client"})

    def args(exc: BaseException, obj: object) -> SimpleNamespace:
        return SimpleNamespace(
            exc_type=type(exc), exc_value=exc, exc_traceback=None, err_msg=None, object=obj
        )

    dropped = args(SerializationError("Footer not read"), sdk_stream())
    other_object = args(SerializationError("Footer not read"), object())
    other_error = args(ValueError("boom"), sdk_stream())
    for unraisable in (dropped, other_object, other_error):
        hook(unraisable)  # type: ignore[arg-type]

    assert seen == [other_object, other_error]


_FINALIZER_SCRIPT = textwrap.dedent(
    """
    import os, sys
    import boto3
    from moto import mock_aws
    from envault.cli import cli, main
    from unit._id_key import create_id_key, install_generate_mac_key_arn_fix

    install_generate_mac_key_arn_fix()
    with mock_aws():
        kms = boto3.client("kms", region_name="us-east-1")
        kid = kms.create_key()["KeyMetadata"]["KeyId"]
        kms.create_alias(AliasName="alias/envault-test", TargetKeyId=kid)
        create_id_key()
        ddb = boto3.client("dynamodb", region_name="us-east-1")
        ddb.create_table(
            TableName="envault-test-state", BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"} for n in
                ("PK", "SK", "current_state", "encrypted_at", "date", "last_updated")],
            KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"},
                       {"AttributeName": "SK", "KeyType": "RANGE"}],
            GlobalSecondaryIndexes=[
                {"IndexName": "state-index", "Projection": {"ProjectionType": "ALL"},
                 "KeySchema": [{"AttributeName": "current_state", "KeyType": "HASH"},
                               {"AttributeName": "encrypted_at", "KeyType": "RANGE"}]},
                {"IndexName": "date-index", "Projection": {"ProjectionType": "ALL"},
                 "KeySchema": [{"AttributeName": "date", "KeyType": "HASH"},
                               {"AttributeName": "last_updated", "KeyType": "RANGE"}]}])
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="envault-test-bucket")
        s3.put_bucket_versioning(Bucket="envault-test-bucket",
                                 VersioningConfiguration={"Status": "Enabled"})
        with open("db.env", "wb") as f:
            f.write(b"x" * 20000)
        try:
            main(["encrypt", "db.env"], standalone_mode=False)
        except SystemExit:
            pass
        # Corrupt the stored ciphertext's last frame so decrypt fails mid-stream,
        # and point the record at the corrupted version.
        table = boto3.resource("dynamodb", region_name="us-east-1").Table("envault-test-state")
        item = next(i for i in table.scan()["Items"] if i["SK"] == "CURRENT")
        key = item["s3_key"]
        body = bytearray(s3.get_object(Bucket="envault-test-bucket", Key=key)["Body"].read())
        body[-200] ^= 0x01
        put = s3.put_object(Bucket="envault-test-bucket", Key=key, Body=bytes(body))
        table.update_item(Key={"PK": item["PK"], "SK": "CURRENT"},
                          UpdateExpression="SET s3_version_id = :v",
                          ExpressionAttributeValues={":v": put["VersionId"]})
        sys.argv = ["envault", "decrypt", "db.env", "-o", "out.env"]
        cli()
    """
)


def test_failed_decrypt_prints_no_sdk_tracebacks_in_a_real_process(tmp_path: pathlib.Path) -> None:
    """End to end in a fresh interpreter: the user sees envault's message and nothing else.

    Covers the SDK's "Error on closing" ERROR log and the "Exception ignored in
    ... Footer not read" finalizer traceback, which only show up in a real
    process (at garbage collection or interpreter shutdown).
    """
    script = tmp_path / "run.py"
    script.write_text(_FINALIZER_SCRIPT)
    env = {
        **{k: v for k, v in os.environ.items() if not k.startswith(("AWS_", "ENVAULT_"))},
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",  # pragma: allowlist secret
        "AWS_DEFAULT_REGION": REGION,
        "ENVAULT_KEY_ID": ALIAS,
        "ENVAULT_BUCKET": BUCKET,
        "ENVAULT_TABLE": TABLE,
        "ENVAULT_ALLOWED_ACCOUNT_IDS": "123456789012",
        "ENVAULT_ID_KEY_ID": ID_KEY_ALIAS,
        "PYTHONPATH": str(TESTS_DIR),
        "TMPDIR": str(tmp_path),
        "COLUMNS": "200",
    }
    proc = subprocess.run(  # noqa: S603
        [sys.executable, str(script)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "Failed to decrypt" in proc.stdout
    assert "Traceback" not in proc.stderr, proc.stderr
    assert "Exception ignored" not in proc.stderr, proc.stderr
    assert "aws_encryption_sdk" not in proc.stderr, proc.stderr
    assert not (tmp_path / "out.env").exists()
