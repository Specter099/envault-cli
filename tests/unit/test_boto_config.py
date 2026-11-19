"""Tests for shared boto3 configuration."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError

from envault.config import boto_config

_ONE_ATTEMPT = {"total_max_attempts": 1, "mode": "standard"}


class _Always500(BaseHTTPRequestHandler):
    """Answers every request with HTTP 500 and counts what it received."""

    hits = 0

    def _fail(self) -> None:
        type(self).hits += 1
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self.send_response(500)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_HEAD = do_POST = do_PUT = _fail  # noqa: N815 - BaseHTTPRequestHandler API

    def log_message(self, *args: Any) -> None:  # silence per-request stderr lines
        pass


@pytest.fixture
def always_500() -> Iterator[str]:
    _Always500.hits = 0
    server = HTTPServer(("127.0.0.1", 0), _Always500)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def _client(service: str, endpoint: str) -> Any:
    return boto3.client(service, region_name="us-east-1", endpoint_url=endpoint, config=boto_config)


def test_boto_config_has_explicit_timeouts():
    """Shared config must set connect and read timeouts."""
    assert boto_config.connect_timeout == 5
    assert boto_config.read_timeout == 30


@pytest.mark.parametrize(
    ("service", "call"),
    [
        ("dynamodb", lambda c: c.get_item(TableName="t", Key={"PK": {"S": "x"}, "SK": {"S": "y"}})),
        ("kms", lambda c: c.describe_key(KeyId="alias/k")),
        ("s3", lambda c: c.get_object(Bucket="envault-test-bucket", Key="k")),
        ("sts", lambda c: c.get_caller_identity()),
    ],
)
def test_boto_config_makes_exactly_one_http_attempt(
    service: str, call: Any, always_500: str
) -> None:
    """One client call must be one HTTP request: tenacity is the only retry layer.

    ``retries={"max_attempts": 1}`` means one *retry* to botocore (two requests
    per call, six per logical call under tenacity's three attempts). Counting
    requests at a server that always fails is the only check that cannot be
    fooled by how botocore spells its configuration.
    """
    client = _client(service, always_500)
    with pytest.raises(ClientError):
        call(client)
    assert _Always500.hits == 1
    assert client.meta.config.retries == _ONE_ATTEMPT


def test_boto_config_ignores_retry_env_overrides(
    always_500: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AWS_MAX_ATTEMPTS / AWS_RETRY_MODE must not re-enable botocore retries."""
    monkeypatch.setenv("AWS_MAX_ATTEMPTS", "5")
    monkeypatch.setenv("AWS_RETRY_MODE", "adaptive")
    client = _client("dynamodb", always_500)
    with pytest.raises(ClientError):
        client.get_item(TableName="t", Key={"PK": {"S": "x"}, "SK": {"S": "y"}})
    assert _Always500.hits == 1
    assert client.meta.config.retries == _ONE_ATTEMPT


def test_boto_config_is_not_rewritten_by_client_creation() -> None:
    """botocore normalises a client's ``retries`` dict in place.

    With ``{"max_attempts": 1}`` the shared module-level config silently became
    ``{"total_max_attempts": 2, ...}`` after the first client was built.
    """
    before = dict(boto_config.retries)
    boto3.client("dynamodb", region_name="us-east-1", config=boto_config)
    assert boto_config.retries == before == _ONE_ATTEMPT
