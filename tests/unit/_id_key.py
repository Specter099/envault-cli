"""The HMAC KMS key that names files (M6), as the unit tests provision it in moto.

envault identifies a new record by ``HMAC-SHA-256(ID key, SHA-256(plaintext))``,
computed by KMS GenerateMac with the key named by ``--id-key-id`` /
``ENVAULT_ID_KEY_ID``. Every moto account a CLI test builds gets this key, and
the CLI environments name it, through the helpers here: one definition of the
alias, key spec and usage for the whole suite.

Imported by ``tests/conftest.py`` and by test modules (``from ._id_key import
...``); child interpreters started by tests import it as ``unit._id_key`` with
the tests directory on ``PYTHONPATH`` (see :data:`TESTS_DIR`).
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import boto3

#: Alias of the test ID key, the value the CLI tests put in ENVAULT_ID_KEY_ID.
ID_KEY_ALIAS = "alias/envault-id-test"
REGION = "us-east-1"
#: Put this on a child interpreter's PYTHONPATH to import ``unit._id_key``.
TESTS_DIR = Path(__file__).resolve().parents[1]


def create_id_key(region: str = REGION, alias: str = ID_KEY_ALIAS) -> str:
    """Create an HMAC_256 / GENERATE_VERIFY_MAC key named ``alias`` in the active moto account.

    Returns the key ARN.
    """
    kms = boto3.client("kms", region_name=region)
    metadata = kms.create_key(
        KeySpec="HMAC_256",
        KeyUsage="GENERATE_VERIFY_MAC",
        Description="envault file identifiers (test)",
    )["KeyMetadata"]
    kms.create_alias(AliasName=alias, TargetKeyId=metadata["KeyId"])
    return str(metadata["Arn"])


def id_key_env(region: str = REGION) -> dict[str, str]:
    """Create the ID key; return the CLI environment variable that names it."""
    create_id_key(region)
    return {"ENVAULT_ID_KEY_ID": ID_KEY_ALIAS}


def file_id_of(content: bytes, *, region: str = REGION, alias: str = ID_KEY_ALIAS) -> str:
    """The identifier envault gives ``content``: hex HMAC of its raw 32-byte SHA-256 digest."""
    kms = boto3.client("kms", region_name=region)
    response = kms.generate_mac(
        KeyId=alias, MacAlgorithm="HMAC_SHA_256", Message=hashlib.sha256(content).digest()
    )
    return bytes(response["Mac"]).hex()


def generate_mac_reporting_key_arn(
    real: Callable[..., tuple[str, str, str]],
) -> Callable[..., tuple[str, str, str]]:
    """Wrap moto's ``KmsBackend.generate_mac`` so the response's KeyId is the key ARN.

    KMS answers GenerateMac with the key ARN in ``KeyId`` (AWS's own example,
    shipped in botocore's ``kms/2014-11-01/examples-1.json``, sends a key ID
    and gets back "the key ARN of the HMAC KMS key used in the operation").
    moto 5.2.5 returns the bare key ID instead. envault records that ARN as the
    trust anchor of every keyed identifier and refuses anything else, so the
    tests restore what KMS does. Everything else about the call stays moto's.
    """

    def generate_mac(self: Any, *args: Any, **kwargs: Any) -> tuple[str, str, str]:
        mac, algorithm, key_id = real(self, *args, **kwargs)
        return mac, algorithm, str(self.keys[key_id].arn)

    return generate_mac


def install_generate_mac_key_arn_fix() -> None:
    """Apply :func:`generate_mac_reporting_key_arn` for the rest of this process.

    For child interpreters; in the test process an autouse fixture in
    conftest applies it per test with monkeypatch.
    """
    from moto.kms.models import KmsBackend

    KmsBackend.generate_mac = generate_mac_reporting_key_arn(  # type: ignore[method-assign]
        KmsBackend.generate_mac
    )
