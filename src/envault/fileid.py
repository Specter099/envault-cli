"""File identifiers: the name envault stores a file under, without giving away its content.

Every record is identified by 64 lowercase hex characters, which form its
DynamoDB key (``FILE#<id>``) and part of its S3 key. Two schemes produce them:

``sha256`` (legacy)
    The identifier is the SHA-256 of the plaintext. Records written before
    keyed identifiers use it; their rows have no ``id_scheme`` attribute. The
    hash is public wherever the identifier goes: the DynamoDB key, the S3 key,
    and the KMS encryption context, which CloudTrail records with every
    GenerateDataKey and Decrypt. For a short or guessable file (a PIN, a
    password, a config with one secret line) that hash gives the content away:
    trying every 6-digit PIN takes a fraction of a second.

``hmac-sha256-v1``
    ``file_id = hex(HMAC-SHA-256(K, SHA-256(plaintext)))``, where ``K`` is a
    KMS HMAC key (key spec ``HMAC_256``, key usage ``GENERATE_VERIFY_MAC``)
    named by ``--id-key-id`` / ``ENVAULT_ID_KEY_ID``. KMS computes the MAC
    (GenerateMac): the key never leaves KMS, and the message is the raw
    32-byte digest, never the plaintext or the hash's hex spelling. Without
    ``K`` nobody can compute an identifier or test a guess against one; with
    it, every computation is a KMS request that CloudTrail records. The result
    has the shape of a SHA-256, so keys, S3 paths and their validators are
    unchanged, and it is deterministic, so ``encrypt`` still recognises a file
    it has stored before.

A keyed record also stores ``id_key_arn``, the ARN KMS returned for the key
that made its identifier. Reading the record back, envault asks KMS
(VerifyMac, under that ARN) whether the decrypted plaintext's digest has that
MAC, before the plaintext is published, sealed or re-encrypted. The ARN is
checked first, without calling KMS: it must name a key in an account trusted to
have encrypted the data, the anchor discovery decryption uses.

Every KMS call here goes through :func:`envault.retry.aws_retry` (transient
failures only) and :data:`envault.config.boto_config`. KMS refusing or failing
to answer is a :class:`~envault.exceptions.KMSError` (availability or
permission); only a MAC that does not verify is an integrity failure
(:class:`~envault.exceptions.FileIdMismatchError`).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from envault.config import boto_config, partition_for_region
from envault.exceptions import FileIdMismatchError, KMSError, UntrustedIdKeyError
from envault.retry import aws_retry, is_transient_aws_error

#: Legacy scheme: the identifier is the plaintext's SHA-256. Never written as
#: an ``id_scheme`` value: rows of this scheme have no such attribute.
ID_SCHEME_SHA256 = "sha256"
#: Keyed scheme: the identifier is the HMAC-SHA-256 of the plaintext's SHA-256
#: digest under the record's ``id_key_arn``.
ID_SCHEME_HMAC_SHA256 = "hmac-sha256-v1"
#: Every scheme envault can read.
ID_SCHEMES = frozenset({ID_SCHEME_SHA256, ID_SCHEME_HMAC_SHA256})

#: The KMS MAC algorithm of :data:`ID_SCHEME_HMAC_SHA256` (an HMAC_256 key's only one).
MAC_ALGORITHM = "HMAC_SHA_256"
#: Identifiers of both schemes: 64 lowercase hex characters.
FILE_ID_HEX_LENGTH = 64

_DIGEST_BYTES = 32
_FILE_ID_RE = re.compile(r"[0-9a-f]{64}")
# A KMS key ARN with every component concrete: partition (aws, aws-cn,
# aws-us-gov, aws-iso-b, ...), region, 12-digit account, and a key ID that is a
# UUID or a multi-Region key ID. Alias ARNs and wildcards do not match.
_KMS_KEY_ARN_RE = re.compile(
    r"arn:(?P<partition>aws(?:-[a-z]+)*)"
    r":kms:(?P<region>[a-z]+(?:-[a-z]+)+-[0-9]+)"
    r":(?P<account>[0-9]{12})"
    r":key/(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})"
)


def is_file_id(value: object) -> bool:
    """True for 64 lowercase hex characters, the shape of an identifier in either scheme."""
    return isinstance(value, str) and bool(_FILE_ID_RE.fullmatch(value))


def sha256_digest(hex_sha256: str) -> bytes:
    """The raw 32-byte digest of a hex SHA-256: what GenerateMac and VerifyMac are given.

    Raises:
        ValueError: ``hex_sha256`` is not 64 lowercase hex characters. The
            message does not repeat the value.
    """
    if not is_file_id(hex_sha256):
        raise ValueError("expected a SHA-256 as 64 lowercase hex characters")
    return bytes.fromhex(hex_sha256)


@dataclass(frozen=True)
class KmsKeyArn:
    """The parts of a KMS key ARN envault checks."""

    arn: str
    partition: str
    region: str
    account: str


def parse_kms_key_arn(value: object) -> KmsKeyArn | None:
    """``value`` as a KMS key ARN, or None if it is anything else (an alias, a bare key ID)."""
    if not isinstance(value, str):
        return None
    match = _KMS_KEY_ARN_RE.fullmatch(value)
    if match is None:
        return None
    return KmsKeyArn(
        arn=value,
        partition=match.group("partition"),
        region=match.group("region"),
        account=match.group("account"),
    )


def check_id_key_arn(key_arn: str, *, region: str, allowed_account_ids: Sequence[str]) -> KmsKeyArn:
    """Accept a record's ``id_key_arn`` only if it names a KMS key envault trusts.

    The anchor is the one discovery decryption uses: the key's account must be
    one of ``allowed_account_ids`` (``ENVAULT_ALLOWED_ACCOUNT_IDS``) and its
    partition the partition of ``region``. The ARN comes from a DynamoDB row,
    which anyone with write access to the table can edit, so this runs before
    any KMS call: a row naming someone else's key never makes envault ask that
    key anything.

    Raises:
        UntrustedIdKeyError: ``key_arn`` is not a KMS key ARN, or names a key
            in another partition or in an untrusted account.
    """
    parsed = parse_kms_key_arn(key_arn)
    if parsed is None:
        raise UntrustedIdKeyError(
            "The record's identifier key (id_key_arn) is not a KMS key ARN; refusing to "
            "use the record. The state table may have been tampered with."
        )
    partition = partition_for_region(region)
    if parsed.partition != partition or partition_for_region(parsed.region) != partition:
        raise UntrustedIdKeyError(
            f"The record's identifier key {key_arn} is not in the {partition} partition of "
            f"region {region}; refusing to use the record."
        )
    if parsed.account not in allowed_account_ids:
        raise UntrustedIdKeyError(
            f"The record's identifier key {key_arn} is in account {parsed.account}, which is "
            f"not one of the trusted accounts ({', '.join(allowed_account_ids)}); refusing to "
            "use the record. Add the account to ENVAULT_ALLOWED_ACCOUNT_IDS only if it "
            "owns your identifier key."
        )
    return parsed


@dataclass(frozen=True)
class KeyedFileId:
    """A keyed identifier and the ARN of the KMS key that made it."""

    file_id: str
    key_arn: str


class IdKey:
    """The HMAC KMS key that names new records (``--id-key-id`` / ``ENVAULT_ID_KEY_ID``).

    ``key_id`` is whatever the operator configured: an alias, a key ID or a
    key ARN. The ARN KMS reports back for it is what records store.
    """

    def __init__(self, key_id: str, region: str) -> None:
        self.key_id = key_id
        self.region = region
        self._client: Any = None

    def file_id(self, digest: bytes) -> KeyedFileId:
        """The keyed identifier of the plaintext whose SHA-256 digest is ``digest``.

        One KMS GenerateMac request with ``MacAlgorithm=HMAC_SHA_256`` and the
        32-byte digest as the message.

        Raises:
            ValueError: ``digest`` is not a raw 32-byte digest.
            KMSError: KMS refused or failed (transient failures were retried),
                or answered with something other than a 32-byte HMAC-SHA-256
                and a key ARN.
        """
        _require_digest(digest)
        if self._client is None:
            self._client = _kms_client(self.region)
        try:
            response = _generate_mac(self._client, self.key_id, digest)
        except (ClientError, BotoCoreError) as exc:
            raise _kms_error("GenerateMac", self.key_id, exc) from exc
        return _keyed_file_id(response, self.key_id)


class FileIdVerifier:
    """Checks decrypted plaintext against keyed identifiers (KMS VerifyMac), for one command.

    Args:
        region: The configured region; key ARNs must be in its partition.
        allowed_account_ids: Accounts trusted to own identifier keys, the
            same list that constrains discovery decryption.
    """

    def __init__(self, *, region: str, allowed_account_ids: Sequence[str]) -> None:
        self.region = region
        self.allowed_account_ids = tuple(allowed_account_ids)
        self._clients: dict[str, Any] = {}

    def verify(self, file_id: str, digest: bytes, *, key_arn: str) -> None:
        """Return only if ``file_id`` is the HMAC of ``digest`` under ``key_arn``.

        ``key_arn`` is checked with :func:`check_id_key_arn` before KMS is
        asked anything. The request goes to the key's own region.

        Raises:
            UntrustedIdKeyError: ``key_arn`` is malformed or not trusted.
            FileIdMismatchError: KMS says the MAC does not verify
                (KMSInvalidMacException, or ``MacValid`` false): the plaintext
                is not the file ``file_id`` names.
            KMSError: KMS refused or failed to answer (access denied, a
                disabled, deleted or non-HMAC key, throttling, network).
            ValueError: ``file_id`` or ``digest`` is malformed.
        """
        arn = check_id_key_arn(
            key_arn, region=self.region, allowed_account_ids=self.allowed_account_ids
        )
        if not is_file_id(file_id):
            raise ValueError("expected a file identifier of 64 lowercase hex characters")
        _require_digest(digest)
        client = self._clients.get(arn.region)
        if client is None:
            client = self._clients[arn.region] = _kms_client(arn.region)
        try:
            response = _verify_mac(client, arn.arn, digest, bytes.fromhex(file_id))
        except ClientError as exc:
            if _error_code(exc) == "KMSInvalidMacException":
                raise FileIdMismatchError(file_id) from exc
            raise _kms_error("VerifyMac", key_arn, exc) from exc
        except BotoCoreError as exc:
            raise _kms_error("VerifyMac", key_arn, exc) from exc
        if response.get("MacValid") is not True:
            raise FileIdMismatchError(file_id)


def _kms_client(region: str) -> Any:
    """A KMS client for ``region`` with the shared timeouts and single HTTP attempt."""
    return boto3.client("kms", region_name=region, config=boto_config)


def _require_digest(digest: bytes) -> None:
    if not isinstance(digest, bytes) or len(digest) != _DIGEST_BYTES:
        raise ValueError("expected the raw 32-byte SHA-256 digest of the plaintext")


@aws_retry()
def _generate_mac(client: Any, key_id: str, digest: bytes) -> dict[str, Any]:
    return dict(client.generate_mac(KeyId=key_id, MacAlgorithm=MAC_ALGORITHM, Message=digest))


@aws_retry()
def _verify_mac(client: Any, key_arn: str, digest: bytes, mac: bytes) -> dict[str, Any]:
    return dict(
        client.verify_mac(KeyId=key_arn, MacAlgorithm=MAC_ALGORITHM, Message=digest, Mac=mac)
    )


def _keyed_file_id(response: dict[str, Any], key_id: str) -> KeyedFileId:
    """Validate a GenerateMac answer: a 32-byte HMAC-SHA-256 and the key's ARN."""
    mac = response.get("Mac")
    algorithm = response.get("MacAlgorithm")
    if not isinstance(mac, bytes) or len(mac) != _DIGEST_BYTES or algorithm != MAC_ALGORITHM:
        raise KMSError(
            f"KMS answered GenerateMac for {key_id} with a {algorithm} MAC of "
            f"{len(mac) if isinstance(mac, bytes) else 0} bytes, not a 32-byte {MAC_ALGORITHM}. "
            "The identifier key must be an HMAC_256 key.",
            operation="GenerateMac",
            error_code="UnexpectedResponse",
            key_id=key_id,
        )
    reported = response.get("KeyId")
    arn = parse_kms_key_arn(reported)
    if arn is None:
        raise KMSError(
            f"KMS answered GenerateMac for {key_id} without a key ARN (KeyId {reported!r}). "
            "envault records the ARN of the key that made each identifier, to check it on "
            "every read, and cannot continue without it.",
            operation="GenerateMac",
            error_code="UnexpectedResponse",
            key_id=key_id,
        )
    return KeyedFileId(file_id=mac.hex(), key_arn=arn.arn)


def _error_code(exc: BaseException) -> str:
    if isinstance(exc, ClientError):
        return str(exc.response.get("Error", {}).get("Code", "")) or "UnknownError"
    return type(exc).__name__


def _kms_error(operation: str, key: str, exc: BaseException) -> KMSError:
    """Map a GenerateMac/VerifyMac failure to KMSError: availability or permission."""
    code = _error_code(exc)
    if isinstance(exc, ClientError):
        message = str(exc.response.get("Error", {}).get("Message", ""))
        detail = f"{code}: {message}" if message else code
    else:
        detail = f"{code}: {exc}"
    transient = is_transient_aws_error(exc)
    if transient:
        advice = "KMS is throttling or unavailable; try again later."
    elif operation == "GenerateMac":
        advice = (
            "Check that the key exists and is enabled, that it is an HMAC key (key spec "
            "HMAC_256, key usage GENERATE_VERIFY_MAC), and that this principal may use it "
            "(kms:GenerateMac)."
        )
    elif code in ("NotFoundException", "InvalidKeyUsageException"):
        advice = (
            "The record names a key that does not exist or is not an HMAC key: the key was "
            "deleted, or the record was altered."
        )
    else:
        advice = "Check that the key is enabled and that this principal may use it (kms:VerifyMac)."
    what = "compute a file identifier" if operation == "GenerateMac" else "verify the file"
    return KMSError(
        f"KMS could not {what} with {key} ({detail}). {advice} This is a KMS availability or "
        "permission problem; it says nothing about the file's content.",
        operation=operation,
        error_code=code,
        transient=transient,
        key_id=key,
    )
