"""envault.fileid: keyed file identifiers through a KMS HMAC key (M6).

``file_id = hex(HMAC-SHA-256(ID key, SHA-256(plaintext)))``, by KMS GenerateMac;
a record's identifier is checked against decrypted plaintext with VerifyMac,
under the key ARN the record names, once that ARN is known to be trusted.
moto 5.2.5 implements HMAC keys, GenerateMac, VerifyMac and
KMSInvalidMacException; KMS failures moto cannot produce (throttling, access
denied, disabled keys) are stubbed at the boto client.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from typing import Any

import boto3
import pytest
from botocore.exceptions import EndpointConnectionError
from botocore.stub import Stubber

from envault import fileid
from envault.config import boto_config
from envault.exceptions import (
    ChecksumMismatchError,
    FileIdMismatchError,
    KMSError,
    UntrustedIdKeyError,
)

from ._id_key import ID_KEY_ALIAS

REGION = "us-east-1"
ACCOUNT = "123456789012"  # moto's account
PIN = b"493017\n"
DIGEST = hashlib.sha256(PIN).digest()
KEY_UUID = "1234abcd-12ab-34cd-56ef-1234567890ab"
FOREIGN_ARN = f"arn:aws:kms:us-east-1:444455556666:key/{KEY_UUID}"
OWN_ARN = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/{KEY_UUID}"


def _moto_mac(message: bytes) -> bytes:
    kms = boto3.client("kms", region_name=REGION)
    response = kms.generate_mac(KeyId=ID_KEY_ALIAS, MacAlgorithm="HMAC_SHA_256", Message=message)
    return bytes(response["Mac"])


def _verifier(accounts: tuple[str, ...] = (ACCOUNT,)) -> fileid.FileIdVerifier:
    return fileid.FileIdVerifier(region=REGION, allowed_account_ids=accounts)


@pytest.fixture
def stubbed(monkeypatch: pytest.MonkeyPatch) -> Iterator[Stubber]:
    """A real KMS client, with botocore's Stubber answering instead of KMS."""
    client = boto3.client("kms", region_name=REGION, config=boto_config)
    stubber = Stubber(client)
    monkeypatch.setattr(fileid, "_kms_client", lambda region: client)
    with stubber:
        yield stubber


# ---------------------------------------------------------------------------
# Computing identifiers (GenerateMac)
# ---------------------------------------------------------------------------


def test_file_id_is_the_hmac_of_the_raw_sha256_digest(id_key: str) -> None:
    keyed = fileid.IdKey(ID_KEY_ALIAS, REGION).file_id(DIGEST)

    assert keyed.file_id == _moto_mac(DIGEST).hex()
    # The 32-byte digest, not its 64-character hex spelling, is the message.
    assert keyed.file_id != _moto_mac(DIGEST.hex().encode()).hex()
    assert fileid.is_file_id(keyed.file_id)
    assert keyed.file_id != DIGEST.hex()
    assert keyed.key_arn == id_key


def test_file_id_is_deterministic_and_content_specific(id_key: str) -> None:
    key = fileid.IdKey(ID_KEY_ALIAS, REGION)

    first, again = key.file_id(DIGEST), key.file_id(DIGEST)
    other = key.file_id(hashlib.sha256(b"493018\n").digest())

    assert first == again
    assert other.file_id != first.file_id


@pytest.mark.parametrize("digest", [DIGEST.hex().encode(), DIGEST[:31], b""])
def test_file_id_takes_only_a_raw_32_byte_digest(id_key: str, digest: bytes) -> None:
    with pytest.raises(ValueError, match="32-byte"):
        fileid.IdKey(ID_KEY_ALIAS, REGION).file_id(digest)


def test_generate_mac_answer_without_a_key_arn_is_refused(stubbed: Stubber) -> None:
    """The ARN in the answer becomes the record's trust anchor: it must be one."""
    stubbed.add_response(
        "generate_mac",
        {"Mac": b"\x01" * 32, "MacAlgorithm": "HMAC_SHA_256", "KeyId": KEY_UUID},
    )

    with pytest.raises(KMSError, match="key ARN"):
        fileid.IdKey(ID_KEY_ALIAS, REGION).file_id(DIGEST)


@pytest.mark.parametrize(
    "answer",
    [
        {"Mac": b"\x01" * 31, "MacAlgorithm": "HMAC_SHA_256", "KeyId": OWN_ARN},
        {"Mac": b"\x01" * 48, "MacAlgorithm": "HMAC_SHA_384", "KeyId": OWN_ARN},
    ],
)
def test_generate_mac_answer_of_another_shape_is_refused(
    stubbed: Stubber, answer: dict[str, Any]
) -> None:
    stubbed.add_response("generate_mac", answer)

    with pytest.raises(KMSError):
        fileid.IdKey(ID_KEY_ALIAS, REGION).file_id(DIGEST)


def test_generate_mac_sends_the_digest_with_hmac_sha_256(stubbed: Stubber) -> None:
    stubbed.add_response(
        "generate_mac",
        {"Mac": b"\x01" * 32, "MacAlgorithm": "HMAC_SHA_256", "KeyId": OWN_ARN},
        expected_params={"KeyId": ID_KEY_ALIAS, "MacAlgorithm": "HMAC_SHA_256", "Message": DIGEST},
    )

    keyed = fileid.IdKey(ID_KEY_ALIAS, REGION).file_id(DIGEST)

    assert keyed == fileid.KeyedFileId(file_id="01" * 32, key_arn=OWN_ARN)


def test_generate_mac_with_a_key_that_is_not_an_hmac_key(kms_key: str) -> None:
    """The data key (SYMMETRIC_DEFAULT) given as --id-key-id: KMS says InvalidKeyUsage."""
    with pytest.raises(KMSError, match="HMAC") as exc_info:
        fileid.IdKey("alias/envault-test", REGION).file_id(DIGEST)

    assert exc_info.value.operation == "GenerateMac"
    assert exc_info.value.error_code == "InvalidKeyUsageException"
    assert not exc_info.value.transient


# ---------------------------------------------------------------------------
# Verifying identifiers (VerifyMac)
# ---------------------------------------------------------------------------


def test_verify_accepts_the_files_own_identifier(id_key: str) -> None:
    file_id = _moto_mac(DIGEST).hex()

    _verifier().verify(file_id, DIGEST, key_arn=id_key)


def test_verify_refuses_other_content_as_an_integrity_failure(id_key: str) -> None:
    file_id = _moto_mac(hashlib.sha256(b"something else").digest()).hex()

    with pytest.raises(FileIdMismatchError) as exc_info:
        _verifier().verify(file_id, DIGEST, key_arn=id_key)

    err = exc_info.value
    assert isinstance(err, ChecksumMismatchError)
    assert err.expected == file_id
    assert file_id[:16] in str(err)  # the expected identifier may be named ...
    for text in (str(err), repr(err), *vars(err).values()):  # ... the plaintext's hash never
        assert DIGEST.hex()[:16] not in str(text)


def test_verify_mac_valid_false_is_a_mismatch(stubbed: Stubber) -> None:
    stubbed.add_response(
        "verify_mac", {"KeyId": OWN_ARN, "MacValid": False, "MacAlgorithm": "HMAC_SHA_256"}
    )

    with pytest.raises(FileIdMismatchError):
        _verifier().verify("01" * 32, DIGEST, key_arn=OWN_ARN)


def test_verify_sends_the_records_key_arn_and_identifier(stubbed: Stubber) -> None:
    stubbed.add_response(
        "verify_mac",
        {"KeyId": OWN_ARN, "MacValid": True, "MacAlgorithm": "HMAC_SHA_256"},
        expected_params={
            "KeyId": OWN_ARN,
            "MacAlgorithm": "HMAC_SHA_256",
            "Message": DIGEST,
            "Mac": bytes.fromhex("ab" * 32),
        },
    )

    _verifier().verify("ab" * 32, DIGEST, key_arn=OWN_ARN)


@pytest.mark.parametrize(
    "key_arn",
    [
        "",
        "alias/envault-id",
        KEY_UUID,
        f"arn:aws:kms:us-east-1:{ACCOUNT}:alias/envault-id",
        f"arn:aws:kms:us-east-1:{ACCOUNT}:key/*",
        f"arn:aws:kms:us-east-1:{ACCOUNT}:key/{KEY_UUID.upper()}",
        f"arn:aws:kms:us-east-1:{ACCOUNT}:key/{KEY_UUID} ",
        f"arn:aws:kms::{ACCOUNT}:key/{KEY_UUID}",
        f"arn:aws:s3:::{KEY_UUID}",
        FOREIGN_ARN,  # well formed, but another account
        f"arn:aws-cn:kms:cn-north-1:{ACCOUNT}:key/{KEY_UUID}",  # another partition
        f"arn:aws:kms:cn-north-1:{ACCOUNT}:key/{KEY_UUID}",  # region and partition disagree
    ],
)
def test_untrusted_or_malformed_key_arn_is_refused_before_any_kms_call(
    monkeypatch: pytest.MonkeyPatch, key_arn: str
) -> None:
    def no_kms(region: str) -> Any:
        raise AssertionError("KMS must not be called for an untrusted key ARN")

    monkeypatch.setattr(fileid, "_kms_client", no_kms)

    with pytest.raises(UntrustedIdKeyError):
        _verifier().verify("ab" * 32, DIGEST, key_arn=key_arn)
    with pytest.raises(UntrustedIdKeyError):
        fileid.check_id_key_arn(key_arn, region=REGION, allowed_account_ids=[ACCOUNT])


@pytest.mark.parametrize(
    ("region", "key_arn"),
    [
        ("us-east-1", OWN_ARN),
        ("eu-west-1", OWN_ARN),  # another region of the same partition
        ("us-east-1", f"arn:aws:kms:ap-southeast-7:{ACCOUNT}:key/mrk-{'0' * 32}"),
        ("us-gov-west-1", f"arn:aws-us-gov:kms:us-gov-east-1:{ACCOUNT}:key/{KEY_UUID}"),
        ("cn-north-1", f"arn:aws-cn:kms:cn-northwest-1:{ACCOUNT}:key/{KEY_UUID}"),
    ],
)
def test_trusted_key_arns(region: str, key_arn: str) -> None:
    parsed = fileid.check_id_key_arn(key_arn, region=region, allowed_account_ids=[ACCOUNT])

    assert parsed.arn == key_arn
    assert parsed.account == ACCOUNT


def test_verify_uses_a_client_in_the_key_arns_region(monkeypatch: pytest.MonkeyPatch) -> None:
    regions: list[str] = []
    client = boto3.client("kms", region_name="eu-west-1", config=boto_config)
    stubber = Stubber(client)
    stubber.add_response(
        "verify_mac", {"KeyId": OWN_ARN, "MacValid": True, "MacAlgorithm": "HMAC_SHA_256"}
    )
    monkeypatch.setattr(fileid, "_kms_client", lambda region: regions.append(region) or client)
    key_arn = f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/{KEY_UUID}"

    with stubber:
        _verifier().verify("ab" * 32, DIGEST, key_arn=key_arn)

    assert regions == ["eu-west-1"]


# ---------------------------------------------------------------------------
# KMS failures: availability and permission, never integrity
# ---------------------------------------------------------------------------


def _call(operation: str) -> None:
    if operation == "generate_mac":
        fileid.IdKey(ID_KEY_ALIAS, REGION).file_id(DIGEST)
    else:
        _verifier().verify("ab" * 32, DIGEST, key_arn=OWN_ARN)


@pytest.mark.parametrize("operation", ["generate_mac", "verify_mac"])
@pytest.mark.parametrize(
    "code",
    [
        "AccessDeniedException",
        "DisabledException",
        "KMSInvalidStateException",
        "NotFoundException",
        "InvalidKeyUsageException",
    ],
)
def test_deterministic_kms_failures_are_kms_errors_and_not_retried(
    stubbed: Stubber, no_retry_sleep: list[float], operation: str, code: str
) -> None:
    stubbed.add_client_error(operation, service_error_code=code, service_message="simulated")

    with pytest.raises(KMSError) as exc_info:
        _call(operation)

    err = exc_info.value
    assert not isinstance(err, ChecksumMismatchError)
    assert err.error_code == code
    assert err.operation == {"generate_mac": "GenerateMac", "verify_mac": "VerifyMac"}[operation]
    assert not err.transient
    assert no_retry_sleep == []  # one attempt
    stubbed.assert_no_pending_responses()


@pytest.mark.parametrize("operation", ["generate_mac", "verify_mac"])
def test_throttling_is_retried_then_reported_as_transient(
    stubbed: Stubber, no_retry_sleep: list[float], operation: str
) -> None:
    for _ in range(3):
        stubbed.add_client_error(
            operation, service_error_code="ThrottlingException", http_status_code=400
        )

    with pytest.raises(KMSError) as exc_info:
        _call(operation)

    assert exc_info.value.transient
    assert exc_info.value.error_code == "ThrottlingException"
    assert len(no_retry_sleep) == 2  # three attempts
    stubbed.assert_no_pending_responses()


@pytest.mark.parametrize("operation", ["generate_mac", "verify_mac"])
def test_throttling_then_success(
    stubbed: Stubber, no_retry_sleep: list[float], operation: str
) -> None:
    stubbed.add_client_error(operation, service_error_code="ThrottlingException")
    if operation == "generate_mac":
        stubbed.add_response(
            operation, {"Mac": b"\x01" * 32, "MacAlgorithm": "HMAC_SHA_256", "KeyId": OWN_ARN}
        )
    else:
        stubbed.add_response(
            operation, {"KeyId": OWN_ARN, "MacValid": True, "MacAlgorithm": "HMAC_SHA_256"}
        )

    _call(operation)

    assert len(no_retry_sleep) == 1


def test_invalid_mac_is_not_retried(stubbed: Stubber, no_retry_sleep: list[float]) -> None:
    stubbed.add_client_error("verify_mac", service_error_code="KMSInvalidMacException")

    with pytest.raises(FileIdMismatchError):
        _call("verify_mac")

    assert no_retry_sleep == []


class _Unreachable:
    def __init__(self) -> None:
        self.calls = 0

    def _fail(self, **kwargs: Any) -> Any:
        self.calls += 1
        raise EndpointConnectionError(endpoint_url="https://kms.us-east-1.amazonaws.com")

    generate_mac = verify_mac = _fail


@pytest.mark.parametrize("operation", ["generate_mac", "verify_mac"])
def test_unreachable_kms_is_retried_then_a_transient_kms_error(
    monkeypatch: pytest.MonkeyPatch, no_retry_sleep: list[float], operation: str
) -> None:
    unreachable = _Unreachable()
    monkeypatch.setattr(fileid, "_kms_client", lambda region: unreachable)

    with pytest.raises(KMSError) as exc_info:
        _call(operation)

    assert exc_info.value.transient
    assert unreachable.calls == 3


def test_kms_clients_use_the_shared_boto_config() -> None:
    client = fileid._kms_client(REGION)

    assert client.meta.config.retries == boto_config.retries
    assert client.meta.config.connect_timeout == boto_config.connect_timeout
    assert client.meta.config.read_timeout == boto_config.read_timeout


@pytest.mark.parametrize(
    ("value", "expected"),
    [("ab" * 32, True), ("AB" * 32, False), ("ab" * 31, False), ("g" * 64, False), (None, False)],
)
def test_is_file_id(value: object, expected: bool) -> None:
    assert fileid.is_file_id(value) is expected
