# tests/unit/test_s3.py
from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws

from envault.s3 import S3Store

BUCKET = "test-bucket"
REGION = "us-east-1"


def _create_versioned_bucket(s3_client) -> None:
    s3_client.create_bucket(Bucket=BUCKET)
    s3_client.put_bucket_versioning(
        Bucket=BUCKET,
        VersioningConfiguration={"Status": "Enabled"},
    )


@mock_aws
def test_upload_returns_version_id(tmp_path: Path):
    """upload_file must return a non-empty VersionId."""
    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)

    p = tmp_path / "secret.txt.encrypted"
    p.write_bytes(b"fake ciphertext")

    store = S3Store(bucket=BUCKET, region=REGION)
    version_id = store.upload_file(local_path=p, s3_key="encrypted/aa/aaa.../secret.txt.encrypted")

    assert isinstance(version_id, str)
    assert len(version_id) > 0


@mock_aws
def test_upload_two_versions_return_distinct_ids(tmp_path: Path):
    """Each upload must return a unique VersionId."""
    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)

    p = tmp_path / "file.enc"
    p.write_bytes(b"version one")
    store = S3Store(bucket=BUCKET, region=REGION)

    v1 = store.upload_file(local_path=p, s3_key="encrypted/aa/aaa.../file.enc")
    p.write_bytes(b"version two")
    v2 = store.upload_file(local_path=p, s3_key="encrypted/aa/aaa.../file.enc")

    assert v1 != v2


@mock_aws
def test_download_specific_version(tmp_path: Path):
    """download_file with version_id must retrieve the correct version."""
    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)

    store = S3Store(bucket=BUCKET, region=REGION)

    p = tmp_path / "data.enc"
    p.write_bytes(b"first content")
    v1 = store.upload_file(p, "encrypted/aa/aaa.../data.enc")

    p.write_bytes(b"second content")
    store.upload_file(p, "encrypted/aa/aaa.../data.enc")

    out = tmp_path / "retrieved.enc"
    store.download_file("encrypted/aa/aaa.../data.enc", out, version_id=v1)
    assert out.read_bytes() == b"first content"


@mock_aws
def test_download_empty_version_id_is_refused(tmp_path: Path):
    """download_file with empty version_id must fail closed."""
    from envault.exceptions import EnvaultError

    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)
    s3_client.put_object(Bucket=BUCKET, Key="encrypted/aa/aaa.../file.enc", Body=b"data")

    store = S3Store(bucket=BUCKET, region=REGION)
    out = tmp_path / "file.enc"

    with pytest.raises(EnvaultError, match="without a VersionId"):
        store.download_file("encrypted/aa/aaa.../file.enc", out, version_id="")


@mock_aws
def test_download_empty_version_id_logs_warning(tmp_path: Path, caplog):
    """download_file with empty version_id and allow_latest must emit a WARNING."""
    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)
    s3_client.put_object(Bucket=BUCKET, Key="encrypted/aa/aaa.../file.enc", Body=b"data")

    store = S3Store(bucket=BUCKET, region=REGION)
    out = tmp_path / "file.enc"

    with caplog.at_level(logging.WARNING, logger="envault.s3"):
        store.download_file("encrypted/aa/aaa.../file.enc", out, version_id="", allow_latest=True)

    assert any("version" in r.message.lower() for r in caplog.records), (
        f"Expected a version warning, got: {[r.message for r in caplog.records]}"
    )


def test_s3_key_for_file_is_content_addressed():
    """S3 key must include sha256 hash to prevent filename collisions."""
    store = S3Store(bucket="b", region="us-east-1")
    sha = "a" * 64

    key = store.s3_key_for_file(sha256_hash=sha, file_name="report.xlsx")

    # Key must contain the hash prefix (sharding) and full hash
    assert sha[:2] in key
    assert sha in key
    assert "report.xlsx.encrypted" in key

    # Two files with same name but different hashes get different keys
    sha2 = "b" * 64
    key2 = store.s3_key_for_file(sha256_hash=sha2, file_name="report.xlsx")
    assert key != key2


def test_s3_key_sanitizes_traversal_characters():
    """Filenames with path-traversal or special chars must be sanitized."""
    store = S3Store(bucket="b", region="us-east-1")
    sha = "c" * 64

    key = store.s3_key_for_file(sha256_hash=sha, file_name="../../etc/passwd")
    assert "../" not in key
    assert "/" not in key.split(sha + "/")[1].replace(".encrypted", "")

    key2 = store.s3_key_for_file(sha256_hash=sha, file_name="file with spaces & (parens).txt")
    assert " " not in key2
    assert "&" not in key2
    assert "(" not in key2


def test_s3_key_sanitize_preserves_safe_names():
    """Safe filenames must pass through unchanged."""
    store = S3Store(bucket="b", region="us-east-1")
    sha = "d" * 64

    key = store.s3_key_for_file(sha256_hash=sha, file_name="my-file_v2.tar.gz")
    assert "my-file_v2.tar.gz.encrypted" in key


def test_sanitize_filename_ascii_only():
    """Unicode word characters must be replaced with underscores."""
    assert S3Store._sanitize_filename("caf\u00e9.txt") == "caf_.txt"
    assert S3Store._sanitize_filename("\u4f60\u597d.txt") == "__.txt"


def test_sanitize_filename_strips_dot_dot():
    """Double-dot sequences must be collapsed."""
    result = S3Store._sanitize_filename("foo..bar.txt")
    assert ".." not in result


def test_sanitize_filename_strips_directory():
    """Directory components must be stripped."""
    assert S3Store._sanitize_filename("../../etc/passwd") == "passwd"
    assert S3Store._sanitize_filename("/absolute/path/file.txt") == "file.txt"


def test_sanitize_filename_empty_returns_underscore():
    """Empty input must return underscore."""
    assert S3Store._sanitize_filename("") == "_"


def test_s3store_uses_shared_boto_config():
    """S3Store must create its client with the shared boto_config."""
    from unittest.mock import patch

    from envault.config import boto_config

    with patch("envault.s3.boto3") as mock_boto3:
        S3Store(bucket="b", region="us-east-1")
        mock_boto3.client.assert_called_once_with("s3", region_name="us-east-1", config=boto_config)


@mock_aws
def test_upload_passes_sse_kms_key_id(tmp_path: Path):
    """upload_file must pass SSEKMSKeyId when kms_key_id is configured."""
    from unittest.mock import patch

    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)

    p = tmp_path / "file.enc"
    p.write_bytes(b"ciphertext")

    kms_key = "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
    store = S3Store(bucket=BUCKET, region=REGION, kms_key_id=kms_key)

    with patch.object(store._s3, "put_object", wraps=store._s3.put_object) as mock_put:
        store.upload_file(local_path=p, s3_key="encrypted/aa/aaa.../file.enc")
        mock_put.assert_called_once()
        call_kwargs = mock_put.call_args.kwargs
        assert call_kwargs.get("SSEKMSKeyId") == kms_key


@mock_aws
def test_upload_without_kms_key_id_omits_sse(tmp_path: Path):
    """upload_file without kms_key_id must not pass SSEKMSKeyId."""
    from unittest.mock import patch

    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)

    p = tmp_path / "file.enc"
    p.write_bytes(b"ciphertext")

    store = S3Store(bucket=BUCKET, region=REGION)

    with patch.object(store._s3, "put_object", wraps=store._s3.put_object) as mock_put:
        store.upload_file(local_path=p, s3_key="encrypted/aa/aaa.../file.enc")
        mock_put.assert_called_once()
        call_kwargs = mock_put.call_args.kwargs
        assert "SSEKMSKeyId" not in call_kwargs


# ---------------------------------------------------------------------------
# In-memory ciphertext fetch (used by `envault exec`)
# ---------------------------------------------------------------------------


@mock_aws
def test_download_to_memory_returns_ciphertext():
    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)
    s3_client.put_object(Bucket=BUCKET, Key="enc/a", Body=b"ciphertext-bytes")

    store = S3Store(bucket=BUCKET, region=REGION)
    assert store.download_to_memory("enc/a", allow_latest=True).read() == b"ciphertext-bytes"


@mock_aws
def test_download_to_memory_honours_version_id():
    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)
    first = s3_client.put_object(Bucket=BUCKET, Key="enc/a", Body=b"v1")["VersionId"]
    s3_client.put_object(Bucket=BUCKET, Key="enc/a", Body=b"v2-overwritten")

    store = S3Store(bucket=BUCKET, region=REGION)
    assert store.download_to_memory("enc/a", version_id=first).read() == b"v1"


@mock_aws
def test_download_to_memory_rejects_oversized_object():
    """A large object must be refused rather than exhausting memory."""
    from envault.exceptions import EnvaultError

    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)
    s3_client.put_object(Bucket=BUCKET, Key="enc/big", Body=b"x" * 128)

    store = S3Store(bucket=BUCKET, region=REGION)
    with patch("envault.s3.MAX_IN_MEMORY_BYTES", 16):
        with pytest.raises(EnvaultError, match="limit for in-memory decryption"):
            store.download_to_memory("enc/big", allow_latest=True)


@mock_aws
def test_download_to_memory_does_not_touch_disk(tmp_path):
    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)
    s3_client.put_object(Bucket=BUCKET, Key="enc/a", Body=b"ciphertext")

    store = S3Store(bucket=BUCKET, region=REGION)
    store.download_to_memory("enc/a", allow_latest=True)
    assert not list(tmp_path.iterdir())


def test_assert_s3_key_matches_hash_accepts_content_addressed_key():
    from envault.s3 import assert_s3_key_matches_hash

    sha = "a" * 64
    assert_s3_key_matches_hash(f"encrypted/{sha[:2]}/{sha}/file.txt.encrypted", sha)


def test_assert_s3_key_matches_hash_rejects_wrong_prefix():
    from envault.exceptions import EnvaultError
    from envault.s3 import assert_s3_key_matches_hash

    sha = "a" * 64
    with pytest.raises(EnvaultError, match="content-addressed"):
        assert_s3_key_matches_hash("other/prefix/file.encrypted", sha)


def test_assert_s3_key_matches_hash_rejects_hash_mismatch():
    from envault.exceptions import EnvaultError
    from envault.s3 import assert_s3_key_matches_hash

    sha = "a" * 64
    other = "b" * 64
    with pytest.raises(EnvaultError, match="content-addressed"):
        assert_s3_key_matches_hash(f"encrypted/{other[:2]}/{other}/file.txt.encrypted", sha)


# ---------------------------------------------------------------------------
# M7: one never-reused key per upload, written with If-None-Match: *
# ---------------------------------------------------------------------------

SHA = "a" * 64
MID = "0123456789abcdef" * 4  # an Encryption SDK message id: 32 bytes as lowercase hex


def test_s3_key_for_file_without_message_id_keeps_old_format():
    store = S3Store(bucket="b", region="us-east-1")
    assert store.s3_key_for_file(SHA, "report.xlsx") == f"encrypted/aa/{SHA}/report.xlsx.encrypted"
    assert (
        store.s3_key_for_file(sha256_hash=SHA, file_name="r.xlsx", message_id=None)
        == f"encrypted/aa/{SHA}/r.xlsx.encrypted"
    )


def test_s3_key_for_file_with_message_id_is_unique_per_upload():
    store = S3Store(bucket="b", region="us-east-1")
    key = store.s3_key_for_file(SHA, "../secrets/db env", message_id=MID)
    assert key == f"encrypted/aa/{SHA}/{MID}/db_env.encrypted"
    other = store.s3_key_for_file(SHA, "../secrets/db env", message_id="f" * 64)
    assert other != key


@pytest.mark.parametrize(
    "bad",
    ["", "abc", MID.upper(), MID[:-1], MID + "0", "g" * 64, f"{MID[:32]}/../{MID[:28]}"],
)
def test_s3_key_for_file_rejects_malformed_message_id(bad: str):
    from envault.exceptions import InvalidS3KeyError

    store = S3Store(bucket="b", region="us-east-1")
    with pytest.raises(InvalidS3KeyError, match="message id"):
        store.s3_key_for_file(SHA, "f.txt", message_id=bad)


def test_s3_key_for_file_with_message_id_rejects_malformed_identifier():
    from envault.exceptions import InvalidS3KeyError

    store = S3Store(bucket="b", region="us-east-1")
    with pytest.raises(InvalidS3KeyError):
        store.s3_key_for_file("../../etc", "f.txt", message_id=MID)


def test_s3_key_validator_accepts_both_formats():
    from envault.s3 import assert_s3_key_matches_hash

    store = S3Store(bucket="b", region="us-east-1")
    old = store.s3_key_for_file(SHA, "f.txt")
    new = store.s3_key_for_file(SHA, "f.txt", message_id=MID)
    assert_s3_key_matches_hash(old, SHA)
    assert_s3_key_matches_hash(new, SHA)
    assert_s3_key_matches_hash(new, SHA, message_id=MID)
    # Old-format keys carry no message id, so there is nothing to compare.
    assert_s3_key_matches_hash(old, SHA, message_id=MID)


@pytest.mark.parametrize(
    "key",
    [
        f"encrypted/aa/{SHA}/{MID.upper()}/f.txt.encrypted",
        f"encrypted/aa/{SHA}/{MID[:-1]}/f.txt.encrypted",
        f"encrypted/aa/{SHA}/{MID}0/f.txt.encrypted",
        f"encrypted/aa/{SHA}/{MID}/extra/f.txt.encrypted",
        f"encrypted/aa/{SHA}/{MID}/.encrypted",
        f"encrypted/aa/{SHA}/{MID}/f.txt",
        f"encrypted/bb/{SHA}/{MID}/f.txt.encrypted",
        f"encrypted/aa/{'b' * 64}/{MID}/f.txt.encrypted",
        f"other/aa/{SHA}/{MID}/f.txt.encrypted",
    ],
)
def test_s3_key_validator_rejects_malformed_keys(key: str):
    from envault.exceptions import EnvaultError, InvalidS3KeyError
    from envault.s3 import assert_s3_key_matches_hash

    with pytest.raises(InvalidS3KeyError, match="content-addressed") as exc_info:
        assert_s3_key_matches_hash(key, SHA)
    assert isinstance(exc_info.value, EnvaultError)


def test_s3_key_validator_checks_message_id_when_given():
    from envault.exceptions import InvalidS3KeyError
    from envault.s3 import assert_s3_key_matches_hash

    key = f"encrypted/aa/{SHA}/{MID}/f.txt.encrypted"
    with pytest.raises(InvalidS3KeyError, match="message id"):
        assert_s3_key_matches_hash(key, SHA, message_id="f" * 64)


KEY = f"encrypted/aa/{SHA}/{MID}/f.txt.encrypted"


@mock_aws
def test_upload_if_none_match_refuses_existing_key(tmp_path: Path, no_retry_sleep):
    """M7: a conditional upload must never replace an object a record may pin."""
    from envault.exceptions import EnvaultError, S3ObjectExistsError

    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)
    pinned = s3_client.put_object(Bucket=BUCKET, Key=KEY, Body=b"pinned ciphertext")["VersionId"]

    p = tmp_path / "new.enc"
    p.write_bytes(b"different ciphertext")
    store = S3Store(bucket=BUCKET, region=REGION)
    with pytest.raises(S3ObjectExistsError) as exc_info:
        store.upload_file(p, KEY, if_none_match=True)

    assert isinstance(exc_info.value, EnvaultError)
    assert exc_info.value.bucket == BUCKET
    assert exc_info.value.s3_key == KEY
    versions = s3_client.list_object_versions(Bucket=BUCKET, Prefix=KEY)["Versions"]
    assert [v["VersionId"] for v in versions] == [pinned]
    assert s3_client.get_object(Bucket=BUCKET, Key=KEY)["Body"].read() == b"pinned ciphertext"
    assert no_retry_sleep == [], "a 412 is deterministic and must not be retried"


@mock_aws
def test_upload_if_none_match_sends_condition_and_returns_version(tmp_path: Path):
    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)
    p = tmp_path / "new.enc"
    p.write_bytes(b"ciphertext")
    store = S3Store(bucket=BUCKET, region=REGION, kms_key_id="alias/k")

    with patch.object(store._s3, "put_object", wraps=store._s3.put_object) as mock_put:
        version_id = store.upload_file(p, KEY, if_none_match=True)

    kwargs = mock_put.call_args.kwargs
    assert kwargs["IfNoneMatch"] == "*"
    assert kwargs["SSEKMSKeyId"] == "alias/k"
    assert kwargs["ChecksumAlgorithm"] == "SHA256"
    versions = s3_client.list_object_versions(Bucket=BUCKET, Prefix=KEY)["Versions"]
    assert [v["VersionId"] for v in versions] == [version_id]


@mock_aws
def test_upload_default_sends_no_condition(tmp_path: Path):
    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)
    p = tmp_path / "new.enc"
    p.write_bytes(b"ciphertext")
    store = S3Store(bucket=BUCKET, region=REGION)
    with patch.object(store._s3, "put_object", wraps=store._s3.put_object) as mock_put:
        store.upload_file(p, KEY)
    assert "IfNoneMatch" not in mock_put.call_args.kwargs


@mock_aws
def test_upload_if_none_match_recovers_from_lost_reply(tmp_path: Path, no_retry_sleep):
    """Our first PUT lands but its reply is lost; the retry's 412 is our own object."""
    from botocore.exceptions import ReadTimeoutError

    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)
    p = tmp_path / "new.enc"
    p.write_bytes(b"our ciphertext")
    store = S3Store(bucket=BUCKET, region=REGION)
    real_put = store._s3.put_object
    calls = {"n": 0}

    def put_then_lose_reply(**kwargs):
        calls["n"] += 1
        response = real_put(**kwargs)
        if calls["n"] == 1:
            raise ReadTimeoutError(endpoint_url="https://s3.us-east-1.amazonaws.com")
        return response

    with patch.object(store._s3, "put_object", side_effect=put_then_lose_reply):
        version_id = store.upload_file(p, KEY, if_none_match=True)

    assert calls["n"] == 2
    versions = s3_client.list_object_versions(Bucket=BUCKET, Prefix=KEY)["Versions"]
    assert [v["VersionId"] for v in versions] == [version_id]


@mock_aws
def test_upload_if_none_match_does_not_adopt_a_foreign_object(tmp_path: Path, no_retry_sleep):
    """After a lost reply, a different object at the key is still a refusal."""
    from botocore.exceptions import ReadTimeoutError

    from envault.exceptions import S3ObjectExistsError

    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)
    p = tmp_path / "new.enc"
    p.write_bytes(b"our ciphertext")
    store = S3Store(bucket=BUCKET, region=REGION)

    def foreign_put_then_lost_reply(**kwargs):
        s3_client.put_object(Bucket=BUCKET, Key=KEY, Body=b"someone else's bytes")
        raise ReadTimeoutError(endpoint_url="https://s3.us-east-1.amazonaws.com")

    real_put = store._s3.put_object
    calls = {"n": 0}

    def put(**kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return foreign_put_then_lost_reply(**kwargs)
        return real_put(**kwargs)

    with patch.object(store._s3, "put_object", side_effect=put):
        with pytest.raises(S3ObjectExistsError):
            store.upload_file(p, KEY, if_none_match=True)
    body = s3_client.get_object(Bucket=BUCKET, Key=KEY)["Body"].read()
    assert body == b"someone else's bytes"


@mock_aws
def test_upload_if_none_match_requires_botocore_support(tmp_path: Path):
    """Old botocore drops nothing silently: it would reject IfNoneMatch client-side."""
    from envault.exceptions import ConfigurationError

    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)
    p = tmp_path / "new.enc"
    p.write_bytes(b"ciphertext")
    store = S3Store(bucket=BUCKET, region=REGION)
    with (
        patch("envault.s3._put_object_supports_if_none_match", return_value=False),
        patch.object(store._s3, "put_object") as mock_put,
    ):
        with pytest.raises(ConfigurationError, match="1.35.2"):
            store.upload_file(p, KEY, if_none_match=True)
    mock_put.assert_not_called()


@mock_aws
def test_download_file_does_not_retry_missing_object(tmp_path: Path, no_retry_sleep):
    """A 404 is deterministic: one attempt, no backoff."""
    from botocore.exceptions import ClientError

    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)
    store = S3Store(bucket=BUCKET, region=REGION)
    with pytest.raises(ClientError):
        store.download_file("encrypted/missing.encrypted", tmp_path / "x", allow_latest=True)
    assert no_retry_sleep == []


# ---------------------------------------------------------------------------
# M4: keys written by the legacy `aws s3 sync ../encrypted s3://$BUCKET/encrypted`
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "encrypted/alpha.txt.encrypted",
        "encrypted/sub/beta.txt.encrypted",
        "encrypted/deep/er/still/fine.env.encrypted",
        "encrypted/.env.encrypted",
        "encrypted/with space/café.txt.encrypted",
        f"encrypted/aa/{SHA}/f.txt.encrypted",
    ],
)
def test_assert_legacy_s3_key_accepts_sync_layout(key: str):
    from envault.s3 import assert_legacy_s3_key

    assert_legacy_s3_key(key)


@pytest.mark.parametrize(
    "key",
    [
        "alpha.txt.encrypted",
        "encrypt/alpha.txt.encrypted",
        "encrypted/alpha.txt",
        "encrypted/alpha.txt.encrypted.bak",
        "/encrypted/alpha.txt.encrypted",
        "encrypted//alpha.txt.encrypted",
        "encrypted/./alpha.txt.encrypted",
        "encrypted/../alpha.txt.encrypted",
        "encrypted/sub/../../x.encrypted",
        "encrypted/sub/..",
        "encrypted/a\\b.txt.encrypted",
        "encrypted/a\x1b[2Jb.encrypted",
        "encrypted/a\nb.encrypted",
        "encrypted/a\x00b.encrypted",
        "encrypted/a\x7fb.encrypted",
        "encrypted/a\x85b.encrypted",
        "encrypted/a‮b.encrypted",
        "encrypted/a​b.encrypted",
        "encrypted/.encrypted",
        "encrypted/sub/.encrypted",
        "encrypted/...encrypted",
        "encrypted/",
        "encrypted",
        "",
        "encrypted/x.encrypted/",
        "encrypted/" + "a" * 1100 + ".encrypted",
    ],
)
def test_assert_legacy_s3_key_rejects_unsafe_keys(key: str):
    from envault.exceptions import EnvaultError, InvalidS3KeyError
    from envault.s3 import assert_legacy_s3_key

    with pytest.raises(InvalidS3KeyError, match="legacy") as exc_info:
        assert_legacy_s3_key(key)
    assert isinstance(exc_info.value, EnvaultError)
    # The message shows the key escaped, so control characters cannot reach a terminal.
    assert "\x1b" not in str(exc_info.value)
    assert "\n" not in str(exc_info.value)
