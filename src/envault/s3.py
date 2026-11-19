"""S3 operations for envault — upload and download encrypted files."""

from __future__ import annotations

import base64
import hashlib
import io
import logging
import os
import re
import unicodedata
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import ClientError

from envault.config import boto_config
from envault.exceptions import (
    ConfigurationError,
    EnvaultError,
    InvalidS3KeyError,
    S3ObjectExistsError,
)
from envault.retry import aws_retry

logger = logging.getLogger(__name__)

# Ceiling for in-memory ciphertext. Secrets are small; anything approaching this
# belongs in the streaming `decrypt` path, not `exec`.
MAX_IN_MEMORY_BYTES = 16 * 1024 * 1024

#: Length of an Encryption SDK message id as hex. Committing algorithm suites
#: (message format v2, the only ones envault encrypts with) use 32-byte ids.
MESSAGE_ID_HEX_LENGTH = 64

_HEX64_RE = re.compile(r"[0-9a-f]{64}")

# Content-addressed object keys, in the two formats envault has written:
#   encrypted/{id[:2]}/{id}/{name}.encrypted               one key per file (reused)
#   encrypted/{id[:2]}/{id}/{message_id}/{name}.encrypted  one key per upload (never reused)
# The per-upload name is always _sanitize_filename output; the older format
# keeps its historical, looser name check.
_S3_KEY_RE = re.compile(r"encrypted/([0-9a-f]{2})/([0-9a-f]{64})/[^/]+\.encrypted")
_S3_UPLOAD_KEY_RE = re.compile(
    r"encrypted/([0-9a-f]{2})/([0-9a-f]{64})/([0-9a-f]{64})/[A-Za-z0-9._-]+\.encrypted"
)

#: Prefix and suffix of keys written by the legacy shell workflow, which ran
#: ``aws s3 sync ../encrypted s3://$S3_BUCKET/encrypted`` over
#: aws-encryption-cli output named ``<file>.encrypted``.
LEGACY_S3_PREFIX = "encrypted/"
LEGACY_S3_SUFFIX = ".encrypted"
_MAX_S3_KEY_BYTES = 1024
# Control characters (C0, DEL, C1), invisible format characters (bidi overrides,
# zero-width), lone surrogates, and line/paragraph separators.
_UNSAFE_CHAR_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})


def assert_s3_key_matches_hash(s3_key: str, file_id: str, *, message_id: str | None = None) -> None:
    """Reject DynamoDB-sourced keys that are not this file's content-addressed path.

    A poisoned ``s3_key`` must not be able to make the CLI fetch an arbitrary
    object from the bucket (or a different file's ciphertext). Both key formats
    are accepted: the original ``encrypted/{h[:2]}/{h}/{name}.encrypted`` and
    the per-upload ``encrypted/{h[:2]}/{h}/{message_id}/{name}.encrypted``.

    Args:
        s3_key: Key from the record.
        file_id: The record's identifier (see :mod:`envault.fileid`); the key
            must be its path.
        message_id: If given and the key is in the per-upload format, the key's
            message id segment must equal it. Ignored for the original format,
            whose keys carry no message id.

    Raises:
        InvalidS3KeyError: If the key is not this identifier's path, or names a
            different upload than ``message_id``.
    """
    upload = _S3_UPLOAD_KEY_RE.fullmatch(s3_key)
    match = upload or _S3_KEY_RE.fullmatch(s3_key)
    if not match or match.group(1) != file_id[:2] or match.group(2) != file_id:
        raise InvalidS3KeyError(
            "Refusing to fetch S3 object: key is not the content-addressed "
            f"path for identifier {file_id[:16]}...."
        )
    if upload and message_id is not None and upload.group(3) != message_id:
        raise InvalidS3KeyError(
            "Refusing to fetch S3 object: the key names a different upload than the "
            "record's message id."
        )


def assert_legacy_s3_key(s3_key: str) -> None:
    """Validate a key written by the legacy ``aws s3 sync ../encrypted s3://$BUCKET/encrypted``.

    Migrated records point at those keys (``encrypted/<relative path>.encrypted``)
    rather than at a content-addressed path, so their keys carry no identifier
    to check against. This confines them to the legacy layout instead: the
    ``encrypted/`` prefix and ``.encrypted`` suffix, no empty, ``.`` or ``..``
    segments, no leading ``/``, no backslash, no control or invisible formatting
    characters, a non-empty file name, and S3's 1024-byte limit. What binds the
    object to the record is the plaintext checksum and encryption context, which
    decrypt verifies before any plaintext is delivered.

    Raises:
        InvalidS3KeyError: If the key is outside the legacy layout.
    """
    problem = _legacy_key_problem(s3_key)
    if problem:
        raise InvalidS3KeyError(
            f"Refusing to use S3 key {s3_key!r}: not a legacy-sync key ({problem})."
        )


def _legacy_key_problem(key: str) -> str | None:
    if not key.startswith(LEGACY_S3_PREFIX):
        return f"must start with {LEGACY_S3_PREFIX!r}"
    if not key.endswith(LEGACY_S3_SUFFIX):
        return f"must end with {LEGACY_S3_SUFFIX!r}"
    if len(key.encode("utf-8", "surrogatepass")) > _MAX_S3_KEY_BYTES:
        return f"longer than S3's {_MAX_S3_KEY_BYTES}-byte limit"
    if "\\" in key:
        return "contains a backslash"
    if any(unicodedata.category(ch) in _UNSAFE_CHAR_CATEGORIES for ch in key):
        return "contains a control or invisible formatting character"
    segments = key.split("/")
    if any(segment in ("", ".", "..") for segment in segments):
        return "has an empty, '.' or '..' path segment"
    if segments[-1][: -len(LEGACY_S3_SUFFIX)] in ("", ".", ".."):
        return f"has no file name before {LEGACY_S3_SUFFIX!r}"
    return None


def _put_object_supports_if_none_match(client: Any) -> bool:
    """True if this botocore models PutObject's If-None-Match (botocore >= 1.35.2).

    Older releases reject the parameter client-side with ParamValidationError.
    """
    shape = client.meta.service_model.operation_model("PutObject").input_shape
    return shape is not None and "IfNoneMatch" in shape.members


def _is_precondition_failed(exc: ClientError) -> bool:
    code = exc.response.get("Error", {}).get("Code")
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return code == "PreconditionFailed" or status == 412


def _sha256_b64(path: Path) -> str:
    """Base64 SHA-256 of a file, the encoding S3 uses for ChecksumSHA256."""
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return base64.b64encode(digest.digest()).decode("ascii")


class S3Store:
    """Handles upload and download of encrypted files to/from S3."""

    def __init__(self, bucket: str, region: str = "us-east-1", kms_key_id: str = "") -> None:
        self._bucket = bucket
        self._kms_key_id = kms_key_id
        self._s3 = boto3.client("s3", region_name=region, config=boto_config)

    # An oversized object is a deterministic rejection: retrying only triples
    # the S3 read cost before failing with the same answer.
    @aws_retry(never=(EnvaultError,))
    def download_to_memory(
        self, s3_key: str, version_id: str = "", *, allow_latest: bool = False
    ) -> io.BytesIO:
        """Fetch an encrypted object into memory instead of onto disk.

        Used by :command:`envault exec`, where the whole point is that nothing
        touches the filesystem. The buffered bytes are ciphertext, so holding
        them in memory carries no plaintext exposure — the size cap exists to
        stop a large or malicious object from exhausting RAM, not to protect
        secrecy.

        Args:
            s3_key: S3 object key.
            version_id: S3 version ID for point-in-time recovery. Required
                unless ``allow_latest`` is true (migrated records).
            allow_latest: If true, an empty ``version_id`` fetches the current
                object. Default is to refuse — latest is not the recorded version.

        Returns:
            A BytesIO positioned at the start of the ciphertext.

        Raises:
            EnvaultError: If the object is larger than MAX_IN_MEMORY_BYTES, or if
                ``version_id`` is empty and ``allow_latest`` is false.
        """
        self._require_version_id(s3_key, version_id, allow_latest)
        kwargs: dict[str, Any] = {"Bucket": self._bucket, "Key": s3_key}
        if version_id:
            kwargs["VersionId"] = version_id

        response = self._s3.get_object(**kwargs)
        length = int(response.get("ContentLength", 0))
        if length > MAX_IN_MEMORY_BYTES:
            raise EnvaultError(
                f"Encrypted object {s3_key} is {length} bytes, over the "
                f"{MAX_IN_MEMORY_BYTES}-byte limit for in-memory decryption. "
                "Use 'envault decrypt' to stream it to a file instead."
            )

        body = response["Body"].read(MAX_IN_MEMORY_BYTES + 1)
        if len(body) > MAX_IN_MEMORY_BYTES:
            raise EnvaultError(
                f"Encrypted object {s3_key} exceeds the {MAX_IN_MEMORY_BYTES}-byte "
                "limit for in-memory decryption."
            )
        logger.info(
            "Fetched ciphertext to memory",
            extra={"bucket": self._bucket, "key": s3_key, "bytes": len(body)},
        )
        return io.BytesIO(body)

    @aws_retry(never=(EnvaultError,))
    def upload_file(self, local_path: Path, s3_key: str, *, if_none_match: bool = False) -> str:
        """Upload a file to S3 and return the version ID atomically.

        Uses put_object (single API call) so the VersionId is returned in the
        same response, eliminating the race window of upload_file + head_object.

        With ``if_none_match`` the request carries ``If-None-Match: *``, so S3
        refuses (412) to create a version over an existing object. A record
        pins its ciphertext by VersionId, and that version must stay the
        current one. If a 412 comes back because an earlier attempt of this same
        call landed and only its reply was lost, the object at the key holds
        exactly this file's bytes (same SHA-256 checksum). That object's
        VersionId is returned instead of an error.

        Args:
            local_path: Local path of the file to upload.
            s3_key: S3 object key.
            if_none_match: Refuse to write if any object exists at ``s3_key``.

        Returns:
            The S3 VersionId of the uploaded object (empty string if bucket not versioned).

        Raises:
            S3ObjectExistsError: ``if_none_match`` is set and a different object
                already exists at ``s3_key``. Never retried.
            ConfigurationError: ``if_none_match`` is set but the installed
                botocore cannot send If-None-Match (needs 1.35.2 or later).
        """
        put_kwargs: dict[str, Any] = {
            "Bucket": self._bucket,
            "Key": s3_key,
            "ChecksumAlgorithm": "SHA256",
        }
        if self._kms_key_id:
            put_kwargs["ServerSideEncryption"] = "aws:kms"
            put_kwargs["SSEKMSKeyId"] = self._kms_key_id
        if if_none_match:
            if not _put_object_supports_if_none_match(self._s3):
                raise ConfigurationError(
                    "Conditional S3 uploads (If-None-Match) need botocore 1.35.2 or later; "
                    "upgrade boto3 and botocore."
                )
            put_kwargs["IfNoneMatch"] = "*"

        logger.info(
            "Uploading to S3",
            extra={"bucket": self._bucket, "key": s3_key, "if_none_match": if_none_match},
        )
        try:
            with local_path.open("rb") as f:
                response = self._s3.put_object(Body=f, **put_kwargs)
        except ClientError as exc:
            if not (if_none_match and _is_precondition_failed(exc)):
                raise
            existing = self._version_holding_same_bytes(local_path, s3_key)
            if existing is None:
                raise S3ObjectExistsError(self._bucket, s3_key) from exc
            logger.info(
                "Object already holds this upload's bytes (an earlier attempt landed)",
                extra={"bucket": self._bucket, "key": s3_key, "version_id": existing},
            )
            return existing
        version_id: str = response.get("VersionId", "")
        logger.info(
            "Upload complete",
            extra={"bucket": self._bucket, "key": s3_key, "version_id": version_id},
        )
        return version_id

    def _require_version_id(self, s3_key: str, version_id: str, allow_latest: bool) -> None:
        """Refuse an unversioned fetch unless the caller opted into latest."""
        if version_id:
            return
        if not allow_latest:
            raise EnvaultError(
                f"Refusing to fetch s3://{self._bucket}/{s3_key} without a VersionId. "
                "That would download the current object, which may not be the ciphertext "
                "recorded at encryption time. Pass --latest for migrated records."
            )
        logger.warning(
            "Fetching S3 object without VersionId — reading latest version. "
            "If the object was overwritten since encryption, "
            "the wrong ciphertext may be retrieved.",
            extra={"bucket": self._bucket, "key": s3_key},
        )

    @aws_retry(never=(EnvaultError,))
    def download_file(
        self,
        s3_key: str,
        local_path: Path,
        version_id: str = "",
        *,
        allow_latest: bool = False,
    ) -> None:
        """Download a file from S3.

        Args:
            s3_key: S3 object key.
            local_path: Destination path on disk.
            version_id: S3 version ID for point-in-time recovery. Required
                unless ``allow_latest`` is true.
            allow_latest: If true, an empty ``version_id`` fetches the current
                object. Default is to refuse.
        """
        self._require_version_id(s3_key, version_id, allow_latest)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        extra_args: dict[str, str] = {}
        if version_id:
            extra_args["VersionId"] = version_id

        logger.info(
            "Downloading from S3",
            extra={"bucket": self._bucket, "key": s3_key, "version_id": version_id},
        )
        self._s3.download_file(
            self._bucket,
            s3_key,
            str(local_path),
            ExtraArgs=extra_args if extra_args else None,
        )
        os.chmod(str(local_path), 0o600)
        logger.info("Download complete", extra={"local_path": str(local_path)})

    @staticmethod
    def _sanitize_filename(name: str) -> str:
        """Sanitize a filename for use in S3 keys.

        Extracts the basename (stripping directory components), replaces any
        character that is not ASCII alphanumeric, dot, hyphen, or underscore
        with an underscore, and collapses '..' sequences to prevent path
        traversal.
        """
        name = Path(name).name
        name = re.sub(r"[^a-zA-Z0-9._\-]", "_", name)
        while ".." in name:
            name = name.replace("..", ".")
        return name or "_"

    def _version_holding_same_bytes(self, local_path: Path, s3_key: str) -> str | None:
        """VersionId of the object at ``s3_key`` if its SHA-256 equals the local file's.

        The upload sent ``ChecksumAlgorithm=SHA256``, so S3 stored the full-object
        checksum. Identical bytes at a key that embeds the message id can only be
        this ciphertext. Returns None for any other object.
        """
        head = self._s3.head_object(Bucket=self._bucket, Key=s3_key, ChecksumMode="ENABLED")
        stored = head.get("ChecksumSHA256")
        if not stored or stored != _sha256_b64(local_path):
            return None
        return str(head.get("VersionId", ""))

    def s3_key_for_file(self, file_id: str, file_name: str, message_id: str | None = None) -> str:
        """Generate a content-addressed S3 key for an encrypted file.

        ``file_id`` is the record's identifier (see :mod:`envault.fileid`): a
        keyed identifier for new records, which reveals nothing about the
        content, or the plaintext's SHA-256 for legacy ones.

        Without ``message_id`` (original format, kept for existing callers):
        ``encrypted/{file_id[:2]}/{file_id}/{filename}.encrypted``. Every upload
        of the same content shares the key, so a later upload makes the
        version a record pins noncurrent.

        With ``message_id`` (the Encryption SDK message id of this ciphertext,
        64 lowercase hex characters):
        ``encrypted/{file_id[:2]}/{file_id}/{message_id}/{filename}.encrypted``.
        Message ids are random per encryption, so the key is never reused.
        Upload it with ``upload_file(..., if_none_match=True)``.

        The two-character prefix shards objects across 256 virtual directories,
        preventing S3 listing bottlenecks at scale.

        Raises:
            InvalidS3KeyError: ``message_id`` is given and it, or ``file_id``,
                is not 64 lowercase hex characters.
        """
        safe_name = self._sanitize_filename(file_name)
        if message_id is None:
            return f"encrypted/{file_id[:2]}/{file_id}/{safe_name}.encrypted"
        if not _HEX64_RE.fullmatch(message_id):
            raise InvalidS3KeyError(
                f"Invalid message id for an S3 key: expected {MESSAGE_ID_HEX_LENGTH} "
                "lowercase hex characters (the Encryption SDK message id)."
            )
        if not _HEX64_RE.fullmatch(file_id):
            raise InvalidS3KeyError(
                "Invalid file identifier for an S3 key: expected 64 lowercase hex characters."
            )
        return f"encrypted/{file_id[:2]}/{file_id}/{message_id}/{safe_name}.encrypted"
