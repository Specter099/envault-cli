"""S3 operations for envault — upload and download encrypted files."""

from __future__ import annotations

import io
import logging
import os
import re
from pathlib import Path
from typing import Any

import boto3
from tenacity import retry, retry_if_not_exception_type, stop_after_attempt, wait_exponential

from envault.config import boto_config
from envault.exceptions import EnvaultError

logger = logging.getLogger(__name__)

# Ceiling for in-memory ciphertext. Secrets are small; anything approaching this
# belongs in the streaming `decrypt` path, not `exec`.
MAX_IN_MEMORY_BYTES = 16 * 1024 * 1024


class S3Store:
    """Handles upload and download of encrypted files to/from S3."""

    def __init__(self, bucket: str, region: str = "us-east-1", kms_key_id: str = "") -> None:
        self._bucket = bucket
        self._kms_key_id = kms_key_id
        self._s3 = boto3.client("s3", region_name=region, config=boto_config)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
        # An oversized object is a deterministic rejection: retrying only triples
        # the S3 read cost before failing with the same answer.
        retry=retry_if_not_exception_type(EnvaultError),
    )
    def download_to_memory(self, s3_key: str, version_id: str = "") -> io.BytesIO:
        """Fetch an encrypted object into memory instead of onto disk.

        Used by :command:`envault exec`, where the whole point is that nothing
        touches the filesystem. The buffered bytes are ciphertext, so holding
        them in memory carries no plaintext exposure — the size cap exists to
        stop a large or malicious object from exhausting RAM, not to protect
        secrecy.

        Args:
            s3_key: S3 object key.
            version_id: Optional S3 version ID for point-in-time recovery.

        Returns:
            A BytesIO positioned at the start of the ciphertext.

        Raises:
            EnvaultError: If the object is larger than MAX_IN_MEMORY_BYTES.
        """
        kwargs: dict[str, Any] = {"Bucket": self._bucket, "Key": s3_key}
        if version_id:
            kwargs["VersionId"] = version_id
        else:
            logger.warning(
                "Fetching S3 object without VersionId — reading latest version. "
                "If the object was overwritten since encryption, "
                "the wrong ciphertext may be retrieved.",
                extra={"bucket": self._bucket, "key": s3_key},
            )

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

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    def upload_file(self, local_path: Path, s3_key: str) -> str:
        """Upload a file to S3 and return the version ID atomically.

        Uses put_object (single API call) so the VersionId is returned in the
        same response, eliminating the race window of upload_file + head_object.

        Args:
            local_path: Local path of the file to upload.
            s3_key: S3 object key.

        Returns:
            The S3 VersionId of the uploaded object (empty string if bucket not versioned).
        """
        logger.info("Uploading to S3", extra={"bucket": self._bucket, "key": s3_key})
        with local_path.open("rb") as f:
            put_kwargs: dict[str, Any] = {
                "Bucket": self._bucket,
                "Key": s3_key,
                "Body": f,
                "ChecksumAlgorithm": "SHA256",
            }
            if self._kms_key_id:
                put_kwargs["ServerSideEncryption"] = "aws:kms"
                put_kwargs["SSEKMSKeyId"] = self._kms_key_id
            response = self._s3.put_object(**put_kwargs)
        version_id: str = response.get("VersionId", "")
        logger.info(
            "Upload complete",
            extra={"bucket": self._bucket, "key": s3_key, "version_id": version_id},
        )
        return version_id

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    def download_file(self, s3_key: str, local_path: Path, version_id: str = "") -> None:
        """Download a file from S3.

        Args:
            s3_key: S3 object key.
            local_path: Destination path on disk.
            version_id: Optional S3 version ID for point-in-time recovery.
        """
        local_path.parent.mkdir(parents=True, exist_ok=True)
        extra_args: dict[str, str] = {}
        if not version_id:
            logger.warning(
                "Downloading S3 object without VersionId — fetching latest version. "
                "If the object was overwritten since encryption, "
                "the wrong ciphertext may be retrieved.",
                extra={"bucket": self._bucket, "key": s3_key},
            )
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

    def s3_key_for_file(self, sha256_hash: str, file_name: str) -> str:
        """Generate a content-addressed S3 key for an encrypted file.

        Format: encrypted/{sha256[:2]}/{sha256}/{filename}.encrypted
        The two-character prefix shards objects across 256 virtual directories,
        preventing S3 listing bottlenecks at scale and ensuring uniqueness.
        """
        safe_name = self._sanitize_filename(file_name)
        return f"encrypted/{sha256_hash[:2]}/{sha256_hash}/{safe_name}.encrypted"
