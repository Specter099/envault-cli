"""S3 operations for envault — upload and download encrypted files."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import boto3
from tenacity import retry, stop_after_attempt, wait_exponential

from envault.config import boto_config

logger = logging.getLogger(__name__)


class S3Store:
    """Handles upload and download of encrypted files to/from S3."""

    def __init__(self, bucket: str, region: str = "us-east-1", kms_key_id: str = "") -> None:
        self._bucket = bucket
        self._region = region
        self._kms_key_id = kms_key_id
        self._s3 = boto3.client("s3", region_name=region, config=boto_config)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    def upload_file(self, local_path: Path, s3_key: str) -> str:
        """Upload a file to S3 and return the version ID atomically.

        Uses put_object (single API call) so the VersionId is returned in the
        same response, eliminating the race window of upload_file + head_object.

        Uses put_object to atomically retrieve the version ID from the response,
        avoiding a TOCTOU race between upload_file + head_object.

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

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
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
