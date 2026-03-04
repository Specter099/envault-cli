"""S3 operations for envault — upload and download encrypted files."""

from __future__ import annotations

import logging
from pathlib import Path

import boto3
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)


class S3Store:
    """Handles upload and download of encrypted files to/from S3."""

    def __init__(self, bucket: str, region: str = "us-east-1") -> None:
        self._bucket = bucket
        self._region = region
        self._s3 = boto3.client("s3", region_name=region)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    def upload_file(self, local_path: Path, s3_key: str) -> str:
        """Upload a file to S3 and return the version ID.

        Uses put_object to atomically retrieve the version ID from the response,
        avoiding a TOCTOU race between upload_file + head_object.

        Args:
            local_path: Local path of the file to upload.
            s3_key: S3 object key (e.g. 'encrypted/secrets.xlsx.encrypted').

        Returns:
            The S3 version ID of the uploaded object (requires bucket versioning).
        """
        logger.info("Uploading to S3", extra={"bucket": self._bucket, "key": s3_key})
        with local_path.open("rb") as f:
            response = self._s3.put_object(
                Bucket=self._bucket,
                Key=s3_key,
                Body=f,
                ServerSideEncryption="aws:kms",
            )
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

    def s3_key_for_file(self, file_name: str) -> str:
        """Generate a canonical S3 key for an encrypted file."""
        return f"encrypted/{file_name}.encrypted"
