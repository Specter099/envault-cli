"""Configuration for envault — values arrive via CLI options or ENVAULT_* env vars."""

from __future__ import annotations

from dataclasses import dataclass

from botocore.config import Config as BotoConfig

# Shared boto3 client config:
# - Explicit timeouts prevent indefinite hangs under partial network failure.
# - Exactly one HTTP attempt per client call. tenacity handles retries at the
#   application layer (envault.retry.aws_retry), so botocore must not add its own
#   (boto3 5x * tenacity 3x = 15x amplification). Spelled as total_max_attempts:
#   botocore reads a bare "max_attempts" as the number of *retries*, so
#   {"max_attempts": 1} meant two requests per call. An explicit mode keeps
#   AWS_RETRY_MODE=adaptive (client-side rate limiting) from changing behaviour.
boto_config = BotoConfig(
    connect_timeout=5,
    read_timeout=30,
    retries={"total_max_attempts": 1, "mode": "standard"},
)


def partition_for_region(region: str) -> str:
    """The AWS partition of ``region``, so GovCloud and China are not excluded.

    Decryption trusts KMS keys only in this partition (and in the allowed
    accounts), for data keys and identifier keys alike.
    """
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    if region.startswith("cn-"):
        return "aws-cn"
    return "aws"


@dataclass
class Config:
    """Settings needed to encrypt a file, resolved from CLI options / ENVAULT_* vars."""

    key_id: str
    bucket: str
    region: str
    audit_ttl_days: int = 365

    def build_encryption_context(
        self, file_id: str, file_name: str, *, legacy: bool = False
    ) -> dict[str, str]:
        """Build per-file encryption context bound to the ciphertext as AAD.

        Returns a dict that is unique per file, preventing cross-file
        ciphertext substitution attacks. The context is not secret: CloudTrail
        records it with every GenerateDataKey and Decrypt. It names the file by
        its identifier (see :mod:`envault.fileid`): under ``file_id`` for keyed
        records, which reveals nothing about the content. Only ``legacy=True``,
        for records identified by the plaintext's SHA-256 (rows written before
        keyed identifiers, which rotate-key keeps in their own scheme), puts it
        under ``sha256`` as those records always had it.
        """
        return {
            "purpose": "envault-backup",
            ("sha256" if legacy else "file_id"): file_id,
            "file_name": file_name,
            "kms_key_alias": self.key_id,
        }
