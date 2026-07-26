"""Caller identity resolution for audit attribution."""

from __future__ import annotations

import logging

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from envault.config import boto_config

logger = logging.getLogger(__name__)

# Recorded when STS is unreachable. Distinguishable from a real ARN so an
# auditor can tell "we could not attribute this" from "nobody looked".
UNKNOWN_PRINCIPAL = "unknown"

_CACHE: dict[str, str] = {}


def caller_arn(region: str = "us-east-1") -> str:
    """Return the ARN of the principal running this command.

    Resolved once per process and cached — every audit event in an invocation
    shares one STS call. A failure here degrades attribution to
    :data:`UNKNOWN_PRINCIPAL` rather than blocking the operation: refusing to
    decrypt because the audit log would be less precise trades an outage for a
    bookkeeping problem, which is the wrong way round.

    Args:
        region: AWS region for the STS endpoint.

    Returns:
        The caller's ARN, or :data:`UNKNOWN_PRINCIPAL` if it cannot be resolved.
    """
    if region in _CACHE:
        return _CACHE[region]
    try:
        sts = boto3.client("sts", region_name=region, config=boto_config)
        arn = str(sts.get_caller_identity()["Arn"])
    except (ClientError, BotoCoreError, KeyError) as exc:
        logger.warning("Could not resolve caller identity for audit trail: %s", exc)
        arn = UNKNOWN_PRINCIPAL
    _CACHE[region] = arn
    return arn


def reset_cache() -> None:
    """Clear the cached identity. For tests."""
    _CACHE.clear()
