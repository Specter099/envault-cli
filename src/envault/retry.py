"""The one retry policy for every AWS-touching call in envault."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from tenacity import retry, retry_if_not_exception_type, stop_after_attempt, wait_exponential

F = TypeVar("F", bound=Callable[..., Any])


def aws_retry(*, never: tuple[type[BaseException], ...] = ()) -> Callable[[F], F]:
    """Retry up to 3 attempts with exponential backoff (1s..10s).

    boto3's own retries are disabled in :data:`envault.config.boto_config`, so
    this is the only retry layer — no 5x * 3x amplification.

    ``reraise=True`` is essential: without it, exhausting the attempts raises
    ``tenacity.RetryError`` instead of the underlying error, which slips past
    every ``except ClientError`` / ``except BotoCoreError`` handler in the CLI
    and surfaces as a traceback — skipping the error message and the cleanup
    those handlers exist to perform.

    Args:
        never: Exception types that are deterministic and must fail on the
            first attempt (bad config, tampered ciphertext, local I/O errors).
    """
    return retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
        retry=retry_if_not_exception_type(never),
    )
