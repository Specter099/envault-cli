"""The one retry policy for every AWS-touching call in envault.

Only *transient* AWS failures are retried: throttling, server-side errors, and
connections that dropped or timed out. Anything else fails on the first attempt.
A missing table, a denied permission or a tampered ciphertext gives the same
answer every time, so retrying it only delays the error by the full backoff.

Interrupts are never retried. ``KeyboardInterrupt`` and ``SystemExit`` (which the
CLI's signal handling raises for SIGTERM/SIGHUP) are how an operator stops
envault. A retry that swallowed one would keep decrypting after the operator
asked it to stop.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import ParamSpec, TypeVar

from botocore.exceptions import (
    ClientError,
    HTTPClientError,
    IncompleteReadError,
)
from botocore.exceptions import (
    ConnectionError as BotocoreConnectionError,
)
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

P = ParamSpec("P")
R = TypeVar("R")

#: Attempts per logical call, including the first. boto3's own retries are off
#: (see :data:`envault.config.boto_config`), so this is the only retry layer.
MAX_ATTEMPTS = 3

#: Error codes AWS services use for throttling and rate limits. This is the
#: union botocore's "standard" retry mode treats as throttling.
THROTTLING_ERROR_CODES: frozenset[str] = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "ThrottledException",
        "RequestThrottledException",
        "TooManyRequestsException",
        "ProvisionedThroughputExceededException",
        "TransactionInProgressException",
        "RequestLimitExceeded",
        "BandwidthLimitExceeded",
        "LimitExceededException",
        "RequestThrottled",
        "SlowDown",
        "PriorRequestNotComplete",
        "EC2ThrottledException",
    }
)

#: Error codes for server-side or in-flight failures that a later attempt can
#: succeed past. Includes the KMS codes its API reference describes as retryable,
#: and S3's 409 for a conditional write that raced another one.
TRANSIENT_ERROR_CODES: frozenset[str] = frozenset(
    {
        "RequestTimeout",
        "RequestTimeoutException",
        "InternalError",
        "InternalFailure",
        "InternalServerError",
        "InternalServerErrorException",
        "ServiceUnavailable",
        "ServiceUnavailableException",
        "KMSInternalException",
        "DependencyTimeoutException",
        "KeyUnavailableException",
        "ConditionalRequestConflict",
    }
)

#: HTTP statuses treated as transient whatever the error code says (codes are
#: absent for bodiless responses such as a failed S3 HEAD).
TRANSIENT_HTTP_STATUS_CODES: frozenset[int] = frozenset({429, 500, 502, 503, 504})

#: botocore exceptions for a connection that could not be made, dropped, or
#: timed out (EndpointConnectionError, ConnectTimeoutError, ConnectionClosedError,
#: ReadTimeoutError, ...). Same classes botocore's standard mode retries.
TRANSIENT_BOTOCORE_ERRORS: tuple[type[Exception], ...] = (
    BotocoreConnectionError,
    HTTPClientError,
    IncompleteReadError,
)

# How far down a __cause__/__context__ chain to look. Real chains are 2-3 deep.
_MAX_CHAIN_DEPTH = 16


def is_transient_aws_error(exc: BaseException) -> bool:
    """Return True if ``exc``, or an error it wraps, is a transient AWS failure.

    The check is the one :func:`aws_retry` applies, exposed so other code can
    decide in the same way whether a failure is worth retrying.

    Wrapped errors count. The AWS Encryption SDK re-raises a throttled KMS call
    as its own ``GenerateKeyError``, and envault re-raises it as
    :class:`~envault.exceptions.KMSError`. Both keep the original
    ``ClientError`` as ``__cause__`` (or ``__context__``), and the chain is
    followed to find it. ``raise ... from None`` declares the earlier error
    irrelevant and stops the walk there.

    Anything that is not an :class:`Exception` (``KeyboardInterrupt``,
    ``SystemExit``, ``GeneratorExit``) is never transient. That holds wherever
    it appears in the chain.

    Transient means:

    * a ``ClientError`` whose code is in :data:`THROTTLING_ERROR_CODES` or
      :data:`TRANSIENT_ERROR_CODES`, or whose HTTP status is in
      :data:`TRANSIENT_HTTP_STATUS_CODES`;
    * a botocore connection or timeout error (:data:`TRANSIENT_BOTOCORE_ERRORS`).
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen and len(seen) < _MAX_CHAIN_DEPTH:
        if not isinstance(current, Exception):
            return False
        if _is_transient_here(current):
            return True
        seen.add(id(current))
        current = _wrapped_error(current)
    return False


def _wrapped_error(exc: BaseException) -> BaseException | None:
    """The error ``exc`` was raised from, as the traceback printer would show it."""
    if exc.__cause__ is not None:
        return exc.__cause__
    if exc.__suppress_context__:
        return None
    return exc.__context__


def _is_transient_here(exc: Exception) -> bool:
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {})
        code = str(error.get("Code", ""))
        if code in THROTTLING_ERROR_CODES or code in TRANSIENT_ERROR_CODES:
            return True
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return status in TRANSIENT_HTTP_STATUS_CODES
    return isinstance(exc, TRANSIENT_BOTOCORE_ERRORS)


def aws_retry(
    *,
    never: tuple[type[BaseException], ...] = (),
    when: Callable[[BaseException], bool] | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Retry transient AWS failures: up to 3 attempts, exponential backoff (1s, 2s).

    An attempt is retried only if all of these hold:

    * it raised an :class:`Exception` (interrupts and ``SystemExit`` always propagate);
    * the exception is not an instance of a type in ``never``;
    * :func:`is_transient_aws_error` says it is transient;
    * ``when`` (if given) returns True for it.

    boto3's own retries are disabled in :data:`envault.config.boto_config`, so
    this is the only retry layer. There is no compounding of botocore and
    tenacity retries.

    ``reraise=True`` is essential. Without it, exhausting the attempts raises
    ``tenacity.RetryError`` instead of the underlying error. That would slip past
    every ``except ClientError`` / ``except BotoCoreError`` handler in the CLI and
    surface as a traceback, skipping the error message and the cleanup those
    handlers exist to perform.

    Args:
        never: Exception types that must fail on the first attempt even when
            they wrap a transient error (bad config, tampered ciphertext, local
            I/O errors).
        when: Extra veto for state the exception cannot show, e.g. "plaintext
            has already been written to the caller's sink".
    """

    def should_retry(exc: BaseException) -> bool:
        if not isinstance(exc, Exception) or isinstance(exc, never):
            return False
        if not is_transient_aws_error(exc):
            return False
        return when is None or when(exc)

    return retry(
        stop=stop_after_attempt(MAX_ATTEMPTS),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
        retry=retry_if_exception(should_retry),
    )
