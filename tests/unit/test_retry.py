"""Tests for envault.retry: what the single retry policy retries, and what it must not.

Two failure modes matter here. Retrying an interrupt (Ctrl-C, or the SystemExit a
signal handler raises) keeps decrypting after the operator asked envault to stop.
Retrying a deterministic AWS error (missing table, denied permission) only delays
the same answer by the full backoff.
"""

from __future__ import annotations

import pytest
from botocore.exceptions import (
    ClientError,
    ConnectionClosedError,
    ConnectTimeoutError,
    EndpointConnectionError,
    NoCredentialsError,
    ParamValidationError,
    ReadTimeoutError,
)

from envault.retry import aws_retry, is_transient_aws_error


def _client_error(code: str, status: int = 400, op: str = "GetItem") -> ClientError:
    return ClientError(
        {
            "Error": {"Code": code, "Message": f"simulated {code}"},
            "ResponseMetadata": {"HTTPStatusCode": status},
        },
        op,
    )


def _failing(exc: BaseException, *, never: tuple[type[BaseException], ...] = ()):
    """A decorated callable that always raises ``exc`` and counts its calls."""
    calls = {"n": 0}

    @aws_retry(never=never)
    def op() -> None:
        calls["n"] += 1
        raise exc

    return op, calls


# ---------------------------------------------------------------------------
# M1: interrupts are never retried
# ---------------------------------------------------------------------------


def test_aws_retry_does_not_retry_keyboard_interrupt(no_retry_sleep: list[float]) -> None:
    """Ctrl-C during attempt 1 must stop the operation, not start attempt 2."""
    calls = {"n": 0}

    @aws_retry()
    def long_running_decrypt() -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            raise KeyboardInterrupt
        return "completed anyway"

    with pytest.raises(KeyboardInterrupt):
        long_running_decrypt()
    assert calls["n"] == 1
    assert no_retry_sleep == []


def test_aws_retry_does_not_retry_system_exit(no_retry_sleep: list[float]) -> None:
    """SIGTERM/SIGHUP become SystemExit so cleanup runs; a retry would swallow it."""
    calls = {"n": 0}

    @aws_retry(never=(OSError,))
    def op() -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            raise SystemExit(128 + 15)
        return "completed anyway"

    with pytest.raises(SystemExit) as exc_info:
        op()
    assert exc_info.value.code == 143
    assert calls["n"] == 1
    assert no_retry_sleep == []


def test_aws_retry_interrupt_after_transient_failure_is_not_retried(
    no_retry_sleep: list[float],
) -> None:
    """An interrupt during a retry attempt ends the loop at once."""
    calls = {"n": 0}

    @aws_retry()
    def op() -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise _client_error("ThrottlingException")
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        op()
    assert calls["n"] == 2
    assert no_retry_sleep == [1]


def test_interrupt_raised_while_handling_transient_error_is_not_transient() -> None:
    """An interrupt that has a throttling error as context is still an interrupt."""
    try:
        try:
            raise _client_error("ThrottlingException")
        except ClientError:
            raise KeyboardInterrupt from None
    except KeyboardInterrupt as interrupt:
        assert not is_transient_aws_error(interrupt)

    try:
        try:
            raise _client_error("ThrottlingException")
        except ClientError:
            raise KeyboardInterrupt  # noqa: B904 - implicit context is the point
    except KeyboardInterrupt as interrupt:
        assert not is_transient_aws_error(interrupt)


# ---------------------------------------------------------------------------
# L1(a): only transient AWS failures are retried
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "status"),
    [
        ("ResourceNotFoundException", 400),
        ("AccessDeniedException", 400),
        ("AccessDenied", 403),
        ("ValidationException", 400),
        ("ConditionalCheckFailedException", 400),
        ("NoSuchKey", 404),
        ("404", 404),
        ("PreconditionFailed", 412),
        ("NotFoundException", 400),
        ("DisabledException", 400),
        ("KMSInvalidStateException", 400),
        ("InvalidCiphertextException", 400),
        ("ExpiredTokenException", 400),
        ("UnrecognizedClientException", 400),
    ],
)
def test_aws_retry_does_not_retry_deterministic_client_errors(
    code: str, status: int, no_retry_sleep: list[float]
) -> None:
    err = _client_error(code, status)
    op, calls = _failing(err)
    with pytest.raises(ClientError) as exc_info:
        op()
    assert exc_info.value is err
    assert calls["n"] == 1, f"{code} is deterministic and must fail on the first attempt"
    assert no_retry_sleep == []


@pytest.mark.parametrize(
    ("code", "status"),
    [
        ("ThrottlingException", 400),
        ("Throttling", 400),
        ("ProvisionedThroughputExceededException", 400),
        ("RequestLimitExceeded", 400),
        ("TooManyRequestsException", 429),
        ("SlowDown", 503),
        ("InternalServerError", 500),
        ("InternalError", 500),
        ("InternalFailure", 500),
        ("ServiceUnavailable", 503),
        ("RequestTimeout", 400),
        ("KMSInternalException", 500),
        ("DependencyTimeoutException", 503),
        ("KeyUnavailableException", 500),
        ("ConditionalRequestConflict", 409),
        ("500", 500),
        ("502", 502),
        ("503", 503),
        ("504", 504),
        ("SomethingNewButServerSide", 500),
    ],
)
def test_aws_retry_retries_transient_client_errors(
    code: str, status: int, no_retry_sleep: list[float]
) -> None:
    err = _client_error(code, status)
    op, calls = _failing(err)
    with pytest.raises(ClientError) as exc_info:
        op()
    # reraise=True: the caller sees the real error, never tenacity.RetryError.
    assert exc_info.value is err
    assert calls["n"] == 3
    assert no_retry_sleep == [1, 2]


@pytest.mark.parametrize(
    "exc",
    [
        EndpointConnectionError(endpoint_url="https://kms.us-east-1.amazonaws.com"),
        ConnectionClosedError(endpoint_url="https://dynamodb.us-east-1.amazonaws.com"),
        ReadTimeoutError(endpoint_url="https://s3.amazonaws.com"),
        ConnectTimeoutError(endpoint_url="https://sts.amazonaws.com"),
    ],
    ids=lambda e: type(e).__name__,
)
def test_aws_retry_retries_network_failures(exc: Exception, no_retry_sleep: list[float]) -> None:
    op, calls = _failing(exc)
    with pytest.raises(type(exc)):
        op()
    assert calls["n"] == 3


@pytest.mark.parametrize(
    "exc",
    [
        NoCredentialsError(),
        ParamValidationError(report="Unknown parameter in input"),
        ValueError("bad input"),
        RuntimeError("simulated network error after write"),
        Exception("anything else"),
    ],
    ids=lambda e: type(e).__name__,
)
def test_aws_retry_does_not_retry_non_aws_or_deterministic_errors(
    exc: Exception, no_retry_sleep: list[float]
) -> None:
    op, calls = _failing(exc)
    with pytest.raises(type(exc)):
        op()
    assert calls["n"] == 1
    assert no_retry_sleep == []


def test_aws_retry_never_takes_precedence_over_transience(no_retry_sleep: list[float]) -> None:
    op, calls = _failing(_client_error("ThrottlingException"), never=(ClientError,))
    with pytest.raises(ClientError):
        op()
    assert calls["n"] == 1


def test_aws_retry_recovers_after_one_throttle(no_retry_sleep: list[float]) -> None:
    calls = {"n": 0}

    @aws_retry()
    def op() -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            raise _client_error("ThrottlingException")
        return "ok"

    assert op() == "ok"
    assert calls["n"] == 2
    assert no_retry_sleep == [1]


def test_aws_retry_when_predicate_can_veto_a_retry(no_retry_sleep: list[float]) -> None:
    """``when`` lets a caller forbid retries its own state makes unsafe."""
    state = {"unsafe": False, "n": 0}

    @aws_retry(when=lambda exc: not state["unsafe"])
    def op() -> None:
        state["n"] += 1
        state["unsafe"] = True  # e.g. bytes already handed to a caller's sink
        raise _client_error("ThrottlingException")

    with pytest.raises(ClientError):
        op()
    assert state["n"] == 1


def test_aws_retry_preserves_function_metadata() -> None:
    @aws_retry()
    def documented() -> int:
        """Docstring survives."""
        return 1

    assert documented.__name__ == "documented"
    assert documented.__doc__ == "Docstring survives."
    assert documented() == 1


# ---------------------------------------------------------------------------
# Wrapped errors: the Encryption SDK re-raises KMS failures as its own types
# ---------------------------------------------------------------------------


class _SdkError(Exception):
    """Stands in for aws_encryption_sdk's GenerateKeyError and friends."""


def test_transient_cause_is_found_through_explicit_chaining() -> None:
    try:
        raise _SdkError("unable to generate data key") from _client_error("ThrottlingException")
    except _SdkError as exc:
        assert is_transient_aws_error(exc)

    try:
        raise _SdkError("unable to generate data key") from _client_error("AccessDeniedException")
    except _SdkError as exc:
        assert not is_transient_aws_error(exc)


def test_transient_context_is_found_through_implicit_chaining() -> None:
    try:
        try:
            raise ReadTimeoutError(endpoint_url="https://kms.us-east-1.amazonaws.com")
        except ReadTimeoutError:
            raise _SdkError("wrapped without 'from'")  # noqa: B904 - implicit context is the point
    except _SdkError as exc:
        assert is_transient_aws_error(exc)


def test_suppressed_context_is_not_consulted() -> None:
    """``raise X from None`` declares the earlier error irrelevant."""
    try:
        try:
            raise _client_error("ThrottlingException")
        except ClientError:
            raise _SdkError("deterministic, by the author's say-so") from None
    except _SdkError as exc:
        assert not is_transient_aws_error(exc)


def test_wrapped_transient_error_is_retried_through_the_decorator(
    no_retry_sleep: list[float],
) -> None:
    calls = {"n": 0}

    @aws_retry()
    def op() -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            raise _SdkError("unable to decrypt") from _client_error("ThrottlingException")
        return "ok"

    assert op() == "ok"
    assert calls["n"] == 2


def test_chain_walk_survives_cycles() -> None:
    first = _SdkError("first")
    second = _SdkError("second")
    first.__cause__ = second
    second.__cause__ = first
    assert not is_transient_aws_error(first)
