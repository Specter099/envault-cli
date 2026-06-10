# Critical Availability Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix the two critical SRE availability findings — boto3 timeout/retry hygiene (C2+M4) and partial failure inconsistency (C1).

**Architecture:** Introduce a shared `BotoConfig` with explicit timeouts and single-attempt retries (letting tenacity be the sole retry layer). Then add error handling to the encrypt/decrypt/rotate-key CLI commands so that DynamoDB state write failures after successful S3 operations are logged with enough context for manual recovery.

**Tech Stack:** Python 3.10+, boto3, botocore, tenacity, moto (tests)

---

## Task 1: Add shared boto3 config with explicit timeouts

This addresses **C2** (no timeouts) and **M4** (double retry). We create a shared `BotoConfig` in `config.py` and use it everywhere boto3 clients are created.

**Files:**
- Modify: `src/envault/config.py:1-88`
- Modify: `src/envault/s3.py:9,18-22`
- Modify: `src/envault/state.py:12,90-94`
- Test: `tests/unit/test_boto_config.py` (new)
- Test: `tests/unit/test_s3.py` (verify existing tests still pass)
- Test: `tests/unit/test_state.py` (verify existing tests still pass)

**Step 1: Write the failing test for boto config**

Create `tests/unit/test_boto_config.py`:

```python
"""Tests for shared boto3 configuration."""

from __future__ import annotations

from envault.config import boto_config


def test_boto_config_has_explicit_timeouts():
    """Shared config must set connect and read timeouts."""
    assert boto_config.connect_timeout == 5
    assert boto_config.read_timeout == 30


def test_boto_config_disables_builtin_retries():
    """Shared config must disable boto3 retries (tenacity handles retries)."""
    assert boto_config.retries["max_attempts"] == 1
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_boto_config.py -v`
Expected: FAIL with `ImportError: cannot import name 'boto_config'`

**Step 3: Implement the shared boto config in config.py**

Add to the top of `src/envault/config.py`, after the existing imports:

```python
from botocore.config import Config as BotoConfig

# Shared boto3 client config:
# - Explicit timeouts prevent indefinite hangs under partial network failure
# - Retries disabled at boto3 level — tenacity handles retries at the application layer
#   to avoid compounding (boto3 5x * tenacity 3x = 15x amplification)
boto_config = BotoConfig(
    connect_timeout=5,
    read_timeout=30,
    retries={"max_attempts": 1},
)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_boto_config.py -v`
Expected: PASS

**Step 5: Write failing test — S3Store uses shared config**

Add to `tests/unit/test_s3.py`:

```python
def test_s3store_uses_shared_boto_config():
    """S3Store must create its client with the shared boto_config."""
    from unittest.mock import patch
    from envault.config import boto_config

    with patch("envault.s3.boto3") as mock_boto3:
        S3Store(bucket="b", region="us-east-1")
        mock_boto3.client.assert_called_once_with("s3", region_name="us-east-1", config=boto_config)
```

**Step 6: Run test to verify it fails**

Run: `pytest tests/unit/test_s3.py::test_s3store_uses_shared_boto_config -v`
Expected: FAIL — `boto3.client` called without `config=` arg

**Step 7: Update S3Store to use shared config**

In `src/envault/s3.py`, add the import and pass config:

```python
# Add to imports (after boto3 import):
from envault.config import boto_config

# Change line 22 in __init__:
self._s3 = boto3.client("s3", region_name=region, config=boto_config)
```

**Step 8: Run test to verify it passes**

Run: `pytest tests/unit/test_s3.py::test_s3store_uses_shared_boto_config -v`
Expected: PASS

**Step 9: Write failing test — StateStore uses shared config**

Add to `tests/unit/test_state.py`:

```python
def test_statestore_uses_shared_boto_config():
    """StateStore must create its DynamoDB resource with the shared boto_config."""
    from unittest.mock import patch
    from envault.config import boto_config

    with patch("envault.state.boto3") as mock_boto3:
        StateStore(table_name="test", region="us-east-1")
        mock_boto3.resource.assert_called_once_with(
            "dynamodb", region_name="us-east-1", config=boto_config
        )
```

**Step 10: Run test to verify it fails**

Run: `pytest tests/unit/test_state.py::test_statestore_uses_shared_boto_config -v`
Expected: FAIL

**Step 11: Update StateStore to use shared config**

In `src/envault/state.py`, add the import and pass config:

```python
# Add to imports (after boto3 import):
from envault.config import boto_config

# Change line 93 in __init__:
self._dynamodb = boto3.resource("dynamodb", region_name=region, config=boto_config)
```

**Step 12: Run full test suite**

Run: `pytest tests/unit/ -v`
Expected: ALL PASS

**Step 13: Run lint and type checks**

Run: `ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/envault/`
Expected: PASS

**Step 14: Commit**

```bash
git add src/envault/config.py src/envault/s3.py src/envault/state.py tests/unit/test_boto_config.py tests/unit/test_s3.py tests/unit/test_state.py
git commit -m "fix: add explicit boto3 timeouts and disable double-retry (C2+M4)

Add shared boto_config with 5s connect / 30s read timeouts and
max_attempts=1 to prevent process hangs under partial network failure.
Disabling boto3's built-in retries eliminates the 15x retry amplification
when nested inside tenacity's 3x retries.

Addresses: SRE review findings C2, M4"
```

---

## Task 2: Fix S3Store.upload_file dead code branch (L3)

While we're touching `s3.py`, fix the dead code branch that both reviewers flagged. The `if self._kms_key_id` / `else` branches are currently identical — the `if` branch should pass `SSEKMSKeyId`.

**Files:**
- Modify: `src/envault/s3.py:42-59`
- Test: `tests/unit/test_s3.py` (existing tests `test_upload_passes_sse_kms_key_id` and `test_upload_without_kms_key_id_omits_sse` already cover this)

**Step 1: Verify existing tests capture the bug**

Run: `pytest tests/unit/test_s3.py::test_upload_without_kms_key_id_omits_sse -v`
Expected: FAIL — current code passes `ServerSideEncryption="aws:kms"` even without kms_key_id

**Step 2: Fix the upload_file method**

Replace lines 42-59 in `src/envault/s3.py` with:

```python
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
```

Add `from typing import Any` to the imports if not already there.

**Step 3: Run tests to verify fix**

Run: `pytest tests/unit/test_s3.py -v`
Expected: ALL PASS (including both SSE tests)

**Step 4: Lint**

Run: `ruff check src/envault/s3.py && ruff format --check src/envault/s3.py`
Expected: PASS

**Step 5: Commit**

```bash
git add src/envault/s3.py
git commit -m "fix: S3 upload uses SSEKMSKeyId when configured, omits SSE otherwise (L3)

The if/else branches were identical dead code. Now the if branch correctly
passes SSEKMSKeyId, and the else branch omits SSE entirely (relying on
bucket default encryption).

Addresses: SRE review finding L3"
```

---

## Task 3: Add partial-failure resilience to encrypt command (C1)

The encrypt workflow does: encrypt_file → S3 upload → DynamoDB state write → DynamoDB event write. If DynamoDB fails after S3 succeeds, we have orphaned ciphertext. We add structured error logging with enough context for manual recovery, without over-engineering a full saga pattern.

**Files:**
- Modify: `src/envault/cli.py:126-188` (`_encrypt_one`)
- Test: `tests/unit/test_cli.py` (add partial failure test)

**Step 1: Write the failing test**

Add to `tests/unit/test_cli.py` (or create a new test file if test_cli.py is too large):

```python
@mock_aws
def test_encrypt_logs_recovery_info_on_state_write_failure(
    tmp_path, kms_key, s3_bucket, dynamodb_table, caplog
):
    """If DynamoDB write fails after S3 upload succeeds, log recovery info."""
    import logging
    from unittest.mock import patch
    from click.testing import CliRunner
    from envault.cli import main
    from envault.exceptions import StateConflictError

    p = tmp_path / "test.txt"
    p.write_text("hello")

    runner = CliRunner()
    with patch("envault.state.StateStore.put_current_state", side_effect=StateConflictError("boom")):
        with caplog.at_level(logging.ERROR, logger="envault"):
            result = runner.invoke(
                main,
                [
                    "encrypt",
                    str(p),
                    "--key-id", KMS_KEY_ALIAS,
                    "--bucket", BUCKET_NAME,
                    "--table", TABLE_NAME,
                    "--region", REGION,
                ],
            )

    # Command should report the error, not crash
    assert result.exit_code == 1
    # The error output should contain the S3 key for manual recovery
    assert "s3://" in result.output or "RECOVERY" in caplog.text or "state write failed" in caplog.text.lower()
```

Note: This test will need the correct fixtures. Check the existing `test_cli.py` patterns first and adapt.

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_cli.py::test_encrypt_logs_recovery_info_on_state_write_failure -v`
Expected: FAIL — currently the StateConflictError propagates without recovery logging

**Step 3: Add recovery logging to _encrypt_one**

Modify `_encrypt_one` in `src/envault/cli.py` (lines ~159-188). After the S3 upload succeeds, wrap the DynamoDB writes in a try/except that logs the S3 key and version_id for manual recovery:

```python
    # After s3.upload_file succeeds (line 159), before DynamoDB writes:
    try:
        store.put_current_state(
            record,
            expected_last_updated=existing.last_updated if existing else None,
        )
        store.put_event(
            record,
            operation="ENCRYPT",
            correlation_id=correlation_id,
            audit_ttl_days=config.audit_ttl_days,
        )
    except Exception:
        logger.error(
            "State write failed after S3 upload. Manual recovery may be needed.",
            extra={
                "sha256": sha256,
                "s3_key": s3_key,
                "s3_version_id": version_id,
                "bucket": config.bucket,
                "file_name": file_path.name,
            },
        )
        raise
```

This preserves the existing error handling (the exception still propagates to the per-file error counter in the `encrypt` command), but adds structured recovery info to the log.

**Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_cli.py::test_encrypt_logs_recovery_info_on_state_write_failure -v`
Expected: PASS

**Step 5: Run full test suite**

Run: `pytest tests/unit/ -v`
Expected: ALL PASS

**Step 6: Lint and type check**

Run: `ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/envault/`
Expected: PASS

**Step 7: Commit**

```bash
git add src/envault/cli.py tests/unit/test_cli.py
git commit -m "fix: log recovery info on state write failure after S3 upload (C1)

When DynamoDB write fails after a successful S3 upload, log the S3 key,
version ID, and SHA256 hash so operators can manually reconcile orphaned
ciphertext. The error still propagates to the per-file error counter.

Addresses: SRE review finding C1 (partial)"
```

---

## Task 4: Add partial-failure resilience to decrypt command (C1)

Same pattern as Task 3 but for the decrypt path.

**Files:**
- Modify: `src/envault/cli.py:247-277` (decrypt command)
- Test: `tests/unit/test_cli.py`

**Step 1: Write the failing test**

```python
@mock_aws
def test_decrypt_logs_recovery_info_on_state_write_failure(
    tmp_path, kms_key, s3_bucket, dynamodb_table, caplog
):
    """If DynamoDB write fails after successful decryption, log recovery info."""
    # Setup: encrypt a file first, then mock put_current_state to fail on decrypt
    ...
```

Adapt to the existing test patterns in test_cli.py. The key assertion is that when `put_current_state` fails during decrypt, the decrypted file is still on disk and the log contains the SHA256 for recovery.

**Step 2: Implement recovery logging in decrypt command**

Wrap the DynamoDB writes (lines 274-275) in try/except with structured logging:

```python
    try:
        store.put_current_state(record, expected_last_updated=original_last_updated)
        store.put_event(record, operation="DECRYPT", correlation_id=correlation_id)
    except Exception:
        logger.error(
            "State write failed after successful decryption. "
            "File was decrypted to disk but state was not updated.",
            extra={
                "sha256": sha256_hash,
                "output_path": str(output_path),
                "s3_key": record.s3_key,
            },
        )
        raise
```

**Step 3: Run tests**

Run: `pytest tests/unit/ -v`
Expected: ALL PASS

**Step 4: Lint**

Run: `ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/envault/`
Expected: PASS

**Step 5: Commit**

```bash
git add src/envault/cli.py tests/unit/test_cli.py
git commit -m "fix: log recovery info on state write failure during decrypt (C1)

Addresses: SRE review finding C1 (partial)"
```

---

## Task 5: Add partial-failure resilience to rotate-key command (C1)

The rotate-key command is the highest-risk path since it iterates over many files. Add recovery logging for the DynamoDB write after S3 re-upload.

**Files:**
- Modify: `src/envault/cli.py:604-614` (rotate-key inner loop)
- Test: `tests/unit/test_cli.py`

**Step 1: Write the failing test**

Similar to Task 3 — mock `put_current_state` to fail after S3 upload succeeds during rotation. Assert that the log contains the S3 key, version ID, old and new KMS key IDs.

**Step 2: Implement recovery logging**

Wrap the DynamoDB writes in the rotate-key loop (lines 613-614) in try/except:

```python
            try:
                store.put_current_state(record, expected_last_updated=original_last_updated)
                store.put_event(record, operation="ROTATE_KEY", correlation_id=correlation_id)
            except Exception:
                logger.error(
                    "State write failed after S3 re-upload during key rotation.",
                    extra={
                        "sha256": record.sha256_hash,
                        "s3_key": record.s3_key,
                        "s3_version_id": new_version_id,
                        "old_kms_key": record.kms_key_id,
                        "new_kms_key": new_key_id,
                        "correlation_id": correlation_id,
                    },
                )
                raise
```

**Step 3: Run tests, lint, commit**

Run: `pytest tests/unit/ -v && ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/envault/`

```bash
git add src/envault/cli.py tests/unit/test_cli.py
git commit -m "fix: log recovery info on state write failure during key rotation (C1)

Addresses: SRE review finding C1 (complete)"
```

---

## Task 6: Final verification

**Step 1: Run full test suite**

Run: `pytest tests/unit/ -v --tb=short`
Expected: ALL PASS

**Step 2: Run all linters**

Run: `ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/envault/`
Expected: ALL PASS

**Step 3: Review diff against main**

Run: `git diff main --stat`
Verify only expected files changed.

**Step 4: Update review checklist**

Mark C1, C2, M4, and L3 as implemented in `tasks/sre-availability-review.md`.
