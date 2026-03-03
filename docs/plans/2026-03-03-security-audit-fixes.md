# Security Audit Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix all 25 findings from the 2026-03-03 security audit (CRITICAL → LOW) so envault is safe for production use.

**Architecture:** Fixes are purely within the existing module boundaries (`config.py`, `crypto.py`, `s3.py`, `state.py`, `cli.py`). No new modules. Shell scripts patched in place. CDK infrastructure updated inline. Tests live in `tests/unit/`.

**Tech Stack:** Python 3.10+, boto3/moto for AWS mocks, pytest, ruff (linting), mypy (strict types). Run tests with `pytest tests/unit/ -v`.

---

## How to run the test suite

```bash
pip install -e ".[dev]"
pytest tests/unit/ -v
# lint
ruff check src/ tests/
# type-check
mypy src/envault/
```

---

## Task 1 — Fix `migrate` command: use content hash, not path hash (C-1)

**Fixes:** C-1 (CRITICAL — wrong hash breaks all migrated records)

**Files:**
- Modify: `src/envault/cli.py` — `_parse_output_json_entry` function
- Test: `tests/unit/test_cli.py` (new file)

### Step 1: Write the failing test

```python
# tests/unit/test_cli.py
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from envault.cli import _parse_output_json_entry


def _make_entry(input_path: str) -> dict:
    return {
        "mode": "encrypt",
        "input": input_path,
        "header": {
            "algorithm": "AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384",
            "message_id": "abcd1234",
            "encryption_context": {"purpose": "backup"},
            "encrypted_data_keys": [
                {"key_provider": {"key_info": "alias/envault"}}
            ],
        },
    }


def test_parse_entry_uses_content_hash(tmp_path: Path):
    """_parse_output_json_entry must hash file CONTENT, not the path string."""
    plaintext = tmp_path / "secret.txt"
    content = b"sensitive data\n"
    plaintext.write_bytes(content)
    expected_hash = hashlib.sha256(content).hexdigest()

    entry = _make_entry(str(plaintext))
    record = _parse_output_json_entry(entry)

    assert record is not None
    assert record.sha256_hash == expected_hash


def test_parse_entry_skips_missing_file(tmp_path: Path):
    """_parse_output_json_entry returns None when the plaintext file doesn't exist."""
    entry = _make_entry("/nonexistent/path/file.txt")
    record = _parse_output_json_entry(entry)
    assert record is None


def test_parse_entry_skips_non_encrypt_mode():
    entry = {"mode": "decrypt", "input": "/some/file"}
    assert _parse_output_json_entry(entry) is None
```

### Step 2: Run test to verify it fails

```bash
pytest tests/unit/test_cli.py::test_parse_entry_uses_content_hash -v
```
Expected: FAIL — the current implementation uses `hashlib.sha256(input_path.encode())` (path, not content).

### Step 3: Implement the fix in `cli.py`

In `_parse_output_json_entry` (around line 395), replace:

```python
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    import hashlib

    sha256_hash = hashlib.sha256(input_path.encode()).hexdigest()
```

with:

```python
    from envault.crypto import sha256_file

    plaintext_path = Path(input_path)
    if not plaintext_path.exists():
        logger.warning(
            "Plaintext file not found for migration, skipping: %s", input_path
        )
        return None

    sha256_hash = sha256_file(plaintext_path)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
```

### Step 4: Run tests to verify they pass

```bash
pytest tests/unit/test_cli.py -v
```
Expected: All 3 new tests PASS.

### Step 5: Commit

```bash
git add src/envault/cli.py tests/unit/test_cli.py
git commit -m "fix(migrate): hash file content not path string (C-1)"
```

---

## Task 2 — Secure temporary file creation and deletion (C-2, H-2)

**Fixes:** C-2 (CRITICAL — plaintext in world-readable /tmp), H-2 (HIGH — predictable TOCTOU-vulnerable temp paths)

**Files:**
- Modify: `src/envault/cli.py` — `_encrypt_one`, `decrypt`, `rotate_key`
- Test: `tests/unit/test_cli.py` (extend)

### Step 1: Write the failing tests

Add to `tests/unit/test_cli.py`:

```python
import os
from envault.cli import _secure_delete


def test_secure_delete_overwrites_before_removal(tmp_path: Path):
    """_secure_delete must zero-out file contents before unlinking."""
    p = tmp_path / "sensitive.bin"
    p.write_bytes(b"TOP SECRET DATA")
    assert p.exists()

    _secure_delete(p)

    assert not p.exists()


def test_secure_delete_missing_file_is_noop(tmp_path: Path):
    """_secure_delete on a non-existent path must not raise."""
    p = tmp_path / "does_not_exist"
    _secure_delete(p)  # should not raise


def test_secure_delete_zero_length_file(tmp_path: Path):
    p = tmp_path / "empty"
    p.write_bytes(b"")
    _secure_delete(p)
    assert not p.exists()
```

### Step 2: Run tests to verify they fail

```bash
pytest tests/unit/test_cli.py::test_secure_delete_overwrites_before_removal -v
```
Expected: FAIL — `_secure_delete` does not exist yet.

### Step 3: Add `_secure_delete` helper to `cli.py`

Add near the bottom of `cli.py`, in the helpers section (after `_parse_tags`):

```python
def _secure_delete(path: Path) -> None:
    """Overwrite a file with zeros then unlink it.

    Prevents plaintext recovery from disk after decryption or key rotation.
    Does nothing if the file does not exist.
    """
    try:
        size = path.stat().st_size
        with path.open("r+b") as f:
            f.write(b"\x00" * size)
            f.flush()
            os.fsync(f.fileno())
    except FileNotFoundError:
        return
    except OSError:
        pass
    path.unlink(missing_ok=True)
```

Add `import os` to `cli.py` imports (it's already present in stdlib — just ensure it's imported).

### Step 4: Replace predictable temp paths with `mkstemp` throughout `cli.py`

**In `_encrypt_one`** (replace lines 117–118):

```python
    # Before:
    encrypted_name = file_path.name + ".encrypted"
    tmp_encrypted = Path(tempfile.gettempdir()) / f"envault_{sha256[:16]}_{encrypted_name}"

    # After:
    _fd, _tmp = tempfile.mkstemp(suffix=".encrypted", prefix="envault_enc_")
    os.close(_fd)
    tmp_encrypted = Path(_tmp)
```

Replace `tmp_encrypted.unlink(missing_ok=True)` (line 131) with just `tmp_encrypted.unlink(missing_ok=True)` — encrypted files don't need secure delete.

**In `decrypt`** (replace line 196):

```python
    # Before:
    tmp_encrypted = Path(tempfile.gettempdir()) / f"envault_dl_{sha256_hash[:16]}.encrypted"

    # After:
    _fd, _tmp = tempfile.mkstemp(suffix=".encrypted", prefix="envault_dl_")
    os.close(_fd)
    tmp_encrypted = Path(_tmp)
```

**In `rotate_key`** (replace lines 484–487):

```python
    # Before:
    tmpdir = Path(tempfile.gettempdir())
    tmp_dl = tmpdir / f"envault_rot_dl_{record.sha256_hash[:16]}.encrypted"
    tmp_pt = tmpdir / f"envault_rot_pt_{record.sha256_hash[:16]}"
    tmp_enc = tmpdir / f"envault_rot_enc_{record.sha256_hash[:16]}.encrypted"

    # After:
    _fd_dl, _tmp_dl = tempfile.mkstemp(suffix=".encrypted", prefix="envault_dl_")
    os.close(_fd_dl)
    tmp_dl = Path(_tmp_dl)
    _fd_pt, _tmp_pt = tempfile.mkstemp(prefix="envault_pt_")
    os.close(_fd_pt)
    tmp_pt = Path(_tmp_pt)
    _fd_enc, _tmp_enc = tempfile.mkstemp(suffix=".encrypted", prefix="envault_enc_")
    os.close(_fd_enc)
    tmp_enc = Path(_tmp_enc)
```

Replace `tmp_pt.unlink(missing_ok=True)` with `_secure_delete(tmp_pt)` — plaintext needs secure deletion.

The encrypted temp files (`tmp_dl`, `tmp_enc`) keep regular `.unlink(missing_ok=True)`.

### Step 5: Run all tests

```bash
pytest tests/unit/ -v
```
Expected: All tests PASS.

### Step 6: Commit

```bash
git add src/envault/cli.py tests/unit/test_cli.py
git commit -m "fix(tempfiles): use mkstemp + secure-delete plaintext temps (C-2, H-2)"
```

---

## Task 3 — Fix legacy shell scripts: env sourcing + code sync (C-3, C-4)

**Fixes:** C-3 (CRITICAL — all env vars leaked to subprocesses), C-4 (CRITICAL — scripts synced to data bucket)

**Files:**
- Modify: `code/encrypt.sh`
- Modify: `code/decrypt.sh`

No unit tests (shell scripts). Manual verification: run `bash -n code/encrypt.sh` to syntax-check.

### Step 1: Fix `code/encrypt.sh`

Replace lines 4–9 (the `.env` sourcing block):

```bash
# Before:
if [[ -f "../.env" ]]; then
    set -a
    . "../.env"
    set +a
fi

# After:
if [[ -f "../.env" ]]; then
    _s3_val="$(grep -E '^S3_BUCKET=' "../.env" | head -1 | cut -d= -f2-)"
    [[ -n "${_s3_val}" ]] && S3_BUCKET="${_s3_val}"
    unset _s3_val
fi
```

Remove lines 59–61 (the code-sync block):

```bash
# Remove these lines entirely:
# Sync code directory
log "Syncing code directory to S3..."
aws s3 sync ../code "s3://${S3_BUCKET}/code"
```

### Step 2: Fix `code/decrypt.sh`

Apply the same `.env` fix (lines 4–9) as above.

Remove lines 54–56 (the code-sync block):

```bash
# Remove these lines entirely:
# Sync code directory
log "Syncing code directory to S3..."
aws s3 sync ../code "s3://${S3_BUCKET}/code"
```

### Step 3: Syntax-check both scripts

```bash
bash -n code/encrypt.sh && echo "encrypt.sh OK"
bash -n code/decrypt.sh && echo "decrypt.sh OK"
```
Expected: both print `OK`.

### Step 4: Commit

```bash
git add code/encrypt.sh code/decrypt.sh
git commit -m "fix(scripts): isolate .env sourcing; remove code-dir S3 sync (C-3, C-4)"
```

---

## Task 4 — Validate `ENVAULT_AUDIT_TTL_DAYS` in config (M-1)

**Fixes:** M-1 (MEDIUM — non-integer env var crashes with bare ValueError)

**Files:**
- Modify: `src/envault/config.py`
- Test: `tests/unit/test_config.py` (extend)

### Step 1: Write the failing tests

Add to `tests/unit/test_config.py`:

```python
def test_config_non_integer_ttl_raises_config_error(monkeypatch):
    monkeypatch.setenv("ENVAULT_KEY_ID", "alias/k")
    monkeypatch.setenv("ENVAULT_BUCKET", "b")
    monkeypatch.setenv("ENVAULT_TABLE", "t")
    monkeypatch.setenv("ENVAULT_AUDIT_TTL_DAYS", "30d")

    with pytest.raises(ConfigurationError, match="ENVAULT_AUDIT_TTL_DAYS"):
        Config.from_env()


def test_config_zero_ttl_raises_config_error(monkeypatch):
    monkeypatch.setenv("ENVAULT_KEY_ID", "alias/k")
    monkeypatch.setenv("ENVAULT_BUCKET", "b")
    monkeypatch.setenv("ENVAULT_TABLE", "t")
    monkeypatch.setenv("ENVAULT_AUDIT_TTL_DAYS", "0")

    with pytest.raises(ConfigurationError, match="ENVAULT_AUDIT_TTL_DAYS"):
        Config.from_env()


def test_config_negative_ttl_raises_config_error(monkeypatch):
    monkeypatch.setenv("ENVAULT_KEY_ID", "alias/k")
    monkeypatch.setenv("ENVAULT_BUCKET", "b")
    monkeypatch.setenv("ENVAULT_TABLE", "t")
    monkeypatch.setenv("ENVAULT_AUDIT_TTL_DAYS", "-1")

    with pytest.raises(ConfigurationError, match="ENVAULT_AUDIT_TTL_DAYS"):
        Config.from_env()
```

### Step 2: Run tests to verify they fail

```bash
pytest tests/unit/test_config.py::test_config_non_integer_ttl_raises_config_error -v
```
Expected: FAIL — current code raises `ValueError`, not `ConfigurationError`.

### Step 3: Implement the fix in `config.py`

Replace line 54:

```python
        # Before:
        audit_ttl_days = int(os.environ.get("ENVAULT_AUDIT_TTL_DAYS", "365"))

        # After:
        _ttl_raw = os.environ.get("ENVAULT_AUDIT_TTL_DAYS", "365")
        try:
            audit_ttl_days = int(_ttl_raw)
            if audit_ttl_days <= 0:
                raise ValueError("must be positive")
        except ValueError:
            raise ConfigurationError(
                f"ENVAULT_AUDIT_TTL_DAYS must be a positive integer (days). Got: {_ttl_raw!r}"
            )
```

### Step 4: Run tests to verify they pass

```bash
pytest tests/unit/test_config.py -v
```
Expected: All PASS.

### Step 5: Commit

```bash
git add src/envault/config.py tests/unit/test_config.py
git commit -m "fix(config): validate ENVAULT_AUDIT_TTL_DAYS; raise ConfigurationError (M-1)"
```

---

## Task 5 — Fix S3 upload: atomic VersionId + integrity (H-5, M-8)

**Fixes:** H-5 (HIGH — head_object race condition), M-8 (MEDIUM — no upload integrity check)

**Files:**
- Modify: `src/envault/s3.py` — `upload_file` method
- Test: `tests/unit/test_s3.py` (new file)

### Step 1: Write the failing tests

```python
# tests/unit/test_s3.py
from __future__ import annotations

from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from envault.s3 import S3Store

BUCKET = "test-bucket"
REGION = "us-east-1"


def _create_versioned_bucket(s3_client) -> None:
    s3_client.create_bucket(Bucket=BUCKET)
    s3_client.put_bucket_versioning(
        Bucket=BUCKET,
        VersioningConfiguration={"Status": "Enabled"},
    )


@mock_aws
def test_upload_returns_version_id(tmp_path: Path):
    """upload_file must return a non-empty VersionId."""
    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)

    p = tmp_path / "secret.txt.encrypted"
    p.write_bytes(b"fake ciphertext")

    store = S3Store(bucket=BUCKET, region=REGION)
    version_id = store.upload_file(local_path=p, s3_key="encrypted/secret.txt.encrypted")

    assert isinstance(version_id, str)
    assert len(version_id) > 0


@mock_aws
def test_upload_two_versions_return_distinct_ids(tmp_path: Path):
    """Each upload must return a unique VersionId."""
    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)

    p = tmp_path / "file.enc"
    p.write_bytes(b"version one")
    store = S3Store(bucket=BUCKET, region=REGION)

    v1 = store.upload_file(local_path=p, s3_key="encrypted/file.enc")
    p.write_bytes(b"version two")
    v2 = store.upload_file(local_path=p, s3_key="encrypted/file.enc")

    assert v1 != v2


@mock_aws
def test_download_specific_version(tmp_path: Path):
    """download_file with version_id must retrieve the correct version."""
    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)

    store = S3Store(bucket=BUCKET, region=REGION)

    p = tmp_path / "data.enc"
    p.write_bytes(b"first content")
    v1 = store.upload_file(p, "encrypted/data.enc")

    p.write_bytes(b"second content")
    store.upload_file(p, "encrypted/data.enc")

    out = tmp_path / "retrieved.enc"
    store.download_file("encrypted/data.enc", out, version_id=v1)
    assert out.read_bytes() == b"first content"
```

### Step 2: Run tests to verify they pass (they should already — but we want to establish baseline)

```bash
pytest tests/unit/test_s3.py -v
```
Expected: Tests PASS with the current `upload_file + head_object` implementation (moto supports it). If they FAIL, fix moto setup before proceeding.

### Step 3: Implement the fix — switch to `put_object`

Replace the `upload_file` method in `src/envault/s3.py`:

```python
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    def upload_file(self, local_path: Path, s3_key: str) -> str:
        """Upload a file to S3 and return the version ID.

        Uses put_object (single API call) to atomically retrieve the VersionId
        in the response, eliminating the race window of upload_file + head_object.

        Args:
            local_path: Local path of the file to upload.
            s3_key: S3 object key.

        Returns:
            The S3 VersionId of the uploaded object.
        """
        logger.info("Uploading to S3", extra={"bucket": self._bucket, "key": s3_key})
        data = local_path.read_bytes()
        response = self._s3.put_object(
            Bucket=self._bucket,
            Key=s3_key,
            Body=data,
            ServerSideEncryption="aws:kms",
        )
        version_id: str = response.get("VersionId", "")
        logger.info(
            "Upload complete",
            extra={"bucket": self._bucket, "key": s3_key, "version_id": version_id},
        )
        return version_id
```

### Step 4: Run all tests

```bash
pytest tests/unit/ -v
```
Expected: All PASS.

### Step 5: Commit

```bash
git add src/envault/s3.py tests/unit/test_s3.py
git commit -m "fix(s3): use put_object for atomic VersionId; eliminate head_object race (H-5)"
```

---

## Task 6 — Fix S3 key collision: include sha256 hash in key (M-2)

**Fixes:** M-2 (MEDIUM — same-named files in different dirs overwrite each other)

**Files:**
- Modify: `src/envault/s3.py` — `s3_key_for_file` signature
- Modify: `src/envault/cli.py` — all callers of `s3_key_for_file`
- Test: `tests/unit/test_s3.py` (extend)

### Step 1: Write the failing test

Add to `tests/unit/test_s3.py`:

```python
def test_s3_key_for_file_is_content_addressed():
    """S3 key must be unique per SHA256 hash to avoid filename collisions."""
    store = S3Store(bucket="b", region="us-east-1")
    sha = "a" * 64

    key = store.s3_key_for_file(sha256_hash=sha, file_name="report.xlsx")

    assert sha[:2] in key
    assert sha in key
    assert "report.xlsx.encrypted" in key
    # Two files with same name but different hashes get different keys
    sha2 = "b" * 64
    key2 = store.s3_key_for_file(sha256_hash=sha2, file_name="report.xlsx")
    assert key != key2
```

### Step 2: Run test to verify it fails

```bash
pytest tests/unit/test_s3.py::test_s3_key_for_file_is_content_addressed -v
```
Expected: FAIL — `s3_key_for_file` doesn't accept `sha256_hash`.

### Step 3: Update `s3_key_for_file` in `s3.py`

```python
    def s3_key_for_file(self, sha256_hash: str, file_name: str) -> str:
        """Generate a content-addressed S3 key that is unique per file content.

        Format: encrypted/{sha256[:2]}/{sha256}/{filename}.encrypted
        The sha256 prefix shards objects into 256 virtual partitions,
        preventing S3 listing bottlenecks at scale.
        """
        return f"encrypted/{sha256_hash[:2]}/{sha256_hash}/{file_name}.encrypted"
```

### Step 4: Update all callers in `cli.py`

In `_encrypt_one` (line ~119):
```python
    # Before:
    s3_key = s3.s3_key_for_file(file_path.name)

    # After:
    s3_key = s3.s3_key_for_file(sha256_hash=sha256, file_name=file_path.name)
```

In `_parse_output_json_entry` (around line 417), the `s3_key` is hard-coded. Update it:
```python
    # Before:
    s3_key=f"encrypted/{file_name}.encrypted",

    # After:
    s3_key=f"encrypted/{sha256_hash[:2]}/{sha256_hash}/{file_name}.encrypted",
```

### Step 5: Run all tests

```bash
pytest tests/unit/ -v
ruff check src/ tests/
mypy src/envault/
```
Expected: All PASS.

### Step 6: Commit

```bash
git add src/envault/s3.py src/envault/cli.py tests/unit/test_s3.py
git commit -m "fix(s3): content-addressed keys prevent filename collision (M-2)"
```

---

## Task 7 — Warn on empty version_id in download (M-7)

**Fixes:** M-7 (MEDIUM — silent fallback to latest version when version_id is empty)

**Files:**
- Modify: `src/envault/s3.py` — `download_file`
- Test: `tests/unit/test_s3.py` (extend)

### Step 1: Write the failing test

Add to `tests/unit/test_s3.py`:

```python
import logging


@mock_aws
def test_download_empty_version_id_logs_warning(tmp_path: Path, caplog):
    """download_file with empty version_id must emit a WARNING."""
    s3_client = boto3.client("s3", region_name=REGION)
    _create_versioned_bucket(s3_client)
    s3_client.put_object(Bucket=BUCKET, Key="encrypted/file.enc", Body=b"data")

    store = S3Store(bucket=BUCKET, region=REGION)
    out = tmp_path / "file.enc"

    with caplog.at_level(logging.WARNING, logger="envault.s3"):
        store.download_file("encrypted/file.enc", out, version_id="")

    assert any("version_id" in r.message.lower() or "version" in r.message.lower()
               for r in caplog.records)
```

### Step 2: Run test to verify it fails

```bash
pytest tests/unit/test_s3.py::test_download_empty_version_id_logs_warning -v
```
Expected: FAIL — no warning is emitted.

### Step 3: Add the warning in `download_file`

After the `extra_args` block in `download_file`, add:

```python
        if not version_id:
            logger.warning(
                "Downloading S3 object without VersionId; fetching latest version. "
                "This may retrieve a different object than was recorded at encryption time.",
                extra={"bucket": self._bucket, "key": s3_key},
            )
```

### Step 4: Run tests to verify they pass

```bash
pytest tests/unit/test_s3.py -v
```
Expected: All PASS.

### Step 5: Commit

```bash
git add src/envault/s3.py tests/unit/test_s3.py
git commit -m "fix(s3): warn when downloading without VersionId (M-7)"
```

---

## Task 8 — Add DynamoDB query pagination (H-3)

**Fixes:** H-3 (HIGH — rotate-key silently skips files beyond the first DynamoDB page)

**Files:**
- Modify: `src/envault/state.py` — add `_paginate_query`, update list methods
- Test: `tests/unit/test_state.py` (extend)

### Step 1: Write the failing test

Add to `tests/unit/test_state.py`:

```python
from unittest.mock import patch


@mock_aws
def test_list_by_state_follows_pagination():
    """list_by_state must call query again when LastEvaluatedKey is present."""
    store = _create_table()

    r1 = _make_record(sha256_hash="a" * 64, encrypted_at="2026-03-03T10:00:00+00:00")
    r2 = _make_record(sha256_hash="b" * 64, encrypted_at="2026-03-03T11:00:00+00:00")

    call_count = 0
    original_query = store._table.query

    def paged_query(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First page: return r1 + a continuation token
            result = original_query(**kwargs)
            result["Items"] = [r1.__dict__]  # simplified; use the real item format
            result["LastEvaluatedKey"] = {"PK": "FILE#" + "a" * 64, "SK": "CURRENT"}
            return result
        # Second page: return r2, no continuation
        result = original_query(**kwargs)
        result["Items"] = [r2.__dict__]
        result.pop("LastEvaluatedKey", None)
        return result

    with patch.object(store._table, "query", side_effect=paged_query):
        records = store.list_by_state(ENCRYPTED)

    assert call_count == 2
```

### Step 2: Run test to verify it fails

```bash
pytest tests/unit/test_state.py::test_list_by_state_follows_pagination -v
```
Expected: FAIL — `call_count` is 1 (no pagination loop).

### Step 3: Add `_paginate_query` to `StateStore` and update list methods

Add this private method to `StateStore` (before `put_current_state`):

```python
    def _paginate_query(self, **query_kwargs: Any) -> list[dict[str, Any]]:
        """Execute a DynamoDB Query, following LastEvaluatedKey until exhausted."""
        items: list[dict[str, Any]] = []
        while True:
            response = self._table.query(**query_kwargs)
            items.extend(response.get("Items", []))
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                break
            query_kwargs["ExclusiveStartKey"] = last_key
        return items
```

Update `list_by_state` to use it:

```python
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    def list_by_state(self, state: str) -> list[FileRecord]:
        """Return all files in a given state (uses state-index GSI)."""
        items = self._paginate_query(
            IndexName="state-index",
            KeyConditionExpression=Key("current_state").eq(state),
        )
        return [_item_to_record(item) for item in items]
```

Update `list_events_for_file` to use it:

```python
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    def list_events_for_file(self, sha256_hash: str) -> list[dict[str, Any]]:
        """Return all event records for a file, sorted by timestamp."""
        return self._paginate_query(
            KeyConditionExpression=(
                Key("PK").eq(f"{FILE_PREFIX}{sha256_hash}") & Key("SK").begins_with(EVENT_PREFIX)
            )
        )
```

Update `list_events_by_date` to use it (also adds the CURRENT-record filter from M-3):

```python
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    def list_events_by_date(self, date_str: str) -> list[dict[str, Any]]:
        """Return only EVENT records for a given date YYYY-MM-DD (date-index GSI).

        Filters out CURRENT-state records that also carry a 'date' attribute,
        so audit queries return only immutable event entries.
        """
        from boto3.dynamodb.conditions import Attr
        return self._paginate_query(
            IndexName="date-index",
            KeyConditionExpression=Key("date").eq(date_str),
            FilterExpression=Attr("SK").begins_with(EVENT_PREFIX),
        )
```

### Step 4: Run all state tests

```bash
pytest tests/unit/test_state.py -v
```
Expected: All PASS.

### Step 5: Commit

```bash
git add src/envault/state.py tests/unit/test_state.py
git commit -m "fix(state): paginate DynamoDB queries; exclude CURRENT records from date-index (H-3, M-3)"
```

---

## Task 9 — Add DiscoveryFilter to restrict KMS decryption (H-4)

**Fixes:** H-4 (HIGH — unconstrained discovery accepts ciphertexts encrypted by any KMS key in any account)

**Files:**
- Modify: `src/envault/config.py` — add `allowed_account_ids`
- Modify: `src/envault/crypto.py` — apply `DiscoveryFilter`
- Modify: `src/envault/cli.py` — pass `allowed_account_ids` through decrypt/rotate_key
- Test: `tests/unit/test_config.py` (extend)

### Step 1: Write the failing tests

Add to `tests/unit/test_config.py`:

```python
def test_config_allowed_account_ids_parsed(monkeypatch):
    monkeypatch.setenv("ENVAULT_KEY_ID", "alias/k")
    monkeypatch.setenv("ENVAULT_BUCKET", "b")
    monkeypatch.setenv("ENVAULT_TABLE", "t")
    monkeypatch.setenv("ENVAULT_ALLOWED_ACCOUNT_IDS", "111111111111,222222222222")

    cfg = Config.from_env()
    assert cfg.allowed_account_ids == ["111111111111", "222222222222"]


def test_config_allowed_account_ids_empty_by_default(monkeypatch):
    monkeypatch.setenv("ENVAULT_KEY_ID", "alias/k")
    monkeypatch.setenv("ENVAULT_BUCKET", "b")
    monkeypatch.setenv("ENVAULT_TABLE", "t")
    monkeypatch.delenv("ENVAULT_ALLOWED_ACCOUNT_IDS", raising=False)

    cfg = Config.from_env()
    assert cfg.allowed_account_ids == []
```

### Step 2: Run tests to verify they fail

```bash
pytest tests/unit/test_config.py::test_config_allowed_account_ids_parsed -v
```
Expected: FAIL — `Config` has no `allowed_account_ids` field.

### Step 3: Add `allowed_account_ids` to `Config`

In `src/envault/config.py`:

```python
@dataclass
class Config:
    """Runtime configuration loaded from environment variables."""

    key_id: str
    bucket: str
    table_name: str
    region: str
    encryption_context: dict[str, str] = field(default_factory=lambda: {"purpose": "backup"})
    audit_ttl_days: int = 365
    allowed_account_ids: list[str] = field(default_factory=list)  # add this line
```

In `from_env()`, before the `return cls(...)`:

```python
        _account_ids_raw = os.environ.get("ENVAULT_ALLOWED_ACCOUNT_IDS", "")
        allowed_account_ids = [a.strip() for a in _account_ids_raw.split(",") if a.strip()]

        return cls(
            key_id=key_id,
            bucket=bucket,
            table_name=table_name,
            region=region,
            audit_ttl_days=audit_ttl_days,
            allowed_account_ids=allowed_account_ids,  # add this
        )
```

Also add to CLAUDE.md environment variable table:

| `ENVAULT_ALLOWED_ACCOUNT_IDS` | No | Comma-separated AWS account IDs allowed for decryption |

### Step 4: Update `decrypt_file` in `crypto.py`

Add `allowed_account_ids` parameter:

```python
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
def decrypt_file(
    input_path: Path,
    output_path: Path,
    expected_sha256: str | None = None,
    region: str = "us-east-1",
    allowed_account_ids: list[str] | None = None,
) -> DecryptResult:
```

Replace the `key_provider` construction in `decrypt_file`:

```python
    if allowed_account_ids:
        from aws_encryption_sdk.key_providers.kms import DiscoveryFilter

        discovery_filter = DiscoveryFilter(
            account_ids=tuple(allowed_account_ids),
            partition="aws",
        )
        key_provider = DiscoveryAwsKmsMasterKeyProvider(
            config=aws_encryption_sdk.key_providers.kms.KMSMasterKeyProviderConfig(
                discovery_filter=discovery_filter
            )
        )
    else:
        key_provider = DiscoveryAwsKmsMasterKeyProvider()
```

**Note:** `DiscoveryAwsKmsMasterKeyProvider` accepts `discovery_filter` as a kwarg that feeds into its config. Verify the exact constructor signature against the installed version with `help(DiscoveryAwsKmsMasterKeyProvider)`.

The simplest form (per the SDK docstring):
```python
    if allowed_account_ids:
        from aws_encryption_sdk.key_providers.kms import DiscoveryFilter

        key_provider = DiscoveryAwsKmsMasterKeyProvider(
            discovery_filter=DiscoveryFilter(
                account_ids=tuple(allowed_account_ids),
                partition="aws",
            )
        )
    else:
        key_provider = DiscoveryAwsKmsMasterKeyProvider()
```

### Step 5: Wire through `cli.py`

In `decrypt` command, pass `allowed_account_ids` to `decrypt_file`. First load the config:

```python
    # At the top of the decrypt() function body, after building store and s3:
    config = Config(key_id="", bucket=bucket, table_name=table, region=region)
    # ... but we don't have key_id here. Instead, read from env:
```

Actually, `decrypt` command currently does not load `Config` at all — it uses raw parameters. The simplest fix is to add `--allowed-account-ids` option or load from env directly:

In the `decrypt` command signature, add:
```python
@click.option(
    "--allowed-account-ids",
    envvar="ENVAULT_ALLOWED_ACCOUNT_IDS",
    default="",
    help="Comma-separated AWS account IDs to trust for decryption.",
)
```

And in the `decrypt` function body:
```python
    account_ids = [a.strip() for a in allowed_account_ids.split(",") if a.strip()]

    decrypt_file(
        input_path=tmp_encrypted,
        output_path=output_path,
        expected_sha256=sha256_hash,
        region=region,
        allowed_account_ids=account_ids or None,
    )
```

Apply the same pattern in `rotate_key` — add `--allowed-account-ids` option and pass to `decrypt_file`.

### Step 6: Run all tests

```bash
pytest tests/unit/ -v
mypy src/envault/
```
Expected: All PASS.

### Step 7: Commit

```bash
git add src/envault/config.py src/envault/crypto.py src/envault/cli.py tests/unit/test_config.py
git commit -m "fix(crypto): add DiscoveryFilter to constrain KMS discovery (H-4)"
```

---

## Task 10 — Narrow exception handling + validate tag inputs (M-4, M-5)

**Fixes:** M-4 (MEDIUM — broad `except Exception` hides bugs), M-5 (MEDIUM — tag keys/values unvalidated)

**Files:**
- Modify: `src/envault/cli.py` — `migrate`, `rotate_key`, `_parse_tags`
- Test: `tests/unit/test_cli.py` (extend)

### Step 1: Write the failing tests

Add to `tests/unit/test_cli.py`:

```python
import pytest
import click
from envault.cli import _parse_tags


def test_parse_tags_valid():
    result = _parse_tags(("project=finance", "env=prod"))
    assert result == {"project": "finance", "env": "prod"}


def test_parse_tags_invalid_key_raises():
    """Tag keys with special characters must raise UsageError."""
    with pytest.raises(click.UsageError, match="Invalid tag key"):
        _parse_tags(("bad key!=value",))


def test_parse_tags_key_too_long_raises():
    """Tag key longer than 64 chars must raise UsageError."""
    long_key = "k" * 65
    with pytest.raises(click.UsageError, match="Invalid tag key"):
        _parse_tags((f"{long_key}=value",))


def test_parse_tags_value_too_long_raises():
    """Tag value longer than 256 chars must raise UsageError."""
    long_val = "v" * 257
    with pytest.raises(click.UsageError, match="exceeds"):
        _parse_tags((f"key={long_val}",))


def test_parse_tags_empty_key_raises():
    with pytest.raises(click.UsageError, match="Invalid tag key"):
        _parse_tags(("=value",))
```

### Step 2: Run tests to verify they fail

```bash
pytest tests/unit/test_cli.py::test_parse_tags_invalid_key_raises -v
```
Expected: FAIL — current `_parse_tags` doesn't validate.

### Step 3: Update `_parse_tags` in `cli.py`

```python
import re

_TAG_KEY_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")
_TAG_VALUE_MAX_LEN = 256


def _parse_tags(tag_strs: tuple[str, ...]) -> dict[str, str]:
    tags: dict[str, str] = {}
    for t in tag_strs:
        if "=" not in t:
            console.print(f"[yellow]Ignoring invalid tag '{t}' (expected KEY=VALUE)[/yellow]")
            continue
        k, _, v = t.partition("=")
        k = k.strip()
        v = v.strip()
        if not _TAG_KEY_RE.match(k):
            raise click.UsageError(
                f"Invalid tag key {k!r}: must be 1–64 characters, "
                "alphanumeric, underscore, or hyphen only."
            )
        if len(v) > _TAG_VALUE_MAX_LEN:
            raise click.UsageError(
                f"Tag value for {k!r} exceeds {_TAG_VALUE_MAX_LEN} characters."
            )
        tags[k] = v
    return tags
```

### Step 4: Narrow exception handling in `migrate` and `rotate_key`

In `migrate` (around line 385), change:
```python
        except Exception as exc:
            logger.warning("Failed to migrate record at line %d: %s", i, exc)
            errors += 1
```
to:
```python
        except (json.JSONDecodeError, KeyError, ValueError, MigrationError) as exc:
            logger.warning("Failed to migrate record at line %d: %s", i, exc)
            errors += 1
```

Add `MigrationError` to the import from `envault.exceptions`.

In `rotate_key` (around line 510), change:
```python
        except Exception as exc:
            console.print(f"[red]Error rotating {record.file_name}: {exc}[/red]")
            errors += 1
```
to:
```python
        except (EnvaultError, ClientError, BotoCoreError) as exc:
            console.print(f"[red]Error rotating {record.file_name}: {exc}[/red]")
            errors += 1
```

Add these imports at the top of `cli.py`:
```python
from botocore.exceptions import BotoCoreError, ClientError
from envault.exceptions import AlreadyEncryptedError, ConfigurationError, MigrationError
```

### Step 5: Run all tests

```bash
pytest tests/unit/ -v
ruff check src/ tests/
mypy src/envault/
```
Expected: All PASS.

### Step 6: Commit

```bash
git add src/envault/cli.py tests/unit/test_cli.py
git commit -m "fix(cli): validate tag inputs; narrow exception handling (M-4, M-5)"
```

---

## Task 11 — Validate `sha256_hash` argument in `decrypt` (from audit)

**Fixes:** Missing input validation — invalid hash format produces confusing DynamoDB errors.

**Files:**
- Modify: `src/envault/cli.py` — `decrypt` command
- Test: `tests/unit/test_cli.py` (extend)

### Step 1: Write the failing test

This test exercises the click CLI runner, so add:

```python
from click.testing import CliRunner
from envault.cli import main


def test_decrypt_rejects_invalid_sha256_format():
    """decrypt must reject hash arguments that are not 64-char hex strings."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "decrypt",
            "not-a-valid-hash",
            "--table", "t",
            "--bucket", "b",
        ],
        env={
            "AWS_ACCESS_KEY_ID": "testing",
            "AWS_SECRET_ACCESS_KEY": "testing",
            "AWS_DEFAULT_REGION": "us-east-1",
        },
    )
    assert result.exit_code != 0
    assert "invalid" in result.output.lower() or "sha256" in result.output.lower()
```

### Step 2: Add validation at the top of the `decrypt` function body

In `decrypt()`, after `store = StateStore(...)`:

```python
    import re
    if not re.fullmatch(r"[0-9a-f]{64}", sha256_hash):
        console.print(
            f"[red]Invalid SHA256 hash: {sha256_hash!r}. "
            "Expected 64 lowercase hexadecimal characters.[/red]"
        )
        sys.exit(1)
```

### Step 3: Run tests to verify they pass

```bash
pytest tests/unit/test_cli.py -v
```
Expected: All PASS.

### Step 4: Commit

```bash
git add src/envault/cli.py tests/unit/test_cli.py
git commit -m "fix(cli): validate sha256_hash argument format in decrypt"
```

---

## Task 12 — Pin GitHub Actions to commit SHAs (M-6)

**Fixes:** M-6 (MEDIUM — floating tags allow silent action substitution)

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/publish.yml`

### Step 1: Retrieve current SHAs for each action

Run (requires `gh` CLI or internet access):
```bash
gh api repos/actions/checkout/git/refs/tags/v4 | jq -r '.object.sha'
gh api repos/actions/setup-python/git/refs/tags/v5 | jq -r '.object.sha'
gh api repos/actions/upload-artifact/git/refs/tags/v4 | jq -r '.object.sha'
gh api repos/zricethezav/gitleaks-action/git/refs/tags/v2 | jq -r '.object.sha'
```

### Step 2: Update `ci.yml`

Replace all action version references with `@<sha>  # vX.Y.Z` format. Example pattern:

```yaml
      - uses: actions/checkout@<SHA_HERE>  # v4 - update SHA when upgrading
```

Do this for every `uses:` line in both `ci.yml` and `publish.yml`.

### Step 3: Verify CI still passes by pushing the branch

```bash
git add .github/workflows/ci.yml .github/workflows/publish.yml
git commit -m "fix(ci): pin GitHub Actions to commit SHAs (M-6)"
```

---

## Task 13 — Remove unused `tag-index` GSI from CDK (L-5)

**Fixes:** L-5 (LOW — GSI adds DynamoDB capacity cost with no functionality)

**Files:**
- Modify: `infra/cdk/stacks/envault_stack.py`

### Step 1: Remove the `tag-index` GSI block

Remove lines 108–116 from `envault_stack.py`:

```python
        # Remove this entire block:
        # GSI: query by tag key (tag_key, tag_value stored as separate attributes)
        # Note: DynamoDB doesn't support map-key GSIs; tags are denormalized as
        # tag_key/tag_value on the record for this GSI.
        table.add_global_secondary_index(
            index_name="tag-index",
            partition_key=dynamodb.Attribute(name="tag_key", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="tag_value", type=dynamodb.AttributeType.STRING),
            projection_type=dynamodb.ProjectionType.KEYS_ONLY,
        )
```

### Step 2: Synthesize to verify no CDK errors

```bash
cd infra/cdk && cdk synth 2>&1 | tail -20
```
Expected: Synthesis succeeds (or shows expected warnings about environment).

### Step 3: Commit

```bash
git add infra/cdk/stacks/envault_stack.py
git commit -m "fix(cdk): remove unused tag-index GSI (L-5)"
```

---

## Task 14 — Final verification and push

### Step 1: Run the full test suite + linting

```bash
pytest tests/unit/ -v --tb=short
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/envault/
```
Expected: All PASS, 0 lint errors, 0 mypy errors.

### Step 2: Review changed files

```bash
git log --oneline origin/main..HEAD
git diff origin/main --stat
```

### Step 3: Push

```bash
git push -u origin claude/security-audit-review-Mdswz
```

---

## Summary of All Fixes

| Task | Findings Fixed | Severity |
|------|---------------|----------|
| 1 | C-1: migrate uses content hash | CRITICAL |
| 2 | C-2, H-2: mkstemp + secure delete | CRITICAL, HIGH |
| 3 | C-3, C-4: shell .env + code-sync | CRITICAL, CRITICAL |
| 4 | M-1: TTL validation | MEDIUM |
| 5 | H-5, M-8: atomic VersionId via put_object | HIGH, MEDIUM |
| 6 | M-2: content-addressed S3 keys | MEDIUM |
| 7 | M-7: warn on empty version_id | MEDIUM |
| 8 | H-3, M-3: DynamoDB pagination + EVENT filter | HIGH, MEDIUM |
| 9 | H-4: DiscoveryFilter on KMS | HIGH |
| 10 | M-4, M-5: narrow exceptions + tag validation | MEDIUM, MEDIUM |
| 11 | sha256_hash input validation | (from audit) |
| 12 | M-6: pin GitHub Actions | MEDIUM |
| 13 | L-5: remove unused tag-index GSI | LOW |
