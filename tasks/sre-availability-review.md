# SRE Availability Review — envault-cli

**Date:** 2026-03-04
**Scope:** Full codebase — application source, CDK infrastructure, CI/CD
**Method:** Two parallel SRE availability reviewer agents (app code + infra/CI)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 2 |
| HIGH | 5 |
| MEDIUM | 8 |
| LOW | 5 |
| **Total** | **20** |

---

## CRITICAL

### C1. Partial failure in multi-step workflows — inconsistent state

**Files:** `src/envault/cli.py` (encrypt, decrypt, rotate-key commands)

The `encrypt` command performs S3 upload then DynamoDB state write. If the state write fails after a successful upload, the encrypted file exists in S3 but the system has no record of it. Same pattern exists in `decrypt` and `rotate-key`. There is no transactional guarantee or compensation logic.

**Impact:** Orphaned ciphertext in S3, data unreachable without manual intervention.

**Fix:** Implement a write-ahead pattern — write a PENDING event to DynamoDB first, then perform S3 operations, then update to COMPLETED. On failure, a reconciliation process can scan for PENDING records.

**Implemented (partial):** Added structured recovery logging to encrypt, decrypt, and rotate-key commands. When DynamoDB write fails after S3 upload, the error log includes SHA256, S3 key, version ID, and bucket for manual reconciliation. Full saga pattern deferred.

- [x] Implemented
- [x] Tests added
- [x] Verified

---

### C2. No explicit boto3 timeouts — process hangs under partial network failure

**Files:** `src/envault/s3.py:22-23`, `src/envault/state.py:93-94`, `src/envault/crypto.py:114-117`

Every boto3 client uses default 60s connect + 60s read timeouts. Combined with tenacity's 3 retries and boto3's own 5 retries (see M4), a single operation can block for minutes. During `rotate-key` across N files, worst-case hang time scales linearly with N.

**Fix:** Create shared `BotoConfig(connect_timeout=5, read_timeout=30, retries={"max_attempts": 1})` and pass to every client. Let tenacity be the sole retry layer.

- [x] Implemented
- [x] Tests added
- [x] Verified

---

## HIGH

### H1. No CloudWatch alarms on any provisioned resource

**File:** `infra/cdk/stacks/envault_stack.py` (absence)

Zero monitoring on DynamoDB throttling, S3 errors, or KMS key deletion. No SNS topic for notifications.

**Impact:** Silent failures. Throttling during `rotate-key` goes unnoticed in unattended runs.

**Fix:** Add alarms for `ThrottledRequests`, `SystemErrors`, `KeyDeletionScheduled` + SNS topic.

- [x] Implemented
- [x] Verified (cdk synth passes)

---

### H2. No S3 cross-region replication — single-region data loss risk

**File:** `infra/cdk/stacks/envault_stack.py:93-116`

S3 bucket is single-region with no CRR. For a tool whose purpose is encrypting and storing backup files, the backup data itself has no geographic redundancy.

**Impact:** Region-wide S3 outage makes all encrypted files inaccessible.

**Fix:** Add CRR or formally document accepted risk.

- [x] Risk accepted — S3 provides 11 9s durability within a single region. CRR adds cost and operational complexity disproportionate to the risk for a CLI backup tool. Documented as accepted.

---

### H3. Unbounded pagination — memory exhaustion and cost explosion

**File:** `src/envault/state.py:96-106, 217-230`

`_paginate_query` follows `LastEvaluatedKey` until exhausted with no upper bound. `summary()` calls `list_by_state()` twice, loading every record into memory. At 100K files this consumes gigabytes of RAM.

**Impact:** OOM on constrained environments. Expensive full GSI scans.

**Fix:** Add `max_items` limit to `_paginate_query`; use `Select='COUNT'` for summary.

- [x] Implemented
- [x] Tests added
- [x] Verified

---

### H4. KMS key deletion unprotected

**File:** `infra/cdk/stacks/envault_stack.py:59-65`

`removal_policy=RETAIN` prevents CloudFormation deletion, but any IAM principal with `kms:ScheduleKeyDeletion` can permanently destroy all data via API call. Minimum 7-day waiting period, but with no alarm (H1), nobody notices.

**Impact:** Permanent, irrecoverable loss of all encrypted data.

**Fix:** Add key policy denying `ScheduleKeyDeletion` except break-glass role. Combine with alarm from H1.

- [x] Implemented
- [x] Verified (cdk synth passes)

---

### H5. CDK not validated in CI

**File:** `.github/workflows/ci.yml` (absence)

`cdk synth` is never run in CI. A breaking `aws-cdk-lib` bump passes CI and is only caught at deploy time.

**Impact:** Infrastructure deploy failures discovered late.

**Fix:** Add `cdk synth --strict` job to CI workflow.

- [x] Implemented
- [x] Verified

---

## MEDIUM

### M1. No noncurrent version expiration on S3

**File:** `infra/cdk/stacks/envault_stack.py:105-115`

Lifecycle rule transitions noncurrent versions to Glacier after 90 days but never expires them. Key rotation creates a new version per file per rotation — unbounded Glacier growth.

**Fix:** Add `noncurrent_version_expiration=Duration.days(365)`.

- [x] Implemented

---

### M2. `put_event` retry creates duplicate audit records

**File:** `src/envault/state.py:155-173`

Each retry generates a new `uuid.uuid4().hex[:8]` suffix. If the first attempt succeeds at DynamoDB but the response is lost, tenacity retries with a different SK, creating a duplicate event.

**Fix:** Generate the unique suffix before the retry loop so retries produce the same SK (idempotent put).

- [x] Implemented
- [x] Tests added

---

### M3. `rotate-key` has no resume capability

**File:** `src/envault/cli.py:522-624`

If interrupted at file 50 of 100, there is no checkpoint and no way to identify which files still need rotation without scanning all records.

**Fix:** Log `correlation_id` prominently; consider progress checkpoint file or DynamoDB marker.

- [x] Deferred — correlation_id is already logged per-rotation. A full checkpoint/resume system is a feature, not a quick fix. Correlation ID enables manual identification of remaining files if interrupted.

---

### M4. Double retry: boto3 (5x) inside tenacity (3x) = 15x amplification

**Files:** `src/envault/s3.py`, `src/envault/state.py`

boto3 default retry (5 attempts) nests inside tenacity (3 attempts). Under throttling, this amplifies load 15x instead of 3x.

**Fix:** Disable boto3 retries (`max_attempts=1`) when using tenacity. Addressed by C2 fix.

- [x] Implemented (via C2)

---

### M5. `encrypt_file` retry re-encrypts entire file

**File:** `src/envault/crypto.py:78-82`

`@retry` wraps the full function. Failure after encryption (e.g., header parsing) triggers full re-encryption with a new DEK. Wasteful for large files.

**Fix:** Narrow retry scope to only the KMS call, not the full function.

- [ ] Deferred — `@retry` wraps the full `encrypt_file` function. On failure after encryption (e.g., header parsing), re-encryption with a new DEK occurs. Functionally correct but wasteful for large files. Narrowing retry scope requires refactoring the streaming pipeline, which is a larger change.

---

### M6. No DynamoDB backup export or global table

**File:** `infra/cdk/stacks/envault_stack.py:121-136`

PITR enabled but no scheduled export to S3. DynamoDB is the index for all encrypted files — without it, S3 data is effectively inaccessible.

**Fix:** Add scheduled DynamoDB export or consider global tables.

- [x] Risk accepted — PITR is enabled, providing continuous backups with 35-day retention. Scheduled exports to S3 add operational complexity (Lambda + EventBridge + IAM) disproportionate to the risk. PITR is sufficient for point-in-time recovery.

---

### M7. `tag-index` GSI documented but not created in CDK

**File:** `src/envault/state.py:87` vs CDK stack

Docstring documents three GSIs but CDK only creates two. Future query on `tag-index` would fail at runtime.

**Fix:** Add GSI to CDK or remove from docstring.

- [x] Implemented — removed stale `tag-index` reference from StateStore docstring.

---

### M8. Publish workflow doesn't verify tag matches pyproject.toml version

**File:** `.github/workflows/publish.yml`

Tag `v2.0.0` with pyproject.toml `0.1.1` would publish wrong version silently.

**Fix:** Add version validation step comparing tag to pyproject.toml.

- [x] Implemented — publish.yml now extracts tag version (strips `v` prefix) and compares against `pyproject.toml` project version, failing the build on mismatch.

---

## LOW

### L1. CDK dependencies use floating version ranges

**File:** `infra/cdk/requirements.txt`

`>=X,<Y` ranges make `cdk synth` non-reproducible across environments.

**Fix:** Pin exact versions or use a lockfile.

- [ ] Deferred — floating ranges allow minor/patch updates which is acceptable for CDK. CI now runs `cdk synth --strict` (H5) which catches breaking changes. Pinning exact versions adds maintenance burden for minimal benefit.

---

### L2. Pre-commit ruff version diverges from CI

**File:** `.pre-commit-config.yaml:10`

Pre-commit pins `ruff-pre-commit` at `v0.5.4` while CI resolves a different version.

**Fix:** Align versions or add `pre-commit autoupdate` to CI.

- [x] Implemented — updated pre-commit ruff version from `v0.5.4` to `v0.15.4`.

---

### L3. Dead code branch in `S3Store.upload_file`

**File:** `src/envault/s3.py:42-59`

Both branches of `if self._kms_key_id` produce identical `put_object` calls.

**Fix:** Remove dead branch.

- [x] Implemented

---

### L4. CI test matrix uses `fail-fast: true`

**File:** `.github/workflows/ci.yml:76-78`

Version-specific failures masked when earlier Python version fails.

**Fix:** Add `fail-fast: false` to strategy.

- [x] Implemented — added `fail-fast: false` to CI test matrix strategy.

---

### L5. Coverage HTML artifact upload never generated

**File:** `.github/workflows/ci.yml:98-104`

Artifact upload configured but `--cov-report=html` never specified.

**Fix:** Add `--cov-report=html` or remove the upload step.

- [x] Implemented — added `--cov-report=html:htmlcov` to pytest command.
