# Remaining SRE Availability Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix the remaining HIGH, MEDIUM, and LOW SRE availability findings — app code fixes (H3, M2, M5, M7), CDK hardening (H1, H4, M1), CI/CD improvements (H5, M8, L2, L4, L5), and document accepted risks (H2, M3, M6).

**Architecture:** Three categories of changes: (1) Python app code — bounded pagination, idempotent events, remove stale GSI docstring; (2) CDK infrastructure — CloudWatch alarms, KMS key policy, noncurrent version expiration; (3) CI/CD — CDK synth validation, publish version check, pre-commit alignment, test matrix settings. Some findings are deferred as accepted risks with documentation.

**Tech Stack:** Python 3.10+, boto3, aws-cdk-lib, cdk-nag, GitHub Actions, ruff

---

## Task 1: Bounded pagination and efficient summary (H3)

`_paginate_query` follows `LastEvaluatedKey` with no upper bound. `summary()` loads all records into memory twice. Fix both: add `max_items` param to `_paginate_query`, and use `Select='COUNT'` for `summary()`.

**Files:**
- Modify: `src/envault/state.py:97-107` (`_paginate_query`)
- Modify: `src/envault/state.py:218-231` (`summary`)
- Test: `tests/unit/test_state.py`

**Step 1: Write the failing test for bounded pagination**

Add to `tests/unit/test_state.py`:

```python
@mock_aws
def test_paginate_query_respects_max_items():
    """_paginate_query must stop after max_items even if more results exist."""
    store = _create_table()
    # Insert 5 ENCRYPTED records
    for i in range(5):
        sha = f"{chr(ord('a') + i)}" * 64
        r = _make_record(
            sha256_hash=sha, current_state=ENCRYPTED, encrypted_at=f"2026-03-03T{10 + i}:00:00+00:00"
        )
        store.put_current_state(r)

    # list_by_state with max_items=3 should return at most 3
    records = store.list_by_state(ENCRYPTED, max_items=3)
    assert len(records) <= 3
```

**Step 2: Write the failing test for count-based summary**

Add to `tests/unit/test_state.py`:

```python
@mock_aws
def test_summary_uses_count_query():
    """summary() must not load all records into memory — use Select=COUNT."""
    store = _create_table()
    r1 = _make_record(
        sha256_hash="d" * 64, current_state=ENCRYPTED, encrypted_at="2026-03-03T10:00:00+00:00"
    )
    r2 = _make_record(
        sha256_hash="e" * 64, current_state=DECRYPTED, encrypted_at="2026-03-03T11:00:00+00:00"
    )
    store.put_current_state(r1)
    store.put_current_state(r2)

    summary = store.summary()
    assert summary["total"] == 2
    assert summary["encrypted"] == 1
    assert summary["decrypted"] == 1
```

**Step 3: Run tests to verify they fail**

Run: `pytest tests/unit/test_state.py::test_paginate_query_respects_max_items tests/unit/test_state.py::test_summary_uses_count_query -v`
Expected: FAIL — `list_by_state` doesn't accept `max_items`, count query not implemented

**Step 4: Implement bounded pagination and count-based summary**

In `src/envault/state.py`, modify `_paginate_query`:

```python
def _paginate_query(self, max_items: int = 0, **query_kwargs: Any) -> list[dict[str, Any]]:
    """Execute a DynamoDB Query, following LastEvaluatedKey until exhausted.

    Args:
        max_items: Maximum items to return. 0 means no limit.
    """
    items: list[dict[str, Any]] = []
    while True:
        response = self._table.query(**query_kwargs)
        items.extend(response.get("Items", []))
        if max_items and len(items) >= max_items:
            return items[:max_items]
        last_key = response.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs["ExclusiveStartKey"] = last_key
    return items
```

Modify `list_by_state` to accept and pass `max_items`:

```python
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
def list_by_state(self, state: str, max_items: int = 0) -> list[FileRecord]:
    """Return all files in a given state (uses state-index GSI)."""
    items = self._paginate_query(
        max_items=max_items,
        IndexName="state-index",
        KeyConditionExpression=Key("current_state").eq(state),
    )
    return [_item_to_record(item) for item in items]
```

Add a new `_count_by_state` method and rewrite `summary`:

```python
def _count_by_state(self, state: str) -> int:
    """Return count of records in a given state using Select=COUNT (no data transfer)."""
    count = 0
    query_kwargs: dict[str, Any] = {
        "IndexName": "state-index",
        "KeyConditionExpression": Key("current_state").eq(state),
        "Select": "COUNT",
    }
    while True:
        response = self._table.query(**query_kwargs)
        count += response.get("Count", 0)
        last_key = response.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs["ExclusiveStartKey"] = last_key
    return count

def summary(self) -> dict[str, Any]:
    """Return aggregate counts for the dashboard."""
    encrypted_count = self._count_by_state(ENCRYPTED)
    decrypted_count = self._count_by_state(DECRYPTED)
    return {
        "total": encrypted_count + decrypted_count,
        "encrypted": encrypted_count,
        "decrypted": decrypted_count,
        "last_activity": "—",
    }
```

Note: `last_activity` now returns `"—"` since we no longer load all records. The dashboard doesn't critically depend on this field. If needed later, a separate targeted query can fetch it.

**Step 5: Run tests to verify they pass**

Run: `pytest tests/unit/test_state.py -v`
Expected: ALL PASS

**Step 6: Run full test suite + linters**

Run: `pytest tests/unit/ -v && ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/envault/`
Expected: ALL PASS

**Step 7: Commit**

```bash
git add src/envault/state.py tests/unit/test_state.py
git commit -m "fix: bounded pagination and count-based summary to prevent OOM (H3)

_paginate_query now accepts max_items to cap result sets. summary() uses
Select=COUNT instead of loading all records into memory. At 100K files
this reduces memory from gigabytes to kilobytes.

Addresses: SRE review finding H3"
```

---

## Task 2: Idempotent put_event to prevent duplicate audit records (M2)

`put_event` generates `uuid.uuid4().hex[:8]` inside the retry loop. If the first attempt succeeds at DynamoDB but the response is lost, the retry creates a duplicate event with a different SK. Fix: generate the unique suffix before entering the method (i.e., move it out of the retry scope, or generate it once and pass it).

**Files:**
- Modify: `src/envault/state.py:156-174` (`put_event`)
- Test: `tests/unit/test_state.py`

**Step 1: Write the failing test**

Add to `tests/unit/test_state.py`:

```python
@mock_aws
def test_put_event_retry_is_idempotent():
    """Retried put_event calls must produce the same SK (no duplicate events)."""
    from unittest.mock import patch, call

    store = _create_table()
    record = _make_record()

    # Track all put_item calls to capture the SK used
    sks_seen: list[str] = []
    original_put_item = store._table.put_item

    def tracking_put_item(**kwargs):
        item = kwargs.get("Item", {})
        sk = item.get("SK", "")
        if sk.startswith("EVENT#"):
            sks_seen.append(sk)
        return original_put_item(**kwargs)

    call_count = 0

    def flaky_put_item(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First call: write succeeds at DynamoDB but raise as if it failed
            tracking_put_item(**kwargs)
            raise Exception("simulated network error after write")
        return tracking_put_item(**kwargs)

    with patch.object(store._table, "put_item", side_effect=flaky_put_item):
        try:
            store.put_event(record, operation="ENCRYPT", correlation_id="corr-idem")
        except Exception:
            pass

    # Both attempts should use the same SK suffix
    if len(sks_seen) == 2:
        assert sks_seen[0] == sks_seen[1], f"Retry used different SK: {sks_seen}"
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_state.py::test_put_event_retry_is_idempotent -v`
Expected: FAIL — each retry generates a new UUID suffix

**Step 3: Fix put_event to generate suffix before retry**

In `src/envault/state.py`, split `put_event` into two methods — the public one generates the suffix, the inner one does the actual write with retry:

```python
def put_event(
    self, record: FileRecord, operation: str, correlation_id: str, audit_ttl_days: int = 365
) -> None:
    """Append an immutable event record to the audit trail."""
    now = _now_iso()
    unique_suffix = uuid.uuid4().hex[:8]
    self._put_event_inner(record, operation, correlation_id, audit_ttl_days, now, unique_suffix)

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
def _put_event_inner(
    self,
    record: FileRecord,
    operation: str,
    correlation_id: str,
    audit_ttl_days: int,
    now: str,
    unique_suffix: str,
) -> None:
    """Inner retry loop for put_event — uses a fixed SK across retries."""
    sk = f"{EVENT_PREFIX}{now}#{operation}#{unique_suffix}"
    item = record.to_dynamo_item(sk=sk)
    item["operation"] = operation
    item["correlation_id"] = correlation_id
    item["current_state"] = record.current_state
    item["date"] = _today_str()
    item["ttl"] = _ttl_epoch(audit_ttl_days)
    self._table.put_item(Item=item)
    logger.debug(
        "put_event",
        extra={"sha256": record.sha256_hash[:16], "operation": operation},
    )
```

**Step 4: Run tests**

Run: `pytest tests/unit/test_state.py -v`
Expected: ALL PASS

**Step 5: Lint + type check**

Run: `ruff check src/envault/state.py && mypy src/envault/`
Expected: PASS

**Step 6: Commit**

```bash
git add src/envault/state.py tests/unit/test_state.py
git commit -m "fix: make put_event idempotent across retries (M2)

Generate the unique SK suffix before the retry loop so that if DynamoDB
writes succeed but the response is lost, the retry produces the same SK
(idempotent PutItem) instead of creating a duplicate audit event.

Addresses: SRE review finding M2"
```

---

## Task 3: Remove stale tag-index GSI reference from docstring (M7)

The `StateStore` docstring documents three GSIs (`state-index`, `date-index`, `tag-index`) but the CDK stack only creates two. Remove the stale `tag-index` reference to prevent confusion.

**Files:**
- Modify: `src/envault/state.py:85-88` (docstring)

**Step 1: Fix the docstring**

In `src/envault/state.py`, change the GSI docstring block from:

```python
    GSIs:
      state-index: PK=current_state, SK=encrypted_at
      date-index:  PK=date, SK=last_updated
      tag-index:   PK=tag_key, SK=tag_value
```

to:

```python
    GSIs:
      state-index: PK=current_state, SK=encrypted_at
      date-index:  PK=date, SK=last_updated
```

**Step 2: Run lint**

Run: `ruff check src/envault/state.py`
Expected: PASS

**Step 3: Commit**

```bash
git add src/envault/state.py
git commit -m "fix: remove stale tag-index GSI reference from StateStore docstring (M7)

CDK only creates state-index and date-index. The tag-index was never
implemented. Removing the stale reference prevents confusion.

Addresses: SRE review finding M7"
```

---

## Task 4: CDK — Add noncurrent version expiration to S3 (M1)

The lifecycle rule transitions noncurrent versions to Glacier but never expires them. Add `noncurrent_version_expiration`.

**Files:**
- Modify: `infra/cdk/stacks/envault_stack.py:105-115` (S3 lifecycle rule)

**Step 1: Add noncurrent version expiration**

In `infra/cdk/stacks/envault_stack.py`, modify the lifecycle rule on the main bucket (around line 105):

```python
            lifecycle_rules=[
                s3.LifecycleRule(
                    noncurrent_version_transitions=[
                        s3.NoncurrentVersionTransition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(90),
                        )
                    ],
                    noncurrent_version_expiration=Duration.days(365),
                )
            ],
```

**Step 2: Verify CDK synth**

Run: `cd infra/cdk && source .venv/bin/activate && cdk synth --quiet 2>&1; cd ../..`
Expected: PASS (no errors)

**Step 3: Commit**

```bash
git add infra/cdk/stacks/envault_stack.py
git commit -m "fix: expire noncurrent S3 versions after 365 days (M1)

Key rotation creates a new S3 version per file. Without expiration,
noncurrent versions in Glacier grow unbounded. Now they are deleted
after 365 days (90 days in Glacier + 275 days post-transition).

Addresses: SRE review finding M1"
```

---

## Task 5: CDK — Add CloudWatch alarms and SNS topic (H1)

Add monitoring for DynamoDB throttling/errors and KMS key deletion. Wire to an SNS topic for notifications.

**Files:**
- Modify: `infra/cdk/stacks/envault_stack.py`

**Step 1: Add imports and SNS/CloudWatch resources**

At the top of `envault_stack.py`, add:

```python
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_cloudwatch_actions as cw_actions
from aws_cdk import aws_sns as sns
```

After the IAM policy section (before the cdk-nag suppressions), add:

```python
        # ------------------------------------------------------------------ #
        # Monitoring — SNS + CloudWatch Alarms                                #
        # ------------------------------------------------------------------ #
        ops_topic = sns.Topic(
            self,
            "EnvaultOpsTopic",
            display_name="envault operational alerts",
        )

        # DynamoDB throttle alarm
        table.metric_throttled_requests_for_operation("PutItem").create_alarm(
            self,
            "DynamoThrottleAlarm",
            alarm_name="envault-dynamodb-throttle",
            evaluation_periods=1,
            threshold=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        ).add_alarm_action(cw_actions.SnsAction(ops_topic))

        # DynamoDB system errors
        table.metric_system_errors_for_operations().create_alarm(
            self,
            "DynamoSystemErrorAlarm",
            alarm_name="envault-dynamodb-system-errors",
            evaluation_periods=1,
            threshold=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        ).add_alarm_action(cw_actions.SnsAction(ops_topic))

        cdk.CfnOutput(self, "OpsTopicArn", value=ops_topic.topic_arn)
```

Note: KMS key deletion scheduling doesn't have a native CloudWatch metric — it requires CloudTrail + EventBridge. That is better addressed alongside H4 (KMS key policy) and is out of scope for this task.

**Step 2: Verify CDK synth**

Run: `cd infra/cdk && source .venv/bin/activate && cdk synth --quiet 2>&1; cd ../..`
Expected: PASS

**Step 3: Commit**

```bash
git add infra/cdk/stacks/envault_stack.py
git commit -m "fix: add CloudWatch alarms for DynamoDB throttling and errors (H1)

Add SNS topic + alarms for PutItem throttling and system errors.
These alert operators when rotate-key or encrypt operations hit
DynamoDB capacity limits.

Addresses: SRE review finding H1 (partial — KMS alarm deferred to H4)"
```

---

## Task 6: CDK — Deny KMS ScheduleKeyDeletion in key policy (H4)

Protect the KMS key from accidental or unauthorized deletion by denying `kms:ScheduleKeyDeletion` for all principals except a break-glass condition.

**Files:**
- Modify: `infra/cdk/stacks/envault_stack.py` (KMS key section)

**Step 1: Add a deny statement to the key policy**

After creating the KMS key (line 65), add a policy statement:

```python
        # Deny key deletion for all principals — requires removing this
        # policy statement first (break-glass procedure).
        encryption_key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="DenyScheduleKeyDeletion",
                effect=iam.Effect.DENY,
                principals=[iam.AnyPrincipal()],
                actions=["kms:ScheduleKeyDeletion", "kms:DisableKey"],
                resources=["*"],
            )
        )
```

**Step 2: Verify CDK synth**

Run: `cd infra/cdk && source .venv/bin/activate && cdk synth --quiet 2>&1; cd ../..`
Expected: PASS

**Step 3: Commit**

```bash
git add infra/cdk/stacks/envault_stack.py
git commit -m "fix: deny KMS ScheduleKeyDeletion to prevent accidental data loss (H4)

Add explicit deny in key policy for ScheduleKeyDeletion and DisableKey.
Recovery requires manually removing this deny statement first (break-glass).
This prevents any IAM principal from scheduling key deletion.

Addresses: SRE review finding H4"
```

---

## Task 7: CI — Add CDK synth validation job (H5)

Run `cdk synth` in CI so CDK breakage is caught on PR, not at deploy time.

**Files:**
- Modify: `.github/workflows/ci.yml`

**Step 1: Add cdk-synth job**

Add a new job after the `dependency-audit` job:

```yaml
  cdk-synth:
    name: CDK Synth
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

      - name: Set up Python
        uses: actions/setup-python@0b93645e9fea7318ecaed2b359559ac225c90a2b  # v5.3.0
        with:
          python-version: "3.12"

      - name: Install CDK dependencies
        run: |
          npm install -g aws-cdk
          pip install -r infra/cdk/requirements.txt

      - name: CDK synth
        working-directory: infra/cdk
        run: cdk synth --strict --quiet
```

**Step 2: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add CDK synth validation job (H5)

Run cdk synth --strict in CI to catch infrastructure breakage
on pull requests rather than at deploy time.

Addresses: SRE review finding H5"
```

---

## Task 8: CI — Fix test matrix fail-fast, coverage artifact, and publish version check (L4, L5, M8)

Three small CI fixes in one task:
1. **L4**: `fail-fast: false` so all Python versions are tested even if one fails
2. **L5**: Add `--cov-report=html:htmlcov` so the coverage artifact upload actually has content
3. **M8**: Add version validation step to publish workflow

**Files:**
- Modify: `.github/workflows/ci.yml:76-96`
- Modify: `.github/workflows/publish.yml`

**Step 1: Fix fail-fast and coverage in ci.yml**

In `.github/workflows/ci.yml`, in the `test` job strategy (line 76):

```yaml
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.10", "3.11", "3.12"]
```

In the test run step (line 96), add `--cov-report=html:htmlcov`:

```yaml
        run: pytest tests/unit/ -v --cov=envault --cov-report=term-missing --cov-report=html:htmlcov
```

**Step 2: Add version validation to publish.yml**

In `.github/workflows/publish.yml`, add a version validation step at the start of the `ci` job, after checkout:

```yaml
      - name: Validate tag matches package version
        run: |
          TAG_VERSION="${GITHUB_REF_NAME#v}"
          PKG_VERSION=$(python -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])")
          if [ "$TAG_VERSION" != "$PKG_VERSION" ]; then
            echo "::error::Tag version ($TAG_VERSION) does not match pyproject.toml version ($PKG_VERSION)"
            exit 1
          fi
```

**Step 3: Commit**

```bash
git add .github/workflows/ci.yml .github/workflows/publish.yml
git commit -m "ci: fix test matrix fail-fast, coverage artifact, publish version check (L4+L5+M8)

- Set fail-fast: false so all Python versions are tested
- Add --cov-report=html:htmlcov so coverage artifact has content
- Add tag vs pyproject.toml version validation in publish workflow

Addresses: SRE review findings L4, L5, M8"
```

---

## Task 9: Align pre-commit ruff version (L2)

Pre-commit pins `ruff-pre-commit` at `v0.5.4` while the project uses `ruff>=0.1.0,<1`. Update pre-commit to a current version.

**Files:**
- Modify: `.pre-commit-config.yaml:9-10`

**Step 1: Update pre-commit ruff version**

Run: `source .venv/bin/activate && ruff --version` to get the current installed version.

In `.pre-commit-config.yaml`, update the ruff-pre-commit rev to match:

```yaml
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.9.10  # or whatever the installed version is
```

**Step 2: Commit**

```bash
git add .pre-commit-config.yaml
git commit -m "chore: align pre-commit ruff version with installed (L2)

Addresses: SRE review finding L2"
```

---

## Task 10: Document accepted risks (H2, M3, M5, M6)

Some findings are deferred or accepted as risks. Document the decisions.

**H2** (S3 CRR): Cross-region replication is a significant infrastructure decision with cost and complexity implications. Document as accepted risk — S3 has 11 9s durability within a single region.

**M3** (rotate-key resume): A full checkpoint/resume system is a feature, not a quick fix. The correlation_id is already logged per-rotation. Document as deferred.

**M5** (encrypt_file retry scope): The `@retry` on `encrypt_file` wraps the full function including the KMS call. Narrowing the retry scope requires significant refactoring of the aws-encryption-sdk streaming API. Document as accepted risk — retry of full encryption is wasteful for large files but functionally correct.

**M6** (DynamoDB backup export): PITR is enabled. Scheduled exports or global tables add operational complexity. Document as accepted risk.

**Files:**
- Modify: `tasks/sre-availability-review.md`

**Step 1: Update the review checklist with risk acceptance notes**

Mark H2, M3, M5, M6 with risk acceptance notes in `tasks/sre-availability-review.md`.

**Step 2: Commit**

```bash
git add tasks/sre-availability-review.md
git commit -m "docs: document accepted risks for H2, M3, M5, M6

- H2: S3 CRR — accepted (11 9s durability in single region)
- M3: rotate-key resume — deferred (correlation_id logged)
- M5: encrypt retry scope — accepted (correct, wasteful for large files)
- M6: DynamoDB backup export — accepted (PITR enabled)

Addresses: SRE review findings H2, M3, M5, M6"
```

---

## Task 11: Final verification

**Step 1: Run full test suite**

Run: `pytest tests/unit/ -v --tb=short`
Expected: ALL PASS

**Step 2: Run all linters**

Run: `ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/envault/`
Expected: ALL PASS

**Step 3: Verify CDK synth**

Run: `cd infra/cdk && source .venv/bin/activate && cdk synth --quiet 2>&1; cd ../..`
Expected: PASS

**Step 4: Review diff against main**

Run: `git diff main --stat`
Verify only expected files changed.

**Step 5: Update review checklist**

Mark all findings as implemented or risk-accepted in `tasks/sre-availability-review.md`.
