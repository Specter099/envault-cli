# Weekly Security Audit — envault-cli

**Reviewer:** Automated weekly static security review
**Date:** 2026-10-26
**Codebase:** `main` @ `a58ea77`; remediations on `cursor/repository-security-audit-58ca`
**Scope:** `src/envault/`, `infra/cdk/`, `.github/workflows/`, `code/`, tests, dependency manifests, git history (secret patterns). Static analysis only — no exploit code, no execution of untrusted payloads, no fetches of URLs found in the repo.

---

## Executive summary

Cryptographic foundations remain sound: streaming AES-256-GCM via the AWS Encryption SDK, `REQUIRE_ENCRYPT_REQUIRE_DECRYPT`, mandatory `DiscoveryFilter` with 12-digit account IDs, checksum-before-rename decrypt, and SHA-pinned GitHub Actions with OIDC PyPI publish.

`main` has not moved since #115 (2026-09-21) and #116. Draft PRs #117–#122 that remediate symlink TOCTOU, VersionId fail-closed, and KMS ARN glob rejection are still unmerged. This week's scan reproduced those findings on `main`, re-lands them (via #122), and adds four follow-ups: `migrate` `FROM_PATH` `O_NOFOLLOW`, S3 bucket denies for non-KMS `PutObject`, `persist-credentials: false` on Actions checkouts, and explicit `BUCKET_OWNER_ENFORCED`.

No hardcoded secrets in the current tree or scanned git history (pattern search over recent commits; `.env` is gitignored; `code/output.json` is not in history).

**This scan (on `main` before remediations):** 0 Critical, 6 High, 16 Medium, 10 Low

**After this PR:** 0 Critical, 2 High (accepted / requires operator action), 6 Medium, 7 Low

---

## Remediations in this PR

Re-landed from #117–#122:

| ID | Severity | Fix |
|----|----------|-----|
| H-D | High | `sha256_file` / `encrypt_file` / S3 `download_file` open with `O_NOFOLLOW` |
| H-E | High | CDK `additional_kms_key_arns` requires a 12-digit account and rejects wildcards |
| H-F | High | S3 upload fails closed when PutObject returns no VersionId |
| H-G | High | `KmsViaStorageServices` includes `additional_kms_key_arns` so `rotate-key` SSE-KMS upload can use the new CMK |
| H-H | High | `open_nofollow` fails closed when `O_NOFOLLOW` is missing instead of `getattr(..., 0)` |
| M-8 | Medium | `best_effort_delete` uses `O_NOFOLLOW`; symlink targets are not overwritten |
| M-9 | Medium | `migrate` rejects non-string encryption-context keys/values; empty context is warned |
| M-10 | Medium | Pin `pygments>=2.20.0` (CVE-2026-4539); Dependabot watches `/infra/cdk` |
| M-11 | Medium | ISO partition mapping; dashboard escapes `last_activity` |
| M-12 | Medium | CI/publish `pip-audit -r infra/cdk/requirements.txt`; pin `pip-audit>=2.7,<3` |
| M-13 | Medium | `migrate` treats `EnvaultError`/`OSError` per line; `file_size_bytes` from `lstat` |
| M-14 | Medium | `decrypt_file` and `upload_file` open ciphertext with `O_NOFOLLOW` |
| M-15 | Medium | `rotate-key` refuses to replace S3 if the in-flight encrypt hash ≠ `record.sha256_hash` |
| L-6 | Low | `encrypt_file` / `sha256_file` `finally` wraps each `os.close` so a failing first close cannot skip the second |

New this week (2026-10-26):

| ID | Severity | Fix |
|----|----------|-----|
| M-16 | Medium | `migrate` reads `FROM_PATH` with `O_NOFOLLOW` so a swapped-in symlink cannot redirect the NDJSON import |
| M-17 | Medium | Data bucket denies `s3:PutObject` unless SSE is `aws:kms` (missing header or AES256) |
| L-9 | Low | Actions checkouts set `persist-credentials: false` |
| L-10 | Low | S3 buckets set `ObjectOwnership.BUCKET_OWNER_ENFORCED` (ACLs disabled) |

---

## Remaining findings (post-remediation)

### High

#### H-B — Rotation is not a revocation primitive

**Location:** `infra/cdk/stacks/envault_stack.py` (noncurrent version expiration 365 days); `src/envault/cli.py` `rotate-key` re-uploads to the same S3 key

**Issue:** Versioning retains ciphertext wrapped under the old key for 365 days. `s3:GetObjectVersion` is still granted on `encrypted/*`.

**Impact:** Anyone who still has `kms:Decrypt` on the old CMK can read prior versions for a year.

**Fix:** After rotation, disable the old CMK (now possible — `DisableKey` is not denied). Optionally shorten noncurrent expiration or write rotation to a new object key. Document this as the true revocation boundary.

```python
# Operator incident response, not a code change:
aws kms disable-key --key-id alias/previous-envault-key
```

#### H-C — `exec` inherits AWS credentials by default

**Location:** `src/envault/cli.py` (`exec`, `--clean-env`)

**Issue:** Without `--clean-env`, the child receives the operator's `AWS_*` environment. A warning is printed; flipping the default is a breaking change.

**Impact:** A compromised or buggy child command can use the operator's AWS credentials.

**Fix:** Prefer `--clean-env` in examples and runbooks. Consider defaulting it in a future major version.

---

### Medium

#### M-A — `state-index` is a two-value partition that also stores legacy events

**Location:** `infra/cdk/stacks/envault_stack.py` (GSI); `src/envault/state.py` `put_event`

**Issue:** New events use `record_state` and stay out of `state-index`. Legacy `EVENT#` rows still project into the index until TTL. The partition key has two values (hot partition at scale). Changing the GSI requires table replacement.

**Impact:** Read cost and latency grow with historical audit rows until they expire.

**Fix:** Sparse-index marker (`gsi_state` only on CURRENT items) in a versioned migration.

#### M-B — CDK L2 `kms.Key` default root `kms:*` policy

**Location:** `infra/cdk/stacks/envault_stack.py` `kms.Key(...)`

**Issue:** CDK's L2 construct grants the account root `kms:*`, delegating to IAM. Standard CDK behavior; risky in shared accounts.

**Fix:** For shared accounts, use an explicit key policy (`CfnKey`) scoped to envault principals.

#### M-C — No lockfile; pip-audit ignores CVE-2026-3219

**Location:** `pyproject.toml`; `.github/workflows/ci.yml`, `publish.yml`

**Issue:** Production deps are ranged, not locked. CI still ignores CVE-2026-3219 (pip, CI installer) with a comment. `pip-audit` is now ranged `>=2.7,<3`. pygments is pinned past CVE-2026-4539.

**Impact:** Reproducible builds and transitive CVE tracking are weaker than a lockfile.

**Fix:** Add `uv.lock` or `requirements.txt` from `pip-compile` for release artifacts.

#### M-D — Filename lookup is O(all encrypted files)

**Location:** `src/envault/state.py` `list_by_file_name`

**Issue:** Queries the whole `ENCRYPTED` GSI partition and filters `file_name` client-side.

**Impact:** `decrypt <name>` cost grows linearly with corpus size.

**Fix:** `name-index` GSI (`file_name`, `encrypted_at`) in a future migration.

#### M-E — Empty migrated `encryption_context` makes AAD checks a no-op

**Location:** `src/envault/crypto.py` `verify_encryption_context`; `src/envault/cli.py` `_parse_output_json_entry`

**Issue:** `any(...)` over an empty expected dict never fires. `migrate` now warns and rejects non-string values, but an empty/partial context still skips the four application keys. Checksum still binds plaintext. Synthesizing keys in DynamoDB would break decrypt, because they were never bound into the ciphertext.

**Impact:** A substituted ciphertext of the same plaintext (or a checksum collision) would not be rejected on `purpose` / `file_name` / `kms_key_alias`.

**Fix:** After migrate, require the four application keys in the ciphertext header (or refuse decrypt when they are absent).

#### M-F — IAM `PutItem` cannot enforce append-only audit events

**Location:** `infra/cdk/stacks/envault_stack.py` `DynamoDBStateAccess`; `src/envault/state.py` `_put_event_inner`

**Issue:** The CLI uses `attribute_not_exists(SK)` on events. The managed policy still grants unconditional `dynamodb:PutItem`, so a principal using the AWS API directly can overwrite `EVENT#` items or rewrite `ttl`.

**Impact:** Audit integrity is client-side. Evidence-grade trails need a write path the CLI principal cannot bypass.

**Fix:** Split event writes through a constrained statement (`dynamodb:LeadingKeys` + deny overwrite of `EVENT#`), or write events via a Lambda the CLI cannot skip.

---

### Low

#### L-1 — GSI projections use `ALL`

**Location:** `infra/cdk/stacks/envault_stack.py`

Changing projection forces table replacement. Acceptable for current query patterns (`rotate-key` reads all attributes). For new stacks, consider `INCLUDE`.

#### L-2 — Access logs bucket uses S3-managed encryption

**Location:** `infra/cdk/stacks/envault_stack.py` `EnvaultAccessLogsBucket`

Log delivery to a CMK-encrypted bucket needs extra key-policy grants. S3-managed SSE plus `BLOCK_ALL` and TLS is acceptable for access logs.

#### L-3 — No MFA Delete on the versioned data bucket

Requires root credentials; cannot be set via CDK. Document as a post-deploy step.

#### L-4 — Fake AWS credentials in CI are job-scoped

**Location:** `.github/workflows/ci.yml` test job env. Intentional for moto. Keep them off later steps.

#### L-5 — No object-delete / purge CLI path

Storage grows monotonically. Honouring a deletion request requires a new command plus a tightly scoped `s3:DeleteObject` grant (not present today).

#### L-7 — Library `encrypt_file` can leave partial ciphertext at `output_path`

The CLI unlinks its temp file. Callers of the library function should delete `output_path` on exception. Not changed this week.

#### L-8 — `migrate` CURRENT-then-event gap

If `put_current_state` succeeds and `put_event` fails, a retry hits `StateConflictError` and skips, leaving CURRENT without an ENCRYPT event. Swapping order would emit duplicate events on re-run of already-imported hashes. Left as a documented residual.

---

## Findings closed this week (do not re-open)

See the remediations table. In addition to the #122 set:

- `migrate` `from_path.read_text()` following a final-component symlink → `open_nofollow` (M-16)
- Data bucket accepting AES256 / header-less PutObject → deny statements (M-17)
- Actions checkout persisting `GITHUB_TOKEN` in the local git helper → `persist-credentials: false` (L-9)
- S3 ACL mutability → `BUCKET_OWNER_ENFORCED` (L-10)

---

## Strengths verified this week (do not re-open)

- Streaming encrypt/decrypt; checksum and encryption context verified before plaintext is renamed into place
- `DiscoveryFilter` with mandatory 12-digit account IDs; partition derived from region (including ISO)
- `attribute_not_exists(SK)` on audit events; decrypt does not flip CURRENT to DECRYPTED
- SHA-pinned Actions, `permissions: read-all`, OIDC PyPI, gitleaks job; no `pull_request_target`
- `os.execvpe` has no shell; `--clean-env` exists
- Filename sanitization for decrypt output (`Path.name`); Rich markup escaped
- No `eval` / `pickle` / `subprocess` with `shell=True` in application code
- `.env` gitignored; `.secrets.baseline` committed; CODEOWNERS present
- Empty S3 VersionId is fail-closed (`--latest` opt-in); unversioned PutObject is also fail-closed
- Content-addressed S3 keys validated before fetch
- Directory-symlink trees skipped on encrypt
- `migrate` confined to the import directory; per-component symlinks rejected; `FROM_PATH` itself is `O_NOFOLLOW`
- cdk-nag suppressions for IAM5 include justification comments (S3 prefix, GSI, `sts:GetCallerIdentity`)
- No Dockerfiles in this repo
- Legacy `code/*.sh` isolate `.env` to `S3_BUCKET` / `KMS_ACCOUNT_ID`; no `aws s3 sync` of `code/`

---

## Prior reports

- `docs/reviews/2026-07-26-deep-review.md` — state-machine findings (mostly fixed in 0.2.0)
- `docs/plans/2026-03-03-security-audit-fixes.md` — original 25-item remediation plan
- Unmerged drafts #117–#122 — re-landed here

---

## Summary count

**This scan (on `main` before remediations):** 0 Critical, 6 High, 16 Medium, 10 Low

**After this PR:** 0 Critical, 2 High, 6 Medium, 7 Low

Verification: `pytest tests/unit/` — **197 passed**; ruff clean. mypy reports a pre-existing tenacity return-type error in `retry.py` (file unchanged). Crypto-safety inspector: PASS (8/8). Migration-safety inspector: PASS (6/6).
