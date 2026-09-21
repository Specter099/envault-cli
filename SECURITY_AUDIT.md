# Weekly Security Audit — envault-cli

**Reviewer:** Automated weekly static security review
**Date:** 2026-09-21
**Codebase:** `main` @ `4b98446`; remediations on `cursor/repository-security-audit-8de4`
**Scope:** `src/envault/`, `infra/cdk/`, `.github/workflows/`, `code/`, tests, dependency manifests, git history (secret patterns). Static analysis only — no exploit code, no execution of untrusted payloads, no fetches of URLs found in the repo.

---

## Executive summary

Cryptographic foundations remain sound: streaming AES-256-GCM via the AWS Encryption SDK, `REQUIRE_ENCRYPT_REQUIRE_DECRYPT`, mandatory `DiscoveryFilter` with 12-digit account IDs, checksum-before-rename decrypt, and SHA-pinned GitHub Actions with OIDC PyPI publish.

`main` has not moved since 2026-08-09 (`4b98446`). Prior weekly PRs (#110–#114) that remediate these items are still unmerged drafts. This week's scan reproduced the same open findings on `main`, re-lands those remediations, and adds three follow-ups from the 2026-09-14 remaining list.

**This scan (on `main` before remediations):** 0 Critical, 8 High, 7 Medium, 6 Low

**After this PR:** 0 Critical, 2 High (accepted / requires operator action), 4 Medium, 5 Low

---

## Remediations in this PR

Re-landed from #110–#114:

| ID | Severity | Fix |
|----|----------|-----|
| H-1 | High | Remove `kms:DisableKey` from the CMK deny (keep `ScheduleKeyDeletion`) |
| H-2 | High | Drop unused `UpdateItem` / `ListBucket`; scope S3 to `encrypted/*`; grant `sts:GetCallerIdentity` |
| H-3 | High | Encrypt the ops SNS topic with the envault CMK |
| H-4 | High | `decrypt --force`; refuse overwrite *before* `mkstemp` |
| H-5 | High | Reject DynamoDB `s3_key` values that are not `encrypted/{aa}/{sha256}/{name}.encrypted` |
| H-6 | High | `os.walk(followlinks=False)` so encrypt does not follow directory symlink trees |
| H-7 | High | `migrate` confines paths to the import directory; rejects `..` and per-component symlinks |
| H-8 | High | Wire `ENVAULT_AUDIT_TTL_DAYS` on encrypt/decrypt/exec/rotate-key/migrate event writes |
| H-9 | High | `rotate-key` `DescribeKey` preflight before any download/decrypt |
| H-10 | High | `last_updated` CAS tokens use microseconds |
| H-11 | High | Dashboard `last_activity` pages until a CURRENT GSI item survives the filter |
| M-1 | Medium | `exec` warns when inheriting `AWS_*` (default unchanged — breaking if flipped) |
| M-2 | Medium | Close encrypt output fd if the SDK stream fails before `fdopen` |
| M-3 | Medium | Document pip-audit CVE ignore rationale in CI |
| M-4 | Medium | Decrypt nests `fdopen` so a missing ciphertext cannot skip `.part` cleanup |
| M-5 | Medium | `migrate` catches non-object NDJSON / null headers per line instead of aborting |
| M-6 | Medium | `rotate-key` preflight requires `KeyState == Enabled` |

New this week (2026-09-21):

| ID | Severity | Fix |
|----|----------|-----|
| M-E | Medium | Fail closed when `s3_version_id` is empty unless `--latest` is passed |
| H-A | High | CDK context `additional_kms_key_arns` grants extra rotation-target CMKs (no `Resource: *`) |
| H-7b | High | `migrate` requires `import_root`; absolute paths are checked for lexical containment before any `lstat` |

---

## Remaining findings (post-remediation)

### High

#### H-B — Rotation is not a revocation primitive

**Location:** `infra/cdk/stacks/envault_stack.py` (noncurrent version expiration 365 days); `src/envault/cli.py` `rotate-key` re-uploads to the same S3 key

**Issue:** Versioning retains ciphertext wrapped under the old key for 365 days. `s3:GetObjectVersion` is still granted on `encrypted/*`.

**Impact:** Anyone who still has `kms:Decrypt` on the old CMK can read prior versions for a year.

**Fix:** After rotation, disable the old CMK (now possible — H-1). Optionally shorten noncurrent expiration or write rotation to a new object key. Document this as the true revocation boundary.

#### H-C — `exec` inherits AWS credentials by default

**Location:** `src/envault/cli.py` (`exec`, `--clean-env`)

**Issue:** Without `--clean-env`, the child receives the operator's `AWS_*` environment. A warning is now printed; flipping the default is a breaking change.

**Impact:** A compromised or buggy child command can use the operator's AWS credentials.

**Fix:** Prefer `--clean-env` in examples and runbooks. Consider defaulting it in a future major version.

---

### Medium

#### M-A — `state-index` is a two-value partition that also stores events

**Location:** `infra/cdk/stacks/envault_stack.py` (GSI); `src/envault/state.py` `put_event` copies `current_state`

**Issue:** Events inherit `current_state` via `asdict`, so they project into `state-index`. Queries filter them out. The partition key has two values (hot partition at scale). Changing the GSI requires table replacement.

**Impact:** Read cost and latency grow with audit history; dashboard paging (H-11) mitigates emptiness but not cost.

**Fix:** Sparse-index marker (`gsi_state` only on CURRENT items) in a versioned migration.

#### M-B — CDK L2 `kms.Key` default root `kms:*` policy

**Location:** `infra/cdk/stacks/envault_stack.py` `kms.Key(...)`

**Issue:** CDK's L2 construct grants the account root `kms:*`, delegating to IAM. Standard CDK behavior; risky in shared accounts.

**Fix:** For shared accounts, use an explicit key policy (CfnKey) scoped to envault principals.

#### M-C — No lockfile; pip-audit ignores two CVEs

**Location:** `pyproject.toml`; `.github/workflows/ci.yml`, `publish.yml`

**Issue:** Production deps are ranged, not locked. CI ignores CVE-2026-4539 (pygments, not a runtime dep) and CVE-2026-3219 (pip, CI installer). Rationale is now commented.

**Impact:** Reproducible builds and transitive CVE tracking are weaker than a lockfile.

**Fix:** Add `uv.lock` or `requirements.txt` from `pip-compile` for release artifacts.

#### M-D — Filename lookup is O(all encrypted files)

**Location:** `src/envault/state.py` `list_by_file_name`

**Issue:** Queries the whole `ENCRYPTED` GSI partition and filters `file_name` client-side.

**Impact:** `decrypt <name>` cost grows linearly with corpus size.

**Fix:** `name-index` GSI (`file_name`, `encrypted_at`) in a future migration.

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

---

## Strengths verified this week (do not re-open)

- Streaming encrypt/decrypt; checksum and encryption context verified before plaintext is renamed into place
- `DiscoveryFilter` with mandatory 12-digit account IDs; partition derived from region
- `attribute_not_exists(SK)` on audit events; decrypt does not flip CURRENT to DECRYPTED
- SHA-pinned Actions, `permissions: read-all`, OIDC PyPI, gitleaks job
- `os.execvpe` has no shell; `--clean-env` exists
- Filename sanitization for decrypt output (`Path.name`); Rich markup escaped
- No `eval` / `pickle` / `subprocess` with `shell=True` in application code
- `.env` gitignored; `.secrets.baseline` committed; CODEOWNERS present
- Empty S3 VersionId is fail-closed (`--latest` opt-in)
- Content-addressed S3 keys validated before fetch
- Directory-symlink trees skipped on encrypt
- `migrate` confined to the import directory

---

## Prior reports

- `docs/reviews/2026-07-26-deep-review.md` — state-machine findings (mostly fixed in 0.2.0)
- `docs/plans/2026-03-03-security-audit-fixes.md` — original 25-item remediation plan
- This file previously held a 2026-03-04 CISO review of commit `5b575e9`; those Critical items (plaintext-before-checksum, no streaming) are fixed. Historical copy belongs in `docs/reviews/` if needed.

---

## Summary count

**This scan (on `main` before remediations):** 0 Critical, 8 High, 7 Medium, 6 Low

**After this PR:** 0 Critical, 2 High, 4 Medium, 5 Low
