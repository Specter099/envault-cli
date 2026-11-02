# Weekly Security Audit — envault-cli

**Reviewer:** Automated weekly static security review
**Date:** 2026-11-02
**Codebase:** `main` @ `a58ea77`; remediations on `cursor/repository-security-review-4e01`
**Scope:** `src/envault/`, `infra/cdk/`, `.github/workflows/`, `code/`, tests, dependency manifests, git history (secret patterns). Static analysis only — no exploit code, no execution of untrusted payloads, no fetches of URLs found in the repo.

---

## Executive summary

Cryptographic foundations remain sound: streaming AES-256-GCM via the AWS Encryption SDK, `REQUIRE_ENCRYPT_REQUIRE_DECRYPT`, mandatory `DiscoveryFilter` with 12-digit account IDs, checksum-before-rename decrypt, and SHA-pinned GitHub Actions with OIDC PyPI publish.

`main` has not moved since 2026-09-25 (`a58ea77`, #115/#116). Drafts #117–#123 remain unmerged; this PR re-lands those remediations and adds three library-path follow-ups from this week's remaining list.

**This scan (on `main` before remediations):** 0 Critical, 6 High, 16 Medium, 10 Low

**After this PR:** 0 Critical, 2 High (accepted / requires operator action), 6 Medium, 7 Low

---

## Remediations in this PR

Re-landed from #117–#123:

| ID | Severity | Fix |
|----|----------|-----|
| H-D | High | CDK `additional_kms_key_arns` requires a 12-digit account and rejects globs |
| H-E | High | `sha256_file` / `encrypt_file` open plaintext with `O_NOFOLLOW` |
| H-F | High | S3 `download_file` writes via `O_NOFOLLOW` + `download_fileobj` + `fchmod` |
| H-G | High | `best_effort_delete` opens with `O_NOFOLLOW` (symlink: skip overwrite, still unlink) |
| H-H | High | S3 upload fails closed when PutObject returns no VersionId |
| M-8 | Medium | `open_nofollow` fails closed if `O_NOFOLLOW` is missing |
| M-9 | Medium | `decrypt_file` / `upload_file` open ciphertext with `O_NOFOLLOW` |
| M-10 | Medium | pygments `>=2.20.0` (CVE-2026-4539); pip-audit no longer ignores it |
| M-11 | Medium | `KmsViaStorageServices` includes extra rotation-target CMKs |
| M-12 | Medium | `rotate-key` compares in-flight encrypt hash to `record.sha256_hash` before S3 replace |
| M-13 | Medium | ISO partitions (`aws-iso`, `aws-iso-b/e/f`) |
| M-14 | Medium | `migrate` rejects non-string encryption-context keys/values |
| M-15 | Medium | Dependabot `/infra/cdk`; CDK `requirements.txt` pip-audit; `pip-audit>=2.7,<3` |
| M-16 | Medium | `migrate` reads `FROM_PATH` with `open_nofollow` |
| M-17 | Medium | Data bucket denies PutObject unless SSE is `aws:kms` |
| L-8 | Low | Dashboard `last_activity` is Rich-escaped |
| L-9 | Low | Actions checkout `persist-credentials: false` |
| L-10 | Low | S3 `ObjectOwnership.BUCKET_OWNER_ENFORCED` |

New this week (2026-11-02):

| ID | Severity | Fix |
|----|----------|-----|
| M-18 | Medium | `encrypt_file` sets `max_encrypted_data_keys=1` (parity with decrypt) |
| M-19 | Medium | `decrypt_to_stream` / `decrypt_file` reject non-12-digit account IDs before DiscoveryFilter |
| M-20 | Medium | `encrypt_file` unlinks partial ciphertext at `output_path` if the SDK stream fails after `O_TRUNC` |

---

## Remaining findings (post-remediation)

### High

#### H-B — Rotation is not a revocation primitive

**Location:** `infra/cdk/stacks/envault_stack.py` (noncurrent version expiration 365 days); `src/envault/cli.py` `rotate-key` re-uploads to the same S3 key

**Issue:** Versioning retains ciphertext wrapped under the old key for 365 days. `s3:GetObjectVersion` is still granted on `encrypted/*`.

**Impact:** Anyone who still has `kms:Decrypt` on the old CMK can read prior versions for a year.

**Fix:** After rotation, disable the old CMK (now possible — H-1). Optionally shorten noncurrent expiration or write rotation to a new object key. Document this as the true revocation boundary. README already notes this.

#### H-C — `exec` inherits AWS credentials by default

**Location:** `src/envault/cli.py` (`exec`, `--clean-env`)

**Issue:** Without `--clean-env`, the child receives the operator's `AWS_*` environment. A warning is printed; flipping the default is a breaking change.

**Impact:** A compromised or buggy child command can use the operator's AWS credentials.

**Fix:** Prefer `--clean-env` in examples and runbooks (README already does). Consider defaulting it in a future major version.

---

### Medium

#### M-A — `state-index` still holds legacy EVENT rows

**Location:** `infra/cdk/stacks/envault_stack.py` (GSI); `src/envault/state.py` `put_event`

**Issue:** New events store `record_state` (not `current_state`) so they stay out of `state-index`. Legacy EVENT rows still project until TTL. Changing the GSI requires table replacement. The partition key still has two values (hot partition at scale).

**Impact:** Read cost and latency grow with remaining audit history until TTL.

**Fix:** Sparse-index marker (`gsi_state` only on CURRENT items) in a versioned table replacement.

#### M-B — CDK L2 `kms.Key` default root `kms:*` policy

**Location:** `infra/cdk/stacks/envault_stack.py` `kms.Key(...)`

**Issue:** CDK's L2 construct grants the account root `kms:*`, delegating to IAM. Standard CDK behavior; risky in shared accounts.

**Fix:** For shared accounts, use an explicit key policy (CfnKey) scoped to envault principals.

#### M-C — No lockfile; pip-audit ignores CVE-2026-3219

**Location:** `pyproject.toml`; `.github/workflows/ci.yml`, `publish.yml`

**Issue:** Production deps are ranged, not locked. CI still ignores CVE-2026-3219 (pip itself, CI installer). pygments is now pinned.

**Impact:** Reproducible builds and transitive CVE tracking are weaker than a lockfile.

**Fix:** Add `uv.lock` or `requirements.txt` from `pip-compile` for release artifacts.

#### M-D — Filename lookup is O(all encrypted files)

**Location:** `src/envault/state.py` `list_by_file_name`

**Issue:** Queries the whole `ENCRYPTED` GSI partition and filters `file_name` client-side.

**Impact:** `decrypt <name>` cost grows linearly with corpus size.

**Fix:** `name-index` GSI (`file_name`, `encrypted_at`) in a future migration.

#### M-E — Empty migrated encryption context skips AAD checks

**Location:** `src/envault/crypto.py` `verify_encryption_context`; `src/envault/cli.py` `_parse_output_json_entry`

**Issue:** `verify_encryption_context` only checks keys present in `expected`. An empty migrated context is a no-op on `purpose`/`sha256`/`file_name`/`kms_key_alias`. Checksum still binds. Migrate now warns and rejects non-string values.

**Impact:** Substituted ciphertext that hashes to the same plaintext would not be caught by context checks on migrated records.

**Fix:** Treat empty context as a migrate skip, or require the four app keys before writing CURRENT.

#### M-F — IAM `PutItem` cannot enforce append-only

**Location:** `infra/cdk/stacks/envault_stack.py` DynamoDB statement; `src/envault/state.py` `put_event`

**Issue:** The managed policy allows `PutItem` on the whole table. Append-only is a client-side `attribute_not_exists(SK)` condition. Anyone holding the policy can overwrite CURRENT (CAS is also client-side).

**Impact:** A stolen CLI identity can mutate current state and, with a guessed SK, attempt to overwrite events (condition fails if the SK already exists; a new SK forges history).

**Fix:** Split writer roles, or use DynamoDB Streams + a verifier. Document as a trust boundary of the managed policy.

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

#### L-6 — `migrate` directory-symlink parent of FROM_PATH

**Location:** `src/envault/cli.py` `import_root = from_path.parent.resolve()`

`O_NOFOLLOW` refuses only the final FROM_PATH component. A directory-symlink parent is resolved and becomes `import_root`, widening the import sandbox to that real directory.

#### L-7 — Pre-commit hooks pinned to tags, not SHAs

**Location:** `.pre-commit-config.yaml`

`rev: v1.5.0` / `v0.15.4` / `v4.6.0` can be retagged. GitHub Actions are SHA-pinned. Pin pre-commit `rev` to commit SHAs for the same guarantee.

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
- Empty S3 VersionId is fail-closed (`--latest` opt-in)
- Content-addressed S3 keys validated before fetch
- Directory-symlink trees skipped on encrypt
- `migrate` confined to the import directory; FROM_PATH itself is `O_NOFOLLOW`
- No hardcoded production secrets in the tree or sampled git history (test fixtures use `testing`)
- cdk-nag suppressions for IAM5 include justification comments scoped to `encrypted/*`, `index/*`, and `sts:GetCallerIdentity`
- No Dockerfiles in this repo

---

## Prior reports

- `docs/reviews/2026-07-26-deep-review.md` — state-machine findings (mostly fixed in 0.2.0)
- `docs/plans/2026-03-03-security-audit-fixes.md` — original 25-item remediation plan
- Weekly PRs #110–#114 (closed unmerged), #115 (merged 2026-09-25), #117–#123 (open drafts this PR supersedes)

---

## Summary count

**This scan (on `main` before remediations):** 0 Critical, 6 High, 16 Medium, 10 Low

**After this PR:** 0 Critical, 2 High, 6 Medium, 7 Low

Verification: `pytest tests/unit/` — **199 passed**; ruff clean. mypy: pre-existing tenacity return-type error in `retry.py` (unchanged). Crypto-safety inspector: PASS (8/8). Migration-safety inspector: PASS (6/6).
