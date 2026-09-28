# Weekly Security Audit — envault-cli

**Reviewer:** Automated weekly static security review
**Date:** 2026-09-28
**Codebase:** `main` @ `a58ea77`; remediations on `cursor/repository-security-audit-320c`
**Scope:** `src/envault/`, `infra/cdk/`, `.github/workflows/`, `code/`, tests, dependency manifests, git history (secret patterns). Static analysis only — no exploit code, no execution of untrusted payloads, no fetches of URLs found in the repo.

---

## Executive summary

Last week's remediations (#115, 2026-09-21) and the follow-up TTL/dead-code PR (#116) are on `main`. Cryptographic foundations remain sound: streaming AES-256-GCM via the AWS Encryption SDK, `REQUIRE_ENCRYPT_REQUIRE_DECRYPT`, mandatory `DiscoveryFilter` with 12-digit account IDs, checksum-before-rename decrypt, sparse `state-index` for new events, and SHA-pinned GitHub Actions with OIDC PyPI publish.

This week's scan found no Critical issues. New High/Medium items that can be fixed in code are remediations in this PR. Remaining High items are operator/revocation policy, not bugs in the encrypt path.

**This scan (on `main` before remediations):** 0 Critical, 3 High, 8 Medium, 6 Low

**After this PR:** 0 Critical, 2 High (accepted / requires operator action), 5 Medium, 6 Low

---

## Remediations in this PR

| ID | Severity | Fix |
|----|----------|-----|
| H-1 | High | `S3Store.upload_file` fails closed when PutObject returns no VersionId |
| M-1 | Medium | `best_effort_delete` uses `O_NOFOLLOW`; symlink targets are not zeroed |
| M-2 | Medium | CDK `additional_kms_key_arns` requires a 12-digit account and rejects `*`/`?` |
| M-3 | Medium | `migrate` rejects non-string encryption-context keys/values |
| M-4 | Medium | Dependabot watches `/infra/cdk`; CI/publish pin `pip-audit>=2.7,<3` |
| L-I | Low | Discovery partition map includes AWS ISO partitions |
| L-S | Low | `download_file` refuses a symlink destination |

---

## Findings

### High

#### H-B — Rotation is not a revocation primitive *(accepted)*

**Location:** `infra/cdk/stacks/envault_stack.py` (noncurrent version expiration 365 days); `src/envault/cli.py` `rotate-key` re-uploads to the same S3 key

**Issue:** Versioning retains ciphertext wrapped under the old key for 365 days. `s3:GetObjectVersion` is still granted on `encrypted/*`.

**Impact:** Anyone who still has `kms:Decrypt` on the old CMK can read prior versions for a year.

**Fix:** After rotation, disable the old CMK (`kms:DisableKey` is allowed; `ScheduleKeyDeletion` remains denied). Optionally shorten noncurrent expiration or write rotation to a new object key. Document disable-the-old-CMK as the true revocation boundary.

#### H-C — `exec` inherits AWS credentials by default *(accepted; breaking to flip)*

**Location:** `src/envault/cli.py` (`exec`, `--clean-env`)

**Issue:** Without `--clean-env`, the child receives the operator's `AWS_*` environment. A warning is printed; flipping the default is a breaking change.

**Impact:** A compromised or buggy child command can use the operator's AWS credentials.

**Fix:** Prefer `--clean-env` in examples and runbooks. Consider defaulting it in a future major version.

#### H-1 — Encrypt succeeded against an unversioned bucket *(fixed in this PR)*

**Location:** `src/envault/s3.py` `upload_file` (previously returned `""`)

**Issue:** If the bucket is not versioned, PutObject has no VersionId. Encrypt stored an empty pin; decrypt then required `--latest`, which follows later overwrites.

**Impact:** A subsequent PutObject on the same key could be decrypted as if it were the original ciphertext.

**Fix:** Raise `EnvaultError` unless VersionId is present. Enable versioning (CDK already does).

---

### Medium

#### M-A — Legacy events still project into `state-index`

**Location:** `src/envault/state.py` `put_event` (new events pop `current_state` → `record_state`); table GSI

**Issue:** New events stay out of `state-index`. Events written before #115 still carry `current_state` until TTL.

**Impact:** Read cost and latency on `status` / filename lookup / dashboard until those items expire.

**Fix:** Wait for TTL, or a one-off rewrite that removes `current_state` from old EVENT items. A sparse-index attribute (`gsi_state` only on CURRENT) still needs table replacement.

#### M-B — CDK L2 `kms.Key` default root `kms:*` policy

**Location:** `infra/cdk/stacks/envault_stack.py` `kms.Key(...)`

**Issue:** CDK's L2 construct grants the account root `kms:*`, delegating to IAM. Standard CDK behavior; risky in shared accounts.

**Impact:** Any principal in the account that can create IAM policy can use the CMK.

**Fix:** For shared accounts, use an explicit key policy (`CfnKey`) scoped to envault principals. Do not drop the root grant without a replacement admin principal (lockout).

#### M-C — No lockfile; pip-audit ignores two CVEs

**Location:** `pyproject.toml`; `.github/workflows/ci.yml`, `publish.yml`

**Issue:** Production deps are ranged, not locked. CI ignores CVE-2026-4539 (pygments, not a runtime dep) and CVE-2026-3219 (pip, CI installer). `pip-audit` is now ranged `>=2.7,<3` rather than floating to whatever PyPI serves.

**Impact:** Reproducible builds and transitive CVE tracking are weaker than a lockfile.

**Fix:** Add `uv.lock` or `requirements.txt` from `pip-compile` for release artifacts.

#### M-D — Filename lookup is O(all encrypted files)

**Location:** `src/envault/state.py` `list_by_file_name`

**Issue:** Queries the whole `ENCRYPTED` GSI partition and filters `file_name` client-side.

**Impact:** `decrypt <name>` cost grows linearly with corpus size.

**Fix:** `name-index` GSI (`file_name`, `encrypted_at`) in a future migration.

#### M-E — Empty migrated `encryption_context` skips AAD checks

**Location:** `src/envault/crypto.py` `verify_encryption_context`; `src/envault/cli.py` `_parse_output_json_entry`

**Issue:** An empty expected dict makes the comparison a no-op. Null headers still import (availability). Non-string values are now rejected. Empty context logs a warning.

**Impact:** Checksum still binds plaintext. Context substitution for migrated records is not detected.

**Fix:** Re-encrypt migrated files so context includes `purpose`, `sha256`, `file_name`, `kms_key_alias`.

#### M-F — DynamoDB `PutItem` IAM cannot enforce append-only

**Location:** `infra/cdk/stacks/envault_stack.py` `DynamoDBStateAccess`; `src/envault/state.py` `attribute_not_exists(SK)` on events

**Issue:** The CLI conditions EVENT writes, but IAM allows raw `PutItem` on the table. An operator using the AWS API can overwrite EVENT or CURRENT items.

**Impact:** Audit integrity is a client-side guarantee. Anyone with the managed policy can already decrypt; they can also rewrite history.

**Fix:** Not expressible as a DynamoDB IAM condition. Options: separate events table with a stream-only writer, or CloudTrail + alerts on `PutItem` that is not the CLI user-agent. Do not grant this policy to untrusted principals.

#### M-1 / M-2 / M-3 / M-4 — see remediations table *(fixed in this PR)*

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

#### L-6 — Legacy `code/*.sh` still present

Deprecated; `encrypt.sh` `aws s3 sync` does not pass SSE-KMS explicitly (relies on bucket default). Prefer the Python CLI.

#### L-I / L-S — see remediations table *(fixed in this PR)*

---

## Strengths verified this week (do not re-open)

- Streaming encrypt/decrypt; checksum and encryption context verified before plaintext is renamed into place
- `DiscoveryFilter` with mandatory 12-digit account IDs; partition derived from region (now including ISO)
- `attribute_not_exists(SK)` on audit events; decrypt does not flip CURRENT to DECRYPTED
- New audit events use `record_state` so they do not project into `state-index`
- SHA-pinned Actions, `permissions: read-all`, OIDC PyPI, gitleaks job, no `pull_request_target`
- `os.execvpe` has no shell; `--clean-env` exists
- Filename sanitization for decrypt output (`Path.name`); Rich markup escaped
- No `eval` / `pickle` / `subprocess` with `shell=True` in application code
- `.env` gitignored; `.secrets.baseline` committed; CODEOWNERS present
- Empty S3 VersionId is fail-closed on download (`--latest` opt-in) and now on upload
- Content-addressed S3 keys validated before fetch
- Directory-symlink trees skipped on encrypt
- `migrate` confined to the import directory; rejects `..` and per-component symlinks
- KMS envelope decrypt/generate require `purpose` in `{envault-backup, backup}`; storage KMS is `ViaService`
- cdk-nag `AwsSolutions-IAM5` suppressions have justifications
- No Dockerfiles, no hardcoded live credentials, no `.env` in git history

---

## Prior reports

- `docs/reviews/2026-07-26-deep-review.md` — state-machine findings (mostly fixed in 0.2.0 / #115)
- `docs/plans/2026-03-03-security-audit-fixes.md` — original 25-item remediation plan
- `SECURITY_AUDIT.md` @ 2026-09-21 — weekly remediations now on `main` via #115

---

## Summary count

**This scan (on `main` before remediations):** 0 Critical, 3 High, 8 Medium, 6 Low

**After this PR:** 0 Critical, 2 High, 5 Medium, 6 Low

Verification: `pytest tests/unit/` — **187 passed**; ruff (src/tests) + mypy clean. Crypto-safety inspector: PASS (8/8). Migration-path guard: PASS.
