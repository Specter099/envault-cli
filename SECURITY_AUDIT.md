# Security audit — envault-cli

**Reviewer:** Weekly repository security audit (static analysis)
**Date:** 2026-08-31
**Codebase:** `cursor/repository-security-audit-4b4b` (based on `main` @ `4b98446`)
**Scope:** `src/envault/`, `infra/cdk/`, `.github/workflows/`, `code/`, tests, dependency manifests, git history (secret patterns). No exploit code, no execution of untrusted payloads, no fetches of URLs found in the repo.

This run remediates High/Medium items that were still open on `main`. Findings marked **Fixed in this PR** are implemented on this branch. Remaining items are documented for the owner.

---

## Already solid (do not re-open)

- Streaming encrypt/decrypt; encryption context checked before plaintext; checksum verified before `os.replace`.
- `CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT`; discovery decryption requires 12-digit account IDs.
- SHA-pinned GitHub Actions, top-level `permissions: read-all`, OIDC PyPI publish gated on CI, gitleaks job, pip-audit job.
- Decrypt does not flip CURRENT to DECRYPTED; audit events use `attribute_not_exists(SK)`.
- `os.execvpe` has no shell; `--clean-env` exists.
- No hardcoded secrets in the tree or in git history matching `AKIA` / PEM private-key patterns.

---

## High

### H-1 — Decrypt silently overwrites an existing plaintext file

- **Severity:** High
- **Location:** `src/envault/cli.py` (decrypt command; previously created temp files before checking the destination)
- **Issue:** `os.replace` wrote decrypted output over any file already at the destination with no prompt.
- **Impact:** A repeated decrypt (or a colliding `file_name`) could destroy an existing local secret.
- **Fix:** **Fixed in this PR.** Check `output_path.exists()` *before* `mkstemp`. Refuse unless `--force`. Repeatable-decrypt tests use distinct output directories.

### H-2 — DynamoDB-sourced `s3_key` used as GetObject key without validation

- **Severity:** High
- **Location:** `src/envault/cli.py` decrypt, rotate-key, `exec` / `_stream_secret`
- **Issue:** `record.s3_key` was passed straight to S3. A CURRENT row rewritten to another prefix (for example access logs, another layout) would be fetched with the envault IAM principal.
- **Impact:** Confused-deputy read of any object the IAM policy can `GetObject` on.
- **Fix:** **Fixed in this PR.** `_require_trusted_s3_key` requires `encrypted/{aa}/{sha256}/{name}.encrypted` and that the path hash matches the record. IAM GetObject is also scoped to `encrypted/*` (see H-5).

### H-3 — Directory symlinks followed when collecting files to encrypt

- **Severity:** High
- **Location:** `src/envault/cli.py` `_collect_files`
- **Issue:** `Path.rglob` can descend into directory symlinks, so `envault encrypt shared/` could encrypt files outside the intended tree.
- **Impact:** Secrets from another directory uploaded to S3 under the operator's KMS key.
- **Fix:** **Fixed in this PR.** `os.walk(..., followlinks=False)` and prune symlink directories; skip file symlinks.

### H-4 — `migrate` followed absolute paths and symlinks

- **Severity:** High
- **Location:** `src/envault/cli.py` `_parse_output_json_entry`
- **Issue:** `..` was rejected, but an absolute path such as `/etc/shadow` was only logged, then hashed. Symlink components were followed.
- **Impact:** A crafted `output.json` could cause migrate to read arbitrary local files into DynamoDB metadata (hash, size, name).
- **Fix:** **Fixed in this PR.** `_confine_migration_path` rejects `..`, per-component symlinks, and any resolved path outside the directory containing the import file.

### H-5 — IAM policy broader than the CLI actually uses

- **Severity:** High
- **Location:** `infra/cdk/stacks/envault_stack.py` `EnvaultUserPolicy`
- **Issue:** `s3:GetObject`/`PutObject`/`ListBucket` on the whole bucket; unused `dynamodb:UpdateItem`; no `sts:GetCallerIdentity` even though audit attribution calls STS.
- **Impact:** Object-level access beyond `encrypted/*`; ListBucket reconnaissance; audit principal always degrades to `unknown` under this policy.
- **Fix:** **Fixed in this PR.** S3 object actions on `encrypted/*` only; drop `ListBucket` and `UpdateItem`; add `sts:GetCallerIdentity` with a justified cdk-nag suppression.

### H-6 — `rotate-key` decrypted plaintext before proving the new CMK is usable

- **Severity:** High
- **Location:** `src/envault/cli.py` `rotate_key`
- **Issue:** Download + decrypt ran first. If `--new-key-id` is a key the principal cannot use, plaintext still hit a temp file.
- **Impact:** Unnecessary plaintext exposure on a doomed rotation. (Rotating *to* a non-stack key still needs an extra IAM grant — see Remaining.)
- **Fix:** **Fixed in this PR.** `kms:DescribeKey` on `--new-key-id` after dry-run return and before any download.

---

## Medium

### M-1 — `ENVAULT_AUDIT_TTL_DAYS` ignored on CLI flag paths

- **Severity:** Medium
- **Location:** `src/envault/cli.py` encrypt/decrypt/exec/rotate-key/migrate; `src/envault/config.py`
- **Issue:** Commands construct `Config(...)` from flags, so `audit_ttl_days` stayed at the default 365. Decrypt/exec/rotate-key/migrate `put_event` calls omitted the argument.
- **Impact:** Retention policy in the environment is not applied; events live 365 days regardless of operator intent.
- **Fix:** **Fixed in this PR.** `Config.parse_audit_ttl_days()` is used on every CLI path; all `put_event` calls pass `audit_ttl_days`.

### M-2 — Optimistic-lock tokens only had second resolution

- **Severity:** Medium
- **Location:** `src/envault/state.py` `_now_iso`
- **Issue:** Two writers in the same UTC second shared a `last_updated` CAS token.
- **Impact:** A lost update on CURRENT if two processes finished in the same second.
- **Fix:** **Fixed in this PR.** `timespec="microseconds"`.

### M-3 — Dashboard `last_activity` used `Limit=1` with a FilterExpression

- **Severity:** Medium
- **Location:** `src/envault/state.py` `_latest_record_timestamp`
- **Issue:** DynamoDB applies Limit before FilterExpression. EVENT items share `current_state`, so the first index item can be filtered out and the dashboard reports `—`.
- **Impact:** Operators cannot rely on last-activity for monitoring.
- **Fix:** **Fixed in this PR.** Page until a CURRENT item survives the filter.

### M-4 — `exec` inherits AWS credentials by default

- **Severity:** Medium
- **Location:** `src/envault/cli.py` `exec_`
- **Issue:** Child environment is `dict(os.environ)` unless `--clean-env`.
- **Impact:** A compromised or careless child command can call AWS as the operator.
- **Fix:** **Fixed in this PR (warning only).** Print the inherited `AWS_*` *names* (not values) and point at `--clean-env`. Defaulting `--clean-env` on would be a breaking change.

### M-5 — Encrypt output fd leaked if the SDK stream failed before `fdopen`

- **Severity:** Medium
- **Location:** `src/envault/crypto.py` `encrypt_file`
- **Issue:** `os.open(..., 0o600)` then `client.stream`; on failure the fd was not closed.
- **Impact:** Descriptor leak; ciphertext file left open.
- **Fix:** **Fixed in this PR.** `finally: os.close(fd)` unless ownership transferred to `fdopen`.

### M-6 — SNS ops topic unencrypted at rest; KMS deny blocked DisableKey

- **Severity:** Medium
- **Location:** `infra/cdk/stacks/envault_stack.py`
- **Issue:** `EnvaultOpsTopic` had TLS-only; CMK resource policy denied `kms:DisableKey`, blocking incident-response freeze.
- **Impact:** Alarm payloads at rest used AWS-owned SNS encryption; a compromised CMK could not be disabled without editing the key policy first.
- **Fix:** **Fixed in this PR.** SNS `master_key=encryption_key`. Deny list is `kms:ScheduleKeyDeletion` only.

---

## Low / Informational (not changed this run)

### L-1 — `rotate-key` IAM still binds only the stack CMK

- **Severity:** Low (operational; High if you treat cross-key rotation as in-scope without extra grants)
- **Location:** `infra/cdk/stacks/envault_stack.py` `KmsEnvelopeEncryption`
- **Issue:** Policy resources are `[encryption_key.key_arn]`. Rotating to a *different* CMK requires a separate grant.
- **Impact:** DescribeKey now fails closed (H-6). Rotation to a new key still needs an attached policy on that key.
- **Fix:** Add a stack parameter for extra key ARNs, or document a companion managed policy.

### L-2 — Old S3 versions remain 365 days after rotate-key

- **Severity:** Low
- **Location:** bucket lifecycle `noncurrent_version_expiration=365 days`
- **Issue:** Rotation is not cryptographic revocation; ciphertext under the old DEK/CMK remains as a noncurrent version.
- **Impact:** Compromise of the old CMK can still decrypt historical versions until expiry.
- **Fix:** Disable the old CMK after a successful rotation; shorten noncurrent expiration if policy allows.

### L-3 — No lockfile; pip-audit ignores CVE-2026-4539 (pygments) and CVE-2026-3219 (pip)

- **Severity:** Low
- **Location:** `pyproject.toml`, `.github/workflows/ci.yml`
- **Issue:** Transitive versions float; ignore list is documented for currently unfixed/dev-only CVEs.
- **Impact:** Reproducible builds and CVE tracking are weaker than a lockfile.
- **Fix:** Add `uv.lock` / `requirements.txt` freeze when ready; revisit ignores when pygments 2.20+ is pulled in.

### L-4 — `state-index` is a two-value partition that also stores EVENT items

- **Severity:** Low
- **Location:** `infra/cdk/stacks/envault_stack.py` GSI `state-index`; `state.py` FilterExpression `SK = CURRENT`
- **Issue:** Events copy `current_state`, so the GSI is not sparse. Queries filter CURRENT in software.
- **Impact:** Cost and latency grow with audit volume; FilterExpression + Limit pitfalls (M-3).
- **Fix:** Replacement GSI that is CURRENT-only (table replacement).

### L-5 — CDK L2 `kms.Key` default policy grants `kms:*` to account root

- **Severity:** Informational
- **Location:** `infra/cdk/stacks/envault_stack.py` `kms.Key`
- **Issue:** Standard CDK behavior (delegates to IAM). In a shared account this is a broad administrative grant.
- **Impact:** Account root (via IAM) can manage the CMK beyond the envault user policy.
- **Fix:** Explicit `CfnKey` policy if the account is multi-tenant.

### L-6 — Access-logs bucket uses S3-managed encryption; no MFA Delete

- **Severity:** Informational
- **Location:** `infra/cdk/stacks/envault_stack.py` `EnvaultAccessLogsBucket`, data bucket
- **Issue:** Common chicken-and-egg for access logs; MFA Delete requires root credentials and cannot be set from CDK.
- **Fix:** Document post-deploy MFA Delete; KMS on log bucket if log-key circularity is solved.

### L-7 — GitHub Actions SHA-pinned (good); fake AWS creds at job `env` in CI

- **Severity:** Informational
- **Location:** `.github/workflows/ci.yml` test job
- **Issue:** Moto placeholders `testing`/`testing` at job scope.
- **Impact:** None for production; normalizes credentials in workflow YAML.
- **Fix:** Scope to the pytest step if new steps are added.

---

## CI/CD & supply chain (reviewed, no new High)

| Control | Status |
|---------|--------|
| Third-party actions SHA-pinned | Yes |
| `pull_request_target` | Not used |
| Top-level `permissions: read-all` | Both workflows |
| PyPI via OIDC Trusted Publisher | Yes; `needs: ci` quality gate |
| Dependabot weekly (pip + actions) | Yes |
| gitleaks on full history | Yes |
| No Dockerfile in repo | N/A |

---

## Summary count

**This review (open on `main` before remediations):** 0 Critical, 6 High, 6 Medium, 7 Low/Informational.

**Remediated on this branch:** 6 High, 6 Medium.

**Still open / accepted:** 0 Critical, 0 High (L-1 is the residual rotate-key extra-ARN grant, tracked as Low given the DescribeKey fail-closed), 0 Medium, 7 Low/Informational.

`0 Critical, 0 High remaining on this branch, 0 Medium remaining, 7 Low/Informational.`
