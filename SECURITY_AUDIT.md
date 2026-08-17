# Weekly security audit — envault-cli

**Date:** 2026-08-17
**Reviewer:** Cursor security-audit automation
**Scope:** Static review of `src/envault/`, `infra/cdk/`, `.github/workflows/`, `code/`, tests, and dependency/CI config on `main`. No exploit code, no execution of untrusted payloads, no fetches of URLs found in the repo.

This report supersedes the in-tree CISO review of commit `5b575e9` (`SECURITY_AUDIT.md` previously claimed unfixed critical decrypt-path bugs that streaming + checksum-before-rename already closed). Residual risk that this run does **not** treat as open Critical is listed under [Already solid](#already-solid).

---

## Already solid

Do not re-open these as Critical:

- Streaming encrypt/decrypt, encryption-context check before plaintext, checksum before `os.replace`.
- `DiscoveryFilter` with mandatory 12-digit account IDs; partition derived from region.
- `attribute_not_exists(SK)` on audit events; decrypt no longer flips CURRENT to DECRYPTED.
- SHA-pinned GitHub Actions, top-level `permissions: read-all`, OIDC PyPI publish, gitleaks job.
- `os.execvpe` with no shell; `--clean-env` exists.
- S3 public access blocked, TLS enforced, CMK encryption, versioning, cdk-nag with justified suppressions.

---

## Remediations in this change

| ID | Severity | Fix |
|----|----------|-----|
| H-1 | High | Dashboard `last_activity` no longer uses `Limit=1` before `FilterExpression` (EVENT items were hiding CURRENT). |
| H-2 | High | Optimistic lock timestamps use microseconds so two writers in the same second cannot share a CAS token. |
| H-3 | High | `decrypt` refuses to overwrite an existing destination unless `--force`; check runs before `mkstemp`. |
| H-4 | High | `_collect_files` uses `os.walk(followlinks=False)` so directory symlinks cannot pull in files outside the tree. |
| H-5 | High | DynamoDB `s3_key` values must match `encrypted/{aa}/{sha256}/{name}.encrypted` before GetObject. |
| H-6 | High | `rotate-key` calls `DescribeKey` on `--new-key-id` before any download/decrypt. |
| H-7 | High | KMS resource policy no longer denies `DisableKey` (incident response). `ScheduleKeyDeletion` stays denied. |
| H-8 | High | IAM: `sts:GetCallerIdentity` granted; unused `UpdateItem` and `ListBucket` removed; S3 object actions scoped to `encrypted/*`. |
| M-1 | Medium | `ENVAULT_AUDIT_TTL_DAYS` is applied on encrypt, decrypt, exec, rotate-key, and migrate event writes. |
| M-2 | Medium | `migrate` rejects absolute paths and symlinks (not just `..` components). |
| M-3 | Medium | `exec` warns when the child will inherit `AWS_*` credentials; `--clean-env` remains the fix. |
| L-1 | Low | pip-audit CVE ignores now have justifications; `.env.example` documents `ENVAULT_*` and `KMS_ACCOUNT_ID`. |

---

## Remaining findings (not fully closed in code)

### High

#### H-R1 — `rotate-key` IAM still covers only the stack CMK

**Location:** `infra/cdk/stacks/envault_stack.py` (`KmsEnvelopeEncryption`)

**Issue:** The managed policy cannot know the operator's next key ARN at synth time. Rotating to `alias/new-key` still requires a separate grant.

**Impact:** Without that grant, rotation fails (now at preflight, before plaintext). With a too-broad grant, a leaked CLI principal could wrap data keys under arbitrary CMKs.

**Fix:** Attach an additional statement for the target key ARN. Do not expand the stack policy to `Resource: "*"`.

#### H-R2 — Rotation is not revocation

**Location:** `infra/cdk/stacks/envault_stack.py` lifecycle rule (`noncurrent_version_expiration=365 days`); `src/envault/cli.py` `rotate-key`

**Issue:** Versioning keeps the previous ciphertext, still decryptable with the old key, for a year. `GetObjectVersion` is granted.

**Impact:** After a suspected key compromise, rotation alone leaves old objects readable until the old key is disabled and noncurrent versions expire.

**Fix:** Disable the old CMK, then shorten noncurrent expiration (or delete noncurrent versions) as an incident-response step. Documented in README.

### Medium

#### M-R1 — `exec` inherits AWS credentials by default

**Location:** `src/envault/cli.py` (`exec_`)

**Issue:** `--clean-env` is opt-in. Default path copies `os.environ` into the child.

**Impact:** A compromised child process can use the operator's AWS credentials to read the rest of the vault.

**Fix:** Prefer `--clean-env`. A warning is now printed when `AWS_*` is present. Making `--clean-env` the default would be a breaking CLI change.

#### M-R2 — No lockfile; pip-audit ignores two CVEs

**Location:** `pyproject.toml`, `.github/workflows/ci.yml`

**Issue:** Production deps are ranged, not hashed. CI ignores CVE-2026-4539 (pygments ReDoS, dev-only) and CVE-2026-3219 (pip, upgraded in the same job).

**Impact:** Reproducible builds and supply-chain pinning are weaker than a lockfile. The ignored CVEs are justified and not in the runtime path.

**Fix:** Add `uv.lock` / `pip-compile` when the project is ready to enforce exact resolves. Remove the ignores once pygments>=2.20 and pip>=26.1 are what CI installs.

#### M-R3 — `state-index` is a two-value partition that also stores events

**Location:** `infra/cdk/stacks/envault_stack.py`, `src/envault/state.py`

**Issue:** GSI PK is `current_state` (two values). Events copy `current_state` via `asdict`, so they inflate the index. Changing the GSI replaces the table.

**Impact:** Hot partition and extra RCU as the audit log grows. Dashboard/list queries pay for events they filter out.

**Fix:** Sparse marker attribute on CURRENT items only; schedule as a versioned table migration.

### Low / Informational

- GSI projection `ALL` increases metadata copies of encryption context.
- No MFA Delete on the versioned bucket (requires root; cannot set via CDK).
- No `s3:DeleteObject` / purge CLI — storage grows monotonically.
- Filename lookup still scans the ENCRYPTED partition (O(n) RCU).
- CDK L2 `kms.Key` default policy still grants `kms:*` to account root (standard; IAM is the real gate).
- Legacy `code/*.sh` remains a parallel encrypt path; Makefile still invokes it.

---

## CI/CD and secrets

- Actions are SHA-pinned. `publish.yml` has `permissions: read-all` and a CI quality gate.
- No hardcoded cloud credentials in the current tree. Test fixtures use `testing` / `moto`.
- `.env` is gitignored. `.secrets.baseline` is committed for detect-secrets.
- Git history was not found to contain live AWS keys in the current scan of tracked files; continue relying on the gitleaks CI job (`fetch-depth: 0`).

---

## Summary count

**This week's newly closed issues:** 0 Critical, 8 High, 3 Medium, 1 Low (fixed in this PR).

**Still open:** 0 Critical, 2 High, 3 Medium, 6 Low/Informational.

0 Critical, 2 High, 3 Medium, 6 Low remaining after remediations.
