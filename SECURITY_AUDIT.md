# Security audit — envault-cli

**Reviewer:** Weekly repository security audit (static analysis)
**Date:** 2026-08-15
**Codebase:** `cursor/repository-security-audit-4737` (based on `main` @ `4b98446`)
**Scope:** `src/envault/`, `infra/cdk/`, `.github/workflows/`, `code/`, tests, dependency manifests, git history (secret patterns). No exploit code, no execution of untrusted payloads, no fetches of URLs found in the repo.

Prior reviews: `SECURITY_AUDIT.md` (2026-03-04) and `docs/reviews/2026-07-26-deep-review.md`. Those documents described bugs that have since been fixed on `main`. This file is the current-state report.

---

## Executive summary

The cryptographic core is in good shape: streaming encrypt/decrypt, `REQUIRE_ENCRYPT_REQUIRE_DECRYPT`, `max_encrypted_data_keys=1`, mandatory discovery-account filters, decrypt-to-temp-then-rename, encryption-context check before any plaintext byte, SHA-pinned Actions, OIDC PyPI publish, and append-only audit writes (`attribute_not_exists(SK)`).

This pass remediates several leftover findings from the July review (IAM over-grants, `DisableKey` deny blocking incident response, ignored audit TTL, silent decrypt overwrite, DynamoDB-controlled S3 keys, rotate-key decrypting before the new key is reachable, second-granularity CAS tokens, dashboard `last_activity` broken by EVENT items).

**Remaining after this change:** **0 Critical, 2 High, 9 Medium, 7 Low**.

---

## This change (remediations landed with the audit)

| Area | Change |
|------|--------|
| KMS key policy | `DisableKey` removed from the blanket DENY so a compromised-key response can disable the CMK without a CloudFormation edit |
| IAM | `dynamodb:UpdateItem` removed (unused; it could rewrite `ttl` on events). S3 `ListBucket` scoped to the bucket ARN; object actions scoped to `bucket/*` |
| S3 keys | Downloads/uploads reject empty, absolute, or `..` component keys; CLI additionally requires the `encrypted/` prefix |
| Decrypt | Refuses to overwrite an existing destination unless `--force` |
| Audit TTL | `ENVAULT_AUDIT_TTL_DAYS` is read for every `put_event` path (encrypt, decrypt, exec, rotate-key, migrate) |
| rotate-key | `DescribeKey` on the target key *before* any file is decrypted |
| exec | Warns when the child will inherit AWS credentials (use `--clean-env`) |
| migrate | Rejects symlink inputs |
| State | `last_updated` uses microsecond precision; dashboard pages past EVENT items when resolving `last_activity` |
| Access logs bucket | Versioning enabled |
| Docs / CI | `.env.example` documents `ENVAULT_*`; pip-audit ignores are justified in-workflow; CODEOWNERS covers `cli.py` and `isolation.py` |

---

## HIGH

### H-1 — `rotate-key` cannot use a new key under the provisioned IAM policy

**Location:** `infra/cdk/stacks/envault_stack.py` (KmsEnvelopeEncryption statement)

**Issue:** The managed policy grants `kms:GenerateDataKey` / `kms:Decrypt` / `kms:DescribeKey` only on the stack CMK. `rotate-key --new-key-id alias/other` needs those actions on the *new* key as well. The CLI now fails closed on `DescribeKey` before writing plaintext, but the command still cannot complete against a second key without a manual policy amendment.

**Impact:** Operators following the documented rotation flow get `AccessDenied` after (previously) decrypting files, or (now) a clean preflight failure. Key rotation as incident response does not work out of the box.

**Fix:** Add a stack parameter for additional key ARNs and include them in the KMS statement, for example:

```python
rotation_target_arns = cdk.CfnParameter(
    self, "RotationTargetKeyArns",
    type="CommaDelimitedList",
    default="",
    description="Extra KMS key ARNs that rotate-key may target.",
)
# resources=[encryption_key.key_arn, *rotation_target_arns.value_as_list]
# (gate the extra ARNs so an empty parameter does not produce an invalid resource)
```

### H-2 — Rotation does not revoke old ciphertext; noncurrent versions last 365 days

**Location:** `infra/cdk/stacks/envault_stack.py` (lifecycle rule on `EnvaultBucket`); `src/envault/cli.py` (`rotate-key` re-uploads to the same S3 key)

**Issue:** Versioning keeps the previous object version — ciphertext wrapped under the old key — and the lifecycle rule expires noncurrent versions only after 365 days. The user policy still grants `s3:GetObjectVersion`. After rotating away from a compromised key, anyone who still has `kms:Decrypt` on that key can read every file for a year.

**Impact:** `rotate-key` is not a revocation primitive. A leaked old key remains useful against historical versions.

**Fix:** After a successful re-upload, delete the previous version (requires a tightly scoped `s3:DeleteObjectVersion` grant used only by rotation) or shorten `noncurrent_version_expiration` for the encrypted prefix. Document that rotation must be followed by disabling the old key (`kms:DisableKey` is now allowed by the key policy).

---

## MEDIUM

### M-1 — `envault exec` inherits AWS credentials by default

**Location:** `src/envault/cli.py` (`exec_`, `--clean-env`)

**Issue:** Without `--clean-env`, the child receives the operator's `AWS_*` credentials *and* the decrypted secrets. `PR_SET_DUMPABLE` is reset by `execve`, so a same-uid attacker can read the child's environ. A warning is now printed; the default is unchanged to avoid breaking `envault exec -- aws …` workflows.

**Impact:** A compromised COMMAND can call KMS/S3/DynamoDB as the operator and exfiltrate the rest of the vault.

**Fix:** Default to stripping `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, and `AWS_SECURITY_TOKEN` unless `--pass-aws` is set; keep `--clean-env` for a fully minimal environment.

### M-2 — Audit events can still be forged as *new* items

**Location:** `src/envault/state.py` (`put_event`); `infra/cdk/stacks/envault_stack.py` (DynamoDB `PutItem`)

**Issue:** Overwrite of an existing `EVENT#` SK is blocked. Any principal with `PutItem` can still insert a new event with a crafted SK (false history). TTL on events can still be set at write time.

**Impact:** The trail is append-only, not tamper-evident against the CLI principal.

**Fix:** Write events through a service that the user cannot `PutItem` directly, or add DynamoDB Streams → S3 Object Lock. IAM `dynamodb:LeadingKeys` conditions do not stop forgery by a legitimate user.

### M-3 — Optimistic locking is still not a monotonic version

**Location:** `src/envault/state.py` (`_now_iso`, `put_current_state`)

**Issue:** CAS now uses microsecond timestamps, which closes the same-second lost-update window. Two writers in the same microsecond can still collide, and a timestamp is not a version.

**Impact:** Concurrent `encrypt --force` / `rotate-key` on the same hash can still lose an update in a tight race.

**Fix:** Integer `version` attribute: `ConditionExpression="version = :v"` and `version = :v + 1`.

### M-4 — `state-index` is a two-value partition that also stores every event

**Location:** `infra/cdk/stacks/envault_stack.py` (GSI); `src/envault/state.py` (`put_event` copies `current_state`)

**Issue:** Every event inherits `current_state` and lands in `state-index`. `list_by_state` / `rotate-key` pay for the full history and filter it server-side. Two hot partitions (`ENCRYPTED` / `DECRYPTED`).

**Impact:** Availability and cost degrade with audit volume; not a direct confidentiality break.

**Fix:** Sparse GSI marker written only on `CURRENT` items (requires a GSI replacement / migration).

### M-5 — Filename lookup is O(all encrypted files)

**Location:** `src/envault/state.py` (`list_by_file_name`)

**Issue:** Queries the entire `ENCRYPTED` partition and filters on `file_name`.

**Impact:** Slow, expensive decrypt-by-name; FilterExpression is not a security boundary.

**Fix:** `name-index` GSI on `file_name` + `encrypted_at`.

### M-6 — No production lockfile

**Location:** `pyproject.toml` (range pins only)

**Issue:** Installs resolve to a moving set of `aws-encryption-sdk`, `cryptography`, and `boto3` versions. Dependabot updates ranges, not a lock.

**Impact:** Supply-chain drift between CI and user installs; a malicious or broken release in range can be pulled.

**Fix:** Publish an `uv.lock` or `requirements.txt` freeze for the release workflow and install from it when building the wheel's test environment. Keep range pins for library consumers.

### M-7 — pip-audit suppressions remain

**Location:** `.github/workflows/ci.yml`, `publish.yml`

**Issue:** `CVE-2026-4539` (pygments AdlLexer ReDoS via rich) and `CVE-2026-3219` (pip archive-format confusion) are ignored. Justifications are now in-workflow. Neither is in the published runtime attack surface of envault itself.

**Impact:** A future, more serious advisory on the same IDs would stay ignored. The pip CVE is an installer issue in CI, not the package.

**Fix:** Drop `CVE-2026-3219` once the runner's default pip is ≥ 26.1. Constrain `pygments>=2.20` once rich allows it, then drop `CVE-2026-4539`.

### M-9 — `migrate` still hashes absolute paths and follows directory symlinks

**Location:** `src/envault/cli.py` (`_parse_output_json_entry`)

**Issue:** `..` components and a symlink *final* component are rejected. An absolute path such as `/etc/passwd` is only logged, then hashed. A parent-directory symlink (`data` → `/etc`, input `data/passwd`) is not detected. `header: null` or a non-dict `encrypted_data_keys[0]` raises `AttributeError` and aborts the whole import.

**Impact:** An operator running `migrate` on an untrusted `output.json` can be induced to hash local files outside the intended tree and write their metadata into DynamoDB. This requires local execution.

**Fix:** Resolve the path, require it to stay under `Path.cwd()` (or `FROM_PATH.parent`), lstat every component, and treat unexpected header types as a per-line `MigrationError`.

### M-8 — Streaming decrypt has no ciphertext size cap

**Location:** `src/envault/crypto.py` (`decrypt_file` / `decrypt_to_stream`)

**Issue:** `exec` caps in-memory fetches at 16 MiB. `decrypt` / `rotate-key` stream to disk with no limit.

**Impact:** A huge object in S3 can fill the local disk (availability), not bypass AEAD.

**Fix:** Honour `file_size_bytes` from the record as a ceiling, or add `--max-bytes`.

---

## LOW

### L-1 — KMS L2 construct keeps the account-root `kms:*` key policy

**Location:** `infra/cdk/stacks/envault_stack.py` (`kms.Key`)

**Issue:** CDK L2 `Key` adds the standard `Enable IAM User Permissions` statement (`Principal: account root`, `Action: kms:*`). IAM is then the only control plane. Fine in a dedicated account; in a shared account any principal that can attach `kms:*` can use the CMK.

**Fix:** For shared accounts, replace with `CfnKey` / an explicit policy that names the envault role and denies `kms:PutKeyPolicy` except to a break-glass admin. Do **not** replace a live key — that destroys decryptability.

### L-2 — SNS ops topic is not customer-managed KMS

**Location:** `infra/cdk/stacks/envault_stack.py` (`EnvaultOpsTopic`)

**Issue:** Alarms may include table/file metadata. Default AWS-managed SNS encryption (or none, depending on account defaults) is weaker than the envault CMK.

**Fix:** `sns.Topic(..., master_key=encryption_key)` plus a key-policy grant for `cloudwatch.amazonaws.com` / `sns.amazonaws.com`. Test alarm delivery before relying on it.

### L-3 — Access logs bucket uses S3-managed encryption

**Location:** `infra/cdk/stacks/envault_stack.py` (`EnvaultAccessLogsBucket`)

**Issue:** Log delivery to a KMS-encrypted bucket needs a service grant and is easy to break. S3-managed SSE is the usual pattern. Versioning is now on.

**Fix:** Leave SSE-S3, or add a dedicated logs CMK with an S3 log-delivery grant.

### L-4 — Hardcoded KMS alias `alias/envault`

**Location:** `infra/cdk/stacks/envault_stack.py`

**Issue:** A second stack in the same account/region cannot create the same alias.

**Fix:** Parameterize the alias (already done for table/policy names).

### L-5 — No delete / purge path

**Location:** CLI + IAM (no `s3:DeleteObject`, no `dynamodb:DeleteItem`)

**Issue:** Storage and records grow forever. `--force` re-encrypt under a new name orphans the previous object.

**Fix:** An explicit `envault purge` with confirmation, scoped delete permissions, and an audit event.

### L-6 — Legacy `code/*.sh` still present

**Location:** `code/encrypt.sh`, `code/decrypt.sh`

**Issue:** Deprecated scripts remain. `encrypt.sh` `aws s3 sync` does not pass `--sse aws:kms` (relies on bucket default). `decrypt.sh` leaves ciphertext in `.trash/`.

**Fix:** Remove the scripts once `migrate` is the only consumer of `output.json`, or add `--sse aws:kms` and stop writing trash.

### L-7 — MFA Delete not enabled on the versioned data bucket

**Location:** `infra/cdk/stacks/envault_stack.py` (`EnvaultBucket`)

**Issue:** A principal with `s3:DeleteObjectVersion` (not granted by EnvaultUserPolicy) can destroy versions. MFA Delete requires root and cannot be set from CDK.

**Fix:** Document a post-deploy root step, or use S3 Object Lock in compliance mode for WORM.

---

## Informational / verified clean

| Area | Result |
|------|--------|
| Hardcoded secrets in tree | None. Test/CI use the literal `testing` moto credentials. |
| Git history (`AKIA…`, `*.pem`, `.env`) | No live key material found in the scanned history. |
| `pull_request_target` | Not used. |
| Third-party Actions | SHA-pinned with version comments. |
| Top-level `GITHUB_TOKEN` | `permissions: read-all` on both workflows; publish job is `id-token: write` only. |
| OIDC PyPI | Trusted Publisher via the `pypi` environment; no long-lived PyPI token. |
| Dockerfiles | None. |
| `eval` / `pickle` / `subprocess` / `shell=True` | None in application code. `os.execvpe` is intentional and does not invoke a shell. |
| Commitment policy | `REQUIRE_ENCRYPT_REQUIRE_DECRYPT` on encrypt and decrypt. |
| Discovery filter | Mandatory 12-digit account IDs; partition derived from region. |
| cdk-nag | `AwsSolutionsChecks` with justified IAM5 suppressions on `bucket/*` and `table/index/*`. |
| S3 public access / TLS / versioning / bucket keys | Present on the data bucket. |
| Prior CRITICAL items (plaintext-before-hash, one-shot decrypt, overwritable events, unconstrained discovery) | Fixed on `main` before this audit. |

---

## Summary count

**0 Critical, 2 High, 9 Medium, 7 Low** (plus the remediations in this change).

Recommended next work: H-1 (rotation key ARNs in IAM) and H-2 (revoke old versions / disable old key runbook), then M-1 (do not pass AWS credentials into `exec` by default).
