# Security Audit — envault-cli

**Review:** 2026-11-14 security review of `main` @ `a58ea77`
**Remediated:** 2026-11-16, released as 0.3.0 (commits `faa0cb8` through `680fd77`)
**Full record:** [docs/reviews/2026-11-14-security-review.md](docs/reviews/2026-11-14-security-review.md)
(scope, method, threat model, evidence, fixes, commits and verification)
**Previous audit:** the 2026-09-21 weekly audit that this file held until now, moved unchanged to
[docs/reviews/2026-09-21-weekly-security-audit.md](docs/reviews/2026-09-21-weekly-security-audit.md);
its open findings are reconciled [below](#previous-audit-2026-09-21-open-findings-reconciled).

---

## Executive summary

The cryptographic core held up: key commitment, a discovery filter confined to trusted
accounts, one encrypted data key per message, the encryption context checked before any
plaintext is written, and verification before publication all survived adversarial testing and
were pinned by new regression tests. The problems were around it.

The one **high** finding was that `-v` logged the plaintext KMS data key and the session token
(H1). Among the **medium** ones: files were named by the unsalted SHA-256 of their content, so a
short secret could be recovered from its S3 key, its DynamoDB key or the encryption context in
CloudTrail (M6); a lookup by hash trusted whatever row it found, so a table writer could make
`decrypt` and `exec` deliver another file (M5); same-named files made `exec` pick one
arbitrarily (M8); SIGTERM and SIGHUP left plaintext on disk (M2) and Ctrl-C was retried (M1);
`migrate` could not import genuine legacy metadata (M4); concurrent uploads could leave a record
pinned to a version due to expire (M7); and CI had been red for weeks (M9).

Release 0.3.0 fixes all of them except two template changes that need a live deployment to
verify (M10 alarm delivery, L9 bucket names) and one design limitation, now documented (L8: the
DynamoDB audit trail is client-side; CloudTrail is authoritative). New files are named by a
keyed HMAC computed in KMS, verified on every read. Verification found ten smaller issues
(N1–N10) and confirmed three queued residuals (R1–R3); all are fixed. Gates pass on Python
3.10–3.13 and in the CDK job.

**Before upgrading, read the README's upgrade steps**: every client must be upgraded first (a
0.2.0 client reads keyed records without checking their content, see P2), and stacks deployed
before 0.3.0 must keep their bucket names.

**Counts.** 2026-11-14 review: 1 high, 10 medium, 10 low (21). After 0.3.0: 18 fixed, 2 fixed in
template, 1 documented; R1–R3 and N1–N10 fixed (N7 in template); found during release
preparation: P2 documented; P1, P3 and P4 fixed. Previous audit's open findings: 1 closed,
1 partly closed, 9 open.

---

## Remediations (2026-11-14 review)

| ID | Severity | Finding | Status | Fix |
|----|----------|---------|--------|-----|
| H1 | High | `-v` logs the plaintext KMS data key and the session token | Fixed | Root logger stays at WARNING; only envault's loggers go verbose; third-party records below WARNING are dropped |
| M1 | Medium | The retry decorator retries KeyboardInterrupt and SystemExit | Fixed | Only `Exception` subclasses are retried |
| M2 | Medium | SIGTERM/SIGHUP leave plaintext behind | Fixed | Signals become `SystemExit(143/129)`; every temporary file is registered and destroyed |
| M3 | Medium | `audit --since DATE` shows only that one day | Fixed | `--since`/`--until` inclusive UTC day range, at most 366 days |
| M4 | Medium | `migrate` rejects every genuine legacy record and exits 0 | Fixed | Plaintext and ciphertext roots, legacy-sync S3 keys, decoded key ARN, exit 1 on failure |
| M5 | Medium | A hash identifier is never compared with the row | Fixed | The row must describe its identifier; the plaintext must hash to what was typed |
| M6 | Medium | The unsalted plaintext SHA-256 is the public identifier | Fixed (new records) | Keyed `file_id` via a KMS HMAC key; VerifyMac on every read; legacy records keep their SHA-256 |
| M7 | Medium | An overwritten upload leaves the record pinned to a noncurrent version | Fixed | A new S3 key per upload, written with `If-None-Match: *` |
| M8 | Medium | Basename-only names make `exec` pick an arbitrary file | Fixed | Relative stored names; ambiguity and ties refused |
| M9 | Medium | Dependency drift broke mypy; CI and the publish gate red | Fixed | `aws_retry` annotation; hash-locked dev and CDK dependencies used by CI and the release |
| M10 | Medium | Alarms cannot publish to the CMK-encrypted ops topic | Fixed in template (not verified live) | The topic has its own key granting CloudWatch; the topic policy admits `envault-*` alarms |
| L1 | Low | The retry policy misfires four ways | Fixed | Transient errors only; one HTTP attempt per call; lost-reply tolerance; KMS failure classification |
| L2 | Low | SDK, OS and some AWS errors escape the CLI handlers | Fixed | One-line errors, per-file reporting, exit 1 |
| L3 | Low | An interrupt between link and unlink zeroes the published file | Fixed | A multiply-linked inode is never overwritten |
| L4 | Low | A symlink swapped in after collection gets encrypted | Fixed | One `O_NOFOLLOW` open per file, checked against the collected inode |
| L5 | Low | Terminal escape sequences from stored names reach the terminal | Fixed | Untrusted values printed with visible escapes |
| L6 | Low | Without `--`, `exec` parses the child's options | Fixed | Option parsing stops at COMMAND |
| L7 | Low | The credential fd's offset is left at EOF | Fixed | `seal()` rewinds the descriptor |
| L8 | Low | Append-only and attribution are client-side only | Documented | Docstrings, README and this file state the limit; CloudTrail is authoritative |
| L9 | Low | Buckets use CloudFormation-generated names | Fixed in template (not verified live) | Account-regional bucket names; `keep_generated_bucket_names` opt-out for existing stacks |
| L10 | Low | `additional_kms_key_arns` validation and coverage gaps | Fixed | Key ARNs only; extra keys in every data-key statement |

**Issues found during verification**, all fixed (details and commits in the record):

| ID | Severity | Issue | Status |
|----|----------|-------|--------|
| R1 | Low | A typed SHA-256 of a keyed file reached DynamoDB before it was mapped | Fixed |
| R2 | Low | `decrypt -o DIR/` with a missing DIR wrote a file named DIR | Fixed |
| R3 | Info | Stale documentation (alias ARNs, SHA-256 identifiers in the agent docs) | Fixed |
| N1 | Low | The M6 acceptance test could not see a hash inside a serialized DynamoDB condition | Fixed |
| N2 | Low | One malformed row crashed lookups for everyone | Fixed |
| N3 | Info | Keyed plaintext was named `.verified` before VerifyMac ran | Fixed |
| N4 | Info | The signal tests failed under `nohup` | Fixed |
| N5 | Info | The third-signal escape did not work inside a deferred section | Fixed |
| N6 | Info | A stop signal just before `execve` could be lost | Fixed (tested by call order) |
| N7 | Low | The ops key's source conditions might never match, silencing the alarms | Fixed in template (not verified live) |
| N8 | Low | `encrypt <symlink>` exited 0 and stored nothing | Fixed |
| N9 | Info | Version still 0.2.0; the sdist shipped `.claude/` | Fixed |
| N10 | Info | `encrypt` did not check the ID key's account | Fixed (warning) |

**Found during release preparation:**

| ID | Severity | Issue | Status |
|----|----------|-------|--------|
| P1 | Low | CI's Gitleaks scan runs with no rules: `.gitleaks.toml` has an allowlist but no `[extend] useDefault = true`, which replaces the default rules | Fixed (`2b062ea`) |
| P2 | Medium | A 0.2.0 client reads keyed records without a content check, and its `rotate-key` leaves their pinned versions noncurrent | Documented (upgrade every client first) |
| P3 | Info | The detect-secrets pre-commit hook failed on 25 unmarked fake values | Fixed (`680fd77`) |
| P4 | Info | Help text says a file ID is shown by `status`, which shows 16 characters | Fixed (`6646621`) |

---

## Residual risks

- **Legacy records keep exposing their raw SHA-256** (S3 key, DynamoDB key, encryption context).
  rotate-key does not convert them; re-encrypting adds a keyed record and leaves the legacy one.
- **GenerateMac and VerifyMac are guessing oracles** for whoever may call them, bounded only by
  KMS quotas and visible in CloudTrail. Grant them only to principals that may decrypt anyway.
  While `ENVAULT_ID_KEY_ID` is set, every 64-hex lookup calls GenerateMac.
- **Name lookups trust anyone who can write the table**; lookups by file ID or SHA-256 are
  verified against the row and the plaintext.
- **L8**: any principal with `dynamodb:PutItem` (every envault user) can rewrite or forge audit
  events or shorten their TTL, and `principal_arn` is self-reported. Use CloudTrail: KMS events,
  plus DynamoDB and S3 data events.
- **Signals**: SIGKILL, an OOM kill or a power loss bypass cleanup; a third stop signal ends
  envault at once and may leave plaintext; zeroing is best effort on copy-on-write filesystems
  and SSDs.
- **exec's last window**: a stop signal that arrives after envault's last check and before
  `execve` kills envault by its default action, without Python cleanup and after the ACCESS
  event was written; the command does not start. The race was not reproduced.
- **ISO partitions**: only `us-gov-` and `cn-` regions map to their partitions; in an `aws-iso*`
  region decryption and the identifier-key check refuse (fail closed).
- **Moto-only assumptions**: GenerateMac returning the key ARN, VerifyMac's mismatch error, S3
  conditional-write status codes, HeadObject checksums, DynamoDB consistent reads after a failed
  condition, and DynamoDB rejecting a GSI key of the wrong type were exercised against moto only.
- **Superseded objects stay current** and orphans accumulate (no delete grant; the lifecycle rule
  expires only noncurrent versions): disable an old CMK to revoke what it encrypted.
- **The ID key must never be deleted or disabled.**

## AWS behaviour not verified

The remediation relies on these and could not check them against AWS (the documentation was not
reachable from the review environment); each is listed with the finding it affects in the
[record](docs/reviews/2026-11-14-security-review.md#residual-risks):

- **KMS:** GenerateMac returns the key ARN in `KeyId`; VerifyMac raises `KMSInvalidMacException`
  on a mismatch; CloudTrail omits the MAC `Message`; HMAC keys exist in the deployment regions
  and are not rotated automatically; IAM authorizes GenerateMac/VerifyMac on the key ARN and
  nothing for an alias ARN in `Resource`; the retryable error codes; NotFound and
  InvalidCiphertext on Decrypt.
- **S3:** `If-None-Match: *` gives 412 on an existing key and 409 on a racing write; HeadObject
  returns `ChecksumSHA256` for SSE-KMS objects; HeadObject on a missing key gives 404 (403
  without `s3:ListBucket`); SSE-KMS uploads need the caller's own KMS permissions.
- **DynamoDB:** consistent reads after ConditionalCheckFailed; data events record GetItem and
  Query keys; a GSI key of the wrong type is rejected.
- **CloudWatch, SNS and KMS:** alarms publish as `cloudwatch.amazonaws.com` and SNS uses its KMS
  permissions; `aws:SourceArn`/`aws:SourceAccount` reach the topic policy; the topic's non-TLS
  deny does not block CloudWatch. Run the README's post-deploy alarm check.
- **CloudFormation:** `BucketNamePrefix` with `BucketNamespace: account-regional`, `Ref`
  returning the full name, and access logging to such a bucket.

## Tooling

- **cdk-nag suppression defect (found and fixed).** The three AwsSolutions-IAM5 suppressions were
  plain dicts whose `applies_to` key never reached cdk-nag, so each waived every IAM5 finding on
  the user policy; a wildcard KMS ARN (L10) passed synth because of it. They are now scoped
  `NagPackSuppression` objects naming the resources' logical IDs (`1022453`). Any new IAM
  wildcard needs its own scoped suppression.
- **Ignored advisory GHSA-464c-974j-9xm6.** aws-cdk-lib before 2.253.0 inverts the `encrypted`
  flag of aws-codebuild's `S3LoggingOptions`. The envault stack defines no CodeBuild project, so
  it does not apply; CI ignores it when auditing the CDK lock (aws-cdk-lib 2.244.0). Drop the
  ignore when aws-cdk-lib reaches 2.253.0; 2.256.0 would also offer typed bucket-namespace props
  (it may need a newer aws-cdk CLI).
- **pip-audit residuals, development and CI only.** CI audits the locked environment on Python
  3.12, where it is clean. On 3.10 the lock pins filelock 4.1.0, with advisories fixed only in
  releases that need Python 3.11; 3.10 and 3.11 virtual environments also carry the setuptools
  that `venv` seeds, which is not in the lock. Neither ships in the package. Python 3.10 reached
  end of life in October 2026; dropping it would remove the first.

---

## Previous audit (2026-09-21): open findings reconciled

| ID | Finding | Status now | Evidence |
|----|---------|------------|----------|
| H-B | Rotation is not a revocation primitive | Open, documented | rotate-key now writes a new S3 key and leaves the old object untouched (M7); the README documents disabling the old CMK as the revocation boundary, which the key policy allows. The old object stays current, readable with the old key until it is disabled. |
| H-C | `exec` inherits AWS credentials by default | Open, accepted | Default unchanged; the warning stays; the README says to use `--clean-env`. |
| M-A | `state-index` is a two-value partition that also stores events | Partly closed | Events stopped projecting into the index before this review (`5a6c856`: they carry `record_state`, not `current_state`); the two-value partition key remains. |
| M-B | CDK L2 `kms.Key` default root `kms:*` policy | Open | Unchanged; the new HMAC key and ops topic key use the same default. |
| M-C | No lockfile; pip-audit ignores two CVEs | Closed | M9: hash locks for development, CI and the release build (`4046296`, `9c659b9`); both CVE ignores removed, the locked versions being unaffected; one documented ignore for the CDK lock. The published package keeps version ranges, as libraries do. |
| M-D | Filename lookup is O(all encrypted files) | Open | Unchanged; M8's basename fallback reads the ENCRYPTED partition once more when no exact name matches. |
| L-1 | GSI projections use `ALL` | Open | Unchanged (changing it replaces the table). |
| L-2 | Access logs bucket uses S3-managed encryption | Open, accepted | Unchanged. |
| L-3 | No MFA Delete on the versioned data bucket | Open | Unchanged; a post-deploy step that needs root credentials. |
| L-4 | Fake AWS credentials in CI are job-scoped | Open, accepted | Unchanged; the test steps of `ci.yml` and `publish.yml` set them. |
| L-5 | No object-delete / purge CLI path | Open | Unchanged, and more visible: superseded objects now stay current (M7). |

---

## Prior reports

- [docs/reviews/2026-11-14-security-review.md](docs/reviews/2026-11-14-security-review.md) — this review in full
- [docs/reviews/2026-09-21-weekly-security-audit.md](docs/reviews/2026-09-21-weekly-security-audit.md) — the previous content of this file
- [docs/reviews/2026-07-26-deep-review.md](docs/reviews/2026-07-26-deep-review.md) — state-machine findings (mostly fixed in 0.2.0)
- [docs/plans/2026-03-03-security-audit-fixes.md](docs/plans/2026-03-03-security-audit-fixes.md) — original 25-item remediation plan
- The 2026-03-04 CISO review of commit `5b575e9`, which this file held before 2026-09-21, is in
  git history: `git show a8fd8f4:SECURITY_AUDIT.md`.
