# envault-cli — Security Review

**Date:** 2026-11-14 (review); remediated 2026-11-16, released as 0.3.0
**Base:** `main` @ `a58ea77`
**Remediation:** commits `faa0cb8` through `680fd77`, listed under each finding below
**Scope:** `src/envault/`, `infra/cdk/`, `.github/workflows/`, dependency manifests and
packaging, `tests/`, and the legacy shell workflow in `code/` as far as `migrate` reads its
output.

Findings marked **CONFIRMED** were reproduced: against moto-backed AWS mocks (in process, or a
moto server for real processes and signals), with genuine aws-encryption-cli 4.3.0 output for
`migrate`, and with a local always-500 HTTP server for the retry findings. **PLAUSIBLE**
findings follow from the code or the synthesized template but depend on AWS behaviour that
could not be exercised here. At the base commit 183 unit tests passed, `ruff` was clean,
`mypy src/envault/` failed with one error, and `cdk synth` with cdk-nag was clean.

---

## Scope, method and threat model

**Method.**

1. Static review of the base commit, then a reproduction script for every finding that could
   be reproduced.
2. Remediation test-first: each finding got an acceptance test that failed on the base code
   before the fix and passed after it. No test was skipped, weakened or deleted to get green;
   tests that encoded wrong behaviour were replaced and named in the commit messages.
3. Independent verification of the remediated tree: every reproduction re-run, every fix
   reverted in a scratch worktree to show that its tests then fail, every CI and publish gate
   run on Python 3.10, 3.11, 3.12 and 3.13 plus the CDK job, and the properties listed under
   [Verification](#verification) re-checked. The issues that pass found (N1–N10) and the
   residuals queued during remediation (R1–R3) were fixed the same way and verified again.

**Threat model.**

- *Assets:* file plaintext, often short secrets (PINs, tokens, connection strings); KMS data
  keys; the operator's AWS credentials; the integrity of what `decrypt` and `exec` deliver; the
  audit trail; alarm delivery.
- *Metadata readers:* anyone who can list the bucket, read S3 access logs, read CloudTrail (KMS
  management events carry the encryption context; DynamoDB and S3 data events carry keys) or
  read the table. They must learn nothing about content.
- *Table writers:* every envault user holds `dynamodb:PutItem` on the table. A writer must not
  be able to make a lookup by file ID or content hash deliver another file, or break lookups
  for everyone else. (Name lookups and the audit trail trust table writers by design; both
  limits are documented.)
- *Local observers:* other processes of the same user, anyone who sees stderr or the terminal,
  temporary directories.
- *Operational events:* interrupts and signals, KMS throttling and outages, lost replies,
  concurrent clients.
- *Supply chain and CI:* unpinned dependencies, drifting tools.
- *Out of scope:* root on the host; a compromised KMS, S3 or DynamoDB; the legacy shell scripts
  beyond the metadata `migrate` reads.

---

## Summary

21 findings: **1 high, 10 medium, 10 low**. After remediation 18 are fixed and verified, 2 are
fixed in the CloudFormation template but cannot be verified without a live deployment (M10,
L9), and 1 is a design limitation that is now documented (L8). Verification found 10 more
issues (N1–N10) and confirmed 3 queued residuals (R1–R3); all are fixed, N7 in the template
only. Release preparation found 4 more (P1–P4): 1 fixed, 1 documented, 2 open.

| ID | Severity | At review | Finding | Result |
|----|----------|-----------|---------|--------|
| H1 | High | CONFIRMED | `-v` logs the plaintext KMS data key and the session token | Fixed |
| M1 | Medium | CONFIRMED | The retry decorator retries KeyboardInterrupt and SystemExit | Fixed |
| M2 | Medium | CONFIRMED | SIGTERM/SIGHUP leave plaintext behind | Fixed |
| M3 | Medium | CONFIRMED | `audit --since DATE` shows only that one day | Fixed |
| M4 | Medium | CONFIRMED | `migrate` rejects every genuine legacy record and exits 0 | Fixed |
| M5 | Medium | CONFIRMED | A hash identifier is never compared with the row | Fixed |
| M6 | Medium | CONFIRMED | The unsalted plaintext SHA-256 is the public identifier | Fixed for new records |
| M7 | Medium | PLAUSIBLE | An overwritten upload leaves the record pinned to a noncurrent version | Fixed |
| M8 | Medium | CONFIRMED | Basename-only names make `exec` pick an arbitrary file | Fixed |
| M9 | Medium | CONFIRMED | Dependency drift broke mypy, so CI and the publish gate are red | Fixed |
| M10 | Medium | PLAUSIBLE | Alarms cannot publish to the CMK-encrypted ops topic | Fixed in template |
| L1 | Low | CONFIRMED | The retry policy misfires four ways | Fixed |
| L2 | Low | CONFIRMED | SDK, OS and some AWS errors escape the CLI handlers | Fixed |
| L3 | Low | CONFIRMED | An interrupt between link and unlink zeroes the published file | Fixed |
| L4 | Low | CONFIRMED | A symlink swapped in after collection gets encrypted | Fixed |
| L5 | Low | CONFIRMED | Terminal escape sequences from stored names reach the terminal | Fixed |
| L6 | Low | CONFIRMED | Without `--`, `exec` parses the child's options | Fixed |
| L7 | Low | PLAUSIBLE | The credential fd's offset is left at EOF | Fixed |
| L8 | Low | CONFIRMED | Append-only and attribution are client-side only | Documented |
| L9 | Low | CONFIRMED | Buckets use CloudFormation-generated names | Fixed in template |
| L10 | Low | CONFIRMED (a), PLAUSIBLE (b, c) | `additional_kms_key_arns` validation and coverage gaps | Fixed |

---

## High

### H1 — `-v` logs the plaintext KMS data key and the session token

**Where:** `cli.py:_setup_logging` set the root logger to DEBUG under `--verbose`.

**Evidence.** botocore logs KMS response bodies and signed request headers at DEBUG. The
32-byte data key scraped from `envault -v encrypt` stderr decrypted the S3 ciphertext with no
KMS call at all. `-v decrypt` and `-v exec` also logged the session token (`botocore.auth`,
`botocore.endpoint`), in about 79 KB of stderr.

**Fix.** The root logger stays at WARNING and only the `envault` loggers go to DEBUG under
`-v`. The stderr handler also drops any third-party record below WARNING, even from a library
that lowers its own logger's level. Encryption SDK records appear only with `-v`, and the
console entry point filters the SDK's "Footer not read" finalizer traceback. After the fix the
scrape finds no data key, the token checks find nothing, and stderr is about 1 KB. Commit
`56b91e3`; tests in `tests/unit/test_cli_logging.py`.

---

## Medium

### M1 — The retry decorator retries KeyboardInterrupt and SystemExit

**Where:** `retry.py:aws_retry`, whose `retry_if_not_exception_type(never)` matched
`BaseException`.

**Evidence.** A Ctrl-C during the first attempt was swallowed and the real `decrypt_file`
still wrote the plaintext; a real process given one SIGINT mid-decrypt exited 0 with
"✓ Decrypted".

**Fix.** Only `Exception` subclasses are retry candidates; interrupts and `SystemExit` always
propagate (combined with L1's transient-only rule). Commit `faa0cb8`.

### M2 — SIGTERM/SIGHUP leave plaintext behind

**Where:** `cli.py:cli` installed no signal handlers; decrypt's staging and `.part` files and
rotate-key's RAM directory were not removed in `finally` blocks.

**Evidence.** SIGTERM mid-decrypt left a 9.6 MB plaintext `.part` file (mode 0600) in the
output directory. SIGHUP mid-rotate-key left a complete plaintext copy in
`/dev/shm/envault_rot_*`, plus two temporary files.

**Fix.** The console entry point turns SIGTERM and SIGHUP into `SystemExit(143)` and
`SystemExit(129)` (SIGINT stays `KeyboardInterrupt`), so every `finally` runs. Only signals at
their default disposition are taken over, so a SIGHUP ignored by `nohup` stays ignored. After
the first signal the next is ignored so cleanup can finish; a third ends the process at once.
Every temporary path is recorded in the same signal-deferred section that creates it and is
destroyed when the command ends, plaintext zero-overwritten first. After the fix: SIGTERM exits
143 with nothing left; SIGHUP during rotate-key exits 129 with no RAM directory and no temporary
files. Commit `bb76ffb`; see also N4, N5 and N6.

### M3 — `audit --since DATE` shows only that one day

**Evidence.** With events on 11-01, 11-05 and 11-09, `--since 2026-11-01` showed one event and
`--since 2026-11-02` printed "No events found".

**Fix.** `StateStore.list_events_between(start, end)` runs one paginated date-index query per
UTC day; `audit --since` starts an inclusive range ending at `--until` (default: today, UTC),
at most 366 days, listed oldest first. After the fix the two commands show 3 and 2 events.
Commits `b44e8f6` (library), `607763f` (CLI).

### M4 — `migrate` rejects every genuine legacy record and exits 0

**Evidence**, on genuine aws-encryption-cli 4.3.0 output:

- the recorded `input` paths are absolute and lie outside FROM_PATH's directory, so every record
  failed ("Migrated 0 records, skipped 0, errors 2") and the command exited 0;
- the S3 key it recorded, `encrypted/{h2}/{sha}/{name}.encrypted`, does not exist: the legacy
  script ran `aws s3 sync ../encrypted s3://$S3_BUCKET/encrypted`;
- `kms_key_id` was stored as undecoded base64.

**Fix.** `--plaintext-root` and `--ciphertext-root` (defaults: `encrypt/` and `encrypted/` next to
FROM_PATH's directory), with both paths confined lexically before any file is touched; records
point at the synced key, `encrypted/<path relative to the ciphertext root>`, marked
`s3_key_scheme=legacy-sync` and validated by `assert_legacy_s3_key` wherever they are read; the
key ARN and message ID are decoded; only the newest record per ciphertext file is imported;
`--bucket` pins each object's VersionId; any failed record makes the command exit 1. After the
fix, on a layout regenerated with a real aws-encryption-cli run twice (four appended records):
2 migrated, 2 superseded and skipped, and `decrypt --latest` byte-identical for both files.
Commits `a814b2c` (validator), `af07013` (CLI).

### M5 — A hash identifier is never compared with the row

**Evidence.** A plain PutItem copying row B's attributes onto `FILE#A` made `decrypt A` print
"✓ Decrypted" with B's content and made `exec -s A=VAR` inject B.

**Fix.** The row found under an identifier must describe that identifier, the plaintext is
checked against the value the operator typed, never against what the row claims, and every
identifier must be 64 hex characters before it is used. After the fix both are refused (exit 1),
and so are eight further variants tried during verification: the same copy looked up by the
typed SHA-256, rows planted under the typed SHA-256 in either scheme, the same with
`s3_key_scheme=legacy-sync`, a keyed row downgraded to legacy and looked up by hash or by name,
and a row pointed at another file's object. Commit
`646958b`; R1 (`2a36860`) later changed the lookup order and kept every check.

### M6 — The unsalted plaintext SHA-256 is the public identifier

**Where:** the encryption context (`sha256`), the S3 key format, the DynamoDB key
`FILE#{sha256}`, console and log output, and the text of `ChecksumMismatchError`.

**Exposure.** S3 keys (bucket listings, access logs, data events), the encryption context
(recorded by CloudTrail with every GenerateDataKey and Decrypt by default) and DynamoDB keys.

**Evidence.** A 6-digit PIN was recovered from its S3 key name alone in 0.28 s.

**Fix.** New records are named by `file_id = hex(HMAC-SHA-256(K, SHA-256(plaintext)))`, where K
is a KMS HMAC key (`HMAC_256`, `GENERATE_VERIFY_MAC`; `alias/envault-id` in the stack) and KMS
computes the MAC over the raw 32-byte digest (GenerateMac). Rows store `file_id`, `id_scheme`
(`hmac-sha256-v1`) and `id_key_arn`, and never a content hash; the encryption context carries
`file_id`. Every read verifies the plaintext with VerifyMac under the record's `id_key_arn`,
after checking, before any KMS call, that the ARN is a key in a trusted account and the
region's partition. The raw SHA-256 of a new record is never stored, uploaded, logged, printed
or put in an exception. Legacy records (no `id_scheme`) keep working for every command, and
rotate-key keeps each record's scheme. The CDK stack adds the key, retained with deletion
scheduling denied, and grants `kms:GenerateMac`/`kms:VerifyMac` on it only. After the fix the
PIN was not recovered from the S3 key, the row or the context after all 10^6 guesses each, and
none of them contains the SHA-256.

Commits `2f88297`, `7ecf13c`, `677a97d`, `06b4b47`, `4158e0d`, `03c4bf1`, `0e2c925`, `e3e3732`,
`7a75546`, `4ee9161`; follow-ups R1 (`2a36860`), N1 (`0813692`), N3 (`46d3591`), N10
(`fdcfd3c`). Legacy records keep exposing their SHA-256 (see
[Residual risks](#residual-risks)).

### M7 — An overwritten upload leaves the record pinned to a noncurrent version

**Evidence.** Two pipelines encrypting the same file uploaded two versions to the same key;
DynamoDB pinned the one S3 reported as `IsLatest=False`, which the lifecycle rule expires after
365 days. Reproduced against moto; the real race depends on timing.

**Fix.** Every upload goes to a key of its own, `encrypted/{id[:2]}/{id}/{message_id}/{name}.encrypted`
(the Encryption SDK's message ID), written with `If-None-Match: *`. A 412 raises
`S3ObjectExistsError`, except when the existing object's checksum shows it is this upload's own
lost reply. `encrypt`, `encrypt --force` and `rotate-key` use it; rotate-key repoints the record
and leaves the old object untouched; an upload whose state write fails is logged as an orphan.
The runtime floor rises to boto3 1.35.2, the first release that sends `IfNoneMatch`. After the
fix: two objects under two keys, and the pinned version is the latest. Commits `a814b2c`,
`fddd1a4`, `86a38c6`.

### M8 — Basename-only names make `exec` pick an arbitrary file

**Evidence.** `encrypt secrets/` with `prod/db.env` and `staging/db.env` wrote two rows named
`db.env` with the same second-precision `encrypted_at`; `exec -s db.env=DATABASE_URL` delivered
the staging file and exited 0.

**Fix.** Files are stored under their path relative to INPUT_PATH. A lookup matches the exact
stored name first and falls back to basenames only for bare names; a match spanning several
stored names is refused with the candidates listed. `encrypted_at` has microseconds and is
compared as a time; `exec` refuses when the two newest records tie, and decrypt then needs
`--version`. After the fix `exec -s db.env` is refused listing both, and `exec -s prod/db.env`
delivers the production file. Commit `646958b`; N2 fixed a crash path this introduced.

### M9 — Dependency drift broke mypy, so CI and the publish gate are red

**Evidence.** The six most recent CI runs (19 Oct–9 Nov) failed, at "Run mypy" in those
inspected; locally, mypy 2.4.1 with tenacity 9.2.1 rejected `retry.py:29`.

**Fix.** `aws_retry` is annotated with `ParamSpec`/`TypeVar`. `requirements/dev.txt` locks the
dev extra and the package's dependencies for Python 3.10 and later with a hash for every file,
and `infra/cdk/requirements-ci.txt` locks the CDK job. CI and the publish workflow install with
`--require-hashes --only-binary :all:`, then the package with `--no-deps --no-build-isolation`,
then `pip check`; the release is built with the locked build tools (`--no-isolation`);
pip-audit audits both locks; dependabot covers `/infra/cdk`. Commits `faa0cb8` (annotation),
`4046296` (lock), `9c659b9` (CI).

### M10 — Alarms cannot publish to the CMK-encrypted ops topic

**Defect.** SNS encrypts with the publisher's KMS permissions, and the data key's policy granted
nothing to `cloudwatch.amazonaws.com`; the topic policy only denied non-TLS publishing. Alarm
actions would fail, so the alarms would be silent.

**Fix.** The ops topic has its own rotating KMS key, which grants CloudWatch `kms:Decrypt` and
`kms:GenerateDataKey*`; the topic policy lets this account's alarms named `envault-*` publish
(`aws:SourceAccount`, `aws:SourceArn`). The data key's policy still admits no AWS service, and
disabling the data key during an incident no longer silences the alarms. N7 later removed the
source conditions from the key's statement. Live delivery could not be verified; the README
gives a post-deploy check. Commits `1022453`, `b90c1cf`.

---

## Low

- **L1 — The retry policy misfires four ways** (CONFIRMED). (a) Deterministic errors were
  retried (ResourceNotFound: 3 calls, 3 s); (b) `{"max_attempts": 1}` meant two HTTP requests
  per call; (c) a PutItem whose reply was lost was retried with a new token and reported a false
  `StateConflictError`; (d) one KMS throttle on Decrypt was reported as possible tampering and
  never retried. Fix: only transient errors are retried, following the exception chain; exactly
  one HTTP attempt per call (`total_max_attempts`); the CAS token is generated once and a
  consistent read accepts our own write; KMS failures on decrypt are classified (KMSError for
  availability and permission, DecryptionError for integrity) and retried safely. After the
  fix: 1 call, 1 HTTP request, the lost reply succeeds, the throttle is retried. Commits
  `faa0cb8` (a, b), `b44e8f6` (c), `55d1388` (d).
- **L2 — SDK, OS and some AWS errors escape the CLI handlers** (CONFIRMED). KMS AccessDenied on
  a three-file `encrypt` produced 3 s of retries, a raw `GenerateKeyError` traceback and no
  summary; rotate-key and a denied DynamoDB lookup produced raw tracebacks. Fix: SDK errors are
  wrapped (`KMSError`, `EncryptionError`); per-file `✗` lines, a summary and exit 1; lookups run
  inside the handlers. Commits `55d1388`, `aa36927`.
- **L3 — An interrupt between link and unlink zeroes the published file** (CONFIRMED). The
  cleanup zero-filled the staging inode, which was also the published file. Fix:
  `best_effort_delete` never overwrites a multiply-linked inode, opens with `O_NOFOLLOW`, and
  removes special files without opening them. Commits `ad77971`, `4ba1e88`.
- **L4 — A symlink swapped in after collection gets encrypted** (CONFIRMED). Fix: each file is
  opened once with `open_regular_nofollow`, only if it is still the `(st_dev, st_ino)` recorded
  during the walk, and hashed and encrypted from that descriptor. Commits `ad77971`, `55d1388`,
  `44659df`, `1d338a0`.
- **L5 — Terminal escape sequences from stored names reach the terminal** (CONFIRMED). `status`
  sent a stored name's raw `\x1b]0;…` title and screen-clearing sequences to the terminal. Fix:
  every untrusted value is printed through `_display`, which shows control, format, surrogate
  and separator characters as visible escapes before Rich escaping; Rich emoji codes are off;
  decrypt falls back to `decrypted_<id prefix>` for unsafe output names. Commit `3fb24c5`.
- **L6 — Without `--`, `exec` parses the child's options** (CONFIRMED).
  `exec -s x=V aws s3 ls --region eu-west-1` made envault use eu-west-1, and `psql -f schema.sql`
  was read as `--file`. Fix: option parsing stops at COMMAND; an unknown option before it is a
  usage error. Commit `91b579e`.
- **L7 — The credential fd's offset is left at EOF** (PLAUSIBLE). After sealing, the offset was
  28 and a read through a duplicate of the descriptor (macOS and BSD `/dev/fd/N`) returned
  nothing; Linux reopens `/proc/self/fd/N` and was unaffected. Fix: `CredentialFd.seal()`
  rewinds to 0. Commit `ad77971`.
- **L8 — Append-only and attribution are client-side only** (CONFIRMED). A plain PutItem, which
  the managed policy grants, rewrote an event's principal to another user's ARN. Fix (by
  design, documentation): the `state.py` and `identity.py` docstrings, the README and
  SECURITY_AUDIT.md say that `attribute_not_exists(SK)` prevents accidental overwrites, not a
  table writer, that `principal_arn` is self-reported, and that CloudTrail (KMS events, and
  DynamoDB and S3 data events) is the authoritative trail. No behaviour change. Commits
  `b44e8f6`, `ea34a2e`.
- **L9 — Buckets use CloudFormation-generated names** (CONFIRMED). Fix: both buckets are created
  in the S3 account-regional namespace (`BucketNamePrefix`, `BucketNamespace: account-regional`)
  as `envault-data-<account>-<region>-an` and `envault-access-logs-<account>-<region>-an`.
  Adding a name replaces an existing bucket, so stacks deployed earlier set
  `keep_generated_bucket_names=true`; with it the buckets, table and keys show no property
  change. CloudFormation support for the properties could not be verified here. Commit
  `1022453`.
- **L10 — `additional_kms_key_arns` validation and coverage gaps.** (a, CONFIRMED)
  `arn:aws:kms:*:*:key/*` passed synth and reached the policy; (b, PLAUSIBLE) extra keys were
  missing from `KmsViaStorageServices` although rotate-key uploads with SSE-KMS under them; (c,
  PLAUSIBLE) alias ARNs in `Resource` authorize nothing. Fix: concrete key ARNs only (no
  wildcards, no aliases), as a string or a list; the extra keys appear in
  `KmsEnvelopeEncryption`, `KmsViaStorageServices` and `KmsDescribeKey`. The same commit fixed
  the cdk-nag suppression defect described under [Verification](#verification). Commit
  `1022453`.

---

## Verification

**Gates.**

| Tree | Python | Unit tests | Lint, format, types | CDK |
|------|--------|-----------|---------------------|-----|
| `4ee9161` (fix waves) | 3.10, 3.11, 3.12, 3.13 | 611 passed on each, 94% coverage | clean | 78 passed; `cdk synth --strict` exit 0, default and with both context flags |
| `7f5e67b` (residual fixes) | 3.10.22, 3.11.18, 3.12.3, 3.13.18 | 682 passed on each; signal tests also under `nohup` | clean | 79 passed; `cdk synth --strict` exit 0, default, `keep_generated_bucket_names=true`, and both flags |
| `680fd77` (release; docs, packaging and comments since) | 3.13 | 682 passed, 94% coverage | clean | not re-run: `infra/` unchanged since `7f5e67b` |

Every gate ran exactly as CI runs it: the hash-locked install, `pip check`,
`ruff check src/ tests/ infra/`, `ruff format --check src/ tests/ infra/`,
`mypy src/envault/`, `pytest tests/unit/`, and in the CDK job the locked
`infra/cdk/requirements-ci.txt`, `python -m pytest` and the aws-cdk CLI 2.1113.0. The publish
job's build (locked `build` and `hatchling`, `python -m build --no-isolation`) succeeds; the
wheel holds only `envault/*`, and from 0.3.0 the sdist no longer holds `.claude/`. pip-audit, as
CI runs it on 3.12, finds nothing in the dev lock and nothing in the CDK lock beyond the one
ignored advisory (see SECURITY_AUDIT.md). At the release commit the detect-secrets hook passes
on all 87 tracked files.

**Reproductions after the fixes.** Each acceptance test named in the remediation plan exists and
passes, and each reproduction now shows the fixed behaviour (the results are given under each
finding). Reverting a fix in a scratch worktree makes its tests fail, for H1, M2, M5, M6 and M7
among others.

**Properties that had to stay true, and did:** the `REQUIRE_ENCRYPT_REQUIRE_DECRYPT` commitment
policy on both clients (a non-committing suite is refused); a discovery filter that refuses an
untrusted account or a wrong partition with zero KMS calls; `max_encrypted_data_keys=1`; the
encryption context checked before any plaintext byte is written (54 truncations and 60 bit
flips all raise `DecryptionError`); the checksum or MAC verified before every publish, seal,
hand-over and re-encrypt; 0600 temporary files; `exec` with no shell, only `/proc/self/fd/N` in
argv, a sealed memfd, `--clean-env`, a fail-closed audit write, and a child with no blocked or
caught stop signals; the overwrite refusal and the `os.link` race closure; paginated queries;
idempotent `put_event`; event TTL; `migrate` confinement; Block Public Access, TLS-only,
versioning, SSE-KMS, PITR, deletion protection and RETAIN in the template; SHA-pinned actions,
no `pull_request_target`, and `id-token: write` only in the publish job.

**cdk-nag defect, found and fixed.** The three AwsSolutions-IAM5 suppressions on the managed
policy were plain dicts. Their snake_case `applies_to` key never reached cdk-nag, so each
suppression waived every IAM5 finding on the policy; that is why a wildcard KMS ARN (L10) passed
synth. They are now `NagPackSuppression` objects scoped to the resources' logical IDs, and any
new IAM wildcard needs a scoped suppression of its own. Commit `1022453`.

---

## Issues found during verification

R1–R3 were queued during remediation; N1–N10 were found by the verification pass.

| ID | Severity | Issue | Fix | Commit |
|----|----------|-------|-----|--------|
| R1 | Low | A typed SHA-256 of a keyed file was sent to DynamoDB as a GetItem key (decrypt, exec, `status --file`) and as a Query condition (`audit --file`) before it was mapped, so DynamoDB data events could record it | With an ID key set, 64 hex characters are mapped with GenerateMac first and only the keyed ID is looked up; the value is looked up as typed only on a miss; a GenerateMac failure stops the lookup. Wire-level tests for all four commands | `2a36860` |
| R2 | Low | `decrypt -o DIR/` with a missing DIR wrote a file named DIR (pre-existing) | A trailing separator requires an existing directory (exit 2) | `aa229e6` |
| R3 | Info | The README allowed alias ARNs in `additional_kms_key_arns`; the agent docs described SHA-256 identifiers | Documentation corrected | `ea34a2e`, `0d27dc8` |
| N1 | Low | The M6 acceptance test inspected call parameters and missed a SHA-256 inside a serialized DynamoDB condition | The test captures prepared requests (URL, headers, body); a planted Query leak now fails it | `0813692` |
| N2 | Low | One row with a non-string `file_name` crashed basename lookups for everyone; a non-map `encryption_context` crashed `status` and `rotate-key` | Rows are type-checked (`MalformedRecordError`): listings skip and report them, rotate-key reports and goes on, a lookup that lands on one is refused | `a5fad84`, `5c49e6c` |
| N3 | Info | Keyed plaintext was renamed to the `.verified` staging name before VerifyMac ran | `verify_digest` runs inside `decrypt_file` before the rename, never retried | `46d3591` |
| N4 | Info | The signal tests assumed SIGHUP at its default disposition and failed under `nohup` | The tests reset SIGHUP; an autouse fixture restores dispositions and the mask | `e8d2c5e` |
| N5 | Info | Inside a deferred section, three SIGTERMs did not end the process | Held signals count towards the third | `3190967` |
| N6 | Info | A stop signal whose handler ran just before `execve` was lost, and the command started with the secret (reasoned, not reproduced) | Stop signals are blocked from the last check until just before `execve`; one that arrives then kills envault; tested by call order and two observable outcomes | `d5f54a3` |
| N7 | Low | The source conditions on the ops topic key's CloudWatch grant might never match on the calls SNS makes, silencing every alarm (M10 again) | Conditions removed from the key statement (the key serves this topic only), kept on the topic policy | `b90c1cf` |
| N8 | Low | `encrypt <symlink>` printed "No files found" and exited 0 (pre-existing) | A symlink INPUT_PATH exits 1 naming its target; skipped entries are listed; a directory of skipped entries only exits 1 | `90c183f` |
| N9 | Info | The version was still 0.2.0, and the sdist shipped `.claude/` | Version 0.3.0; the sdist excludes `.claude/` | `0137af0` |
| N10 | Info | `encrypt` did not check the ID key's account, so reads later refused the records | `encrypt` and `migrate` warn once when `ENVAULT_ALLOWED_ACCOUNT_IDS` is set and excludes it | `fdcfd3c` |

Also in this pass: the help texts describe IDENTIFIER as a file ID, a content SHA-256 or a
stored name (`0f418e5`), and the `EnvaultEnvVars` output exports `ENVAULT_ALLOWED_ACCOUNT_IDS`
(`7f5e67b`).

---

## Found during release preparation

- **P1 — CI's Gitleaks scan runs with no rules** (Low, CONFIRMED; open). `.gitleaks.toml`
  holds only an `[allowlist]`. A configuration file without `[extend] useDefault = true`
  replaces gitleaks' default rules, so the scan CI runs can find nothing. Shown with gitleaks
  8.24.3, 8.28.0 and 8.30.1: a secret-shaped AWS access key ID and GitHub token in a probe file
  are reported with the default configuration and not with the repository's. With the default
  rules added, `a58ea77..HEAD` has 7 findings and the tree 8, all false positives (CloudFormation
  logical IDs, a placeholder key UUID, a test fixture's base64 commitment key, a private-key
  header written by a test). Fix: extend the defaults and allowlist those, or mark them
  `gitleaks:allow`. Not changed in this release.
- **P2 — 0.2.0 clients and keyed records** (Medium, CONFIRMED; documented). Run in process
  against moto with the 0.2.0 release code (`5aec2b1`): a 0.2.0 client reads a keyed record
  with no content check (the row has no `sha256_hash`, and 0.2.0 skips the check when it is
  empty); after one PutItem pointed the row at another file's object it delivered that file and
  exited 0, where 0.3.0 refused. Its `rotate-key` fails on keyed records but first uploads a new
  version over each record's key, leaving the versions the records pin noncurrent, which the
  lifecycle rule expires after 365 days. Clients built from `main` after 0.2.0 (`a58ea77`)
  refuse keyed records instead. The README's upgrade steps start with upgrading every client.
- **P3 — The detect-secrets hook failed on 25 fake values** (Info; fixed). Test credentials,
  fixture key headers and a docs line were neither baselined nor marked, so the pre-commit hook
  failed on any commit touching those files. They are marked `pragma: allowlist secret` (the
  docs line is baselined). Commit `680fd77`.
- **P4 — Help text overstates what `status` shows** (Info; open). `decrypt --help` calls a file
  ID "64 hex characters as `status` lists it", and the `--file` help of `status` and `audit` says
  "as status lists it", but both commands show only the first 16 characters. The full ID is in
  the S3 key `encrypt` prints. Needs a code change.

---

## Residual risks

- **Legacy records keep exposing their raw SHA-256** in their S3 key, DynamoDB key and
  encryption context. rotate-key keeps their scheme, and re-encrypting a file adds a keyed record
  but leaves the legacy row and object.
- **GenerateMac and VerifyMac are guessing oracles** for anyone allowed to call them, limited
  only by KMS quotas and visible in CloudTrail. While `ENVAULT_ID_KEY_ID` is set every 64-hex
  lookup costs a GenerateMac call and fails if it is denied.
- **Name lookups trust table writers**: a principal with PutItem can point a name at another
  file's record. Lookups by file ID or SHA-256 are verified. The basename fallback reads every
  ENCRYPTED row, so its cost grows with the table.
- **L8**: the audit trail can be rewritten or forged by any PutItem holder, and `principal_arn`
  is self-reported; CloudTrail is authoritative, with DynamoDB and S3 data events enabled.
- **Signals**: SIGKILL, an OOM kill or a power loss bypass every cleanup; the third-signal escape
  can leave plaintext by design; Python runs handlers between bytecodes, so a long C call delays
  them; zero-overwriting is best effort on copy-on-write filesystems and SSDs.
- **exec's last window**: a stop signal between envault's last check and `execve` kills envault
  by its default action, with no Python cleanup (exec holds no temporary files then, and its
  memfds die with it), after the ACCESS event was written. The race itself was not reproduced;
  tests pin the order of operations. Without `pthread_sigmask` nothing is blocked.
- **ISO partitions**: `partition_for_region` maps only `us-gov-` and `cn-` regions, so in an
  `aws-iso*` region discovery and the identifier-key check expect the `aws` partition and refuse
  (fail closed).
- **Moto-only assumptions**: GenerateMac's KeyId is assumed to be the key ARN (moto returns the
  bare ID, and the tests patch it); VerifyMac's `KMSInvalidMacException`; If-None-Match's 412 and
  409; HeadObject's `ChecksumSHA256` for SSE-KMS objects; DynamoDB `ConsistentRead` after a
  failed condition (moto ignores it); DynamoDB rejecting a GSI key of the wrong type (moto
  accepts it, and its own index sort then crashes).
- **Superseded objects stay current** (no `s3:DeleteObject` grant; the lifecycle rule expires
  only noncurrent versions) and orphans accumulate: old ciphertext stays readable with the old
  key until that key is disabled.
- **Infrastructure not verified live**: alarm delivery (M10, N7) and CloudFormation's support for
  account-regional bucket names (L9). The README's post-deploy alarm check covers the first; a
  deploy fails loudly on the second.
- **The ID key** must never be deleted or disabled: keyed records would become unreadable
  through envault.
- **Smaller items**: `os.walk` silently skips an unreadable subdirectory (N8); the N10 warning
  checks the key's account, not its partition; `migrate --bucket` reports a missing object as
  "AWS error" rather than "does not exist" without `s3:ListBucket`, which the managed policy
  does not grant (fail-closed either way); the SDK finalizer-noise filter is installed only by
  the console entry point.

**AWS behaviour this remediation relies on but could not verify** (the AWS documentation was not
reachable from the review environment):

- KMS: GenerateMac returns the key ARN in `KeyId`; VerifyMac raises `KMSInvalidMacException` on a
  mismatch; CloudTrail omits the MAC `Message`; HMAC keys are available in the deployment regions
  and are not rotated automatically; IAM authorizes GenerateMac and VerifyMac on the key ARN and
  authorizes nothing for an alias ARN in `Resource`; the retryable error codes; Decrypt's
  NotFoundException for a deleted key and InvalidCiphertextException for an altered data key.
- S3: `If-None-Match: *` returns 412 on an existing key and 409 ConditionalRequestConflict on a
  racing write; HeadObject returns `ChecksumSHA256` for SSE-KMS single-part uploads to a caller
  with `s3:GetObject`; HeadObject on a missing key returns 404 (or 403 without `s3:ListBucket`);
  SSE-KMS uploads need the caller's own KMS permissions.
- DynamoDB: `ConsistentRead` after ConditionalCheckFailed; data events record GetItem and Query
  key values; a GSI key attribute of the wrong type is rejected on write.
- CloudWatch, SNS and KMS: alarms publish as `cloudwatch.amazonaws.com` and SNS uses CloudWatch's
  KMS permissions; `aws:SourceArn` and `aws:SourceAccount` are present for the topic policy; the
  topic needs an explicit Allow; its non-TLS deny does not block CloudWatch.
- CloudFormation: `BucketNamePrefix` with `BucketNamespace: account-regional`, `Ref` returning
  the full generated name, and server access logging to such a bucket.
