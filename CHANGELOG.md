# Changelog

All notable changes to `envault` are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [0.3.0] - 2026-11-16

The remediation release for the 2026-11-14 security review. IDs in parentheses are that
review's findings (H1, M1–M10, L1–L10), the residuals R1–R3 it queued, and the issues N1–N10
found while verifying the fixes; [the review record](docs/reviews/2026-11-14-security-review.md)
and [SECURITY_AUDIT.md](SECURITY_AUDIT.md) describe them.

**Upgrading from 0.2.0:** follow the ordered steps in the README's
[Upgrading from 0.2.0 to 0.3.0](README.md#upgrading-from-020-to-030). Upgrade every client
first: a 0.2.0 client reads records written by 0.3.0 without checking their content, and its
`rotate-key` leaves their pinned S3 versions noncurrent. Stacks deployed before 0.3.0 must
deploy with `keep_generated_bucket_names=true`, or CloudFormation replaces both buckets.

### Security

- `-v` no longer logs the plaintext KMS data key or the AWS session token: only envault's own
  loggers become verbose, other libraries' loggers never go below WARNING, and the Encryption
  SDK's records appear only with `-v` (H1).
- New files are named by a keyed identifier, `HMAC-SHA-256(ID key, SHA-256(plaintext))`,
  computed by a KMS HMAC key (`ENVAULT_ID_KEY_ID`), instead of the plaintext's SHA-256, which
  gave a short secret away to anyone who could list the bucket, read the table or read the
  encryption context in CloudTrail. The raw SHA-256 of a new file is never stored, uploaded,
  logged, printed or put in an exception. Every read of a keyed record checks its identifier
  with KMS `VerifyMac`, under the key ARN the record names, which must be in an account listed in
  `ENVAULT_ALLOWED_ACCOUNT_IDS`; that check runs before any KMS call for the record (M6).
- With `ENVAULT_ID_KEY_ID` set, a 64-hex IDENTIFIER is mapped through `GenerateMac` before any
  lookup, so the SHA-256 of a keyed file never reaches DynamoDB or its CloudTrail data events;
  if KMS fails the lookup stops, with no fallback (R1).
- A row found by file ID or SHA-256 must describe that identifier, and the plaintext must hash
  to the value typed: a principal who can write the table can no longer make `decrypt <hash>` or
  `exec` deliver another file (M5). Name lookups still trust the table; the README says so.
- Plaintext is named `.verified`, published, sealed, handed to a command or re-encrypted only
  after its checksum and, for a keyed record, its MAC have been verified (N3).
- SIGTERM and SIGHUP now run cleanup (exit 143 and 129): decrypt's partial or verified plaintext
  and rotate-key's plaintext copies no longer outlive an interrupted command. A second signal is
  ignored while cleanup runs; a third ends the process at once, also inside a short deferred
  section (M2, N5).
- Ctrl-C and SystemExit are no longer retried, so an interrupted decrypt stops instead of
  finishing and delivering (M1).
- `exec` can no longer start the command after a stop signal: signals are held from envault's
  last check until just before `execve`, and one that arrives in that window kills envault
  before the command starts (N6).
- Names stored by `encrypt` are paths relative to INPUT_PATH, so `exec` no longer picks an
  arbitrary file among several with the same basename; an ambiguous name, or two newest records
  with the same timestamp, is refused (M8).
- `encrypt` hashes and encrypts each file from one descriptor, opened without following
  symlinks and only if it is the inode found during the walk: a path swapped for a symlink or
  another file after collection is refused (L4).
- Names and other values read from the table are printed with control and invisible characters
  as visible escapes; a crafted name can no longer drive the terminal (L5).
- CDK: `additional_kms_key_arns` accepts only concrete KMS key ARNs. Wildcards (which reached the
  policy) and alias ARNs (which grant nothing) fail synth (L10).
- CDK: the cdk-nag IAM5 suppressions were plain dicts whose `applies_to` never reached cdk-nag,
  so each waived every IAM5 finding on the policy, a wildcard KMS ARN included. They are now
  scoped `NagPackSuppression` objects.
- CDK: buckets are created in the S3 account-regional namespace, so no other account can claim
  their names (L9).
- Documentation: the audit-event write condition is client-side only (any principal with
  `dynamodb:PutItem` can rewrite or forge events, and `principal_arn` is self-reported);
  CloudTrail is the authoritative record (L8).
- `decrypt` fails closed on audit: the DECRYPT event is written before verified plaintext
  is moved into place, and the plaintext is discarded if that write fails (previously the
  file was left on disk with a warning).
- `decrypt` refuses to overwrite an existing file unless `--force` is given.
- `rotate-key` keeps temporary plaintext in a private directory on RAM-backed `/dev/shm`
  where available, instead of the default (often disk-backed) temp directory.
- CDK: the IAM policy's direct `kms:Decrypt`/`kms:GenerateDataKey` now require an envault
  encryption context (`purpose` = `envault-backup` or legacy `backup`); bucket/table
  encryption is granted only via S3 and DynamoDB (`kms:ViaService`). Unused
  `dynamodb:UpdateItem` removed.
- CI: the Gitleaks scan ran with no rules, because `.gitleaks.toml` replaced the default rules
  instead of extending them. It now extends them, and allowlists by exact value the seven
  non-secret values they flag in this repository (P1).

### Breaking

- `encrypt` and `migrate` require `--id-key-id` / `ENVAULT_ID_KEY_ID` (exit 2 without it).
  Principals need `kms:GenerateMac` (encrypt, migrate, and every 64-hex lookup while the
  variable is set, a file ID included) and `kms:VerifyMac` (every read of a keyed record) on
  the ID key; the CDK stack's managed policy grants both (M6, R1).
- Rows written by 0.3.0 carry `file_id`, `id_scheme` and `id_key_arn` instead of
  `sha256_hash`; only legacy rows have `sha256_hash`. Tooling that reads the table must switch.
  The encryption context of a new file carries `file_id`, not `sha256`. Clients older than
  0.3.0 must not read or rotate these records: upgrade them first (M6).
- `audit --since DATE` is now the first day of an inclusive range of UTC days ending at
  `--until` (default: today), not a single day. A range that ends before it starts, spans more
  than 366 days, or an `--until` without `--since`, is a usage error (exit 2) (M3).
- `exec` stops reading its own options at COMMAND: options go before it, and an unknown option
  before COMMAND is a usage error (exit 2) (L6).
- `decrypt -o PATH/` with a trailing separator requires PATH to be an existing directory
  (exit 2); it used to write a file named PATH (R2).
- `encrypt` of a directory stores each file under its path relative to INPUT_PATH; a name that
  matches several stored names is refused (exit 1), and `exec` refuses when the two newest
  records of a name tie (M8).
- `encrypt` of a symbolic link exits 1 and names the path it points to (it printed "No files
  found" and exited 0); a directory holding nothing but skipped entries exits 1 (N8).
- `migrate` reads the plaintext and ciphertext roots from `--plaintext-root` and
  `--ciphertext-root` (defaults: `encrypt/` and `encrypted/` next to FROM_PATH's directory),
  treats a missing plaintext as an error, and exits 1 if any record failed (M4).
- `rotate-key --dry-run` exits 1 when a record is malformed (N2).
- CDK: bucket names are now `envault-data-<account>-<region>-an` and
  `envault-access-logs-<account>-<region>-an`. A stack deployed before 0.3.0 must set
  `keep_generated_bucket_names=true`, or CloudFormation replaces both buckets and orphans every
  object the records pin (L9). `additional_kms_key_arns` values that are alias ARNs or contain
  wildcards must be replaced with key ARNs (L10).
- Requires boto3 1.35.2 or later (PutObject `IfNoneMatch`) (M7).
- Library API: `FileRecord(file_id, ..., *, id_scheme, id_key_arn="")` replaces `sha256_hash`;
  `Config.build_encryption_context(file_id, file_name, *, legacy=False)`;
  `S3Store.s3_key_for_file(file_id, file_name, message_id=None)`;
  `ChecksumMismatchError(expected, message=None)` no longer carries `actual`, and no message
  names the plaintext's hash; `AlreadyEncryptedError(file_id, file_name)`;
  `StateStore.get_current_state` raises `MalformedRecordError` for a row of the wrong shape.

### Added

- CDK `AlertEmailParam` subscribes an email address to the operational alarm topic.
- CDK context `additional_kms_key_arns` grants extra rotation-target CMKs without a
  wildcard IAM grant.
- `--id-key-id` / `ENVAULT_ID_KEY_ID` on `encrypt`, `migrate` (required) and on `decrypt`,
  `exec`, `status`, `audit` (lookup by SHA-256) (M6).
- `audit --until` (M3); `migrate --plaintext-root`, `--ciphertext-root` and `--bucket` (M4).
- `--allowed-account-ids` / `ENVAULT_ALLOWED_ACCOUNT_IDS` on `encrypt` and `migrate`: a warning
  when the ID key's account is not listed, since reads would refuse the records (N10).
- `encrypt` lists the symlinks and special files it skips in a directory (N8).
- CDK: the HMAC key `alias/envault-id` (`HMAC_256`, `GENERATE_VERIFY_MAC`; retained, deletion
  scheduling denied), the `KmsFileIdentifiers` statement (`kms:GenerateMac`, `kms:VerifyMac` on
  that key only) and the `IdKeyAlias` output (M6); the ops topic's own key (M10); the
  `keep_generated_bucket_names` context flag (L9); `EnvaultEnvVars` exports `ENVAULT_ID_KEY_ID`
  and `ENVAULT_ALLOWED_ACCOUNT_IDS` (the stack's account); CDK assertion tests in
  `infra/cdk/tests`, run by CI.
- Hash-locked dependencies for development and CI, `requirements/dev.txt` and
  `infra/cdk/requirements-ci.txt` (M9).
- Library: `envault.fileid` (`IdKey`, `FileIdVerifier`, `check_id_key_arn`, `is_file_id`);
  `crypto.encrypt_fd`, `crypto.sha256_fd`, and `verify_digest=` on `decrypt_file` and
  `decrypt_to_stream`; `fileutils.open_regular_nofollow`; `S3Store.upload_file(...,
  if_none_match=)` and `s3.assert_legacy_s3_key`; `StateStore.list_events_between` and
  `StateStore.has_current_state`; `retry.is_transient_aws_error` and `aws_retry(when=)`;
  exceptions `KMSError`, `EncryptionError`, `UnsafeFileError`, `InvalidS3KeyError`,
  `S3ObjectExistsError`, `FileIdMismatchError`, `UntrustedIdKeyError`, `MalformedRecordError`.

### Changed

- Every upload goes to a key of its own (see Fixed, M7); superseded objects stay current in the
  bucket and readable with their old key until it is disabled.
- `exec` starts the command with default handling of SIGINT, SIGTERM, SIGHUP, SIGPIPE and
  SIGXFSZ and no signal blocked; a SIGHUP ignored by `nohup` stays ignored (M2, N6).
- `encrypted_at` has microsecond precision; versions of a name are ordered by time, not by the
  stored string (M8).
- `status` and `audit` show the first 16 characters of the file ID ("ID (16)"); the decrypt
  context-mismatch message shows "ID:" (M6).
- CI and the release install from the hash locks; the release builds with the locked build
  tools (`python -m build --no-isolation`); pip-audit audits both locks, with one documented
  ignore (GHSA-464c-974j-9xm6, not applicable) and the stale pygments and pip ignores removed;
  ruff also checks `infra/`; dependabot covers `/infra/cdk`; the CDK job runs the assertion
  tests and `cdk synth --strict`. The `aws_retry` annotation makes mypy clean again (M9).
- The version is 0.3.0: the package still said 0.2.0 after the breaking changes above; the
  sdist no longer ships the `.claude/` directory (N9).

### Fixed

- `ENVAULT_AUDIT_TTL_DAYS` is honoured (it was documented but ignored); also available as
  `--audit-ttl-days` on every command that writes audit events.
- Audit events no longer appear in `state-index`, so `status`, `rotate-key`,
  decrypt-by-name and `dashboard` stop reading the whole audit history. Events written by
  earlier versions stay in the index until their TTL expires; queries still filter them.
- `dashboard` "Last activity" no longer shows "—" once any audit event exists.
- `decrypt -o FILE` writes to `FILE` instead of `FILE`'s parent directory.
- CDK: non-current S3 versions are no longer moved to Glacier. Records pin a `VersionId`,
  and an archived version cannot be read.
- KMS key policy no longer denies `DisableKey`, so a compromised CMK can be frozen during
  incident response without a CloudFormation change.
- IAM: unused `s3:ListBucket` removed; S3 object actions scoped to `encrypted/*`;
  `sts:GetCallerIdentity` granted for audit attribution.
- Ops SNS topic is encrypted with the envault CMK (since M10, with a KMS key of its own; see
  below).
- S3 downloads require a content-addressed key (`encrypted/{aa}/{sha256}/{name}.encrypted`)
  so a poisoned DynamoDB `s3_key` cannot fetch an arbitrary object. (0.3.0 writes per-upload
  keys named by the file ID, and migrated records keep legacy-sync keys; the check accepts each
  record's own layout only, see M7 and M4 below.)
- Directory-symlink trees are skipped by `os.walk(followlinks=False)` during encrypt.
- `migrate` confines input paths to the import directory and rejects per-component
  symlinks; non-object NDJSON lines are per-record errors. (Since M4 the directories are the
  plaintext and ciphertext roots; see below.)
- `rotate-key` calls `DescribeKey` on the target CMK (must be `Enabled`) before any
  download or decrypt.
- `last_updated` CAS tokens use microsecond timestamps.
- `exec` warns when the child will inherit `AWS_*` credentials; `--clean-env` remains
  opt-in. In-memory secret buffers are wiped if `--secret` rejects a non-UTF-8 or NUL value.
- Encrypt/decrypt close leftover fds if the SDK stream fails before `fdopen`.
- Empty `s3_version_id` no longer fetches the latest S3 object. `decrypt` / `exec` /
  `rotate-key` require `--latest` for migrated records.
- `audit --since` showed only that one day, so later events were missed (M3).
- `migrate` rejected every genuine aws-encryption-cli record (absolute paths outside
  FROM_PATH's directory), pointed records at S3 keys the legacy sync never created, stored the
  key ARN undecoded, and exited 0. It now confines both paths to their roots, records the key
  `aws s3 sync` wrote (`encrypted/<path>.encrypted`, validated as a legacy-sync key), decodes
  the key ARN and message ID, imports only the newest record per ciphertext file, can pin each
  object's VersionId (`--bucket`), and exits 1 if any record failed (M4).
- Two uploads of the same content no longer share an S3 key: every upload (encrypt,
  `encrypt --force`, rotate-key) goes to `encrypted/{id[:2]}/{id}/{message_id}/{name}.encrypted`
  with `If-None-Match: *`, so a lost race can no longer leave a record pinned to a noncurrent
  version that the lifecycle rule later expires. rotate-key repoints the record and leaves the
  old object untouched; an upload whose state write fails is logged as an orphan (M7).
- CDK: alarms could not publish to the CMK-encrypted ops topic. The topic has its own KMS key,
  CloudWatch may use it, and the topic policy lets this account's `envault-*` alarms publish
  (M10). The key's grant carries no source conditions, which might never match on the calls SNS
  makes for CloudWatch and would silence every alarm again (N7).
- Retries: only transient AWS errors are retried (not AccessDenied, NotFound or a refused
  conditional write); each attempt is one HTTP request, as `{"max_attempts": 1}` meant two;
  a DynamoDB write whose reply was lost no longer reports a false conflict; a throttled KMS
  Decrypt is retried and never reported as tampering (L1).
- SDK, OS and AWS errors are reported in one line instead of a traceback; batch commands go on
  with the remaining files and exit 1 at the end (L2).
- An interrupt between publishing and removing the staging file no longer zero-fills the
  published output: a multiply-linked file is unlinked, never overwritten (L3).
- `exec --file`: the credential descriptor is rewound after sealing, so a child that reads
  through a duplicate of it (macOS and BSD `/dev/fd/N`) sees the content (L7).
- A state row with an attribute of the wrong type no longer crashes lookups for everyone:
  `status` warns and goes on, `rotate-key` reports it and rotates the rest, name lookups by
  basename ignore it, and a lookup that lands on it is refused (N2).
- Documentation: `additional_kms_key_arns` takes key ARNs only; the agent docs describe keyed
  identifiers and the current context keys (R3).
- Tests: the check that no request carries the plaintext's SHA-256 inspects serialized
  requests, which it missed inside DynamoDB conditions (N1); the signal tests pass under
  `nohup` and leave no signal disposition changed (N4).
- Help: `decrypt`, `status --file` and `audit --file` no longer say that `status` lists a full
  file ID. It shows the first 16 characters; the full ID is in the object key `encrypt`
  prints (P4).

### Removed

- `Config.from_env`, `Config.table_name`, `Config.allowed_account_ids`,
  `FileRecord.ttl`, `FileRecord.decrypted_at` (unused).

## [0.2.0] - 2026-07-26

### Added

- `envault exec` — run a command with secrets supplied in memory. `--secret NAME=VAR`
  injects into the child's environment; `--file NAME=VAR` writes to a sealed anonymous
  `memfd` and passes `/proc/self/fd/N`, for programs that require a file path. A `{VAR}`
  token in the command is substituted with that path. `--clean-env` starts the child from a
  minimal environment.
- `envault.isolation` — process hardening (`PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, best-effort
  `mlockall`) applied before any plaintext exists, and `CredentialFd` for credential
  material that has no filesystem path.
- Audit events now record the calling AWS principal ARN, and `envault audit` shows it.
- `crypto.decrypt_to_stream` — streaming decrypt to any sink, verifying the encryption
  context from the ciphertext header before writing a single plaintext byte.
- `S3Store.download_to_memory` for fetching ciphertext without touching disk.

### Fixed

- A file could only ever be decrypted once: `decrypt` required state `ENCRYPTED` and then
  set `DECRYPTED`, making the record unreachable by name and invisible to `rotate-key`.
  Reads are now recorded as events and no longer mutate the stored state, which also removes
  optimistic-lock contention between concurrent readers.
- `rotate-key` silently skipped every previously-decrypted file and exited 0. It now covers
  records left in `DECRYPTED` by earlier versions and exits non-zero if any file could not be
  rotated.
- Audit events could be silently overwritten at a known PK/SK. Event writes now use
  `attribute_not_exists(SK)`.
- Encryption context was verified only after the plaintext had been written to its
  destination; it is now checked before any plaintext is produced.
- Untrusted file names from DynamoDB were rendered as Rich markup, misrepresenting the name
  and raising `MarkupError` on unbalanced tags. All external strings are now escaped.
- KMS discovery hardcoded the `aws` partition, excluding GovCloud and China regions.
- An oversized in-memory fetch was retried three times before failing with the same answer.

### Changed

- `rotate-key` now exits non-zero if any file could not be rotated, rather than reporting
  a partial rotation as success.

## [0.1.0] - 2026-03-03

### Added

- `envault` pip-installable Python package (PEP 517, `hatchling` build backend)
- Client-side envelope encryption via `aws-encryption-sdk` v4:
  - `StrictAwsKmsMasterKeyProvider` for encrypt (explicit key required)
  - `DiscoveryAwsKmsMasterKeyProvider` for decrypt (key from ciphertext header)
  - `REQUIRE_ENCRYPT_REQUIRE_DECRYPT` commitment policy (AEAD, no downgrade)
  - SHA256 checksum integrity verification before encrypt and after decrypt
- DynamoDB state store (`envault.state.StateStore`) replacing flat `output.json`:
  - Single-table design: current state + append-only event log in one table
  - GSIs: `state-index` (by encrypted/decrypted), `date-index` (audit by date)
  - TTL on event records (configurable, default 365 days)
  - Full upsert idempotency on current state records
- CLI commands via `click`: `encrypt`, `decrypt`, `status`, `audit`, `dashboard`, `rotate-key`, `migrate`
- Config from environment variables only (`ENVAULT_KEY_ID`, `ENVAULT_BUCKET`, `ENVAULT_TABLE`, `ENVAULT_REGION`)
- CDK Python stack (`infra/cdk/stacks/envault_stack.py`) provisioning:
  - KMS CMK with annual key rotation
  - S3 bucket with versioning, SSE-KMS, block-public-access
  - DynamoDB table with on-demand billing, KMS encryption, PITR, all GSIs
  - IAM managed policy (least-privilege)
- 21 unit tests using `moto` AWS service mocks (no real AWS required)
- GitHub Actions CI: lint (`ruff`), type check (`mypy`), unit tests on Python 3.10/3.11/3.12
- GitHub Actions publish: PyPI Trusted Publishers (OIDC, no stored API tokens)
- Pre-commit hooks: `detect-secrets`, `ruff`, `ruff-format`, `no-commit-to-branch`
- `tenacity` retry with exponential backoff on all AWS API calls
- `rich` progress display and dashboard table
- `python-json-logger` structured JSON logging with per-operation correlation IDs

### Security

- Removed hardcoded KMS ARN and AWS account ID from `code/decrypt.conf`
- Updated `.gitignore` to exclude `output.json`, build artifacts, `.venv/`
- `detect-secrets` baseline added to block future credential commits
- KMS alias only in config — ARN resolved at runtime via `kms:DescribeKey`

### Migration

Existing `code/output.json` metadata can be imported to DynamoDB:

```bash
envault migrate --from code/output.json --dry-run
envault migrate --from code/output.json
```

After verifying all records, remove `output.json` from git history:

```bash
git-filter-repo --path code/output.json --invert-paths
```
