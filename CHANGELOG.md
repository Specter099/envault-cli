# Changelog

All notable changes to `envault` are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Security

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
- Ops SNS topic is encrypted with the envault CMK.
- S3 downloads require a content-addressed key (`encrypted/{aa}/{sha256}/{name}.encrypted`)
  so a poisoned DynamoDB `s3_key` cannot fetch an arbitrary object.
- Directory-symlink trees are skipped by `os.walk(followlinks=False)` during encrypt.
- `migrate` confines input paths to the import directory and rejects per-component
  symlinks; non-object NDJSON lines are per-record errors.
- `rotate-key` calls `DescribeKey` on the target CMK (must be `Enabled`) before any
  download or decrypt.
- `last_updated` CAS tokens use microsecond timestamps.
- `exec` warns when the child will inherit `AWS_*` credentials; `--clean-env` remains
  opt-in. In-memory secret buffers are wiped if `--secret` rejects a non-UTF-8 or NUL value.
- Encrypt/decrypt close leftover fds if the SDK stream fails before `fdopen`.
- Empty `s3_version_id` no longer fetches the latest S3 object. `decrypt` / `exec` /
  `rotate-key` require `--latest` for migrated records.

### Added

- CDK `AlertEmailParam` subscribes an email address to the operational alarm topic.
- CDK context `additional_kms_key_arns` grants extra rotation-target CMKs without a
  wildcard IAM grant.

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
