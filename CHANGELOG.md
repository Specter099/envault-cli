# Changelog

All notable changes to `envault` are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

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

## [Unreleased]

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
