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
