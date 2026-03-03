# envault Design Document

**Date:** 2026-03-03
**Status:** Implemented (v0.1.0)

---

## Problem Statement

The original `aws-encryption` repository used bash scripts wrapping `aws-encryption-sdk-cli` with:

- **Critical security issue**: 807 records of sensitive file metadata committed in `code/output.json`
- **Critical security issue**: Hardcoded KMS ARN and AWS account ID in `decrypt.conf`
- Flat file state store (`output.json`) — unreliable, git-polluting, no audit trail
- No pip-installable package structure
- No automated tests or CI/CD

---

## Design Goals

1. Pip-installable Python package (`envault`) with a clean CLI
2. DynamoDB for reliable state tracking with full audit trail
3. Client-side envelope encryption (plaintext never leaves the machine)
4. CDK Python stack for all AWS infrastructure
5. No committed secrets or metadata files

---

## Encryption Model

**Client-side envelope encryption with customer-owned KMS CMK:**

- `aws-encryption-sdk` generates a unique data encryption key (DEK) per file
- File is encrypted locally (AES-256-GCM via `AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384`) using the DEK — **plaintext never leaves the machine**
- DEK is wrapped by the customer's KMS CMK (owned and controlled in their AWS account)
- AWS only performs key-wrapping; it never sees plaintext file content
- Decryption requires AWS credentials with `kms:Decrypt` on the CMK
- CDK stack provisions the CMK with automatic annual rotation enabled

---

## Package Structure

```
aws-encryption/
├── src/envault/
│   ├── __init__.py
│   ├── cli.py           # Click entry points
│   ├── crypto.py        # Encryption/decryption (aws-encryption-sdk v4)
│   ├── state.py         # DynamoDB state store
│   ├── s3.py            # S3 upload/download
│   ├── config.py        # Config from env vars only
│   └── exceptions.py    # Custom exceptions
├── infra/cdk/
│   ├── app.py
│   ├── requirements.txt
│   └── stacks/envault_stack.py
├── tests/
│   ├── conftest.py
│   ├── unit/
│   └── integration/
├── .github/workflows/
│   ├── ci.yml           # Lint + test on PR
│   └── publish.yml      # PyPI Trusted Publishers on tag
└── pyproject.toml
```

---

## Technology Choices

| Concern | Choice | Rationale |
|---------|--------|-----------|
| Encryption | `aws-encryption-sdk` v4 (Python) | Native library, no subprocess |
| CLI | `click` | Mature, composable |
| AWS SDK | `boto3` | Standard |
| State store | DynamoDB | Serverless, consistent, queryable |
| Testing | `pytest` + `moto` | AWS service mocks, no real AWS needed |
| Linting | `ruff` | Fast, replaces flake8+isort+pyupgrade |
| Typing | `mypy` (strict) | Catches bugs at development time |
| Retry | `tenacity` | Exponential backoff on AWS API calls |
| Display | `rich` | Progress bars and tables |
| Build | `hatchling` | PEP 517/518, simple config |

---

## DynamoDB Schema (Single-Table Design)

**Table:** `envault-state` (on-demand billing, KMS encryption, PITR enabled)

### Current State Record (one per unique file, upserted)

```
PK: FILE#{sha256_hash}
SK: CURRENT
Attributes: file_name, sha256_hash, current_state (ENCRYPTED|DECRYPTED),
            s3_key, s3_version_id, kms_key_id (alias only),
            encryption_context, algorithm, message_id,
            file_size_bytes, tags, encrypted_at, last_updated, ttl
```

### Event Record (append-only audit log)

```
PK: FILE#{sha256_hash}
SK: EVENT#{timestamp}#{operation}
Attributes: operation (ENCRYPT|DECRYPT|ROTATE_KEY), correlation_id,
            + all current state fields at time of event
```

### Global Secondary Indexes

| Index | PK | SK | Purpose |
|-------|----|----|---------|
| `state-index` | `current_state` | `encrypted_at` | List all encrypted files |
| `date-index` | `date` (YYYY-MM-DD) | `last_updated` | Audit by date |

---

## CLI Commands

```bash
# Core operations
envault encrypt --input ./secret.txt --key-id alias/s3_key --bucket my-bucket \
                --tag project=finance --tag owner=brian
envault decrypt --input ./secret.txt.encrypted --output ./secret.txt

# State queries
envault status --state encrypted          # list all encrypted files
envault status --file <sha256>            # current state of one file
envault audit  --since 2026-01-01         # events for date range
envault dashboard                          # rich summary table

# Key rotation
envault rotate-key --new-key-id alias/new_key

# Migration from legacy output.json
envault migrate --from code/output.json
```

---

## Configuration

All config via environment variables (no config files with secrets):

| Variable | Required | Description |
|----------|----------|-------------|
| `ENVAULT_KEY_ID` | Yes | KMS key alias (e.g. `alias/s3_key`) |
| `ENVAULT_BUCKET` | Yes | S3 bucket name |
| `ENVAULT_TABLE` | Yes | DynamoDB table name |
| `ENVAULT_REGION` | No | AWS region (default: `us-east-1`) |
| `ENVAULT_AUDIT_TTL_DAYS` | No | Event TTL in days (default: `365`) |

---

## Security Hardening Applied

1. **Removed hardcoded KMS ARN** from `code/decrypt.conf` — replaced with `${KMS_KEY_ARN}`
2. **Updated `.gitignore`** — excludes `output.json`, build artifacts, `.venv/`, secrets baseline
3. **Pre-commit hooks** — `detect-secrets`, `ruff`, `ruff-format`, standard checks
4. **`no-commit-to-branch`** — blocks direct commits to `main`
5. **CDK KMS key** — auto-rotation enabled, KMS-encrypted DynamoDB and S3

---

## CI/CD

- **`ci.yml`**: Runs on every PR — `ruff check`, `ruff format --check`, `mypy`, `pytest tests/unit/` across Python 3.10/3.11/3.12
- **`publish.yml`**: Triggered on `v*.*.*` tags — builds wheel + sdist, publishes to TestPyPI then PyPI via OIDC Trusted Publishers (no stored API tokens)

---

## Migration Path

For existing installations with `code/output.json`:

```bash
# Dry run first
envault migrate --from code/output.json --dry-run

# Import to DynamoDB
envault migrate --from code/output.json

# After verifying all records in DynamoDB:
# Remove output.json from git history using git-filter-repo
git-filter-repo --path code/output.json --invert-paths
```
