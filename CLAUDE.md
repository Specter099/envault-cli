# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**envault** — a Python CLI tool and PyPI package for client-side envelope encryption of files using AWS KMS, with DynamoDB state tracking and S3 storage. Files are encrypted locally with AES-256-GCM via the AWS Encryption SDK; only the data encryption key (DEK) is sent to KMS for wrapping.

## Build & Development Commands

```bash
# Setup
python -m venv .venv && source .venv/bin/activate
PIP_USER=false pip install -e ".[dev]"

# Run unit tests (no AWS credentials required — uses moto mocks)
pytest tests/unit/ -v

# Run a single test
pytest tests/unit/test_crypto.py::test_encrypt_file -v

# Lint
ruff check src/ tests/
ruff format --check src/ tests/

# Type check (strict mode)
mypy src/envault/

# CDK infrastructure
cd infra/cdk && pip install -r requirements.txt && cdk synth
```

## Architecture

### Python Package (`src/envault/`)

The CLI is a Click application (`cli.py:main`) published as the `envault` console script. Data flows through three layers:

```
CLI (cli.py) → crypto / s3 / state → AWS (KMS, S3, DynamoDB)
```

- **`cli.py`** — Click command group: `encrypt`, `decrypt`, `status`, `audit`, `dashboard`, `rotate-key`, `migrate`. Orchestrates the other modules. Uses Rich for terminal output.
- **`crypto.py`** — Pure-Python encryption/decryption via `aws-encryption-sdk`. `encrypt_file()` uses `StrictAwsKmsMasterKeyProvider` (requires explicit key ID); `decrypt_file()` uses `DiscoveryAwsKmsMasterKeyProvider` (discovers key from ciphertext). SHA256 checksum verification on decrypt.
- **`s3.py`** — `S3Store` class for upload/download with tenacity retry. Captures S3 version IDs.
- **`state.py`** — `StateStore` with DynamoDB single-table design. PK=`FILE#{sha256}`, SK=`CURRENT` (upserted) or `EVENT#{timestamp}#{operation}` (append-only audit trail). Three GSIs: `state-index`, `date-index`, `tag-index`.
- **`config.py`** — `Config` dataclass loaded from `ENVAULT_*` environment variables.
- **`exceptions.py`** — Exception hierarchy rooted at `EnvaultError`.

### CDK Infrastructure (`infra/cdk/`)

Single stack (`EnvaultStack`) provisioning KMS CMK, S3 bucket (versioned, SSE-KMS), DynamoDB table (on-demand, PITR, KMS-encrypted), and IAM managed policy.

### Legacy Shell Scripts (`code/`)

Original shell-based encrypt/decrypt using `aws-encryption-cli` with `@filename.conf` pattern. The Makefile targets (`make encrypt`, `make decrypt`) invoke these. The `migrate` CLI command imports `code/output.json` into DynamoDB.

## Testing

Tests use **moto** to mock AWS services — no real credentials needed. Shared fixtures in `tests/conftest.py` create mocked DynamoDB tables, S3 buckets, and KMS keys. CI runs against Python 3.10, 3.11, 3.12.

## Configuration

All runtime config via environment variables (no config files with secrets):

| Variable | Required | Description |
|----------|----------|-------------|
| `ENVAULT_KEY_ID` | Yes | KMS key alias (e.g. `alias/my-key`) |
| `ENVAULT_BUCKET` | Yes | S3 bucket for encrypted files |
| `ENVAULT_TABLE` | Yes | DynamoDB table name |
| `ENVAULT_REGION` | No | AWS region (default: `us-east-1`) |
| `ENVAULT_AUDIT_TTL_DAYS` | No | Audit event retention (default: `365`) |

## CI/CD

- **ci.yml** — lint (ruff + mypy) + unit tests on PR/push to main
- **publish.yml** — builds and publishes to PyPI on semantic version tags (`v*.*.*`) using Trusted Publishers (OIDC)
- **Pre-commit hooks** — `detect-secrets`, `ruff`, `ruff-format`, trailing whitespace, `no-commit-to-branch` (main)

## Code Style

- **ruff** with rules E, F, I, UP, B, S (S101 allowed for tests). Line length 100, target py310.
- **mypy** strict mode with `ignore_missing_imports`.
- All AWS calls wrapped with `tenacity` retry (3 attempts, exponential backoff).

## Key Patterns

- Encryption uses key **alias** (`alias/s3_key`); decryption uses **discovery** (key auto-detected from ciphertext header)
- `--commitment-policy require-encrypt-require-decrypt` is mandatory on all operations
- SHA256 of plaintext is the primary file identifier across the entire system (DynamoDB PK, CLI lookup)
- DynamoDB events are append-only and TTL-expired; current state is upserted separately
