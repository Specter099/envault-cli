# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**envault** — a Python CLI tool and PyPI package for client-side envelope encryption of files using AWS KMS, with DynamoDB state tracking and S3 storage. Files are encrypted locally with AES-256-GCM via the AWS Encryption SDK; only the data encryption key (DEK) is sent to KMS for wrapping.

## Build & Development Commands

```bash
# Setup: the hash-locked install CI uses (requirements/dev.txt; the command
# that regenerates it is next to the dev extra in pyproject.toml)
python -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary :all: -r requirements/dev.txt
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
.venv/bin/python -m pip check
source .venv/bin/activate

# Run unit tests (no AWS credentials required — uses moto mocks)
pytest tests/unit/ -v

# Run a single test
pytest tests/unit/test_crypto.py::test_roundtrip_encrypt_decrypt -v

# Lint
ruff check src/ tests/ infra/
ruff format --check src/ tests/ infra/

# Type check (strict mode)
mypy src/envault/

# Dependency audit (CI also audits infra/cdk/requirements-ci.txt)
pip-audit

# CDK infrastructure, as CI's cdk-synth job runs it (Python 3.12, aws-cdk CLI 2.1113.0),
# in its own venv: the CDK lock pins differ from requirements/dev.txt
cd infra/cdk && python -m venv .venv && source .venv/bin/activate
python -m pip install --require-hashes --only-binary :all: -r requirements-ci.txt
python -m pytest && cdk synth --strict --quiet
```

## Architecture

### Python Package (`src/envault/`)

The CLI is a Click application (`cli.py:main`) published as the `envault` console script. Data flows through three layers:

```
CLI (cli.py) → crypto / s3 / state → AWS (KMS, S3, DynamoDB)
```

- **`cli.py`** — Click command group: `encrypt`, `decrypt`, `exec`, `status`, `audit`, `dashboard`, `rotate-key`, `migrate`. Orchestrates the other modules. Uses Rich for terminal output.
- **`crypto.py`** — Pure-Python encryption/decryption via `aws-encryption-sdk`. `encrypt_file()` uses `StrictAwsKmsMasterKeyProvider` (requires explicit key ID); `decrypt_file()` uses `DiscoveryAwsKmsMasterKeyProvider` (discovers key from ciphertext). SHA256 checksum verification on decrypt.
- **`fileid.py`** — File identifier schemes. New records: `file_id = hex(HMAC-SHA-256(ID key, SHA-256(plaintext)))` via KMS `GenerateMac` (`IdKey`), verified on read with `VerifyMac` under the record's `id_key_arn` (`FileIdVerifier`, after `check_id_key_arn`: trusted account and partition, before any KMS call). Legacy records: the raw SHA-256.
- **`s3.py`** — `S3Store` class for upload/download with tenacity retry. Captures S3 version IDs. Every upload goes to its own key, `encrypted/{id[:2]}/{id}/{message_id}/{name}.encrypted`, written with `IfNoneMatch="*"`; `assert_s3_key_matches_hash` and `assert_legacy_s3_key` (migrated records) validate a record's key before any download.
- **`state.py`** — `StateStore` with DynamoDB single-table design. PK=`FILE#{file_id}`, SK=`CURRENT` (upserted) or `EVENT#{timestamp}#{operation}` (append-only audit trail). Two GSIs: `state-index`, `date-index`. `FileRecord` carries `file_id`, `id_scheme`, `id_key_arn`; keyed rows store `file_id`/`id_scheme`/`id_key_arn`, legacy rows `sha256_hash` and no `id_scheme`.
- **`config.py`** — shared `boto_config` and the `Config` dataclass that builds the per-file encryption context. Env vars are read by Click options (`envvar=`), not by `Config`.
- **`retry.py`** — `aws_retry`, the one retry policy for AWS calls (see Code Style).
- **`fileutils.py`** — `open_regular_nofollow` (encrypt opens each input once, without following symlinks, and only if it is the inode collected) and `best_effort_delete` (zero-fill then unlink; never zeroes a multiply-linked inode).
- **`isolation.py`** / **`identity.py`** — process hardening and sealed `memfd` credentials for `exec`; the caller ARN recorded on audit events (self-reported).
- **`exceptions.py`** — Exception hierarchy rooted at `EnvaultError`.

### CDK Infrastructure (`infra/cdk/`)

Single stack (`EnvaultStack`) provisioning KMS CMK, KMS HMAC key `alias/envault-id` (file identifiers; retained, deletion denied), S3 bucket (versioned, SSE-KMS), DynamoDB table (on-demand, PITR, KMS-encrypted), and IAM managed policy (including `kms:GenerateMac`/`kms:VerifyMac` on the HMAC key only).

### Legacy Shell Scripts (`code/`)

Original shell-based encrypt/decrypt using `aws-encryption-cli` with `@filename.conf` pattern. The Makefile targets (`make encrypt`, `make decrypt`) invoke these. The `migrate` CLI command imports `code/output.json` into DynamoDB.

## Testing

Tests use **moto** to mock AWS services — no real credentials needed. Shared fixtures in `tests/conftest.py` create mocked DynamoDB tables, S3 buckets, and KMS keys (the data key and the HMAC ID key, see `tests/unit/_id_key.py`). CI runs against Python 3.10, 3.11, 3.12. The CDK assertion tests live in `infra/cdk/tests` and are run from `infra/cdk` (`python -m pytest`), never by `pytest tests/unit`.

## Configuration

All runtime config via environment variables (no config files with secrets):

| Variable | Required | Description |
|----------|----------|-------------|
| `ENVAULT_KEY_ID` | For encrypt | KMS key that wraps data keys: alias (e.g. `alias/envault`), key ID or ARN |
| `ENVAULT_ID_KEY_ID` | For encrypt/migrate | KMS HMAC key (HMAC_256, GENERATE_VERIFY_MAC) that names files, e.g. `alias/envault-id`; elsewhere enables lookup by the SHA-256 of a file's content, and while set every 64-hex lookup is mapped through it first (`kms:GenerateMac`) |
| `ENVAULT_BUCKET` | For encrypt/decrypt/exec/rotate-key | S3 bucket for encrypted files (`migrate`: optional, pins VersionIds) |
| `ENVAULT_TABLE` | Yes | DynamoDB table name |
| `ENVAULT_ALLOWED_ACCOUNT_IDS` | For decrypt/exec/rotate-key | Comma-separated 12-digit AWS account IDs trusted for KMS discovery and for a record's `id_key_arn`; optional for encrypt/migrate (a warning if the ID key's account is not listed) |
| `ENVAULT_REGION` | No | AWS region (default: `us-east-1`) |
| `ENVAULT_AUDIT_TTL_DAYS` | No | Audit event retention (default: `365`) |

## CI/CD

- **ci.yml** — on PR/push to main: Gitleaks secrets scan, lint (ruff + mypy), pip-audit of both locks, unit tests on 3.10/3.11/3.12, and the CDK job (assertion tests, `cdk synth --strict`); every job installs from the hash locks
- **publish.yml** — on semantic version tags (`v*.*.*`): the same quality gate, a tag/version check, `python -m build --no-isolation` with the locked build tools, and publication to PyPI using Trusted Publishers (OIDC)
- **Pre-commit hooks** — `detect-secrets`, `ruff`, `ruff-format`, trailing whitespace, `no-commit-to-branch` (main)

## Code Style

- **ruff** with rules E, F, I, UP, B, S (S101 allowed for tests). Line length 100, target py310.
- **mypy** strict mode with `ignore_missing_imports`.
- AWS calls go through `envault.retry.aws_retry` (tenacity): 3 attempts with waits of 1 s then 2 s, for transient errors only (throttling, 429/5xx, KMS internal or unavailable errors, connection and timeout errors); everything else fails at once, and `KeyboardInterrupt`/`SystemExit` are never retried. `boto_config` makes exactly one HTTP attempt per AWS call (botocore retries off, so `AWS_MAX_ATTEMPTS`/`AWS_RETRY_MODE` are ignored), the Encryption SDK's KMS clients included.

## Key Patterns

- Encryption names its key (`ENVAULT_KEY_ID`, e.g. the stack's `alias/envault`; the legacy shell scripts use `alias/s3_key`); decryption uses **discovery** (key auto-detected from ciphertext header), confined to `ENVAULT_ALLOWED_ACCOUNT_IDS` and the region's partition
- The `REQUIRE_ENCRYPT_REQUIRE_DECRYPT` commitment policy is mandatory on all operations (`--commitment-policy require-encrypt-require-decrypt` in the legacy scripts)
- The file identifier (DynamoDB PK, S3 key component, encryption context `file_id`, CLI lookup) is `HMAC-SHA-256(ID key, SHA-256(plaintext))`, never the SHA-256 itself: the raw hash of a new record's plaintext must not be stored, uploaded, logged, printed or put in an exception. Legacy rows (no `id_scheme`) are identified by the raw SHA-256 and keep working; rotate-key keeps each record's scheme. `encrypt`/`migrate` require `ENVAULT_ID_KEY_ID`; with the ID key configured, a 64-hex IDENTIFIER is first mapped as a SHA-256 through GenerateMac and only the keyed ID is looked up (no fallback if KMS fails); only on a miss is it looked up as typed (a file ID, or a legacy row's SHA-256); without the ID key, only as typed
- DynamoDB events are written with `attribute_not_exists(SK)` and TTL-expired; current state is upserted separately. The condition is client-side only: any principal with `dynamodb:PutItem` can rewrite events, and `principal_arn` is self-reported, so CloudTrail is the authoritative record
