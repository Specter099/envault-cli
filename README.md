# envault

Client-side envelope encryption for files using AWS KMS, with DynamoDB state tracking and a full audit trail.

[![CI](https://github.com/Specter099/envault-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/Specter099/envault-cli/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/envault-cli)](https://pypi.org/project/envault-cli/)
[![Python](https://img.shields.io/pypi/pyversions/envault-cli)](https://pypi.org/project/envault-cli/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

> **Beta Software** — This project is under active development and is not yet recommended for production use. APIs, CLI flags, and storage formats may change between releases. Use at your own risk.

---

## How it works

- Files are encrypted **locally** using AES-256-GCM via the [AWS Encryption SDK](https://github.com/aws/aws-encryption-sdk-python)
- The data encryption key (DEK) is wrapped by your KMS customer-managed key (CMK) — **plaintext never leaves your machine**
- Encrypted files are stored in S3; state and audit events are tracked in DynamoDB
- Decryption requires AWS credentials with `kms:Decrypt` on the CMK

---

## Installation

```bash
pip install envault-cli
```

Requires Python 3.10+.

---

## Quick start

```bash
# Set required environment variables
export ENVAULT_KEY_ID=alias/my-kms-key
export ENVAULT_BUCKET=my-encrypted-files-bucket
export ENVAULT_TABLE=envault-state

# Encrypt a file
envault encrypt ./secret.txt --tag project=finance

# Check state
envault dashboard

# Decrypt by filename (or SHA256 hash)
envault decrypt secret.txt -o ./
```

---

## Configuration

All config via environment variables — no config files with secrets.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ENVAULT_KEY_ID` | Yes | — | KMS key alias (e.g. `alias/my-key`) |
| `ENVAULT_BUCKET` | Yes | — | S3 bucket for encrypted files |
| `ENVAULT_TABLE` | Yes | — | DynamoDB table name |
| `ENVAULT_REGION` | No | `us-east-1` | AWS region |
| `ENVAULT_AUDIT_TTL_DAYS` | No | `365` | Days to retain audit events |

---

## CLI reference

```bash
# Encrypt a file (or directory) and store in S3
envault encrypt INPUT_PATH [--tag KEY=VALUE]... [--force]

# Decrypt by filename or SHA256 hash
envault decrypt IDENTIFIER [-o OUTPUT_DIR] [--version N]

# List all encrypted/decrypted files
envault status [--state encrypted|decrypted|all]

# Show state for a specific file
envault status --file SHA256

# View audit events
envault audit [--since YYYY-MM-DD] [--file SHA256]

# Summary dashboard
envault dashboard

# Re-encrypt all files with a new KMS key
envault rotate-key --new-key-id alias/new-key [--dry-run]

# Migrate from legacy output.json (NDJSON format)
envault migrate FROM_PATH [--dry-run]
```

---

## AWS infrastructure (CDK)

The `infra/cdk/` directory contains a CDK Python stack that provisions:

- **KMS CMK** with automatic annual key rotation
- **S3 bucket** — versioned, SSE-KMS, block-public-access enforced
- **DynamoDB table** — on-demand billing, KMS encryption, PITR, all GSIs
- **IAM managed policy** — least-privilege, ready to attach to users/roles

```bash
cd infra/cdk
pip install -r requirements.txt
cdk synth
cdk deploy
```

---

## Development

```bash
# Install with dev dependencies
python -m venv .venv
source .venv/bin/activate
PIP_USER=false pip install -e ".[dev]"

# Run unit tests (no AWS credentials required)
pytest tests/unit/ -v

# Lint and type check
ruff check src/ tests/
mypy src/envault/
```

---

## Security

- KMS alias only in config — ARN is never stored or committed
- `detect-secrets` pre-commit hook prevents credential leaks
- SHA256 checksum verified before encrypt and after decrypt
- DynamoDB events are append-only (never updated)
- S3 bucket policy enforces SSE-KMS on all objects

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
