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
# Accounts trusted to have encrypted your data — required for every read
export ENVAULT_ALLOWED_ACCOUNT_IDS=123456789012

# Encrypt a file
envault encrypt ./secret.txt --tag project=finance

# Check state
envault dashboard

# Run a command with the secret in its environment — never written to disk
envault exec -s secret.txt=API_TOKEN -- ./my-app

# Or decrypt to a file, by filename or SHA256 hash
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
| `ENVAULT_ALLOWED_ACCOUNT_IDS` | For reads | — | Comma-separated AWS account IDs trusted to have encrypted the data. Required by `decrypt`, `exec`, and `rotate-key`: it constrains KMS discovery so a ciphertext header cannot name a key outside your control. |
| `ENVAULT_REGION` | No | `us-east-1` | AWS region |
| `ENVAULT_AUDIT_TTL_DAYS` | No | `365` | Days to retain audit events |

---

## CLI reference

```bash
# Encrypt a file (or directory) and store in S3
envault encrypt INPUT_PATH [--tag KEY=VALUE]... [--force]

# Run a command with secrets supplied in memory, never on disk
envault exec -s IDENTIFIER=VAR [-f IDENTIFIER=VAR]... [--clean-env] -- COMMAND [ARGS]...

# Decrypt by filename or SHA256 hash
envault decrypt IDENTIFIER [-o OUTPUT_DIR] [--version N] [--force]

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

## Running commands with secrets

`envault exec` decrypts into a process and nothing else. There is no temporary file to clean
up and no plaintext left behind if the command crashes.

```bash
# As an environment variable
envault exec -s db.env=DATABASE_URL -- ./server

# As a file, for programs that insist on a path (certs, keystores, kubeconfigs)
envault exec -f server.pem=TLS_CERT -- curl --cert {TLS_CERT} https://api.internal

# Both, from a minimal environment that drops your ambient AWS credentials
envault exec --clean-env -s db.env=DATABASE_URL -f server.pem=TLS_CERT -- ./server
```

`--file` writes the plaintext to an anonymous in-memory descriptor (`memfd`), seals it once
the checksum and encryption context verify, and passes `$VAR` as `/proc/self/fd/N`. No
directory entry ever exists, so no other process can open it by name. A `{VAR}` token
anywhere in the command is replaced with that path.

Before decrypting, envault disables core dumps and sets `PR_SET_DUMPABLE=0` so a same-uid
process cannot `ptrace` it or read `/proc/<pid>/mem` while the secret is in flight, and
attempts to lock its pages out of swap.

**What this does not protect against.** `PR_SET_DUMPABLE` is reset by `execve`, so it covers
the envault process, not the command it launches — a same-uid attacker can still read that
child's `/proc/<pid>/environ`. Nothing here stops root. CPython cannot reliably zero plaintext
it has already copied, so `--file` is the stronger mode wherever the consumer accepts a path.

Access is recorded in the audit trail, attributed to the calling AWS principal, **before** the
command starts. If that write fails the command does not run: an unlogged secret read is
treated as a failure, not a warning.

Without `--clean-env`, the child inherits this process's environment, including `AWS_*`
credentials. envault prints a warning when those variables are present. Prefer `--clean-env`
unless the child itself must call AWS.

---

## Key rotation

`envault rotate-key --new-key-id alias/new-key` re-wraps every tracked object. The CDK
managed policy grants `kms:GenerateDataKey` / `kms:Decrypt` / `kms:DescribeKey` only on
**this stack's CMK**. Before rotating to a different key, attach a matching statement for
that key's ARN. The CLI calls `DescribeKey` on `--new-key-id` *before* downloading or
decrypting anything; an `AccessDenied` fails closed with no plaintext on disk.

S3 versioning keeps the previous ciphertext (wrapped under the old key) as a noncurrent
version for 365 days. Rotation is not a revocation primitive — disable the old CMK
(`kms:DisableKey` is allowed; `kms:ScheduleKeyDeletion` is denied) and shorten noncurrent
version expiration if the old key may be compromised.

`decrypt` will not overwrite an existing destination file unless you pass `--force`.

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
- Encryption context and SHA256 checksum are both verified **before** any plaintext is
  written or handed to a command — a substituted ciphertext never materialises
- KMS discovery is constrained to explicitly trusted account IDs, so a ciphertext header
  cannot direct a decrypt at a key outside your control
- DynamoDB events are append-only, enforced by a write condition rather than convention,
  and record the AWS principal responsible
- S3 bucket policy enforces SSE-KMS on all objects
- `envault exec` keeps plaintext out of the filesystem entirely (see above for the limits)

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
