# envault

Client-side envelope encryption for files using AWS KMS, with DynamoDB state tracking and an audit trail.

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
- Each file is identified by a keyed HMAC of its content hash, computed by a KMS HMAC key, so
  its identifier reveals nothing about its content (see [File identifiers](#file-identifiers))
- Decryption requires AWS credentials with `kms:Decrypt` on the CMK, and `kms:VerifyMac` on the
  HMAC key for files encrypted by 0.3.0 or later

---

## Installation

```bash
pip install envault-cli
```

Requires Python 3.10+ and boto3 1.35.2 or later (installed as a dependency).

---

## Quick start

```bash
# Set the environment variables (the CDK stack's EnvaultEnvVars output prints them)
export ENVAULT_KEY_ID=alias/envault
# KMS HMAC key that names files (see "File identifiers") — required to encrypt
export ENVAULT_ID_KEY_ID=alias/envault-id
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

# Or decrypt to a file, by name, file ID or the SHA-256 of its content
envault decrypt secret.txt -o ./
```

---

## Configuration

All configuration comes from command-line options or environment variables; there is no
config file. Every variable has an option of the same meaning, and the option wins.

| Variable | Option | Used by | Default | Description |
|----------|--------|---------|---------|-------------|
| `ENVAULT_KEY_ID` | `--key-id` | `encrypt` (required) | — | KMS key that wraps each file's data key: alias (e.g. `alias/envault`), key ID or ARN. `rotate-key` takes its target key as `--new-key-id` instead. |
| `ENVAULT_ID_KEY_ID` | `--id-key-id` | `encrypt`, `migrate` (required); `decrypt`, `exec`, `status`, `audit` (optional) | — | KMS HMAC key (key spec `HMAC_256`, usage `GENERATE_VERIFY_MAC`) that names files: alias, key ID or ARN, e.g. `alias/envault-id` from the CDK stack. `encrypt` and `migrate` exit 2 without it. Elsewhere it lets IDENTIFIER be the SHA-256 of a file's content; while it is set, every 64-hex IDENTIFIER is mapped through it first (`kms:GenerateMac`). See [File identifiers](#file-identifiers). |
| `ENVAULT_BUCKET` | `--bucket` | `encrypt`, `decrypt`, `exec`, `rotate-key` (required); `migrate` (optional) | — | S3 bucket for encrypted files. For `migrate` it pins each legacy object's VersionId. |
| `ENVAULT_TABLE` | `--table` | every command (required) | — | DynamoDB table name |
| `ENVAULT_ALLOWED_ACCOUNT_IDS` | `--allowed-account-ids` | `decrypt`, `exec`, `rotate-key` (required); `encrypt`, `migrate` (optional) | — | Comma-separated 12-digit AWS account IDs trusted to have encrypted the data. KMS discovery, and the identifier key a record names, are confined to these accounts. Commands that read exit 1 without it. For `encrypt` and `migrate` it only adds a warning when the ID key's account is not listed (records written then would be refused on read). |
| `ENVAULT_REGION` | `--region` | every command | `us-east-1` | AWS region |
| `ENVAULT_AUDIT_TTL_DAYS` | `--audit-ttl-days` | `encrypt`, `decrypt`, `exec`, `rotate-key`, `migrate` | `365` | Days before DynamoDB TTL expires an audit event (at least 1) |

AWS credentials come from the usual AWS SDK sources (environment, shared config, instance or
task role). `AWS_MAX_ATTEMPTS` and `AWS_RETRY_MODE` have no effect on envault: it makes exactly
one HTTP request per AWS call and retries on its own terms (see [Reading errors](#reading-errors)).

---

## CLI reference

```bash
envault [-v] COMMAND [ARGS]...

envault encrypt INPUT_PATH [--tag KEY=VALUE]... [--force]
envault decrypt IDENTIFIER [-o PATH] [--version N] [--force] [--latest]
envault exec [-s IDENTIFIER=VAR]... [-f IDENTIFIER=VAR]... [--clean-env] [--latest] [--] COMMAND [ARGS]...
envault status [--state encrypted|decrypted|all] [--file ID]
envault audit [--file ID] [--since YYYY-MM-DD [--until YYYY-MM-DD]]
envault dashboard
envault rotate-key --new-key-id KEY [--dry-run] [--latest]
envault migrate FROM_PATH [--plaintext-root DIR] [--ciphertext-root DIR] [--bucket BUCKET] [--dry-run]
```

The connection options (`--table`, `--bucket`, `--region`, `--key-id`, `--id-key-id`,
`--allowed-account-ids`, `--audit-ttl-days`) are left out above; each command takes those listed
for it under [Configuration](#configuration). `envault COMMAND --help` lists everything.

**Exit status.** 0 on success; 1 when envault refuses or fails (a one-line message says why;
batch commands report each file and exit 1 at the end); 2 for a usage error (a bad option,
argument or combination). Interrupted commands exit 143 (SIGTERM), 129 (SIGHUP) or 1 (Ctrl-C,
"Aborted."); see [Signals](#signals-and-interrupted-commands).

**`-v`, `--verbose`.** envault logs JSON lines to stderr: warnings and errors by default, and its
own debug records with `-v`. Other libraries' loggers never go below WARNING, `-v` or not:
botocore's debug output contains signed request headers (the session token) and KMS responses
(the plaintext data key). The Encryption SDK's own warnings and errors appear only with `-v`;
envault reports those failures itself, in one line. The traceback of a file that failed to
encrypt is logged only with `-v`.

**IDENTIFIER.** `decrypt` and `exec` accept any of:

- a **file ID**: the record's full 64-character identifier. `status` and `audit` show its first
  16 characters; the full value is part of the S3 key `encrypt` prints;
- the **SHA-256 of the file's content**, with `ENVAULT_ID_KEY_ID` set: the decrypted content
  must then also hash to the value typed;
- a **stored name**: the path the file was stored under (see `encrypt`), or its basename when
  that is unambiguous. An exact stored name is matched first. Only when nothing is stored under
  exactly that name, and the name has no `/`, are records whose stored path has that basename
  matched (records from before 0.3.0 store bare basenames). Matches that span more than one
  stored name are refused as ambiguous (exit 1), with the candidates listed: use the full
  stored name or the file ID.

`status --file` and `audit --file` take a file ID or, with `ENVAULT_ID_KEY_ID`, a SHA-256;
anything else is "Invalid identifier" (exit 1).

### encrypt

```bash
envault encrypt INPUT_PATH [--tag KEY=VALUE]... [--force]
```

- INPUT_PATH is a regular file or a directory, walked recursively. **Symbolic links are never
  followed.** If INPUT_PATH is itself a symbolic link (Kubernetes secret mounts are), encrypt
  exits 1 and names the path it points to: pass that instead. A FIFO, socket or device, or a
  path that cannot be read, also exits 1.
- In a directory, symbolic links and anything that is not a regular file are listed as
  `⏭ <path>: skipped (...)`. If only such entries were found, encrypt exits 1; an empty
  directory prints "No files found" and exits 0.
- **Stored names.** A file found in a directory is stored under its path relative to
  INPUT_PATH, with `/` separators (`prod/db.env`); a single file under its basename. `decrypt`
  and `exec` take that name. The S3 key and decrypt's default output file use the basename.
- Each file is opened once, without following a symlink and only if it is still the file found
  during the walk; it is hashed and encrypted from that one descriptor. A file swapped after the
  walk is refused with a `✗` line.
- A file whose identifier already has an ENCRYPTED record is skipped
  (`⏭ ... already ENCRYPTED`). `--force` encrypts it again, as a new upload to a new S3 key; the
  previous object stays where it was.
- Every upload goes to an S3 key of its own (see [Storage layout](#storage-layout)).
- `--tag KEY=VALUE` (repeatable): keys of 1–64 letters, digits, `_` or `-`, values of at most 256
  characters (exit 2 otherwise). An argument without `=` is ignored with a warning.
- Each failed file gets a `✗ <name>: <reason>` line and the others are still encrypted; then
  "N file(s) failed to encrypt." and exit 1. Without the ID key, exit 2.
- With `ENVAULT_ALLOWED_ACCOUNT_IDS` set, envault warns once on stderr if the ID key is in none
  of those accounts: reads refuse a record whose identifier key is in an untrusted account. The
  exit status is unaffected.

### decrypt

```bash
envault decrypt IDENTIFIER [-o PATH] [--version N] [--force] [--latest]
```

- **`-o`, `--output PATH`** (default `.`):
  - an existing directory: the file is written there under the basename of its stored name.
    A name that is empty, starts with `.`, or contains control or invisible characters is
    replaced by `decrypted_<first 16 characters of the file ID>`;
  - anything else is the output file's path;
  - a PATH that ends in `/` must be an existing directory: otherwise decrypt exits 2 before
    reading anything (earlier versions wrote a file named after the directory);
  - an existing output file is replaced only with `--force` (exit 1 otherwise).
- **`--version N`** chooses among records stored under the same exact name, newest first by
  encryption time: 1 is the newest (the default), 2 the one before, and so on. N must be at
  least 1 (exit 2); a version that does not exist exits 1. When several exist, decrypt says
  which one it used. If the two newest were encrypted at the same instant, decrypt refuses
  (exit 1) and lists them with their `--version` numbers: pass one.
- **`--latest`** allows a record with no S3 VersionId (migrated records not pinned with
  `migrate --bucket`) to fetch the bucket's current object. Without it such records are refused.
- Before any plaintext reaches the output, decrypt checks that a row found by file ID or SHA-256
  describes that identifier, that the record's S3 key is its own, that a keyed record's
  identifier key is in a trusted account, and that the ciphertext's encryption context matches
  the record (before a single plaintext byte is written). The plaintext must then hash to the
  record's identifier: its SHA-256 for a legacy record, KMS `VerifyMac` for a keyed one, and the
  SHA-256 typed, if one was. Only then is it named `.NAME.<hex>.verified` (hidden, mode 0600)
  next to the output.
- The DECRYPT audit event is written next. If that write fails, the plaintext is destroyed and
  decrypt exits 1: an unlogged read is a failure. Only then is the file published (a hard link,
  so an existing file is never replaced unless `--force`).

### exec

```bash
envault exec [-s IDENTIFIER=VAR]... [-f IDENTIFIER=VAR]... [--clean-env] [--latest] [--] COMMAND [ARGS]...
```

- **envault's options go before COMMAND.** Everything from COMMAND on is passed to it unchanged,
  including options such as `--region` or `-f`, so `--` is optional. An unknown option before
  COMMAND is a usage error (exit 2).
- `-s`, `--secret IDENTIFIER=VAR` puts the plaintext in environment variable VAR, minus one
  trailing newline. It must be UTF-8 without NUL bytes (exit 2 otherwise: use `-f`).
- `-f`, `--file IDENTIFIER=VAR` writes the plaintext to a sealed anonymous memory file and sets
  VAR to its path, `/proc/self/fd/N`. A `{VAR}` token anywhere in COMMAND is replaced with that
  path. Without `memfd` (other platforms) the plaintext goes to an unlinked temporary file, with
  a note; on macOS and BSD the path is `/dev/fd/N`.
- At least one `-s` or `-f` is required; VAR must be a valid environment variable name, used
  once (exit 2).
- A name resolves as for `decrypt`, but exec always takes the newest record and has no
  `--version`: an ambiguous name, or two newest records encrypted at the same instant, is
  refused (exit 1). Use the file ID.
- **`--clean-env`** starts COMMAND with only `PATH`, `HOME`, `LANG`, `LC_ALL`, `TERM`, `TZ` and
  `USER` from envault's environment, plus the secrets. Without it COMMAND inherits everything,
  including any AWS credentials, and envault warns when `AWS_*` variables are present.
- `--latest`: as for `decrypt`.
- One ACCESS audit event per secret is written before COMMAND starts. If it cannot be written,
  nothing runs and no secret is delivered (exit 1).
- **Exit status.** Once COMMAND starts it replaces envault (`execve`), so the status is
  COMMAND's own. Before that: 1 when envault refuses (nothing ran, no secret delivered), 2 for a
  usage error, 127 when COMMAND cannot be started.
- **Signals.** A SIGTERM, SIGHUP or Ctrl-C that arrives before COMMAND starts stops envault as
  for any command (143, 129, or 1 with "Aborted.") and COMMAND never runs. In the last instant
  before `execve`, while envault holds those signals, one that arrives kills envault by its
  default action instead: the shell sees 128 + the signal number (130 for SIGINT, 143 for
  SIGTERM, 129 for SIGHUP), and COMMAND does not run either. Either way the ACCESS event may
  already have been written. COMMAND starts with default handling of SIGINT, SIGTERM, SIGHUP,
  SIGPIPE and SIGXFSZ and no signal blocked; a SIGHUP ignored by `nohup` stays ignored.

See also [Running commands with secrets](#running-commands-with-secrets).

### status

```bash
envault status [--state encrypted|decrypted|all] [--file ID]
```

Lists records (all states by default), newest first: stored name, state, the first 16
characters of the file ID, encryption time and tags. `--file` shows one record, found by file ID
or SHA-256 (see IDENTIFIER); not found exits 1. A malformed record (an attribute of a type
envault never writes) is left out of the listing with a warning (exit 0); `--file` refuses one
(exit 1).

### audit

```bash
envault audit [--file ID] [--since YYYY-MM-DD [--until YYYY-MM-DD]]
```

- `--since` and `--until` give an inclusive range of **UTC** calendar days. `--until` defaults to
  today (UTC) and needs `--since`. A range that ends before it starts, or spans more than 366
  days, is a usage error (exit 2); a malformed date exits 1.
- Without `--file`, `--since` is required (exit 1 otherwise) and every event in the range is
  shown. `--file` shows one file's events, limited to the range if one is given.
- Events are listed oldest first: time, operation (ENCRYPT, DECRYPT, ACCESS, ROTATE_KEY), stored
  name, the first 16 characters of the file ID, the principal the client recorded, and the
  correlation ID. "No events found." exits 0.
- With `ENVAULT_ID_KEY_ID` set, `--file` with a SHA-256 is mapped first; the value is looked up
  as typed only if nothing (no event and no record) is stored under the mapped identifier.

### dashboard

```bash
envault dashboard
```

Counts of tracked files by state and the time of the last activity.

### rotate-key

```bash
envault rotate-key --new-key-id KEY [--dry-run] [--latest]
```

- Re-encrypts every tracked file under KEY (alias, key ID or ARN): records in ENCRYPTED, and
  records that versions before 0.2.0 left in DECRYPTED. First, `DescribeKey` must show KEY
  enabled and usable, or nothing is downloaded (exit 1).
- For each record: download and decrypt it, verify it (its checksum; `VerifyMac` for a keyed
  record) before re-encrypting, refuse if the bytes changed between decryption and
  re-encryption, upload to a new S3 key with If-None-Match, repoint the record, and write a
  ROTATE_KEY event. The plaintext copy lives in a private RAM-backed directory under `/dev/shm`
  when there is one with room, else in a 0600 temporary file overwritten with zeros before it
  is deleted (best effort on copy-on-write filesystems and SSDs).
- **Schemes are kept.** A keyed record keeps its file ID and identifier key; a legacy record
  stays legacy (its encryption context keeps the `sha256` key) and keeps its SHA-256 as its
  identifier. Migrated records move to a per-upload envault key.
- **The old object is not touched**: it stays current in the bucket and readable with the old
  key until you disable that key (see [Storage layout](#storage-layout)).
- A file that fails gets an error line and the rest continue; then "Rotation incomplete" and
  exit 1. A malformed record is reported with a `✗` and counts as a failure.
- `--dry-run` lists what would be rotated without the key check, downloads or writes. It exits
  0, or 1 if any record is malformed ("Rotation would be incomplete").
- `--latest`: as for `decrypt`. `ENVAULT_ALLOWED_ACCOUNT_IDS` is required, `--dry-run` included.
  The stack's managed policy covers only the stack key and the keys in `additional_kms_key_arns`
  (see [AWS infrastructure](#aws-infrastructure-cdk)).

### migrate

```bash
envault migrate FROM_PATH [--plaintext-root DIR] [--ciphertext-root DIR] [--bucket BUCKET] [--dry-run]
```

Imports the metadata the legacy shell workflow wrote (`code/encrypt.sh` runs aws-encryption-cli
from `code/` with `--metadata-output output.json`: one JSON record per line, with absolute
paths) as ENCRYPTED records that point at the objects
`aws s3 sync ../encrypted s3://$S3_BUCKET/encrypted` uploaded. The local ciphertext need not
exist any more; only its recorded path is used.

- **`--plaintext-root DIR`**: the directory the legacy workflow encrypted (its INPUT_DIR).
  Default: `encrypt/` next to FROM_PATH's directory. The plaintext must still be there: it is
  hashed to give the record its keyed identifier. Records are stored under their path relative
  to this root.
- **`--ciphertext-root DIR`**: where aws-encryption-cli wrote the ciphertext (its OUTPUT_DIR).
  Default: `encrypted/` next to FROM_PATH's directory. A record points at
  `encrypted/<path relative to this root>`.
- Both paths of a record are checked against their root before anything is opened; relative
  paths are taken from FROM_PATH's directory. `..`, paths outside the roots and symbolic links
  inside them are refused. A project that has moved needs the paths in the metadata rewritten.
- **`--bucket BUCKET`** (default `ENVAULT_BUCKET`) checks that each object exists (HeadObject,
  which needs `s3:GetObject`) and pins its current VersionId, so decrypt needs no `--latest`.
  `--bucket ""` turns this off; the records then have no VersionId and `decrypt`, `exec` and
  `rotate-key` need `--latest`.
- **`--id-key-id`** / `ENVAULT_ID_KEY_ID` is required (exit 2). **`--allowed-account-ids`** is
  optional and warns as for `encrypt`.
- `--dry-run` parses and checks every record, hashes the plaintext and computes identifiers
  (GenerateMac; HeadObject with `--bucket`), and writes nothing to DynamoDB.
- Each record stores the KMS key ARN decoded from the metadata, the message ID in hex, the
  encryption context without the SDK's `aws-crypto-*` keys, the tag `source=migrated`, and an
  ENCRYPT event.
- **Skipped**, not errors: records that are not encryptions; a record followed by a later one
  for the same ciphertext file (aws-encryption-cli appends to the metadata file, and only the
  newest record describes the synced object); content already imported from an earlier line;
  records already in the table.
- **Refused** with a `✗` line, the rest continuing: a missing plaintext, a path outside its root,
  an algorithm suite without key commitment, more than one encrypted data key, a key provider
  other than KMS, a `key_info` that is not a KMS key ARN, a line that is not a JSON object.
- Exit 1 if any record failed (the summary is printed first) or FROM_PATH cannot be read;
  2 without the ID key.

### Signals and interrupted commands

- SIGTERM and SIGHUP make envault clean up and exit 143 and 129. Ctrl-C (SIGINT) prints
  "Aborted." and exits 1. A signal the parent process ignored (`nohup` ignores SIGHUP) stays
  ignored.
- Cleanup removes every temporary file: downloaded ciphertext, decrypt's hidden `.part` and
  staging files, rotate-key's plaintext copies and its `/dev/shm/envault_rot_*` directory.
  Plaintext is overwritten with zeros first (best effort on copy-on-write filesystems and SSDs).
- After the first stop signal the next one is ignored, so cleanup can finish. A third ends
  envault at once with the signal's default action, which can leave temporary files, plaintext
  included, behind. Signals that arrive while envault creates or destroys a temporary file are
  held until that short step ends, and count towards the third.
- SIGKILL, an out-of-memory kill or a power loss skip cleanup: hidden
  `..NAME.<hex>.verified.<random>.part` and `.NAME.<hex>.verified` files next to decrypt's
  output, `envault_*` files in the temporary directory and `/dev/shm/envault_rot_*` directories
  can remain, and may hold plaintext.

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

# The -- is optional: envault stops reading its own options at COMMAND
envault exec -s db.env=DATABASE_URL psql -f schema.sql
```

`--file` writes the plaintext to an anonymous in-memory descriptor (`memfd`), seals it once
the checksum, identifier and encryption context verify, and passes `$VAR` as
`/proc/self/fd/N`. No directory entry ever exists, so no other process can open it by name.
A `{VAR}` token anywhere in the command is replaced with that path.

Before decrypting, envault disables core dumps and sets `PR_SET_DUMPABLE=0` so a same-uid
process cannot `ptrace` it or read `/proc/<pid>/mem` while the secret is in flight, and
attempts to lock its pages out of swap.

**What this does not protect against.** `PR_SET_DUMPABLE` is reset by `execve`, so it covers
the envault process, not the command it launches — a same-uid attacker can still read that
child's `/proc/<pid>/environ`. Nothing here stops root. CPython cannot reliably zero plaintext
it has already copied, so `--file` is the stronger mode wherever the consumer accepts a path.
Without `--clean-env` the command also inherits your AWS credentials.

Access is recorded in the audit trail, attributed to the calling AWS principal, **before** the
command starts. If that write fails the command does not run: an unlogged secret read is
treated as a failure, not a warning.

---

## File identifiers

Every stored file has a 64-character hex identifier: its DynamoDB key, part of its S3 key, the
value `status` and `audit` show (shortened). New files are named by a keyed hash,

```text
file_id = HMAC-SHA-256(ID key, SHA-256(plaintext))
```

computed by KMS `GenerateMac` with the HMAC key in `ENVAULT_ID_KEY_ID` (the CDK stack creates
`alias/envault-id`). The plain SHA-256 of a new file is never stored, uploaded, put in the
encryption context, logged or printed: for a short secret such as a PIN it gives the content
away to anyone who can list the bucket or read CloudTrail. `encrypt` and `migrate` refuse to
run without the key (exit 2).

- **Every read of a keyed file is verified.** After decrypting, and before anything is named,
  written, sealed, handed to a command or re-encrypted, KMS `VerifyMac` must confirm that the
  plaintext has the record's identifier, under the key ARN stored on the record. That ARN must be
  in an account listed in `ENVAULT_ALLOWED_ACCOUNT_IDS` and in the region's partition; envault
  checks this before any KMS call for the record.
- **Files stored by earlier versions** keep their SHA-256 identifier (rows without `id_scheme`),
  and decrypt, exec, rotate-key, status, audit and dashboard keep working with them. Their hash
  stays where it already was (S3 key, DynamoDB key, encryption context); `rotate-key` does not
  convert them. Encrypting such a file again creates a new, keyed record next to the old one.
- **Lookup order.** With `ENVAULT_ID_KEY_ID` set, a 64-hex IDENTIFIER (`decrypt`, `exec -s/-f`,
  `status --file`, `audit --file`) is first taken as the SHA-256 of a file's content: KMS
  `GenerateMac` maps it to a keyed identifier, and only that is looked up. The record found must
  be keyed with the configured key, and the plaintext must hash to the value typed. Only if
  nothing is stored under the mapped identifier is the value looked up as typed: a file ID, or
  the SHA-256 that is a legacy record's identifier. So, while the variable is set:
  - **every 64-hex lookup needs `kms:GenerateMac`**, a file ID included;
  - if GenerateMac fails, the lookup stops there (exit 1, "KMS could not compute a file
    identifier …"). It never falls back to sending the value to DynamoDB;
  - a SHA-256 of a keyed file never reaches DynamoDB;
  - if a file has both a legacy and a keyed record, its SHA-256 finds the keyed one.

  Without the variable, a value is looked up as typed only, and the SHA-256 of a keyed file is
  not found (the message says to set `ENVAULT_ID_KEY_ID`). A principal with `kms:VerifyMac` but
  not `kms:GenerateMac` should leave the variable unset and use file IDs or names.
- **IAM.** `kms:GenerateMac` (encrypt, migrate, 64-hex lookups while the ID key is set) and
  `kms:VerifyMac` (every read of a keyed file) on the ID key. Either lets a principal test
  guesses against an identifier, so give them only to principals that may decrypt the files
  anyway. The stack's managed policy grants both, on that key only.
- **What CloudTrail can record.**
  - KMS events, recorded by default: each `GenerateMac` and `VerifyMac` request (key, caller,
    time). The `Message` sent with it (the SHA-256 digest) is a sensitive parameter in the KMS
    API and is not expected in the record. `GenerateDataKey` and `Decrypt` events carry the
    encryption context: `purpose`, `file_id` (`sha256` on legacy records), `file_name` (the
    stored name) and `kms_key_alias`.
  - DynamoDB data events, if you enable them, can record the item keys envault reads and
    writes: `FILE#<file ID>`, and for a legacy record `FILE#<its SHA-256>`, which is its key and
    already in its S3 key and encryption context.
  - S3 data events and the bucket's server access logs record object keys, which carry the file
    ID and the basename of the stored name (for migrated records, their legacy path).
- **Keep the key.** KMS does not rotate HMAC keys automatically, and deleting or disabling the
  key makes every keyed record unverifiable, so unreadable through envault. The stack retains the
  key and denies `kms:ScheduleKeyDeletion` on it. Changing `ENVAULT_ID_KEY_ID` gives new files
  new identifiers, and SHA-256 lookups then map only through the configured key.

---

## Storage layout

**DynamoDB.** One table: per file, a `CURRENT` row (key `FILE#<file ID>`) holding the stored
name, state, S3 key and VersionId, KMS key, encryption context, identifier scheme and tags; and
append-only `EVENT#<time>#<operation>#…` rows that DynamoDB TTL expires after
`ENVAULT_AUDIT_TTL_DAYS`. Keyed rows carry `file_id`, `id_scheme` and `id_key_arn`; legacy rows
carry `sha256_hash` and no `id_scheme`.

**S3 keys.** Every upload — `encrypt`, `encrypt --force` and each file `rotate-key` rotates —
goes to a key of its own,

```text
encrypted/<file ID[:2]>/<file ID>/<message ID>/<basename>.encrypted
```

where the message ID is the Encryption SDK's 64-hex message ID. The upload is conditional
(`If-None-Match: *`): S3 refuses to create an object over an existing key, so no upload can make
the version a record pins noncurrent. Each record pins its object's VersionId. Keys written by
earlier versions (`encrypted/<file ID[:2]>/<file ID>/<basename>.encrypted`) and migrated records'
legacy keys (`encrypted/<path>.encrypted`) are still read; every record's key is checked against
its layout before the object is fetched.

**Orphans.** If the state write fails after an upload (typically a concurrent `encrypt` of the
same content won the conditional write), the new object is an orphan: current, but no record
points to it. envault logs it at ERROR, with the word "orphan", its key and VersionId; it can be
deleted.

**Superseded objects stay current.** `encrypt --force` and `rotate-key` leave the previous
object in place: it is not deleted (the managed policy grants no `s3:DeleteObject`) and, being
the current version of its own key, it is not expired by the lifecycle rule, which expires only
noncurrent versions (after 365 days). Delete such objects yourself if you need them gone.

**Revocation.** Rotating does not revoke anything: the old object can still be decrypted by
anyone with `kms:Decrypt` on the old CMK. **Disabling the old CMK** (`aws kms disable-key`) once
rotation has finished is the revocation boundary. The stack's key policy denies scheduling key
deletion but allows disabling, so this needs no CloudFormation change.

---

## Reading errors

**KMS or integrity?**

- A message with **"KMS could not …"** in it, whatever its headline ("KMS error:" or
  "Decryption error:" from `decrypt`, "Refusing to run:" from `exec`, "Error:" from `status` and
  `audit`, or a `✗` line), is about KMS availability or permission: throttling, a network
  failure, AccessDenied, a disabled key, a key that is not an HMAC key. It says nothing about the
  file or the ciphertext.
- An **integrity** failure says so: a **checksum mismatch** (also reported when a keyed file's
  MAC does not verify), an **encryption context mismatch**, a ciphertext that "may be corrupted,
  truncated, or tampered with", or a row that "describes a different file" or "may have been
  tampered with". No plaintext was written, sealed or handed over.
- "KMS has no key …" when decrypting: the key named in the ciphertext was deleted (its data
  cannot be recovered), or the ciphertext header was altered.

**Retries.** AWS calls are tried up to 3 times, waiting 1 s and then 2 s, and only for
transient failures: throttling and rate limits, HTTP 429, 500, 502, 503 and 504, internal or
unavailable service errors (KMS included), S3's ConditionalRequestConflict, and dropped or
timed-out connections. Anything else (AccessDenied, NotFound, a refused conditional write, a
tampered ciphertext) fails at once. Each attempt is exactly one HTTP request: botocore's own
retries are off for every client envault creates, the Encryption SDK's KMS clients included, so
`AWS_MAX_ATTEMPTS` and `AWS_RETRY_MODE` are ignored. Ctrl-C and stop signals are never retried.
A failed MAC check is not retried, and `exec` retries a decrypt only while nothing has been
written to the secret's buffer. Three calls are not retried at all: `dashboard`'s count queries,
`rotate-key`'s check of the target key, and the caller lookup that attributes audit events
(which records the principal as `unknown` if it fails).

---

## Security model

- Encryption is local, with key commitment (`REQUIRE_ENCRYPT_REQUIRE_DECRYPT`) and exactly one
  encrypted data key per message.
- KMS discovery is constrained to the accounts in `ENVAULT_ALLOWED_ACCOUNT_IDS` and the region's
  partition: a ciphertext whose data key names a key anywhere else is refused without a KMS
  call.
- The encryption context and the file's identifier (its keyed HMAC, or the SHA-256 for files
  from earlier versions) are both verified **before** any plaintext is named, written, sealed or
  handed to a command — a substituted ciphertext never materialises.
- Files are named by a keyed HMAC of their content hash, never by the hash itself (see
  [File identifiers](#file-identifiers)). Records written before 0.3.0 keep their SHA-256.
- **Lookups by file ID or SHA-256 are verified**: the row must describe the identifier it was
  found under, and the plaintext must hash (or MAC) to it. **Lookups by name trust anyone who
  can write to the table**: such a principal can point a name at another file's record. Use the
  file ID where that matters.
- Configuration can name keys by alias, but the table does store key ARNs: `id_key_arn` on
  keyed records (checked against the trusted accounts on every read) and `kms_key_id` on
  migrated records (decoded from the legacy metadata). Other records store the key as it was
  given to `--key-id` or `--new-key-id`.
- **The DynamoDB audit trail is an index, not evidence.** envault writes each event with a
  condition (`attribute_not_exists(SK)`) so that it never overwrites one by accident, and
  records the principal that ran the command. The condition is applied by the client only: any
  principal with `dynamodb:PutItem` on the table, which every envault user has, can rewrite or
  forge events (or shorten their TTL), and `principal_arn` is whatever the writing client
  reported. **CloudTrail is the authoritative record**: KMS events (`Decrypt`,
  `GenerateDataKey`, `GenerateMac`, `VerifyMac`), plus DynamoDB and S3 data events if you enable
  them.
- The bucket blocks public access and its policy denies any request not made over TLS. Objects
  are SSE-KMS-encrypted because the bucket's default encryption is SSE-KMS with the envault CMK
  and envault's uploads ask for SSE-KMS explicitly; the bucket policy does not itself refuse an
  upload without it.
- `-v` never logs KMS data keys or AWS credentials; names and other values read from the table
  are printed with control and invisible characters shown as visible escapes.
- `envault exec` keeps plaintext out of the filesystem entirely (see above for the limits).
- A `detect-secrets` pre-commit hook checks staged changes against `.secrets.baseline`.

---

## AWS infrastructure (CDK)

The `infra/cdk/` directory contains a CDK Python stack, checked with cdk-nag's AwsSolutions
rules at synth, that provisions:

- **KMS CMK** (`alias/envault`) with automatic annual key rotation; retained, and its key policy
  denies `kms:ScheduleKeyDeletion` but allows disabling the key.
- **KMS HMAC key** (`alias/envault-id`, `HMAC_256`, `GENERATE_VERIFY_MAC`) that names files;
  retained, deletion scheduling denied, no automatic rotation (see
  [File identifiers](#file-identifiers)).
- **S3 data bucket** `envault-data-<account>-<region>-an` — versioned, default encryption
  SSE-KMS with the CMK (S3 Bucket Key), Block Public Access, TLS-only bucket policy, server access
  logging, noncurrent versions expire after 365 days; retained.
- **S3 access-log bucket** `envault-access-logs-<account>-<region>-an` — SSE-S3, Block Public
  Access, TLS only, logs expire after 365 days; retained.
- **DynamoDB table** (`TableNameParam`, default `envault-state`) — on-demand, encrypted with the
  CMK, point-in-time recovery, deletion protection, TTL on `ttl`, GSIs `state-index` and
  `date-index`; retained.
- **IAM managed policy** (`PolicyNameParam`, default `EnvaultUserPolicy`), ready to attach to
  users and roles. Direct KMS use of the CMK is limited to envault ciphertexts (encryption
  context `purpose` = `envault-backup`, or `backup` for the legacy scripts); bucket and table
  encryption is allowed only via S3 and DynamoDB; `kms:GenerateMac`/`kms:VerifyMac` on the HMAC
  key only; `s3:PutObject`, `s3:GetObject` and `s3:GetObjectVersion` on `encrypted/*`;
  `dynamodb:PutItem`, `GetItem` and `Query` on the table and its indexes;
  `sts:GetCallerIdentity`. It grants no action that deletes an object or an item.
- **SNS topic and alarms** for operations: the topic is encrypted with a KMS key of its own
  (`EnvaultOpsTopicKey`, deleted with the stack after a 30-day waiting period), and two alarms,
  `envault-dynamodb-throttle` and `envault-dynamodb-system-errors`, publish to it. Pass
  `AlertEmailParam` to subscribe an email address. The topic policy lets only this account's
  CloudWatch alarms whose names start with `envault-` publish, so **name any new alarm
  `envault-*`**. The key grants CloudWatch its use without source conditions, because the key
  encrypts nothing but this topic, the topic policy already decides which alarms may publish,
  and a condition that KMS might never see on the calls SNS makes for CloudWatch would silently
  stop every alarm.

```bash
cd infra/cdk
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
npm install -g aws-cdk@2.1113.0      # the CLI version CI uses
cdk diff                             # an existing stack: see the warning below
cdk deploy --parameters AlertEmailParam=<alert email address>
```

**Bucket names.** The buckets are created in the S3 account-regional namespace
(`BucketNamePrefix` with `BucketNamespace: account-regional`), so CloudFormation names them
`envault-data-<account>-<region>-an` and `envault-access-logs-<account>-<region>-an`, and only
your account can create those names.

**Existing stacks must keep their bucket names.** A stack deployed before 0.3.0 has buckets
with CloudFormation-generated names. Deploying this version to it without the opt-out makes
CloudFormation **replace both buckets**: new, empty buckets; the old ones are retained but
orphaned, with every object and every VersionId your records pin (versions do not survive a
copy); and the managed policy stops covering them. Every existing record would become
unreadable through envault. For such stacks, set the flag on every `cdk diff` and `cdk deploy`,
or once in `infra/cdk/cdk.json`:

```bash
cdk diff -c keep_generated_bucket_names=true      # must show no AWS::S3::Bucket replacement
cdk deploy -c keep_generated_bucket_names=true
```

```json
{
  "app": "python3 app.py",
  "context": { "keep_generated_bucket_names": true }
}
```

The flag takes `true` or `false`. Always run `cdk diff` first and read it.

**Extra keys for `rotate-key`.** `additional_kms_key_arns` adds KMS keys to the managed policy's
data-key statements (`KmsEnvelopeEncryption`, `KmsViaStorageServices`, `KmsDescribeKey`), so
`rotate-key --new-key-id` can use them. It takes **key ARNs only**
(`arn:<partition>:kms:<region>:<account>:key/<key id>`), comma-separated, or a JSON list in
`cdk.json`. Wildcards and alias ARNs fail synth: IAM authorizes KMS use against the key ARN, so
an alias ARN in a policy grants nothing. `rotate-key --new-key-id` may still be given the alias.

```bash
aws kms describe-key --key-id alias/new-key --query KeyMetadata.Arn --output text
cdk deploy -c additional_kms_key_arns=arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab
```

**Outputs.** `KmsKeyAlias`, `IdKeyAlias`, `BucketName`, `TableName`, `ManagedPolicyArn`,
`OpsTopicArn`, and `EnvaultEnvVars`, which prints the exports the CLI needs:
`ENVAULT_KEY_ID`, `ENVAULT_ID_KEY_ID`, `ENVAULT_BUCKET`, `ENVAULT_TABLE`, and
`ENVAULT_ALLOWED_ACCOUNT_IDS` set to the stack's account. If a key in `additional_kms_key_arns`
is in another account, add that account to `ENVAULT_ALLOWED_ACCOUNT_IDS` yourself.

**After deploying, check that alarms can notify.** Force the throttle alarm into ALARM and read
its action history:

```bash
aws cloudwatch set-alarm-state --alarm-name envault-dynamodb-throttle \
  --state-value ALARM --state-reason test
aws cloudwatch describe-alarm-history --alarm-name envault-dynamodb-throttle \
  --history-item-type Action
```

The history should report that the SNS action was executed successfully. A failed action means
alarms cannot reach the topic. The alarm returns to its computed state at its next evaluation.

---

## Upgrading from 0.2.0 to 0.3.0

0.3.0 is the remediation release of the 2026-11-14 security review (see
[CHANGELOG.md](CHANGELOG.md) and [SECURITY_AUDIT.md](SECURITY_AUDIT.md)). In this order:

1. **Upgrade every client first.** Older clients keep writing legacy records, and they mishandle
   what 0.3.0 writes:
   - a **0.2.0** client finds no SHA-256 on a keyed record and decrypts it without any content
     check, so a principal who can write the table can make it deliver another file. Its
     `rotate-key` fails on keyed records, but only after uploading a new version over each
     record's object, which leaves the version the record pins noncurrent: the bucket's
     lifecycle rule deletes noncurrent versions after 365 days;
   - a client built from `main` between 0.2.0 and 0.3.0 refuses keyed records, and records that
     0.3.0 has rotated to per-upload S3 keys, failing closed with the records unchanged; so it
     cannot rotate a record after a 0.3.0 rotation either.
2. **Run `cdk diff`, then deploy**, with `keep_generated_bucket_names=true` on any stack
   deployed before 0.3.0 (see [AWS infrastructure](#aws-infrastructure-cdk)). The diff should
   add the HMAC key, its alias, the ops topic's own key, policy statements and outputs, and must
   not replace any `AWS::S3::Bucket`, `AWS::DynamoDB::Table` or `AWS::KMS::Key`.
3. **Set `ENVAULT_ID_KEY_ID`** (`alias/envault-id`, from the `EnvaultEnvVars` output) wherever
   envault runs. `encrypt` and `migrate` exit 2 without it.
4. **Grant IAM to principals that do not use the stack's managed policy**: `kms:GenerateMac`
   and `kms:VerifyMac` on the ID key's ARN. The key's account must be listed in
   `ENVAULT_ALLOWED_ACCOUNT_IDS`.
5. **Never delete or disable the ID key**: keyed records would become unreadable through
   envault.

Also:

- **Existing records stay legacy**: still readable, still identified by their SHA-256, also
  after `rotate-key`. Encrypting a file again creates a keyed record next to the legacy one.
  Records from before 0.3.0 store bare basenames, and a name is matched exactly before
  basenames are tried, so after re-encrypting a directory use the new relative name
  (`prod/db.env`) or the file ID.
- **Tooling that reads the table directly** must read `file_id` and `id_scheme` (and
  `id_key_arn`) instead of `sha256_hash`, which only legacy rows have.
- **`additional_kms_key_arns`**: replace alias ARNs and wildcards with key ARNs, or synth fails.
- **`migrate`**: rows that an earlier `migrate` wrote point at S3 keys the legacy sync never
  created; delete them before running `migrate` again.
- Behaviour changes worth knowing: `audit --since` is now the start of a range (to today, or
  `--until`); exec options must come before COMMAND; `decrypt -o DIR/` needs DIR to exist;
  directory files are stored under relative names; every 64-hex lookup needs
  `kms:GenerateMac` while `ENVAULT_ID_KEY_ID` is set. The [CHANGELOG](CHANGELOG.md) lists them
  all.

---

## Development

CI installs exactly the versions in the hash-locked `requirements/dev.txt` (wheels only, every
file hash-checked), then the package without its dependencies:

```bash
python -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary :all: -r requirements/dev.txt
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
.venv/bin/python -m pip check
. .venv/bin/activate
```

The gates CI runs (the unit tests on Python 3.10, 3.11 and 3.12, the rest on 3.12):

```bash
pytest tests/unit/ -v --cov=envault --cov-report=term-missing   # no AWS credentials needed (moto)
ruff check src/ tests/ infra/
ruff format --check src/ tests/ infra/
mypy src/envault/
pip-audit
pip-audit --disable-pip --require-hashes --ignore-vuln GHSA-464c-974j-9xm6 -r infra/cdk/requirements-ci.txt
```

The ignored advisory affects only aws-codebuild's S3 log settings in aws-cdk-lib < 2.253.0; the
stack defines no CodeBuild project.

After changing a dependency in `pyproject.toml`, regenerate the lock from the repository root
with uv 0.13 or later (add `--upgrade` to move every package to the newest version the ranges
allow):

```bash
uv pip compile pyproject.toml --extra dev --universal --python-version 3.10 --generate-hashes --output-file requirements/dev.txt
```

The CDK job uses its own lock, `infra/cdk/requirements-ci.txt` (generated for Python 3.12 on
Linux from `requirements-dev.txt`, which has its regeneration command), and the aws-cdk CLI
2.1113.0. The assertion tests in `infra/cdk/tests` are not collected by `pytest tests/unit`:

```bash
npm install -g aws-cdk@2.1113.0
python -m venv .venv-cdk
.venv-cdk/bin/python -m pip install --require-hashes --only-binary :all: -r infra/cdk/requirements-ci.txt
.venv-cdk/bin/python -m pip check
. .venv-cdk/bin/activate
cd infra/cdk
python -m pytest
cdk synth --strict --quiet
cdk synth --strict --quiet -c keep_generated_bucket_names=true \
  -c additional_kms_key_arns=arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
