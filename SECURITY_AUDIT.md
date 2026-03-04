# Security Audit Report — envault-cli

**Auditor:** Senior Security Reviewer
**Date:** 2026-03-03
**Codebase version:** 0.1.1 (`main` branch)
**Scope:** Full source review — Python package (`src/envault/`), legacy shell scripts (`code/`), CDK infrastructure (`infra/cdk/`), CI/CD workflows (`.github/workflows/`), tests.

---

## Executive Summary

`envault` implements client-side envelope encryption using AWS KMS and the AWS Encryption SDK. The cryptographic design is sound: AES-256-GCM is applied locally, only the data-encryption key (DEK) is sent to KMS, and the commitment policy `REQUIRE_ENCRYPT_REQUIRE_DECRYPT` is enforced throughout. The CDK infrastructure enforces KMS-SSE on both S3 and DynamoDB, blocks public access, enables versioning, and sets PITR on DynamoDB.

Despite this solid foundation, **four bugs are severe enough to cause either data loss or a security breach in production**, and several additional weaknesses reduce the overall assurance level below what the design intends.

Findings are grouped by severity. Every finding references the exact file and line(s) where the issue appears.

---

## Severity Definitions

| Severity | Meaning |
|----------|---------|
| **CRITICAL** | Exploitable in normal use; causes data loss, integrity failure, or unauthorized access |
| **HIGH** | Significant security or reliability risk; exploitable under plausible conditions |
| **MEDIUM** | Weakness that reduces defence-in-depth or can be chained with another finding |
| **LOW / INFO** | Best-practice gap with low standalone impact |

---

## CRITICAL Findings

### C-1 — `migrate` computes a hash of the file *path*, not the file *content*

**File:** `src/envault/cli.py:411`

```python
sha256_hash = hashlib.sha256(input_path.encode()).hexdigest()
```

`input_path` is a string such as `"../encrypt/payroll.xlsx"`. The hash stored in DynamoDB is therefore **a hash of the path string**, not the file content.

The entire system uses SHA256 of plaintext *content* as the primary identifier:

- DynamoDB PK: `FILE#{content_sha256}` (`state.py:53`)
- Integrity check on decrypt: `expected_sha256` is compared against the freshly-computed content hash (`crypto.py:163`)
- CLI `decrypt` command looks up records by content hash (`cli.py:188`)

Consequence: every record imported via `migrate` will have a PK that can **never** match a real decrypt lookup. Furthermore, if a user attempts to decrypt a migrated record by supplying the migrated (path-based) hash, the decryption will produce a different content hash, triggering `ChecksumMismatchError` and deleting the decrypted output (`crypto.py:164`). Migrated data is effectively **unrecoverable through the CLI**.

**Recommendation:** Either (a) read the actual file and compute its SHA256 content hash during migration, or (b) deprecate the `migrate` command entirely if it cannot access the original plaintext files.

---

### C-2 — Plaintext written to a predictable, world-readable path during key rotation

**File:** `src/envault/cli.py:486`

```python
tmp_pt = tmpdir / f"envault_rot_pt_{record.sha256_hash[:16]}"
```

During `rotate-key`, each encrypted file is downloaded, decrypted, re-encrypted, and uploaded. The intermediate *plaintext* is written to `/tmp/envault_rot_pt_<16-hex-chars>`.

Three distinct vulnerabilities arise here:

1. **World-readable `/tmp`** — on a multi-user Linux host, any process running as another user can `open()` this path while the rotate-key loop is processing, reading the plaintext data.

2. **Predictable filename** — the first 16 hex characters of the SHA256 hash are not secret; they appear in the CLI's status output (`cli.py:269`), in audit records, and in log lines. An attacker with read access to `/tmp` can wait for the specific path rather than guessing.

3. **No secure deletion** — `tmp_pt.unlink(missing_ok=True)` (`cli.py:496`) removes the directory entry but does not zero-out the inode data. On non-journalling filesystems, or after a crash between encrypt and unlink, the plaintext bytes remain on disk until overwritten by subsequent writes.

The encrypted temp files (`tmp_dl`, `tmp_enc`) are less critical but share the same predictability and non-secure-deletion problems.

**Recommendation:** Use `tempfile.NamedTemporaryFile(delete=False, mode='wb')` with `os.chmod(fd, 0o600)` immediately after creation to get a randomly-named, owner-only file. Before unlinking, overwrite the file contents with zeroes (`file.write(b'\x00' * file_size)`). Consider using Python's `secrets`-based temp file wrappers, or process the rotation entirely in memory when file sizes permit.

---

### C-3 — Legacy shell scripts source `.env` without restriction, leaking all credentials to subprocesses

**Files:** `code/encrypt.sh:5-9`, `code/decrypt.sh:5-9`

```bash
if [[ -f "../.env" ]]; then
    set -a
    . "../.env"
    set +a
fi
```

`set -a` causes every variable assigned in `.env` to be automatically exported. All subsequent child processes — including `aws-encryption-cli` and `aws s3 sync` — inherit **every** variable defined in `.env`. If `.env` contains `AWS_SECRET_ACCESS_KEY`, `DATABASE_PASSWORD`, or any other credential, those values are exposed through `/proc/<pid>/environ` to any process on the host with sufficient permissions, and to any subcommand that logs its environment.

The scripts validate only `S3_BUCKET`; all other variables from `.env` pass through silently.

**Recommendation:** Replace the sourcing pattern with explicit, targeted exports:

```bash
S3_BUCKET="$(grep -E '^S3_BUCKET=' ../.env | cut -d= -f2-)"
export S3_BUCKET
```

Alternatively, use a secrets manager and remove `.env` support entirely from these scripts.

---

### C-4 — Encryption scripts upload themselves to the same S3 bucket as encrypted data

**Files:** `code/encrypt.sh:61`, `code/decrypt.sh:56`

```bash
aws s3 sync ../code "s3://${S3_BUCKET}/code"
```

Both the encryption and decryption shell scripts are synced to `s3://<bucket>/code/` — the same bucket that stores production encrypted data. This creates a supply-chain attack surface:

- An attacker who gains **write** access to the S3 bucket (e.g., via misconfigured bucket policy, a compromised AWS credential, or a server-side request-forgery vulnerability) can replace `encrypt.sh` or `decrypt.sh`.
- The next time a developer runs `make encrypt`, they execute the attacker's version, which may exfiltrate plaintext before encrypting.

There is no code-signing or integrity check on the downloaded scripts.

**Recommendation:** Remove the code-sync lines entirely. Scripts should be distributed via version-controlled mechanisms (git, package manager), not the same bucket that holds sensitive data. If script archival is genuinely needed, use a separate bucket with tighter access controls and enable S3 Object Lock.

---

## HIGH Findings

### H-1 — Non-atomic state transitions leave the system in an inconsistent state

**File:** `src/envault/cli.py:122-154` (encrypt flow), `cli.py:199-216` (decrypt flow)

The encrypt workflow performs three sequential, independent operations:

1. `encrypt_file()` — writes ciphertext to `/tmp`
2. `s3.upload_file()` — copies ciphertext to S3
3. `store.put_current_state()` + `store.put_event()` — records state in DynamoDB

Each step retries independently. If S3 upload succeeds but DynamoDB write fails after three retries, the encrypted file is permanently stored in S3 with **no corresponding DynamoDB record**. The file is therefore unrecoverable through the CLI.

Conversely, during decrypt (cli.py:199-216): the plaintext file is written to disk before `put_current_state` is called. If the state update fails, the plaintext is on disk but the audit trail shows the file is still ENCRYPTED — a state lie.

**Recommendation:** Wrap the S3 upload and DynamoDB write in a compensating-transaction pattern: if the DynamoDB write fails after S3 upload succeeds, delete the S3 object (or record it as orphaned). For the CURRENT-state record, use DynamoDB conditional writes (`ConditionExpression="attribute_not_exists(PK)"` for new records, version checks for updates).

---

### H-2 — Predictable temp file names are vulnerable to TOCTOU/symlink attacks

**Files:** `src/envault/cli.py:118`, `cli.py:196`

```python
tmp_encrypted = Path(tempfile.gettempdir()) / f"envault_{sha256[:16]}_{encrypted_name}"
tmp_encrypted = Path(tempfile.gettempdir()) / f"envault_dl_{sha256_hash[:16]}.encrypted"
```

These filenames are deterministic. On a shared system, an attacker who can predict the hash prefix can:

1. Create a symlink at `/tmp/envault_<prefix>_<name>.encrypted` pointing to a sensitive file (e.g., `/etc/cron.d/backdoor`).
2. When `encrypt_file()` calls `output_path.parent.mkdir(parents=True, exist_ok=True)` followed by `output_path.open("wb")` (`crypto.py:90-92`), Python's `open()` in write mode follows the symlink and overwrites the target file with ciphertext.

This is a classic symlink attack enabled by `/tmp`'s sticky bit.

**Recommendation:** Replace manually-constructed temp paths with `tempfile.mkstemp()`, which uses `O_EXCL | O_CREAT` to atomically create a file that cannot pre-exist, eliminating the TOCTOU window.

---

### H-3 — `list_by_state` and `list_events_by_date` do not paginate DynamoDB results

**Files:** `src/envault/state.py:135-141`, `state.py:153-160`

```python
response = self._table.query(
    IndexName="state-index",
    KeyConditionExpression=Key("current_state").eq(state),
)
return [_item_to_record(item) for item in response.get("Items", [])]
```

DynamoDB Query returns at most 1 MB of data per call. If the `current_state=ENCRYPTED` index partition exceeds 1 MB (approximately 2,000–5,000 records depending on field sizes), `LastEvaluatedKey` is set in the response but **never checked**. Subsequent pages are silently dropped.

`rotate-key` calls `list_by_state(ENCRYPTED)` to enumerate all files to re-encrypt. For large deployments, files beyond the first page remain under the old KMS key even though the operator receives a "Rotated N files, 0 errors" success message. This is a **silent correctness failure** in a security-critical operation.

**Recommendation:** Implement a `_paginate_query()` helper that follows `LastEvaluatedKey` until exhausted, and use it in all query methods.

---

### H-4 — `DiscoveryAwsKmsMasterKeyProvider` imposes no account or region constraints

**File:** `src/envault/crypto.py:148`

```python
key_provider = DiscoveryAwsKmsMasterKeyProvider()
```

Discovery mode will attempt to use **any** KMS key referenced in the ciphertext header, including keys in foreign AWS accounts or regions. The AWS Encryption SDK provides `DiscoveryFilter` to restrict discovery to specific account IDs and AWS regions:

```python
discovery_filter = DiscoveryFilter(account_ids=["123456789012"], partition="aws")
key_provider = DiscoveryAwsKmsMasterKeyProvider(discovery_filter=discovery_filter)
```

Without this filter, if an attacker substitutes a crafted ciphertext (e.g., by uploading a malicious object to S3 under a predictable key path), `decrypt_file` will make an outbound KMS `Decrypt` call to an attacker-controlled key, potentially leaking information about the calling IAM identity or triggering unexpected billing.

**Recommendation:** Configure `DiscoveryFilter` with the expected AWS account ID(s), read from environment variables (`ENVAULT_ALLOWED_ACCOUNTS`) or derived from the configured key ARN.

---

### H-5 — Version ID race condition between `upload_file` and `head_object`

**File:** `src/envault/s3.py:34-47`

```python
self._s3.upload_file(str(local_path), self._bucket, s3_key, ...)
head = self._s3.head_object(Bucket=self._bucket, Key=s3_key)
version_id: str = head.get("VersionId", "")
```

Two separate API calls retrieve the version ID. In a concurrent scenario where two processes encrypt files with the same name simultaneously, `head_object` may return the version ID from the *other* process's upload, causing DynamoDB to store a pointer to the wrong S3 object version. The decrypt command would then download the wrong ciphertext — leading to a `ChecksumMismatchError` at best, or silent wrong-file decryption if the file names are also the same.

**Recommendation:** Use `boto3`'s `put_object` (which returns the `VersionId` in the response) instead of `upload_file` + `head_object`. For files already using `upload_file` for multipart support, switch to `create_multipart_upload` / `complete_multipart_upload` which also returns the version ID.

---

## MEDIUM Findings

### M-1 — `ENVAULT_AUDIT_TTL_DAYS` raises an unhandled `ValueError` on non-numeric input

**File:** `src/envault/config.py:54`

```python
audit_ttl_days = int(os.environ.get("ENVAULT_AUDIT_TTL_DAYS", "365"))
```

If the environment variable is set to a non-integer value (e.g., `"30d"` or an accidental space), Python raises `ValueError` with a generic traceback rather than the application's `ConfigurationError` with an actionable message. This is inconsistent with the explicit validation done for `ENVAULT_KEY_ID`, `ENVAULT_BUCKET`, and `ENVAULT_TABLE`.

**Recommendation:** Wrap the conversion in a `try/except ValueError` and raise `ConfigurationError` with a descriptive message.

---

### M-2 — S3 key derived only from base filename; directory collisions silently overwrite data

**File:** `src/envault/s3.py:77`

```python
return f"encrypted/{file_name}.encrypted"
```

Only the basename is used. Encrypting `/finance/Q1/report.xlsx` and `/ops/Q2/report.xlsx` both produce `encrypted/report.xlsx.encrypted`. The second upload overwrites the first in S3's current-object pointer (the older version is retained by versioning, but the DynamoDB `CURRENT` record for the first file's hash now points to the second upload's version ID — i.e., wrong ciphertext). The user receives no warning.

**Recommendation:** Incorporate the SHA256 hash into the S3 key: `f"encrypted/{sha256_hash[:2]}/{sha256_hash}/{file_name}.encrypted"`. This makes keys content-addressable, eliminates collisions, and aligns with common object storage patterns.

---

### M-3 — `audit` command returns CURRENT records mixed with EVENT records

**Files:** `src/envault/state.py:99`, `state.py:153-160`

`put_current_state` sets `item["date"] = _today_str()`, so every CURRENT-state record has a `date` attribute. The `date-index` GSI therefore indexes both CURRENT and EVENT items. `list_events_by_date` returns all items where `date = <requested_date>`, including CURRENT-state snapshots.

In the `audit` command (`cli.py:308-311`), the sort key is parsed:

```python
parts = sk.split("#")
ts = parts[1] if len(parts) > 1 else ""
op = parts[2] if len(parts) > 2 else e.get("operation", "")
```

For CURRENT records (`SK = "CURRENT"`), `parts[1]` is an empty string and `parts[2]` does not exist — the fallback to `e.get("operation", "")` returns `""`. The table silently shows empty rows for state records, polluting the audit output. Worse, an operator scanning for all DECRYPT events on a given date will see incomplete results.

**Recommendation:** Filter by `SK begins_with "EVENT#"` in the `date-index` query, or add a record-type discriminator attribute and use a `FilterExpression`.

---

### M-4 — Broad `except Exception` in `migrate` and `rotate-key` swallows programming errors

**Files:** `src/envault/cli.py:385-387`, `cli.py:510-512`

```python
except Exception as exc:
    logger.warning("Failed to migrate record at line %d: %s", i, exc)
    errors += 1
```

`Exception` is caught so broadly that `AttributeError`, `NameError`, `TypeError` — i.e., programming bugs — are silently counted as "errors" and processing continues. In `rotate-key`, this means a Python bug in the rotation code could cause every file to fail silently while the operator sees "Rotated 0 files, 47 errors" and does not know whether to re-run or investigate.

More critically: after a partial rotate-key failure, some files remain under the old KMS key. There is no report of *which* files failed, making remediation manual and error-prone.

**Recommendation:** Catch specific exception classes (`EnvaultError`, `ClientError`, `BotoCoreError`). Let programming errors propagate so they surface as unhandled exceptions in the traceback.

---

### M-5 — Tag key/value inputs are not length- or character-validated

**File:** `src/envault/cli.py:528-536`

```python
k, _, v = t.partition("=")
tags[k.strip()] = v.strip()
```

DynamoDB attribute names and values have size limits (attribute name: 255 bytes; item total: 400 KB). Tag values that contain newlines, NUL bytes, or control characters may cause unexpected behaviour in the Rich terminal output or in downstream log processing. There is no validation beyond checking for the presence of `=`.

**Recommendation:** Validate tag keys against `[a-zA-Z0-9_\-]{1,64}` and tag values against printable ASCII with a reasonable length cap.

---

### M-6 — GitHub Actions workflow pins action versions by floating tag, not commit SHA

**File:** `.github/workflows/ci.yml:17,22,29,32,59,75`

```yaml
uses: actions/checkout@v6
uses: actions/setup-python@v6
uses: zricethezav/gitleaks-action@v2
uses: actions/upload-artifact@v7
```

Floating version tags (e.g., `@v6`) allow action maintainers — or an attacker who compromises their account — to silently push malicious code under the existing tag. The next CI run executes the modified action with full repository access and the `GITHUB_TOKEN`.

**Recommendation:** Pin all actions to specific commit SHAs. Use Dependabot or Renovate to receive automated SHA-update PRs.

Example:
```yaml
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

---

### M-7 — `s3.download_file` silently falls back to latest version when `version_id` is empty

**File:** `src/envault/s3.py:60-61`

```python
if version_id:
    extra_args["VersionId"] = version_id
```

If `s3_version_id` is empty in the DynamoDB record (e.g., for a bucket without versioning enabled, or for a migrated record), the download silently fetches the **latest** object version rather than the version recorded at encryption time. This is a time-of-check/time-of-use (TOCTOU) gap: if the S3 object has been overwritten since encryption, the wrong ciphertext is decrypted and the checksum check will fail — or succeed against a different plaintext if an attacker controls the S3 bucket.

**Recommendation:** Log a `WARNING` when `version_id` is empty. Consider treating an empty version ID as an error for production-mode decrypts.

---

### M-8 — `upload_file` does not verify upload integrity with a checksum algorithm

**File:** `src/envault/s3.py:34-39`

`boto3`'s `upload_file` (via the underlying S3 Transfer Manager) does not, by default, compute a checksum of the uploaded data for S3 to verify on its end. Silent bit-flip corruption during transit would produce an S3 object whose content does not match what was written.

**Recommendation:** Add `ChecksumAlgorithm="SHA256"` to `ExtraArgs` in `upload_file`. boto3 will compute and send the checksum header; S3 will reject the upload if the received bytes differ.

---

## LOW / INFORMATIONAL Findings

### L-1 — `current_state` records not excluded from CURRENT-state GSI pagination

The `state-index` GSI partition key is `current_state`, which holds values `ENCRYPTED` or `DECRYPTED`. CURRENT records and EVENT records are both written to this GSI. The EVENT records created immediately after encryption also carry `current_state = "ENCRYPTED"`, so the GSI partition is inflated by an order of magnitude (one CURRENT record + N EVENT records per file). At scale this significantly increases read capacity consumption on `list_by_state` queries.

**Recommendation:** Filter on `SK = "CURRENT"` using a `FilterExpression` in `list_by_state`, or use a separate record-type attribute to distinguish item types.

---

### L-2 — `ENVAULT_REGION` not validated; silent fallback may cause cross-region surprises

**File:** `src/envault/config.py:53`

`region = os.environ.get("ENVAULT_REGION", "us-east-1")` — accepted without format validation. A typo (`us-eas-1`) causes obscure boto3 errors rather than a clear config failure.

**Recommendation:** Validate against known AWS region strings or let the first boto3 call's error surface early with an explanatory wrapper.

---

### L-3 — Dependency versions use open-ended `>=` constraints with no upper bound

**File:** `pyproject.toml:25-31`

```toml
"aws-encryption-sdk>=3.1.1",
"boto3>=1.26.0",
```

Open-ended constraints allow pip to install future major versions that may introduce breaking API changes or new security behaviour. The `aws-encryption-sdk` in particular has had breaking changes between major versions.

**Recommendation:** Use compatible-release constraints (`~=3.1`) or upper bounds (`>=3.1.1,<4.0.0`) for all security-relevant dependencies.

---

### L-4 — S3 access logging not enabled in CDK stack

**File:** `infra/cdk/stacks/envault_stack.py:51-71`

S3 server-access logs capture request-level detail (requester, operation, object key, response code) that is essential for forensic investigation of unauthorized access. Without them, a breach leaves no S3-level audit trail beyond CloudTrail data events (if enabled separately).

**Recommendation:** Add `server_access_logs_bucket` and `server_access_logs_prefix` to the bucket construct, or enable CloudTrail data events for the bucket.

---

### L-5 — `tag-index` GSI is defined in CDK but never populated or queried

**Files:** `infra/cdk/stacks/envault_stack.py:111-116`, `src/envault/state.py` (no tag-index query exists)

The GSI indexes `tag_key` and `tag_value` attributes, but `to_dynamo_item` (`state.py:47-57`) never writes these attributes — it serializes `tags` as a DynamoDB Map under the key `tags`. The GSI is consuming capacity without providing any functionality.

**Recommendation:** Either implement tag-based lookup (denormalize `tags` into `tag_key`/`tag_value` attributes) or remove the GSI from the CDK stack to avoid unnecessary cost.

---

### L-6 — Log output includes file paths and KMS key identifiers

**File:** `src/envault/crypto.py:76`

```python
logger.info("Encrypting file", extra={"input": str(input_path), "key_id": key_id})
```

If verbose/structured logs are forwarded to a centralised SIEM, the file name (potentially sensitive, e.g. `salary_h2_2025.xlsx`) and KMS key alias appear in plaintext. File names are also stored unencrypted in DynamoDB `file_name` fields.

**Recommendation:** Document this data-flow explicitly in the README. Consider offering a `--log-sanitize` flag that replaces file paths with their SHA256 hash in log output.

---

### L-7 — `detect-secrets` pre-commit hook references a baseline file that may not exist

**File:** `.pre-commit-config.yaml` (referenced in CLAUDE.md)

If `.secrets.baseline` does not exist in the repository, `detect-secrets` will fail on the first pre-commit run, blocking all commits until the baseline is manually generated. This creates developer friction and the risk of developers disabling the hook.

**Recommendation:** Commit an empty baseline (`detect-secrets scan --no-verify > .secrets.baseline`) or add a CI step that fails if the baseline is absent.

---

### L-8 — Encrypt script cleanup uses `|| true`, masking partial S3 sync failures

**File:** `code/encrypt.sh:57`

```bash
find "$OUTPUT_DIR" -type f -delete 2>/dev/null || true
```

The cleanup of local encrypted files is attempted regardless of whether the preceding S3 sync succeeded in full. If `aws s3 sync` transferred only a subset of files before being interrupted (e.g., network cut), the remaining files are still deleted locally. Combined with `|| true`, any cleanup errors are also silently ignored.

**Recommendation:** Verify S3 sync success with a post-sync object count comparison before deleting local files.

---

## Summary Table

| ID | Severity | File | Finding |
|----|----------|------|---------|
| C-1 | CRITICAL | `cli.py:411` | `migrate` hashes file path, not content — migrated records are unresolvable |
| C-2 | CRITICAL | `cli.py:486` | Plaintext written to predictable world-readable `/tmp` during key rotation |
| C-3 | CRITICAL | `code/encrypt.sh:5-9`, `decrypt.sh:5-9` | Unrestricted `.env` sourcing leaks all credentials to subprocesses |
| C-4 | CRITICAL | `code/encrypt.sh:61`, `decrypt.sh:56` | Encryption scripts synced to production data bucket — supply-chain risk |
| H-1 | HIGH | `cli.py:122-154`, `cli.py:199-216` | Non-atomic state transitions; S3/DynamoDB partial failures orphan data |
| H-2 | HIGH | `cli.py:118`, `cli.py:196` | Deterministic `/tmp` paths enable TOCTOU/symlink attacks |
| H-3 | HIGH | `state.py:135-141`, `state.py:153-160` | DynamoDB queries not paginated; rotate-key silently skips files at scale |
| H-4 | HIGH | `crypto.py:148` | `DiscoveryAwsKmsMasterKeyProvider` unconstrained; no account/region filter |
| H-5 | HIGH | `s3.py:34-47` | Version ID fetched in a separate `head_object` call — race condition |
| M-1 | MEDIUM | `config.py:54` | Non-numeric `ENVAULT_AUDIT_TTL_DAYS` raises unhandled `ValueError` |
| M-2 | MEDIUM | `s3.py:77` | S3 key from basename only; same-named files in different dirs collide |
| M-3 | MEDIUM | `state.py:99`, `state.py:153-160` | `date-index` GSI returns CURRENT records alongside EVENT records |
| M-4 | MEDIUM | `cli.py:385-387`, `cli.py:510-512` | Broad `except Exception` hides programming errors; rotation failures untracked |
| M-5 | MEDIUM | `cli.py:528-536` | Tag key/value inputs not length or character validated |
| M-6 | MEDIUM | `ci.yml` | GitHub Actions pinned by floating tag, not commit SHA |
| M-7 | MEDIUM | `s3.py:60-61` | Empty `version_id` silently downloads latest S3 version |
| M-8 | MEDIUM | `s3.py:34-39` | S3 upload integrity not verified with a checksum algorithm |
| L-1 | LOW | `state.py`, CDK | EVENT records inflate `state-index` GSI; CURRENT records not filtered |
| L-2 | LOW | `config.py:53` | `ENVAULT_REGION` not validated against known region strings |
| L-3 | LOW | `pyproject.toml:25-31` | Open-ended `>=` dependency constraints; no upper bound |
| L-4 | LOW | CDK stack | S3 access logging not enabled |
| L-5 | LOW | CDK stack, `state.py` | `tag-index` GSI defined but never used |
| L-6 | LOW | `crypto.py:76` | File paths and KMS key IDs logged in structured output |
| L-7 | LOW | `.pre-commit-config.yaml` | `detect-secrets` baseline file may be absent |
| L-8 | LOW | `code/encrypt.sh:57` | Local file deletion not gated on verified S3 sync success |

---

## Recommended Remediation Order

### Immediate (before any production workload)

1. **C-1** — Fix or remove `migrate`. If the original plaintext files are accessible, re-implement to read content and compute the actual SHA256.
2. **C-2** — Replace manual `/tmp` paths with `tempfile.mkstemp()` throughout `cli.py`; zero-overwrite plaintext temp files before unlinking.
3. **C-3** — Remove unrestricted `.env` sourcing from shell scripts; export only validated, named variables.
4. **C-4** — Remove code-sync lines from `encrypt.sh` and `decrypt.sh`.
5. **H-3** — Implement DynamoDB query pagination in `state.py` before deploying `rotate-key` against any non-trivial dataset.

### Short-term (next release)

6. **H-1** — Add compensating-transaction logic or DynamoDB conditional writes to enforce consistent state.
7. **H-2** — Switch to `tempfile.mkstemp()` to eliminate TOCTOU.
8. **H-4** — Add `DiscoveryFilter` with account ID and partition to `decrypt_file`.
9. **H-5** — Replace `upload_file` + `head_object` with `put_object` which returns `VersionId` atomically.
10. **M-2** — Include SHA256 hash in S3 object key to avoid filename collisions.
11. **M-3** — Add `FilterExpression` to `list_events_by_date` to exclude CURRENT records.
12. **M-6** — Pin all GitHub Actions to specific commit SHAs.

### Medium-term

13. **M-1**, **M-4**, **M-5**, **M-7**, **M-8** — Input validation, exception specificity, upload integrity verification.
14. **L-3**, **L-4**, **L-5** — Dependency upper-bound pinning, S3 access logging, remove unused GSI.

---

*End of report.*
