# CISO Final Security Review — envault-cli

**Reviewer:** CISO Final Security Review
**Date:** 2026-03-04
**Codebase version:** commit `5b575e9` on `main` (post-remediation of prior audit findings)
**Scope:** Full codebase — Python package (`src/envault/`), CDK infrastructure (`infra/cdk/`), CI/CD workflows (`.github/workflows/`), legacy shell scripts (`code/`), tests (`tests/`), dependencies, pre-commit configuration.
**Prior audit:** v1 dated 2026-03-03

---

## Executive Summary

The envault-cli codebase demonstrates strong security fundamentals: client-side envelope encryption with AES-256-GCM, KMS commitment policy enforcement (`REQUIRE_ENCRYPT_REQUIRE_DECRYPT`), discovery filters with mandatory account ID restrictions, least-privilege IAM, CMK encryption on all data stores, SHA-pinned CI actions with OIDC Trusted Publisher for PyPI, and optimistic locking on DynamoDB state transitions.

The prior security audit (2026-03-03) identified 4 critical, 5 high, and 8 medium findings. All critical and high findings from that audit have been remediated in the current codebase (see [Prior Audit Remediation Status](#prior-audit-remediation-status) below).

However, this final review identifies **3 critical, 8 high, 10 medium, and 7 low findings** that must be addressed before production deployment. The critical findings center on the **decrypt path**: plaintext is written to disk before integrity verification, the entire file is buffered in memory with no streaming support, and these code paths have zero test coverage.

---

## Severity Definitions

| Severity | Meaning |
|----------|---------|
| **CRITICAL** | Exploitable in normal use; causes data loss, integrity failure, or unauthorized access |
| **HIGH** | Significant security or reliability risk; exploitable under plausible conditions |
| **MEDIUM** | Weakness that reduces defence-in-depth or can be chained with another finding |
| **LOW** | Best-practice gap with low standalone impact |

---

## CRITICAL Findings

### C-1 — Plaintext written to disk before checksum verification

**File:** `src/envault/crypto.py:178-188`

```python
output_path.parent.mkdir(parents=True, exist_ok=True)
with output_path.open("wb") as out:
    out.write(plaintext)
os.chmod(output_path, 0o600)

actual_sha256 = sha256_file(output_path)
file_size = output_path.stat().st_size

if expected_sha256 and actual_sha256 != expected_sha256:
    output_path.unlink(missing_ok=True)
    raise ChecksumMismatchError(expected=expected_sha256, actual=actual_sha256)
```

**Description:** Decrypted plaintext is written to the output file, then re-read from disk for SHA256 verification. If the checksum fails (indicating tampering or corruption), the file is deleted — but it already existed on disk in the clear. On copy-on-write filesystems (APFS on macOS, ZFS), the data persists in filesystem snapshots even after `unlink()`. Additionally, between the write and the check, another process could read the potentially tampered plaintext.

**Attack scenario:** An attacker substitutes ciphertext in S3 with a different validly-encrypted file (encrypted under the same KMS key). The user decrypts it. Tampered plaintext hits disk at the user-specified path before the integrity check catches it. On APFS, it survives in a Time Machine snapshot. On any filesystem, a watching process can exfiltrate it during the verification window.

**Recommendation:** Compute SHA256 on the in-memory `plaintext` bytes before writing to disk. Only write if the hash matches:

```python
actual_sha256 = hashlib.sha256(plaintext).hexdigest()
if expected_sha256 and actual_sha256 != expected_sha256:
    raise ChecksumMismatchError(expected=expected_sha256, actual=actual_sha256)
# Only write after verification passes
fd = os.open(str(output_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "wb") as out:
    out.write(plaintext)
```

This also addresses H-3 (file permissions race) by creating the file with `0o600` atomically.

---

### C-2 — No streaming — entire plaintext/ciphertext held in memory

**Files:** `src/envault/crypto.py:87-92` (encrypt), `src/envault/crypto.py:172-176` (decrypt)

```python
# encrypt
with input_path.open("rb") as plaintext_file:
    ciphertext, header = client.encrypt(
        source=plaintext_file, key_provider=key_provider,
        encryption_context=encryption_context,
    )

# decrypt
with input_path.open("rb") as encrypted_file:
    plaintext, header = client.decrypt(
        source=encrypted_file, key_provider=key_provider,
    )
```

**Description:** Both `client.encrypt()` and `client.decrypt()` return the full content as a Python `bytes` object in memory. Two security consequences:

1. **Memory exhaustion / DoS:** A maliciously large ciphertext causes OOM. There is no file size validation.
2. **Plaintext exposure in memory:** Sensitive plaintext in Python `bytes` cannot be securely zeroed — it persists in process memory (and potentially swap) until garbage collected. Python's memory allocator does not guarantee overwrite on deallocation.

**Attack scenario:** (1) Attacker uploads a multi-GB ciphertext to S3; user's `envault decrypt` OOMs or causes system instability. (2) After decryption, plaintext bytes remain recoverable from process memory or swap via forensic tools.

**Recommendation:** Use `client.stream(mode='e'/'d', ...)` for chunked I/O directly to output files. This also enables computing SHA256 during streaming, eliminating the TOCTOU in C-1 and M-8:

```python
with client.stream(mode='d', source=encrypted_file, key_provider=key_provider) as decryptor:
    hasher = hashlib.sha256()
    for chunk in decryptor:
        hasher.update(chunk)
        out.write(chunk)
```

---

### C-3 — Zero test coverage on critical integrity checks

**Files:** `tests/unit/test_crypto.py`, `tests/unit/test_cli.py`

**Description:** The two most important security invariants in the system have **no test coverage**:

1. **`ChecksumMismatchError` during decrypt** — The only test (`test_checksum_mismatch_error` at `test_crypto.py:102`) tests the exception's `__str__` method, never the actual `decrypt_file` code path that raises it. A regression in the checksum comparison, file cleanup, or retry exclusion would be invisible.

2. **`EncryptionContextMismatchError`** — Never tested anywhere. The `decrypt` command (`cli.py:270`) and `rotate-key` command (`cli.py:601`) both check for context mismatches, but neither path is exercised by any test.

3. **CLI `encrypt` and `decrypt` commands** — Never invoked via `CliRunner` except a single hash-format validation test for `decrypt`. The entire security-critical orchestration flow (tempfile creation, encryption, S3 upload, DynamoDB state write, tempfile cleanup, error handling) is untested.

4. **`rotate-key` command** — The most complex operation in the system (download, decrypt, re-encrypt, upload, state update, 3 temp files) has zero tests.

5. **Temp file cleanup on failure** — `finally` blocks that clean up temp files (including `_best_effort_delete` for plaintext) have zero test coverage.

6. **File permission setting** — `os.chmod(output_path, 0o600)` after encrypt/decrypt is untested.

**Impact:** Any regression in checksum verification, encryption context comparison, temp file cleanup, file permissions, or error handling would be completely invisible to CI.

**Recommendation:** Add tests for each of the above. At minimum:
- Call `decrypt_file` with a mismatched `expected_sha256` and assert `ChecksumMismatchError` is raised and output file is deleted
- Mock `decrypt_file` to return a mismatched `encryption_context` and assert `EncryptionContextMismatchError` is raised
- Use `CliRunner` with mocked crypto and moto-backed AWS to test full encrypt/decrypt/rotate-key flows
- Simulate failures at each stage and verify temp file cleanup
- Verify output file permissions are `0o600`

---

## HIGH Findings

### H-1 — Path traversal via `file_name` from DynamoDB during decrypt

**File:** `src/envault/cli.py:253`

```python
output_path = (output if output.is_dir() else output.parent) / record.file_name
```

**Description:** `record.file_name` comes from DynamoDB and is used unsanitized in the output path construction. The `_sanitize_filename()` method exists in `S3Store` and is used for S3 key generation, but is NOT applied to the output path during decryption. The `file_name` stored in DynamoDB is the raw `file_path.name` from the original encryption.

**Attack scenario:** An attacker with DynamoDB write access (or who corrupts the migration source) sets `file_name = "../../.ssh/authorized_keys"`. A user running `envault decrypt <hash>` writes the decrypted file to an arbitrary filesystem path.

**Recommendation:** Sanitize `record.file_name` before constructing the output path:

```python
safe_name = Path(record.file_name).name  # Strip directory components
if not safe_name or safe_name.startswith('.'):
    safe_name = f"decrypted_{record.sha256_hash[:16]}"
output_path = (output if output.is_dir() else output.parent) / safe_name
```

---

### H-2 — Symlink traversal in `_collect_files`

**File:** `src/envault/cli.py:650-653`

```python
def _collect_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    return [p for p in path.rglob("*") if p.is_file()]
```

**Description:** `Path.rglob("*")` follows symbolic links by default. `path.is_file()` returns `True` for symlinks pointing to files. An attacker who can create symlinks within a target directory can cause envault to encrypt files outside the intended directory tree.

**Attack scenario:** A shared directory contains `symlink -> /home/victim/.ssh/id_rsa`. User runs `envault encrypt shared_dir/`. The tool follows the symlink, encrypts the victim's SSH key, and uploads it to S3 where the attacker can decrypt it.

**Recommendation:** Filter out symlinks:

```python
def _collect_files(path: Path) -> list[Path]:
    if path.is_symlink():
        return []
    if path.is_file():
        return [path]
    return [p for p in path.rglob("*") if p.is_file() and not p.is_symlink()]
```

---

### H-3 — Output file permissions race (chmod after write)

**Files:** `src/envault/crypto.py:95-97` (encrypt), `src/envault/crypto.py:179-181` (decrypt)

```python
with output_path.open("wb") as out:
    out.write(plaintext)
os.chmod(output_path, 0o600)
```

**Description:** Files are created with the process's default umask permissions (typically `0o644`), then restricted to `0o600` afterward. Between creation and chmod, other users on the system can read the file contents. This is particularly concerning for the decryption case where plaintext is being written.

**Attack scenario:** On a multi-user system, another user reads the plaintext file during the window between `open("wb")` and `os.chmod()`.

**Recommendation:** Use `os.open()` with explicit mode to create the file atomically with restricted permissions:

```python
fd = os.open(str(output_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "wb") as out:
    out.write(plaintext)
```

Note: Temp files created with `mkstemp` already have `0o600` permissions — this issue only affects final output files.

---

### H-4 — `encrypt_file` retry doesn't exclude non-retryable exceptions

**File:** `src/envault/crypto.py:54-57`

```python
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
def encrypt_file(...) -> EncryptResult:
```

**Description:** The `@retry` decorator on `encrypt_file` retries ALL exceptions including `ConfigurationError` and other non-retryable errors. The `decrypt_file` decorator correctly uses `retry=retry_if_not_exception_type((ConfigurationError, ChecksumMismatchError))` to exclude non-retryable types. This inconsistency means a misconfigured KMS key causes 3 unnecessary KMS API calls, and each retry generates a different data encryption key producing different ciphertext.

**Recommendation:** Add retry exclusion to match `decrypt_file`:

```python
@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_not_exception_type(ConfigurationError),
)
```

---

### H-5 — Publish workflow missing top-level `permissions` restriction

**File:** `.github/workflows/publish.yml`

**Description:** Unlike `ci.yml` which sets `permissions: read-all` at the top level, the publish workflow has no top-level permissions declaration. The `build` job inherits the default GITHUB_TOKEN permissions, which in many repository configurations is `write` for contents, packages, pull-requests, and more.

**Attack scenario:** A compromised or future third-party action in the build job runs with elevated GITHUB_TOKEN permissions, potentially pushing malicious code, creating releases, or modifying PR reviews.

**Recommendation:** Add `permissions: read-all` at the top level; scope per-job as needed:

```yaml
permissions: read-all

jobs:
  build:
    permissions:
      contents: read
    ...
  publish-pypi:
    permissions:
      id-token: write
    ...
```

---

### H-6 — PyPI publish has no CI quality gate

**File:** `.github/workflows/publish.yml:3-6`

```yaml
on:
  push:
    tags:
      - "v*.*.*"
```

**Description:** Anyone with push access can create a tag matching `v*.*.*` and trigger a full PyPI release. The publish workflow does NOT depend on CI passing — no tests, linting, or type checking are required before publication.

**Attack scenario:** A compromised contributor account pushes a tag on a commit containing malicious code. The package is built and published to PyPI without any quality checks, distributing a supply-chain attack to all `pip install envault-cli` users.

**Recommendation:** Combine multiple defenses:
1. Add the CI workflow as a `needs:` dependency in the publish workflow
2. Configure the `pypi` GitHub Environment with required reviewers
3. Restrict tag creation to administrators via branch protection rules

```yaml
jobs:
  ci:
    uses: ./.github/workflows/ci.yml
  build:
    needs: ci
    ...
```

---

### H-7 — `decrypt.conf` shell variable not expanded by aws-encryption-cli

**File:** `code/decrypt.conf:2`

```
--wrapping-keys key=${KMS_KEY_ARN}
```

**Description:** The `@filename` argument-file syntax in `aws-encryption-cli` reads literal text without shell variable expansion. The string `${KMS_KEY_ARN}` is passed literally as the key identifier, causing decryption to fail with an obscure KMS error or silently attempt to use a key named `${KMS_KEY_ARN}`.

In contrast, `encrypt.conf` hardcodes `key=alias/s3_key`, creating an inconsistency between encrypt and decrypt configurations.

**Recommendation:** Use `--wrapping-keys discovery=true` in the legacy scripts (matching the Python code's discovery pattern), or generate the conf file dynamically at runtime.

---

### H-8 — Temp file cleanup on encryption/decryption failure is untested

**Files:** `src/envault/cli.py:143-161` (encrypt), `src/envault/cli.py:250-268` (decrypt)

**Description:** Both `_encrypt_one` and the `decrypt` command create temp files via `tempfile.mkstemp`. The `finally` blocks are responsible for cleaning up these files even on failure, including calling `_best_effort_delete` for plaintext files. No test verifies this behavior. Additionally, the `_best_effort_delete` test (`test_best_effort_delete_overwrites_before_removal`) only verifies the file no longer exists — it does not verify the file was zeroed before deletion.

**Attack scenario:** A transient AWS error causes encryption to fail. Temp files containing ciphertext or plaintext are left on disk. During key rotation, a decrypted plaintext temp file could remain indefinitely if the re-encryption step fails and the `finally` block has a regression.

**Recommendation:** Add tests that simulate failures at various stages and verify all temp files are cleaned up. Modify `_best_effort_delete` test to verify zeroing occurs before unlinking.

---

## MEDIUM Findings

### M-1 — Broad `except Exception` in encrypt command hides programming errors

**File:** `src/envault/cli.py:116-119`

```python
except Exception as exc:
    console.print(f"[red]✗[/red] {file_path.name}: {exc}")
    logger.exception("Failed to encrypt %s", file_path)
    errors += 1
```

**Description:** The encrypt command catches `Exception` broadly. `TypeError`, `AttributeError`, and `NameError` (indicating bugs) are silently counted as "errors" and processing continues. A programming bug could cause every file in a batch to silently fail. The `rotate-key` command (`cli.py:630`) correctly narrowed this to `(EnvaultError, ClientError, BotoCoreError)`.

**Recommendation:** Match the pattern used in `rotate-key`:

```python
except (EnvaultError, ClientError, BotoCoreError) as exc:
```

---

### M-2 — SHA256 hash validation inconsistent across commands

**Files:** `src/envault/cli.py:302` (status), `src/envault/cli.py:356` (audit)

**Description:** The `decrypt` command validates the SHA256 hash with `re.fullmatch(r"[0-9a-f]{64}", sha256_hash)` at line 224, but the `status` and `audit` commands pass `sha256_hash` directly to DynamoDB queries without validation. A malformed input produces confusing "not found" errors.

**Recommendation:** Extract the validation into a shared helper and apply consistently:

```python
def _validate_sha256(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise click.BadParameter("Expected 64 lowercase hexadecimal characters")
    return value
```

---

### M-3 — `_best_effort_delete` allocates full file size in memory

**File:** `src/envault/cli.py:676-696`

```python
size = path.stat().st_size
with path.open("r+b") as f:
    f.write(b"\x00" * size)
```

**Description:** `b"\x00" * size` allocates a single bytes object equal to the file size. For a 1GB file, this allocates 1GB of zeros in memory.

**Recommendation:** Write zeros in chunks:

```python
CHUNK_SIZE = 65536
remaining = size
with path.open("r+b") as f:
    while remaining > 0:
        to_write = min(CHUNK_SIZE, remaining)
        f.write(b"\x00" * to_write)
        remaining -= to_write
    f.flush()
    os.fsync(f.fileno())
```

---

### M-4 — No format validation on `--allowed-account-ids`

**Files:** `src/envault/cli.py:234`, `src/envault/cli.py:556`

```python
account_ids = [a.strip() for a in allowed_account_ids.split(",") if a.strip()]
```

**Description:** AWS account IDs are 12-digit numeric strings. The code does not validate format before passing to `DiscoveryFilter`. A malformed account ID (e.g., `*`, empty string, non-numeric) could either cause a runtime error or weaken the discovery filter.

**Recommendation:** Validate each account ID:

```python
for account_id in account_ids:
    if not re.fullmatch(r"\d{12}", account_id):
        console.print(f"[red]Invalid AWS account ID: {account_id!r}. Must be 12 digits.[/red]")
        sys.exit(1)
```

---

### M-5 — `EncryptionContextMismatchError` leaks full encryption context in error message

**File:** `src/envault/exceptions.py:41-44`

```python
super().__init__(
    f"Encryption context mismatch: expected {expected!r}, got {actual!r}. "
    "The ciphertext may have been tampered with or swapped."
)
```

**Description:** The full encryption context dictionaries (containing SHA256 hash, file name, and KMS key alias) are included in the exception message. If this exception propagates to logs or console output, it reveals metadata about the encrypted file. `ChecksumMismatchError` already truncates hashes to 16 chars, but this exception does not.

**Recommendation:** Remove context details from the user-facing message:

```python
super().__init__(
    "Encryption context mismatch detected. "
    "The ciphertext may have been tampered with or swapped."
)
```

Log the full context at DEBUG level for troubleshooting.

---

### M-6 — S3 upload missing checksum verification

**File:** `src/envault/s3.py:42-47`

```python
response = self._s3.put_object(
    Bucket=self._bucket,
    Key=s3_key,
    Body=f,
    ServerSideEncryption="aws:kms",
)
```

**Description:** The `put_object` call does not specify `ChecksumAlgorithm`. While AES-256-GCM provides authentication, a bit-flip during transit to S3 could corrupt the ciphertext before it's stored, leading to silent decryption failures later.

**Recommendation:** Add `ChecksumAlgorithm="SHA256"` so S3 validates upload integrity server-side.

---

### M-7 — `.secrets.baseline` referenced but does not exist

**File:** `.pre-commit-config.yaml:6`

```yaml
- id: detect-secrets
  args: ["--baseline", ".secrets.baseline"]
```

**Description:** The `.secrets.baseline` file is referenced in pre-commit config and listed in `.gitignore` (line 62), but does not exist in the repository. Because it's in `.gitignore`, even if generated locally it won't be committed. This means the `detect-secrets` hook fails on every commit, causing developers to skip hooks with `--no-verify` or disable the hook.

**Recommendation:** Remove `.secrets.baseline` from `.gitignore`, generate it with `detect-secrets scan > .secrets.baseline`, audit false positives, and commit it.

---

### M-8 — TOCTOU: file read twice between hash and encrypt

**File:** `src/envault/cli.py:137-157`

```python
sha256 = sha256_file(file_path)  # First read
...
result = encrypt_file(
    input_path=file_path,  # Second read
    ...
)
```

**Description:** The file is read once to compute the SHA256 hash (which becomes the DynamoDB primary key) and again for encryption. If the file is modified between these two reads, the SHA256 stored in DynamoDB won't match the actual encrypted content. Upon decryption, the checksum verification would fail.

**Recommendation:** Compute SHA256 as part of the encryption operation, or read the file once and use the same bytes for both. The streaming API fix (C-2) naturally resolves this.

---

### M-9 — No dependency vulnerability scanning in CI

**File:** `.github/workflows/ci.yml`

**Description:** The CI pipeline runs linting, type checking, and unit tests, but no dependency vulnerability scanner (`pip-audit`, `safety`). For a security-critical encryption tool depending on `cryptography`, `aws-encryption-sdk`, `cffi`, and `boto3`, CVE monitoring is essential.

**Recommendation:** Add a CI step:

```yaml
- name: Audit dependencies
  run: pip install pip-audit && pip-audit
```

---

### M-10 — CDK infrastructure requirements use open-ended version constraints

**File:** `infra/cdk/requirements.txt`

```
aws-cdk-lib>=2.100.0
cdk-nag>=2.28.0
constructs>=10.0.0
```

**Description:** All three dependencies use `>=` with no upper bound. A `pip install` could pull in a future major version with breaking or security-behavioral changes.

**Recommendation:** Add upper bounds:

```
aws-cdk-lib>=2.100.0,<3
cdk-nag>=2.28.0,<3
constructs>=10.0.0,<11
```

---

## LOW Findings

### L-1 — S3 bucket missing `bucket_key_enabled`

**File:** `infra/cdk/stacks/envault_stack.py:69-91`

**Description:** The S3 bucket uses KMS-SSE but does not set `bucket_key_enabled=True`. Without S3 Bucket Keys, every `PutObject`/`GetObject` makes a separate KMS request, increasing cost, latency, and CloudTrail noise (reducing signal-to-noise for security monitoring).

**Recommendation:** Add `bucket_key_enabled=True` to the bucket construct.

---

### L-2 — No MFA Delete on versioned S3 bucket

**File:** `infra/cdk/stacks/envault_stack.py:69-91`

**Description:** Versioning is enabled but MFA Delete is not configured. An attacker who compromises IAM credentials with `s3:DeleteObjectVersion` could permanently destroy all encrypted file versions. The `EnvaultUserPolicy` does not grant delete permissions, but other principals might.

**Recommendation:** Document and enable MFA Delete post-deployment (requires root account credentials; cannot be configured via CDK).

---

### L-3 — Hardcoded table name and policy name prevent multi-environment deployment

**Files:** `infra/cdk/stacks/envault_stack.py:99` (`table_name="envault-state"`), `infra/cdk/stacks/envault_stack.py:135` (`managed_policy_name="EnvaultUserPolicy"`)

**Description:** Hardcoded names prevent deploying multiple stack instances in the same account/region (e.g., staging and production). Hardcoded IAM policy names also risk CloudFormation replacement failures.

**Recommendation:** Parameterize names or let CDK generate unique names.

---

### L-4 — GSI projections use `ALL`, increasing storage and exposure surface

**File:** `infra/cdk/stacks/envault_stack.py:114-127`

**Description:** Both GSIs project ALL attributes, replicating `encryption_context`, `s3_key`, `kms_key_id`, and `tags` into each index. This increases the attack surface if a query against a GSI inadvertently exposes sensitive metadata.

**Recommendation:** Use `KEYS_ONLY` or `INCLUDE` projection with only the attributes needed for each query pattern.

---

### L-5 — S3 `put_object` doesn't specify `SSEKMSKeyId`

**File:** `src/envault/s3.py:42-47`

**Description:** The upload specifies `ServerSideEncryption="aws:kms"` but not `SSEKMSKeyId`, so S3 uses the bucket's default KMS key. If the bucket default differs from the envault CMK, server-side encryption uses a different key than intended.

**Recommendation:** Pass the KMS key ID to `put_object`.

---

### L-6 — Fake AWS credentials in CI set at job level

**File:** `.github/workflows/ci.yml:73-76`

**Description:** Fake AWS credentials (`testing`) for moto mocking are set at the job level. Any future CI step added after tests would inherit these environment variables, normalizing credentials in workflow env blocks.

**Recommendation:** Scope the env block to the specific `run:` step, or add a comment documenting the intent.

---

### L-7 — No `CODEOWNERS` file for security-critical paths

**File:** (missing)

**Description:** No `CODEOWNERS` file enforces review requirements for changes to `.github/workflows/`, `src/envault/crypto.py`, `infra/cdk/`, or `pyproject.toml`. Any contributor with write access can modify the publish pipeline or cryptographic code without mandatory security review.

**Recommendation:** Add `.github/CODEOWNERS`:

```
/.github/workflows/  @security-team
/src/envault/crypto.py  @security-team
/infra/cdk/  @security-team
/pyproject.toml  @security-team
```

---

## CDK Infrastructure Assessment

The CDK infrastructure has no CRITICAL or HIGH findings. Key observations:

| Area | Status |
|------|--------|
| KMS CMK with auto-rotation | Enabled |
| S3 encryption with CMK | Enabled |
| S3 public access blocked | `BLOCK_ALL` on both buckets |
| TLS enforced | `enforce_ssl=True` on both buckets |
| S3 versioning | Enabled |
| S3 access logging | Enabled (dedicated bucket) |
| DynamoDB CMK encryption | `CUSTOMER_MANAGED` |
| DynamoDB PITR | Enabled |
| DynamoDB deletion protection | Enabled |
| Removal policies | `RETAIN` on all stateful resources |
| IAM least privilege | No delete permissions; scoped to specific ARNs |
| cdk-nag integration | `AwsSolutionsChecks` with justified suppressions |

**Notable CDK-specific items:**
- Default KMS key policy grants `kms:*` to account root (standard CDK behavior, delegates to IAM). For shared accounts, consider adding conditions.
- Access logs bucket uses legacy ACL-based delivery (`ObjectWriter`). `BLOCK_ALL` mitigates the primary risk.
- No CloudTrail data events provisioned (expected to be configured at account/org level).

---

## Security Strengths

These represent meaningful security engineering:

1. **`CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT`** — strongest setting, prevents key commitment attacks
2. **`DiscoveryFilter` with mandatory account IDs** — hard failure if `ENVAULT_ALLOWED_ACCOUNT_IDS` unset
3. **Per-file encryption context as AAD** — cryptographic binding prevents ciphertext substitution at the AEAD layer
4. **Optimistic locking** — `ConditionExpression` on DynamoDB writes prevents concurrent modification
5. **Zero shell invocations** — no `subprocess`, `os.system`, `shell=True` anywhere in Python code
6. **Temp files via `mkstemp`** with `_best_effort_delete` zero-overwrite
7. **SHA-pinned GitHub Actions** with OIDC Trusted Publisher for PyPI
8. **Least-privilege IAM** — no delete permissions, scoped to specific resource ARNs
9. **CMK encryption on all data stores** with key rotation enabled
10. **cdk-nag `AwsSolutionsChecks`** with properly scoped, justified suppressions
11. **S3 public access fully blocked**, TLS enforced, versioning enabled, access logging to dedicated bucket
12. **DynamoDB PITR + deletion protection** with `RemovalPolicy.RETAIN`
13. **Content-addressed S3 keys** — `encrypted/{sha256[:2]}/{sha256}/{filename}.encrypted` prevents collisions
14. **Paginated DynamoDB queries** — `_paginate_query()` follows `LastEvaluatedKey` until exhaustion
15. **Tag input validation** — strict regex for keys, length limits for values
16. **JSON structured logging** to stderr via `python-json-logger`

---

## Prior Audit Remediation Status

All findings from the v1 audit (2026-03-03) have been verified:

| Prior ID | Severity | Finding | Status | Evidence |
|----------|----------|---------|--------|----------|
| C-1 | CRITICAL | `migrate` hashes file path, not content | **FIXED** | `cli.py:478-485` calls `sha256_file(plaintext_path)` |
| C-2 | CRITICAL | Predictable world-readable `/tmp` paths | **FIXED** | Uses `tempfile.mkstemp()` with `_best_effort_delete()` |
| C-3 | CRITICAL | Unrestricted `.env` sourcing in shell scripts | **FIXED** | `encrypt.sh:5-8`, `decrypt.sh:5-8` extract only `S3_BUCKET` via `grep` |
| C-4 | CRITICAL | Code synced to production S3 bucket | **FIXED** | `aws s3 sync ../code` lines removed |
| H-1 | HIGH | Non-atomic state transitions | **PARTIAL** | Optimistic locking added; compensating transactions not yet implemented |
| H-2 | HIGH | Predictable temp file names / TOCTOU | **FIXED** | `tempfile.mkstemp()` used throughout |
| H-3 | HIGH | DynamoDB queries not paginated | **FIXED** | `_paginate_query()` at `state.py:96-106` |
| H-4 | HIGH | `DiscoveryAwsKmsMasterKeyProvider` unconstrained | **FIXED** | `crypto.py:163-170` uses `DiscoveryFilter` |
| H-5 | HIGH | Version ID race (`upload_file` + `head_object`) | **FIXED** | `s3.py:42` uses `put_object` returning `VersionId` |
| M-1 | MEDIUM | Non-numeric `ENVAULT_AUDIT_TTL_DAYS` | **FIXED** | Validates with try/except raising `ConfigurationError` |
| M-2 | MEDIUM | S3 key from basename only (collisions) | **FIXED** | Content-addressed keys with SHA256 prefix |
| M-3 | MEDIUM | `date-index` returns CURRENT records | **FIXED** | Filters on `SK.begins_with(EVENT_PREFIX)` |
| M-4 | MEDIUM | Broad `except Exception` in rotate-key | **FIXED** | Now catches `(EnvaultError, ClientError, BotoCoreError)` |
| M-5 | MEDIUM | Tag inputs not validated | **FIXED** | Validates keys with regex, values with length limit |
| M-6 | MEDIUM | Actions pinned by floating tag | **FIXED** | All actions pinned to commit SHAs |
| M-7 | MEDIUM | Empty `version_id` downloads latest | **OPEN** | Still falls back silently |
| M-8 | MEDIUM | S3 upload integrity not verified | **OPEN** | See current M-6 |

---

## Summary Table

| ID | Severity | Component | Finding |
|----|----------|-----------|---------|
| C-1 | CRITICAL | `crypto.py:178-188` | Plaintext written to disk before checksum verification |
| C-2 | CRITICAL | `crypto.py:87-92, 172-176` | No streaming; entire file buffered in memory |
| C-3 | CRITICAL | `tests/` | Zero test coverage on critical integrity checks |
| H-1 | HIGH | `cli.py:253` | Path traversal via `file_name` from DynamoDB |
| H-2 | HIGH | `cli.py:650-653` | Symlink traversal in `_collect_files` |
| H-3 | HIGH | `crypto.py:95-97, 179-181` | File permissions race (chmod after write) |
| H-4 | HIGH | `crypto.py:54-57` | `encrypt_file` retry includes non-retryable exceptions |
| H-5 | HIGH | `publish.yml` | Missing top-level `permissions` restriction |
| H-6 | HIGH | `publish.yml:3-6` | PyPI publish has no CI quality gate |
| H-7 | HIGH | `code/decrypt.conf:2` | Shell variable not expanded by aws-encryption-cli |
| H-8 | HIGH | `cli.py:143-161, 250-268` | Temp file cleanup on failure is untested |
| M-1 | MEDIUM | `cli.py:116-119` | Broad `except Exception` hides programming errors |
| M-2 | MEDIUM | `cli.py:302, 356` | SHA256 validation inconsistent across commands |
| M-3 | MEDIUM | `cli.py:676-696` | `_best_effort_delete` allocates full file size in memory |
| M-4 | MEDIUM | `cli.py:234, 556` | No format validation on `--allowed-account-ids` |
| M-5 | MEDIUM | `exceptions.py:41-44` | Encryption context leaked in error message |
| M-6 | MEDIUM | `s3.py:42-47` | S3 upload missing checksum verification |
| M-7 | MEDIUM | `.pre-commit-config.yaml:6` | `.secrets.baseline` non-functional |
| M-8 | MEDIUM | `cli.py:137-157` | TOCTOU between hash computation and encryption |
| M-9 | MEDIUM | `ci.yml` | No dependency vulnerability scanning |
| M-10 | MEDIUM | `infra/cdk/requirements.txt` | Open-ended version constraints |
| L-1 | LOW | CDK stack | S3 bucket missing `bucket_key_enabled` |
| L-2 | LOW | CDK stack | No MFA Delete on versioned S3 bucket |
| L-3 | LOW | CDK stack | Hardcoded resource names prevent multi-env |
| L-4 | LOW | CDK stack | GSI projections use `ALL` |
| L-5 | LOW | `s3.py:42-47` | S3 upload doesn't specify `SSEKMSKeyId` |
| L-6 | LOW | `ci.yml:73-76` | Fake credentials at job level |
| L-7 | LOW | Missing | No `CODEOWNERS` for security-critical paths |

---

## Remediation Priority

### Block Release — Before Production

| # | ID | Effort | Description |
|---|-----|--------|-------------|
| 1 | C-1 | 1h | Verify checksum in memory before writing plaintext to disk |
| 2 | H-1 | 15m | Sanitize `record.file_name` in decrypt output path |
| 3 | H-2 | 15m | Skip symlinks in `_collect_files` |
| 4 | H-3 | 30m | Atomic file creation with `os.open()` and `0o600` |
| 5 | H-5 | 5m | Add `permissions: read-all` to `publish.yml` |
| 6 | H-6 | 30m | Gate PyPI publish on CI passing |
| 7 | M-1 | 10m | Narrow `except Exception` to specific types |
| 8 | M-5 | 10m | Remove encryption context from error messages |

### Next Release

| # | ID | Effort | Description |
|---|-----|--------|-------------|
| 9 | C-2 | 4h | Switch to streaming encrypt/decrypt API |
| 10 | C-3 | 8h | Add test coverage for all integrity checks and CLI flows |
| 11 | H-4 | 10m | Add `retry_if_not_exception_type` to encrypt retry |
| 12 | H-8 | 2h | Add tests for temp file cleanup on failure paths |
| 13 | M-2 | 30m | Unify SHA256 validation across all commands |
| 14 | M-3 | 15m | Chunk zero-overwrite in `_best_effort_delete` |
| 15 | M-4 | 15m | Validate account ID format |
| 16 | M-6 | 10m | Add `ChecksumAlgorithm` to S3 upload |
| 17 | M-7 | 15m | Fix detect-secrets baseline |
| 18 | M-9 | 30m | Add `pip-audit` to CI |

### Hardening

| # | ID | Effort | Description |
|---|-----|--------|-------------|
| 19 | L-1 | 5m | Enable S3 Bucket Keys |
| 20 | L-7 | 10m | Add CODEOWNERS |
| 21 | M-10 | 10m | Add upper bounds to CDK requirements |
| 22 | L-2 | 30m | Document/enable MFA Delete post-deploy |
| 23 | L-5 | 10m | Pass KMS key ID to S3 `put_object` |

---

## Compliance Assessment

| Framework | Assessment |
|-----------|------------|
| **SOC 2 (CC6.1, CC6.7)** | Strong. Encryption at rest (CMK) and in transit (TLS enforced). Access logging provides audit. Gap: no CloudTrail data events for object-level auditing. |
| **PCI-DSS (Req 3, 7, 10)** | Partially met. Encryption and access control are solid. Req 10 needs CloudTrail data events. MFA Delete recommended for Req 3. |
| **HIPAA (164.312)** | Partially met. Encryption and access controls strong. Object Lock (WORM) would strengthen PHI storage compliance. |

---

## Verdict

The cryptographic foundations are sound and the prior audit remediations are solid. The critical gap is the **decrypt path** — plaintext hits disk before integrity verification, and this entire flow is untested. Items 1-8 above (Block Release) are release blockers. After those fixes plus test coverage (items 9-12), this codebase meets production-grade security standards for a client-side encryption tool.

---

*End of report.*
