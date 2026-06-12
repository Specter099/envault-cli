# Filename-Based Decrypt Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Allow `envault decrypt` to accept a filename (not just a full SHA256 hash), defaulting to the most recent encrypted version with a `--version` flag for older versions.

**Architecture:** Add a `list_by_file_name()` method to `StateStore` that queries the existing `state-index` GSI with a `FilterExpression` on `file_name`. Add a `_resolve_identifier()` helper in `cli.py` that detects whether the argument is a SHA256 hash or filename, resolves it to a `FileRecord`, and handles the multi-version case.

**Tech Stack:** Python, Click, boto3/DynamoDB, moto (testing)

---

### Task 1: Add `list_by_file_name()` to StateStore

**Files:**
- Modify: `src/envault/state.py:202-218` (near `list_by_state`)
- Test: `tests/unit/test_state.py`

**Step 1: Write failing tests**

Add to `tests/unit/test_state.py`:

```python
@mock_aws
def test_list_by_file_name_returns_matching_records():
    """list_by_file_name returns only CURRENT records with the given file_name."""
    store = _create_table()
    r1 = _make_record(sha256_hash="a" * 64, file_name="secret.env")
    r2 = _make_record(sha256_hash="b" * 64, file_name="secret.env")
    r3 = _make_record(sha256_hash="c" * 64, file_name="other.env")
    store.put_current_state(r1)
    store.put_current_state(r2)
    store.put_current_state(r3)
    # Also add an event for r1 to ensure events are excluded
    store.put_event(r1, operation="ENCRYPT", correlation_id="corr-1")

    results = store.list_by_file_name("secret.env", ENCRYPTED)
    assert len(results) == 2
    names = {r.file_name for r in results}
    assert names == {"secret.env"}


@mock_aws
def test_list_by_file_name_returns_empty_for_no_match():
    """list_by_file_name returns empty list when no files match."""
    store = _create_table()
    r1 = _make_record(sha256_hash="a" * 64, file_name="secret.env")
    store.put_current_state(r1)

    results = store.list_by_file_name("nonexistent.txt", ENCRYPTED)
    assert results == []


@mock_aws
def test_list_by_file_name_sorted_by_encrypted_at_descending():
    """list_by_file_name returns results sorted newest-first by encrypted_at."""
    store = _create_table()
    r_old = _make_record(
        sha256_hash="a" * 64,
        file_name="data.csv",
        encrypted_at="2026-01-01T00:00:00+00:00",
    )
    r_new = _make_record(
        sha256_hash="b" * 64,
        file_name="data.csv",
        encrypted_at="2026-03-04T12:00:00+00:00",
    )
    store.put_current_state(r_old)
    store.put_current_state(r_new)

    results = store.list_by_file_name("data.csv", ENCRYPTED)
    assert len(results) == 2
    assert results[0].encrypted_at >= results[1].encrypted_at
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_state.py::test_list_by_file_name_returns_matching_records tests/unit/test_state.py::test_list_by_file_name_returns_empty_for_no_match tests/unit/test_state.py::test_list_by_file_name_sorted_by_encrypted_at_descending -v`
Expected: FAIL with `AttributeError: 'StateStore' object has no attribute 'list_by_file_name'`

**Step 3: Implement `list_by_file_name` in `src/envault/state.py`**

Add this method to the `StateStore` class, right after `list_by_state` (after line 218):

```python
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
def list_by_file_name(self, file_name: str, state: str) -> list[FileRecord]:
    """Return CURRENT records matching a file_name in a given state.

    Results are sorted by encrypted_at descending (newest first).
    Uses state-index GSI with FilterExpression on file_name and SK.
    """
    from boto3.dynamodb.conditions import Attr

    items = self._paginate_query(
        IndexName="state-index",
        KeyConditionExpression=Key("current_state").eq(state),
        FilterExpression=Attr("SK").eq(CURRENT) & Attr("file_name").eq(file_name),
    )
    records = [_item_to_record(item) for item in items]
    records.sort(key=lambda r: r.encrypted_at, reverse=True)
    return records
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/test_state.py -v -k "list_by_file_name"`
Expected: 3 PASSED

**Step 5: Commit**

```bash
git add src/envault/state.py tests/unit/test_state.py
git commit -m "feat(state): add list_by_file_name() method for filename-based lookup"
```

---

### Task 2: Add `_resolve_identifier()` helper and update `decrypt` command in CLI

**Files:**
- Modify: `src/envault/cli.py:205-303` (decrypt command) and `src/envault/cli.py:670-684` (helpers)
- Test: `tests/unit/test_cli.py`

**Step 1: Write failing tests for identifier resolution**

Add to `tests/unit/test_cli.py`. The existing test `test_decrypt_rejects_invalid_sha256_format` (line 224) needs updating since filenames like `"not-a-valid-hash"` should now be accepted as filename lookups, not rejected. Also add new tests:

```python
def test_decrypt_accepts_filename_identifier():
    """decrypt command should accept a filename and resolve it."""
    runner = CliRunner()
    # With a filename that doesn't match any record, we should get a
    # "no encrypted files found" error, NOT an "invalid SHA256" error.
    result = runner.invoke(
        main,
        ["decrypt", "myfile.txt", "--table", "t", "--bucket", "b"],
        env={
            "AWS_ACCESS_KEY_ID": "testing",
            "AWS_SECRET_ACCESS_KEY": "testing",
            "AWS_DEFAULT_REGION": "us-east-1",
            "ENVAULT_ALLOWED_ACCOUNT_IDS": "123456789012",
        },
    )
    assert result.exit_code != 0
    # Should NOT say "Invalid SHA256" — should say "no encrypted files"
    assert "invalid sha256" not in result.output.lower()


def test_decrypt_version_flag_out_of_range():
    """--version N where N > number of matches should error."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "decrypt", "myfile.txt",
            "--version", "5",
            "--table", "t",
            "--bucket", "b",
        ],
        env={
            "AWS_ACCESS_KEY_ID": "testing",
            "AWS_SECRET_ACCESS_KEY": "testing",
            "AWS_DEFAULT_REGION": "us-east-1",
            "ENVAULT_ALLOWED_ACCOUNT_IDS": "123456789012",
        },
    )
    assert result.exit_code != 0
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_cli.py::test_decrypt_accepts_filename_identifier tests/unit/test_cli.py::test_decrypt_version_flag_out_of_range -v`
Expected: FAIL (test functions don't exist yet, or `--version` flag not recognized)

**Step 3: Implement the changes in `src/envault/cli.py`**

**3a.** Add `_is_sha256()` helper near the existing `_validate_sha256` (around line 671):

```python
def _is_sha256(value: str) -> bool:
    """Return True if value looks like a full 64-char hex SHA256 hash."""
    return bool(_SHA256_RE.fullmatch(value))
```

**3b.** Add `_resolve_identifier()` helper after `_is_sha256`:

```python
def _resolve_identifier(
    identifier: str,
    version: int,
    store: StateStore,
) -> FileRecord:
    """Resolve an identifier (SHA256 or filename) to a FileRecord.

    For SHA256: direct lookup via get_current_state().
    For filename: query by file_name, return the Nth most recent (version=1 is newest).
    Exits with error if not found or version out of range.
    """
    if _is_sha256(identifier):
        record = store.get_current_state(identifier)
        if not record:
            console.print(
                f"[red]No record found for hash {identifier[:16]}...[/red]"
            )
            sys.exit(1)
        return record

    # Filename lookup
    records = store.list_by_file_name(identifier, ENCRYPTED)
    if not records:
        console.print(
            f"[red]No encrypted files found with name {identifier!r}.[/red]"
        )
        sys.exit(1)

    if version < 1 or version > len(records):
        console.print(
            f"[red]Version {version} out of range. "
            f"Found {len(records)} version(s) of {identifier!r}.[/red]"
        )
        sys.exit(1)

    if len(records) > 1:
        selected = records[version - 1]
        console.print(
            f"[dim]{len(records)} versions found. "
            f"Decrypting {'most recent' if version == 1 else f'version {version}'} "
            f"({selected.encrypted_at}). "
            f"Use --version N to pick another.[/dim]"
        )

    return records[version - 1]
```

**3c.** Update the `decrypt` command signature (lines 209-236):

Replace:
```python
@main.command()
@click.argument("sha256_hash")
@click.option(
    "--output", "-o", type=click.Path(path_type=Path), default=Path("."), show_default=True
)
```

With:
```python
@main.command()
@click.argument("identifier")
@click.option(
    "--output", "-o", type=click.Path(path_type=Path), default=Path("."), show_default=True
)
@click.option(
    "--version", "version", type=int, default=1, show_default=True,
    help="Which version to decrypt when multiple exist (1=most recent).",
)
```

Update the function signature:
```python
def decrypt(
    ctx: click.Context,
    identifier: str,
    output: Path,
    version: int,
    table: str,
    bucket: str,
    region: str,
    allowed_account_ids: str,
) -> None:
    """Decrypt a file by filename or SHA256 hash.

    IDENTIFIER is a filename (e.g. secret.env) or full 64-char SHA256 hash.
    When multiple versions of a filename exist, the most recent is decrypted
    by default. Use --version N to select an older version.
    """
```

**3d.** Replace the body's lookup logic. Remove lines:
```python
    _validate_sha256(sha256_hash)
    ...
    record = store.get_current_state(sha256_hash)
    if not record:
        console.print(f"[red]No record found for hash {sha256_hash[:16]}...[/red]")
        sys.exit(1)
    if record.current_state != ENCRYPTED:
        console.print(f"[yellow]File is in state {record.current_state}, not ENCRYPTED.[/yellow]")
        sys.exit(1)
```

Replace with:
```python
    record = _resolve_identifier(identifier, version, store)
    sha256_hash = record.sha256_hash

    if record.current_state != ENCRYPTED:
        console.print(
            f"[yellow]File is in state {record.current_state}, not ENCRYPTED.[/yellow]"
        )
        sys.exit(1)
```

The rest of the decrypt function uses `sha256_hash` and `record` — both are now set correctly. No other changes needed in the body.

**3e.** Update the existing test `test_decrypt_rejects_invalid_sha256_format` (line 224 in `test_cli.py`):

This test passes `"not-a-valid-hash"` and expects it to be rejected. With filename support, this is now a valid filename identifier (it will fail because no DynamoDB record exists, not because of SHA256 validation). Update the test to check for the filename-not-found message instead:

```python
def test_decrypt_rejects_invalid_sha256_format():
    """decrypt treats non-SHA256 input as a filename lookup."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "decrypt",
            "not-a-valid-hash",
            "--table",
            "t",
            "--bucket",
            "b",
        ],
        env={
            "AWS_ACCESS_KEY_ID": "testing",
            "AWS_SECRET_ACCESS_KEY": "testing",
            "AWS_DEFAULT_REGION": "us-east-1",
            "ENVAULT_ALLOWED_ACCOUNT_IDS": "123456789012",
        },
    )
    assert result.exit_code != 0
    # Now treated as filename lookup, not SHA256 validation error
    assert "no encrypted files" in result.output.lower()
```

**Step 4: Run all tests**

Run: `pytest tests/unit/ -v`
Expected: All pass

**Step 5: Run linters and type check**

Run: `ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/envault/`
Expected: Clean

**Step 6: Commit**

```bash
git add src/envault/cli.py tests/unit/test_cli.py
git commit -m "feat(cli): accept filename in decrypt command with --version flag"
```

---

### Task 3: Final verification

**Step 1: Run full test suite**

Run: `pytest tests/unit/ -v`
Expected: All pass (should be ~85 tests)

**Step 2: Run all linters**

Run: `ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/envault/`
Expected: Clean

**Step 3: Manual smoke test**

Run: `source .venv/bin/activate && envault decrypt --help`
Expected: Help text shows `IDENTIFIER` (not `SHA256_HASH`) and `--version` option

**Step 4: Use `superpowers:finishing-a-development-branch` to push and create PR**
