# Filename-Based Decrypt

**Date:** 2026-03-04
**Status:** Approved

## Problem

The `decrypt` command requires a full 64-character SHA256 hash, but `envault status`
displays only the first 16 characters. Users cannot copy-paste from status output to
decrypt. Filenames are more intuitive identifiers for human users.

## Design

### Identifier Resolution

The `decrypt` argument changes from `SHA256_HASH` to `IDENTIFIER`. Resolution order:

1. **Full SHA256** (64 hex chars) — direct lookup via `get_current_state()` (unchanged)
2. **Filename** (anything else) — query encrypted records, filter by `file_name`
   - 1 match → decrypt it
   - Multiple matches → decrypt most recent by `encrypted_at`, print info note
   - 0 matches → error

### Version Selection

`--version N` flag (1-indexed, default 1) selects which version when multiple exist:
- `--version 1` = most recent (default)
- `--version 2` = second most recent
- etc.

### Changes Required

**`state.py`** — New method `list_by_file_name(name: str, state: str) -> list[FileRecord]`:
- Queries `state-index` GSI with `KeyConditionExpression=Key("current_state").eq(state)`
- Adds `FilterExpression` for `Attr("SK").eq(CURRENT) & Attr("file_name").eq(name)`
- Returns results sorted by `encrypted_at` descending

**`cli.py`** — Modify `decrypt` command:
- Rename argument from `sha256_hash` to `identifier`
- Add `--version` option (int, default 1)
- New `_resolve_identifier()` helper that returns a `FileRecord`
- Remove `_validate_sha256()` call; detect full hash via regex instead
- Update help text and docstring

### What Does NOT Change

- `status`, `audit`, `dashboard` commands
- Data model / DynamoDB schema
- No new GSIs required

## Example Usage

```bash
# By filename (single version)
envault decrypt test_file.txt

# By filename (multiple versions — decrypts most recent)
envault decrypt test_file.txt
# prints: "2 versions found. Decrypting most recent (2026-03-04T16:59:22)."

# By filename (specific older version)
envault decrypt test_file.txt --version 2

# By full SHA256 (still works)
envault decrypt d9014c4624844aa5...full64chars...
```
