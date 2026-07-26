# envault-cli — Deep Review

**Date:** 2026-07-26
**Base:** `main` @ `af491ab`
**Scope:** `src/envault/`, `infra/cdk/`, `.github/workflows/`, `code/`, `tests/`, packaging and docs.

Findings marked **[verified]** were reproduced by running the code against moto-backed AWS
mocks; the reproduction scripts are described inline. The unit suite passes as-is
(113 passed, 83% line coverage) — everything below is a gap the suite does not cover.

---

## Executive summary

The cryptographic core is in good shape. Streaming encrypt/decrypt, a mandatory
`REQUIRE_ENCRYPT_REQUIRE_DECRYPT` commitment policy, `max_encrypted_data_keys=1`, a
mandatory discovery-account filter, decrypt-to-temp-then-rename, `O_NOFOLLOW` on the
encrypt output, and 0600 temp files are all correct and better than most tools in this
category. The prior audit's crypto findings have genuinely been fixed.

The problems are one layer up, in the **state machine and the lifecycle it drives**. The
`ENCRYPTED`/`DECRYPTED` field is used both as "what happened to this file last" and as "is
this object still protected", and those two meanings have diverged. That single conflation
produces the top three findings, including a file that can only ever be decrypted once and
a key rotation that silently skips files.

Counts: **3 critical, 5 high, 7 medium, 8 low**, plus 11 simplification opportunities.

| # | Finding | Severity |
|---|---------|----------|
| C-1 | A file can only be decrypted once, ever | Critical |
| C-2 | `rotate-key` silently skips every previously-decrypted file | Critical |
| C-3 | Audit events are silently overwritable — the trail is not append-only | Critical |
| H-1 | `rotate-key` cannot work with the IAM policy the CDK provisions | High |
| H-2 | Rotation does not revoke the old key; old ciphertext lives 365 more days | High |
| H-3 | `dashboard` always reports `last_activity: —` | High |
| H-4 | `ENVAULT_AUDIT_TTL_DAYS` is documented but silently ignored | High |
| H-5 | Documented quick-start fails: `ENVAULT_ALLOWED_ACCOUNT_IDS` is undocumented but required | High |
| M-1..M-7 | Optimistic-lock granularity, raw tracebacks, silent overwrite, markup injection, GSI design, O(n) filename lookup, late context check | Medium |
| L-1..L-8 | Partition hardcoding, IAM over-grants, missing lifecycle commands, CI drift, stale audit doc, … | Low |

---

## Critical

### C-1 — A file can only ever be decrypted once **[verified]**

**Files:** `src/envault/cli.py:301-303`, `cli.py:364-371`, `cli.py:846`

`decrypt` refuses to run unless the record is `ENCRYPTED` (`cli.py:301`), and then sets the
record to `DECRYPTED` on success (`cli.py:366`). Nothing ever sets it back. The S3 object is
untouched — it is still ciphertext — but the record now says otherwise.

Reproduced end-to-end against moto (`encrypt secret.txt`, then `decrypt` twice):

```
--- decrypt #1 (exit 0) ---
✓ Decrypted → out1/secret.txt

--- decrypt #2 (exit 1) ---
No encrypted files found with name 'secret.txt'.       # filename lookup
File is in state DECRYPTED, not ENCRYPTED.             # by-hash lookup
```

By filename the record is invisible because `_resolve_identifier` queries
`list_by_file_name(identifier, ENCRYPTED)` (`cli.py:846`); by hash it is rejected by the
state guard. There is no CLI command that returns a record to `ENCRYPTED` short of
re-encrypting the plaintext you no longer have. **For a backup/escrow tool, one-shot
restore is a data-availability failure.**

**Fix.** Separate the two concepts. `current_state` should describe the stored object
(`ENCRYPTED` while ciphertext exists in S3), and "someone decrypted a copy at time T"
belongs in the event log, which already records it via `put_event(..., "DECRYPT")`. Drop the
`!= ENCRYPTED` guard on decrypt, stop mutating `current_state` on decrypt, and keep
`decrypted_at` as a last-access timestamp. `status` can render "last decrypted" from that
field. This also fixes C-2.

---

### C-2 — `rotate-key` silently skips every previously-decrypted file **[verified]**

**File:** `src/envault/cli.py:692`

```python
records = store.list_by_state(ENCRYPTED)
if not records:
    console.print("[yellow]No ENCRYPTED files found.[/yellow]")
    return
```

Because of C-1, any file that has been decrypted once is no longer in `ENCRYPTED`, so
rotation skips it — and reports success. Verified: after a single decrypt, `rotate-key
--dry-run` printed `No ENCRYPTED files found.` while the ciphertext sat in S3 under the old
key.

This is the security-critical half of C-1. The whole point of `rotate-key` is incident
response — you rotate because a key may be compromised. The command silently leaves behind
exactly the objects that have been accessed most, and exits 0, so an operator has no signal
that coverage was partial.

**Fix.** With C-1's fix this resolves itself. In the interim, rotate over all records
regardless of state, and make the command report `rotated / skipped / failed` counts and
exit non-zero if any file was skipped.

---

### C-3 — Audit events are silently overwritable — the trail is not append-only **[verified]**

**Files:** `src/envault/state.py:169-191`, `infra/cdk/stacks/envault_stack.py:203-212`

`_put_event_inner` writes events with a bare `put_item` and **no condition expression**,
while the IAM policy grants unconditional `dynamodb:PutItem` on the table. Any principal
that can run `envault` can therefore overwrite or forge history at a known PK/SK. Verified:

```
events for b: 1 SK: EVENT#2026-07-26T00:00:18+00:00#ENCRYPT#37271657
after overwrite, operation = FORGED
```

The docstring calls this an "immutable audit trail" (`state.py:164`) and the README
advertises "a full audit trail". Nothing enforces it at either layer.

**Fix, two parts:**

1. Application: `ConditionExpression="attribute_not_exists(SK)"` on the event write. This
   is a one-line change and also makes the `_put_event_inner` retry genuinely idempotent.
2. IAM: split the managed policy so event writes are constrained, e.g. a `PutItem`
   statement with `dynamodb:LeadingKeys` scoping plus a separate deny on overwriting
   `EVENT#` items — or, more robustly, write events through a small Lambda/API the CLI
   principal cannot bypass. If the audit trail is meant to be evidence, also enable
   DynamoDB Streams → S3 Object Lock, since a principal with table access can still let
   TTL expire records early by rewriting `ttl`.

---

## High

### H-1 — `rotate-key` cannot work with the IAM policy the CDK provisions

**File:** `infra/cdk/stacks/envault_stack.py:188-192`

```python
iam.PolicyStatement(
    sid="KmsEnvelopeEncryption",
    actions=["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"],
    resources=[encryption_key.key_arn],     # the one key this stack created
)
```

`rotate-key --new-key-id alias/new-key` calls `GenerateDataKey` against the *new* key and
sets it as the S3 `SSEKMSKeyId`. The provisioned policy scopes KMS to the original key ARN
only, so the command fails with `AccessDenied` for every file — after it has already
downloaded and decrypted plaintext to `/tmp`. The stack ships a rotation command it does
not grant permission to run.

**Fix.** Document the required policy amendment, or add a stack parameter for additional
rotation-target key ARNs. At minimum, have `rotate-key` verify `kms:DescribeKey` on the new
key *before* it starts writing plaintext to disk.

### H-2 — Rotation does not revoke the old key; old ciphertext survives 365 days

**Files:** `infra/cdk/stacks/envault_stack.py:120-133`, `:78-86`; `src/envault/cli.py:749`

`rotate-key` re-uploads to the same S3 key (`cli.py:749`). With versioning on, the previous
version — ciphertext wrapped under the **old** key — remains fully retrievable, and the
lifecycle rule keeps noncurrent versions for 365 days
(`noncurrent_version_expiration=Duration.days(365)`). The IAM policy grants
`s3:GetObjectVersion`. So after rotating away from a compromised key, anyone holding
`kms:Decrypt` on the old key can still read every file for a year.

Compounding it, the key resource policy denies key disablement to all principals:

```python
sid="DenyScheduleKeyDeletion",
effect=iam.Effect.DENY,
principals=[iam.AnyPrincipal()],
actions=["kms:ScheduleKeyDeletion", "kms:DisableKey"],
```

Denying `ScheduleKeyDeletion` is sound anti-footgun design. Denying **`DisableKey`** is not:
disabling a key is the primary incident response to a suspected compromise, and this makes
it impossible without first shipping a CloudFormation change to the key policy — during an
incident, under time pressure.

**Fix.** Remove `kms:DisableKey` from the deny statement (keep `ScheduleKeyDeletion`). Have
`rotate-key` either write to a new S3 key and delete the old object, or document that
rotation must be followed by expiring noncurrent versions. State the true revocation
boundary in the README.

### H-3 — `dashboard` always reports `last_activity: —` **[verified]**

**File:** `src/envault/state.py:282-297`

```python
response = self._table.query(
    IndexName="state-index",
    KeyConditionExpression=Key("current_state").eq(state),
    FilterExpression=Attr("SK").eq(CURRENT),
    ScanIndexForward=False,
    Limit=1,
)
```

DynamoDB applies `Limit` **before** `FilterExpression`. `put_event` copies the full record
into each event item (`state.py:181`, via `asdict`), including `current_state` and
`encrypted_at`, so every event also lands in `state-index` with the same sort key as its
CURRENT record. Descending, `EVENT#…` sorts above `CURRENT`, so the single item fetched is
always an event, is always filtered out, and the query returns empty.

Reproducing the exact `envault encrypt` sequence (`put_current_state` then `put_event`):

```
REALISTIC encrypt flow -> dashboard summary:
{'total': 1, 'encrypted': 1, 'decrypted': 0, 'last_activity': '—'}
```

The field is broken on every deployment, not in a corner case. The method also sorts by
`encrypted_at` but returns `last_updated`, which is a second inconsistency.

**Fix.** Drop `Limit=1` and page until a `CURRENT` item is found, or keep events out of
`state-index` entirely (see M-5) — which is the better fix and also cuts read cost.

### H-4 — `ENVAULT_AUDIT_TTL_DAYS` is documented but silently ignored **[verified]**

**Files:** `src/envault/cli.py:51-56`, `cli.py:135`, `cli.py:234`

`_load_config()` — the only caller of `Config.from_env()` — is **dead code**. Nothing in the
CLI invokes it. Commands read env vars through Click's `envvar=`, and `encrypt` builds its
config positionally:

```python
config = Config(key_id=key_id, bucket=bucket, table_name=table, region=region)
```

`audit_ttl_days` is never passed, so it always takes the dataclass default of 365 and that
is what reaches `put_event` at `cli.py:234`. Verified with `ENVAULT_AUDIT_TTL_DAYS=1`:

```
ENVAULT_AUDIT_TTL_DAYS env = 1
config.audit_ttl_days used by encrypt = 365
-> env var honoured: False
```

The variable is documented in both README and CLAUDE.md. An operator setting a 90-day
retention policy for compliance gets 365 and no warning. The same dead path means
`Config.__post_init__`'s account-ID validation never runs in production either — it is
covered by tests and by nothing else.

**Fix.** Either route all commands through `_load_config()`/`Config.from_env()`, or delete
`from_env`/`_load_config` and add a proper `--audit-ttl-days`/`envvar` Click option. Do not
leave two config systems where only one is wired up. See S-3.

### H-5 — The documented quick-start fails on decrypt

**Files:** `README.md:34-47`, `src/envault/crypto.py:228-233`, `cli.py:875-888`

`decrypt_file` raises `ConfigurationError` unless `allowed_account_ids` is supplied, and
`_validate_account_ids` exits 1 when it is empty. `ENVAULT_ALLOWED_ACCOUNT_IDS` appears
nowhere in the README config table, the README CLI reference, or CLAUDE.md — all of which
list exactly five variables. Following the quick-start verbatim yields:

```
Error: ENVAULT_ALLOWED_ACCOUNT_IDS is required.
```

The requirement itself is a good security decision. It is just undocumented, so the first
experience of the tool is a failed restore.

**Fix.** Add it to the README table (Required: **for decrypt**), the quick-start export
block, and CLAUDE.md.

---

## Medium

### M-1 — Optimistic locking is second-granular, so concurrent writes can be lost **[verified]**

**Files:** `src/envault/state.py:66`, `state.py:131`

`_now_iso()` uses `timespec="seconds"`, and `put_current_state` uses `last_updated` as the
CAS token. Two writers within the same wall-clock second read the same token, and the second
write's condition still matches — because the first writer wrote back the *same* value.

```
LOST UPDATE: second writer succeeded with a stale expected_last_updated -> writer2
```

**Fix.** Use a monotonic integer `version` attribute
(`ConditionExpression="version = :v"`, `version = :v + 1`), or at minimum microsecond
timestamps plus a random nonce. A timestamp is not a version.

### M-2 — Unhandled exceptions in `encrypt`/`decrypt` surface as raw tracebacks

**Files:** `src/envault/cli.py:92-104`, `cli.py:299`, `cli.py:369-382`

`cli()` catches only `click.UsageError` and `click.Abort`. `status`, `audit` and `dashboard`
each wrap their bodies in `except (ClientError, BotoCoreError) / except EnvaultError`, but
`decrypt` does not: `_resolve_identifier` at `cli.py:299` runs outside any handler, so a
DynamoDB error during lookup prints a stack trace. Worse, the post-decrypt state write at
`cli.py:370` re-raises `StateConflictError` — so a *successful* decrypt whose state update
raced another process ends in a traceback, and the user cannot tell the file was written.

**Fix.** One `@handle_aws_errors` decorator applied to every command (see S-1), and treat
post-success state-write failure as a warning with a non-zero exit, not a traceback.

### M-3 — `decrypt` silently overwrites an existing destination file

**File:** `src/envault/crypto.py:283`

`os.replace(tmp_path, output_path)` clobbers whatever is at the destination with no prompt
and no flag. `envault decrypt config.yaml -o .` in a directory that already has a
`config.yaml` destroys the local copy.

**Fix.** Refuse to overwrite unless `--force` is given (`os.link`/`O_EXCL` probe before the
rename), or write to `name.1` on collision.

### M-4 — Untrusted filenames are rendered as Rich markup **[verified]**

**Files:** `src/envault/cli.py:430-447`, `cli.py:152-156`, `cli.py:248`

`file_name` comes back from DynamoDB and goes straight into `Table.add_row` and f-strings
passed to `console.print`, with markup enabled. Two consequences:

```
Table cell "[bold red]NOT-MY-NAME[/bold red]"  renders as → NOT-MY-NAME
console.print(f"... {'[/nope]'}")              → MarkupError: closing tag '[/nope]'
                                                 doesn't match any open tag
```

So (a) a crafted filename displays as something other than what it is — an operator
auditing `status` output cannot trust the File column — and (b) an unmatched closing tag
crashes `status`, `audit` and `encrypt` output entirely. A filename containing `[` is
enough; it need not be malicious.

**Fix.** `rich.markup.escape()` every externally-sourced string, or pass
`Text(value)` objects instead of `str`.

### M-5 — `state-index` is a two-value partition key that also carries every event

**Files:** `infra/cdk/stacks/envault_stack.py:159-166`, `src/envault/state.py:212-217`

The GSI partitions on `current_state`, which takes exactly two values, so the entire table
funnels into two physical partitions — a textbook DynamoDB hot-partition anti-pattern with
a hard per-partition throughput ceiling. On top of that, every event item is projected into
the index (they inherit `current_state` from `asdict`), so `list_by_state` and
`_count_by_state` pay read capacity for the full event history and discard it with a
server-side filter. `status` and `rotate-key` therefore get slower and more expensive with
every operation performed, forever.

**Fix.** Add a sparse-index marker attribute written only on `CURRENT` items (e.g.
`gsi_state = current_state`, absent on events) and key the GSI on that. Removes the filter,
removes the event bloat, and fixes H-3 as a side effect. Note the migration cost — the
comment at `:157` correctly warns that changing an existing GSI forces replacement, so this
belongs in a versioned migration.

### M-6 — Filename lookup reads every encrypted record

**File:** `src/envault/state.py:221-236`

`list_by_file_name` queries the whole `ENCRYPTED` partition and filters on `file_name`
client-side after a full pagination loop. Every `envault decrypt <name>` costs O(total
encrypted files) in read capacity.

**Fix.** A `name-index` GSI keyed `PK=file_name, SK=encrypted_at` turns this into a single
targeted query and gives the `--version N` ordering for free.

### M-7 — Encryption context is verified only after plaintext is at its destination

**Files:** `src/envault/cli.py:318-337`, `cli.py:741-743`

`decrypt_file` renames the plaintext into `output_path`, and only then does the caller run
`_verify_encryption_context`; on mismatch the file is `_best_effort_delete`d. So a
context-mismatched decrypt does briefly place plaintext at the user's chosen path, and if a
file already existed there it has already been clobbered (M-3) and is not restored by the
cleanup.

The residual risk is low — the SHA256 check inside `decrypt_file` already binds content to
the record's primary key, so substitution is caught before the rename. But the ordering is
backwards relative to the design intent.

**Fix.** Pass the expected context into `decrypt_file` and verify it against
`decryptor.header.encryption_context` immediately after the header is read (`crypto.py:269`),
before any plaintext is written.

---

## Low

- **L-1 — KMS partition hardcoded.** `DiscoveryFilter(partition="aws")` (`crypto.py:246`)
  breaks in GovCloud (`aws-us-gov`) and China (`aws-cn`). Derive it from the region.
- **L-2 — IAM over-grants.** `dynamodb:UpdateItem` and `s3:ListBucket`
  (`envault_stack.py:199,209`) are granted but never called by any code path. Remove.
- **L-3 — No delete or purge path.** No CLI command and no `s3:DeleteObject` grant, so
  storage and records grow monotonically and there is no way to honour a deletion request.
  `--force` re-encryption under a changed filename also orphans the previous S3 object,
  which stays readable but unreferenced.
- **L-4 — `status` output is unbounded.** `list_by_state` pages the entire table into memory
  and prints it. Add `--limit`/pagination; the `max_items` plumbing already exists but no
  caller uses it.
- **L-5 — Undocumented CVE suppressions and CI drift.** `ci.yml` runs
  `pip-audit --ignore-vuln CVE-2026-4539 --ignore-vuln CVE-2026-3219`; `publish.yml`
  ignores only the first. So a release can fail a gate that PR CI passes. Neither
  suppression records a rationale or an expiry date.
- **L-6 — `SECURITY_AUDIT.md` is stale and alarming.** It reviews commit `5b575e9`, and its
  three "CRITICAL" findings (plaintext-before-verification, no streaming, temp cleanup) were
  all fixed — `crypto.py` streams and verifies before rename today. A reader of the repo
  sees an in-tree document asserting the tool has unfixed critical flaws. Move it to
  `docs/reviews/` with a resolved-status header.
- **L-7 — `.env.example` describes the deprecated shell workflow only.** It documents
  `KMS_KEY_ARN`, `ENCRYPTION_CONTEXT` and `S3_BUCKET` — none of which the CLI reads — and
  omits every `ENVAULT_*` variable. It also omits `KMS_ACCOUNT_ID`, which `decrypt.sh`
  hard-requires.
- **L-8 — `claude.yml` triggers on `issue_comment` from any commenter.** The job gate is
  only `contains(github.event.comment.body, '@claude')`. Worth confirming the action's
  author-association gating is what you want on a public repo, since the job carries
  `CLAUDE_CODE_OAUTH_TOKEN`.

---

## Simplification

The package is ~1,900 lines of source. Roughly 250 of them are duplication or dead weight.

- **S-1 — Four copies of the same AWS error handler.** `status`, `audit` and `dashboard`
  each repeat the identical `except (ClientError, BotoCoreError) → msg → exit(1)` /
  `except EnvaultError` pair (`cli.py:421-427`, `498-504`, `534-540`). `encrypt` and
  `decrypt` are missing it, which is exactly M-2. One `@handle_aws_errors` decorator removes
  ~40 lines *and* closes the gap.
- **S-2 — Account-ID validation exists three times.** `config.py:13` `_ACCOUNT_ID_RE`,
  `cli.py:872` `_ACCOUNT_ID_RE` (identical regex, separate constant), and a third copy in
  `code/decrypt.sh:38`. Keep the one in `config.py`.
- **S-3 — Two config systems, one wired up.** `Config.from_env`, `_load_config` and
  `Config.__post_init__` are reachable only from tests (H-4). Either adopt `Config` as the
  single entry point for all commands or delete `from_env` and lean on Click's `envvar=`.
  Right now `encrypt` builds a `Config`, `decrypt` and `rotate-key` pass loose strings, and
  `status`/`audit`/`dashboard` use neither — three conventions for one job.
- **S-4 — `encrypt` reads every file twice.** `_encrypt_one` calls `sha256_file`
  (`cli.py:176`), then `encrypt_file` re-reads and re-hashes the same bytes through
  `_HashingReader`. The pre-read exists to key the "already encrypted?" lookup, but the same
  result is available by encrypting to the temp file first and doing the state lookup on the
  streamed hash before upload. Halves I/O on large inputs; the modification check at
  `cli.py:198` becomes unnecessary rather than merely redundant.
- **S-5 — `code/` and the `Makefile` duplicate the CLI.** Both shell scripts print
  "deprecated, use `envault` instead" as their first act. They still carry live
  `.env`-parsing and account-ID logic that must be kept in sync (S-2). `migrate` is the only
  reason to keep `output.json` parsing; the scripts themselves can go, along with the
  `encrypt`/`decrypt` Makefile targets.
- **S-6 — Function-level imports used as a habit.** `from boto3.dynamodb.conditions import
  Attr` appears inside five separate methods of `state.py` (`Key` is already module-level);
  `from envault.crypto import sha256_file` appears inside two `cli.py` functions;
  `DiscoveryFilter` inside `decrypt_file`; `JsonFormatter` inside `_setup_logging`. None
  break a cycle. Hoist them.
- **S-7 — Dead parameter.** `list_by_state(..., max_items)` (`state.py:203`) is never called
  with a non-default value. Either wire it to a `--limit` flag (L-4) or drop it.
- **S-8 — Trivial wrappers.** `_extract_algorithm` (`cli.py:639`) is a one-line
  `str(header.get(...))`. Inline it with its two siblings.
- **S-9 — Duplicated docstring paragraph.** `S3Store.upload_file` (`s3.py:30-43`) explains
  the put_object/TOCTOU rationale twice, in consecutive paragraphs.
- **S-10 — Redundant chmod.** `os.fchmod(_fd_pt, 0o600)` (`cli.py:724`) — `mkstemp` already
  creates 0600, and the two sibling temp files in the same block don't do this.
- **S-11 — The two CI quality gates are copy-paste.** `ci.yml`'s lint/test/audit jobs and
  `publish.yml`'s `ci` job run the same commands with drifting flags (L-5). Extract a
  reusable workflow called by both.

---

## Test gaps worth closing

Coverage is 83% overall but 71% on `cli.py`, and the misses are concentrated in exactly the
paths that carry these bugs:

- `status` / `audit` / `dashboard` command bodies — `cli.py:403-447`, `462-504`, `521-540`.
  H-3 would have been caught by one assertion on `summary()["last_activity"]` after a
  realistic `put_current_state` + `put_event` pair.
- `migrate` — `cli.py:558-586`, entirely uncovered.
- `_resolve_identifier`'s filename branch — `cli.py:851-869`. C-1 is one round-trip test:
  encrypt → decrypt → decrypt again.
- A `rotate-key` test that decrypts a file first would have caught C-2.

None of these need new infrastructure; `tests/conftest.py` already provides moto-backed
DynamoDB, S3 and KMS fixtures.

---

## Suggested order of work

1. **C-1 / C-2** — split "object state" from "last operation". One change, unblocks restore
   and makes rotation complete. Add the three regression tests above.
2. **H-4** — pick one config system; `ENVAULT_AUDIT_TTL_DAYS` should work or stop being
   documented.
3. **C-3** — `attribute_not_exists(SK)` on event writes (one line), then decide how much
   tamper-evidence the IAM layer needs.
4. **H-5, L-6, L-7** — documentation truth-up. Cheap, and currently the first thing a new
   user hits.
5. **H-1 / H-2** — make `rotate-key` either work end-to-end or fail loudly and early; fix
   the `DisableKey` deny.
6. **H-3, M-5** — the sparse-index change fixes both; schedule with a migration.
7. **S-1, S-3, S-6** — the structural cleanups that make the rest easier to land.
