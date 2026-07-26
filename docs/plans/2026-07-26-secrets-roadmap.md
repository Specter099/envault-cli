# envault — Feature Roadmap: Secrets, Evidence, and the v0.2 Break

**Date:** 2026-07-26
**Status:** Proposal, derived from a design interview
**Companion:** `docs/reviews/2026-07-26-deep-review.md`

## What you told me

| Question | Answer |
|---|---|
| Dominant content | Secrets & credentials |
| Operators | Single operator today; built for teams |
| Ambition | Serious OSS product |
| Identity model | Name-addressed with versions (breaking change accepted) |
| Consumption | `envault exec -- cmd` — and nothing else was selected |
| Ships next | Compliance evidence |
| Evidence audience | SOC 2, for *your adopters* |
| Tamper-evidence | WORM export to S3 Object Lock |
| Attribution | AWS principal ARN |
| Artifact | Report, verifiable export, live query, SIEM push |

You selected every option on three of the multi-selects. I've sequenced them rather than
asking again — that sequencing is most of what follows.

---

## Positioning

> **SOPS gives you a file format. Secrets Manager gives you a service. envault gives you an
> audited secret lifecycle where the plaintext never leaves your machine.**

One correction to the competitive frame from our interview. You benchmarked against SOPS,
but for *secrets specifically* your real competitor is **AWS Secrets Manager** — it already
does name-addressed versioned secrets with CloudTrail audit, which is most of what you're
about to build. You need an honest answer to "why not just use Secrets Manager," and you
have four:

1. **Different trust boundary.** Secrets Manager encrypts server-side — AWS holds your
   plaintext at rest in their process. envault wraps a DEK and never transmits plaintext.
   This is the one thing neither competitor can copy, and it should be the headline.
2. **Cost at scale.** Secrets Manager is ~$0.40/secret/month. At 500 secrets that's
   $2,400/year versus single-digit dollars on S3 + DynamoDB. Publish this table.
3. **Arbitrary files.** Secrets Manager caps at 64KB and is string/JSON oriented.
   Certificates, keystores, and SSH keys are awkward there and native here.
4. **Portable evidence.** CloudTrail is coarse, AWS-scoped, and not secret-name aware. Your
   event log knows which *named secret* was read, by whom, for what process.

Against SOPS the answer is simpler and you already named it: nothing sensitive in git, and
rotation doesn't rewrite history.

---

## The architectural change everything depends on

Content addressing was the right instinct for archival and the wrong one for secrets. The
fix is not to abandon it — it's to **demote `sha256` from identity to integrity**.

```
PK = SECRET#{name}
SK = CURRENT              → pointer: {current_version, last_rotated, principal}
SK = V#{version:012d}     → immutable version record (sha256, s3_key, s3_version_id,
                             kms_key_id, encryption_context, created_at, created_by)
SK = EVENT#{ts}#{seq}     → access event (hash-chained, see below)
```

What this buys, in order of importance:

- **A stable identity for a rotating value.** `envault get DATABASE_URL` finally means
  something. This is the thing the current model cannot express at all.
- **C-1 and C-2 disappear structurally.** There is no `ENCRYPTED`/`DECRYPTED` flag to get
  stuck in. A version exists or it doesn't; reading it is an event, not a state transition.
  Rotation iterates versions, so it can't silently skip anything.
- **Integrity survives.** `sha256` stays on every version record and is still verified on
  read. You keep the property, you lose the identity coupling.
- **The guessing oracle closes.** `sha256(plaintext)` stops being the partition key, so
  DynamoDB read access no longer lets someone confirm a guessed API key by hashing it.
- **Real optimistic locking.** A monotonic integer version replaces the second-granularity
  timestamp CAS that I demonstrated losing writes (M-1).

Cost: dedupe goes away. For secrets that's irrelevant — you *want* two identical passwords
in two places to be two independently rotatable records.

Do this once, and design the event schema in the same motion. That's the argument for
resequencing I made during the interview and it still holds: migrated evidence is weaker
evidence, because continuity of the record is part of what makes it credible.

---

## v0.2.0 — Foundation (breaking)

The window for this closes with adoption. You're at 0.1.2, alpha, "not recommended for
production." Take the break now.

- `envault set NAME <file|->` — store a new version, print the version number
- `envault get NAME [--version N]` — retrieve; **refuses to write to a TTY** without
  `--force`, so the default path can't dump a credential into scrollback
- `envault ls` / `envault versions NAME` / `envault rm NAME [--version N]`
- Storage migration to `SECRET#{name}` + `V#{n}`; `envault migrate --from-v1` reads the
  existing `FILE#{sha256}` layout
- **Principal ARN on every event** via `sts:GetCallerIdentity`, cached once per process.
  Without this the audit trail has no actor and the differentiator doesn't exist.
- Integer version CAS replacing timestamp CAS
- `attribute_not_exists(SK)` on event writes — one line, do it now, don't wait for WORM
- Delete `code/`, the `encrypt`/`decrypt` Makefile targets, and `_load_config` dead code

Keep `encrypt`/`decrypt` as thin deprecated aliases for one minor version, then drop them.

## v0.3.0 — `exec`, and the disappearance of plaintext

You picked `exec` and *nothing else*. I'm treating that as a principle rather than a
preference: **materializing plaintext to disk stops being the default path.**

- `envault exec [--secret NAME=ENV_VAR]... -- cmd args` — decrypt into the child's
  environment, never touching disk. **Shipped.**
- `envault exec [--file NAME=ENV_VAR]...` — **the file-consuming case, and a hole in the
  first draft of this plan.** Certificates, keystores and kubeconfigs cannot be passed as
  environment variables; nginx, Postgres and the JVM all demand a path. Saying
  "materializing plaintext to disk stops being the default" left half the stated content
  type with no supported route at all.

  The resolution keeps the principle rather than abandoning it: decrypt into an anonymous
  `memfd`, seal it once the checksum and encryption context verify, and hand the child
  `/proc/self/fd/N` by descriptor inheritance. No directory entry ever exists, so there is no
  path for another process to open, no cleanup that can fail, and no plaintext surviving a
  crash. A `{VAR}` token in the command is substituted with the path. **Shipped.**
- Process hardening around both modes: `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, and a
  best-effort `mlockall`, applied before any plaintext exists. **Shipped.**
- `.envault.yaml` manifest mapping secrets to env var names, so `envault exec -- ./server`
  works with no flags
- `--format json|dotenv` on `get` for CI, still TTY-guarded
- GitHub Action wrapping `exec`, with OIDC role assumption
- systemd `LoadCredential=`/`SetCredentialEncrypted=` emitter for the long-running service
  case — TPM-sealed and namespace-isolated, and cheaper to integrate than to reimplement
- `envault run --watch` deferred; it's a nice demo and a large surface

**Be honest in the docs about what `exec` does and doesn't buy.** On Linux a child's
environment is readable via `/proc/PID/environ` by the same user and leaks through `ps e` on
some configurations. `exec` is a large improvement over a file that persists after the
process exits, but it is not isolation. `PR_SET_DUMPABLE` is reset by `execve` for non-setuid
binaries, so it protects the envault process while the secret is in flight and cannot be
inherited by the child. Overclaiming any of this would undercut the trust the rest of the
product is built on.

`--file` is the stronger of the two modes — the material is never in the child's environment
at all — and should be the documented preference wherever the consumer accepts a path.

## v0.4.0 — Evidence (your chosen differentiator)

One correction on the mechanism you selected. **You picked WORM export but not hash
chaining — and you also picked "verifiable export" as an artifact. Those are the same
requirement.** An export is only verifiable if it carries its own proof of completeness;
otherwise you've moved an assertion to a bucket that can't be deleted. Chaining is the
prerequisite, not the alternative:

- **Hash-chained events.** Each event carries `seq` and `prev_hash` (hash of the prior event
  in that secret's chain). `envault verify-audit NAME` walks the chain and proves no event
  was edited, deleted, or reordered. No new infrastructure, no recurring cost.
- **Daily global checkpoint** — one record containing every secret's chain head, so a whole
  secret's history can't be dropped unnoticed.
- **WORM export.** `envault export-audit --since` writes chain + checkpoints to an S3 Object
  Lock bucket. Now tampering is *prevented* for the exported copy and *detectable* in the
  primary store.
- **Ship Object Lock in GOVERNANCE mode by default, not COMPLIANCE.** COMPLIANCE mode cannot
  be shortened or deleted by anyone including the root account for the full retention
  period. As an opt-in for a regulated adopter that's the point; as a default in an OSS tool
  it's a footgun that will generate angry issues and unpayable S3 bills. Gate COMPLIANCE
  behind an explicit flag with a typed confirmation.
- **`envault report --since --until`** — SOC 2 shaped: access by principal, access by
  secret, rotation history, secrets not rotated in N days, failed access attempts.
- **SIEM sink** — EventBridge or CloudWatch Logs, so adopters who already solved retention
  don't have to adopt yours.
- Extend `audit` with `--principal`, `--secret`, `--operation` filters. Cheapest item here;
  it's mostly a GSI and argument parsing.

The SOC 2 control you're actually serving is *"logical access to production secrets is
logged and reviewed."* Say that in the README. Adopters trying to satisfy an auditor will
search for exactly that sentence.

## v0.5.0 and beyond

- **Rotation as a secrets operation.** `envault rotate NAME --exec ./rotate.sh` — generate,
  store, verify the new value works, then retire the old version. This is different from
  today's `rotate-key` (which rotates the *KMS key*, not the secret) and is the feature that
  makes the SOC 2 rotation control real rather than aspirational.
- **Staleness reporting.** "These 12 secrets haven't rotated in 400 days." Directly maps to
  an audit finding, trivial to compute once versions are first-class, and demos beautifully.
- **`envault init`** — wrap the CDK deploy so onboarding is one command. Your "frictionless
  onboarding" win condition; it lands better once the storage model is stable.
- **Time-boxed grants** for external recipients — only if the single-operator assumption
  changes.

---

## What I would not build

- **A daemon or server.** It destroys the "no infrastructure to run" story that makes you
  cheaper than Secrets Manager.
- **A web UI.** This is a CLI product; a UI would consume the entire roadmap.
- **Multi-tenancy.** Contradicts both the solo-operator reality and the simplicity pitch.
- **Required `--reason` strings.** You didn't select it, and it taxes every invocation to
  serve an auditor who is satisfied by the principal ARN.
- **Keeping `.env` materialization as a first-class path.** It's the one thing that
  undermines the strongest claim you have.

---

## Risks worth holding in view

1. **Self-attested evidence is weak evidence.** SOC 2 material generated by a tool the
   auditee controls is discounted unless something outside their control anchors it. The
   WORM export and the chain are what make it credible — and the auditor will ask who can
   write to the lock bucket. Document a separate-account setup for it.
2. **`exec` is better, not airtight.** See the `/proc` caveat above. Claim precisely.
3. **You are about to compete with an AWS first-party service.** That's viable on trust
   boundary and cost, but only if you say so explicitly and early. Adopters will otherwise
   assume you didn't know Secrets Manager existed.
4. **Name-addressed storage forfeits dedupe.** Correct for secrets; call it out in the
   migration notes so archival users of v0.1 understand what changed.
5. **The lifecycle bugs are still load-bearing.** C-1, C-2, and C-3 from the review are
   fixed *by* v0.2 rather than before it — so v0.2 cannot slip into a long branch. If it
   does, land the one-line `attribute_not_exists(SK)` fix on `main` independently.

---

## Suggested sequence

```
v0.2.0  Storage model + principal ARN + version CAS      ← unblocks everything
v0.3.0  exec, manifest, CI action                        ← drives real usage
v0.4.0  Chain, WORM export, report, SIEM, query          ← the differentiator
v0.5.0  Secret rotation, staleness, envault init         ← the SOC 2 story completes
```

Compliance evidence still ships as the headline feature — it just ships on a foundation that
can carry it, one release later than you picked, with its schema designed two releases
earlier.
