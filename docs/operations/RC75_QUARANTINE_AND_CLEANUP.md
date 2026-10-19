# RC7.5 Quarantine and Cleanup

How resources that cannot be safely destroyed are held, and the exact
semantics of every cleanup outcome.

## Cleanup outcomes (INV-01)

| Outcome | Meaning | `cleanup_pending` cleared? |
|---|---|---|
| `REMOVED_VERIFIED` | Removed and independently confirmed absent | yes |
| `ALREADY_ABSENT_VERIFIED` | Authorized instance verifiably gone | yes |
| `RETAINED_BY_POLICY` | Intentionally kept (e.g. `keep_sandboxes`) — resolved by policy, **not** a claim of absence | yes |
| `IDENTITY_MISMATCH` | A *different* instance occupies the name — the substitute survives by design | **no** |
| `IDENTITY_UNVERIFIABLE` | Current identity could not be read | **no** |
| `REMOVAL_UNCERTAIN` | Remove may have landed; state unresolved | **no** |

Only `ResolvesObligation()` outcomes clear the flag — verified absence
or an explicit retention decision. Everything else is explicit
residue — the resource stays named in the ledger until absence is
proven, not until it is assumed. `RETAINED_BY_POLICY` never feeds
absence accounting: `ProvesAbsent()` remains false for it, so
retention is tracked separately from `REMOVED_VERIFIED` and
`ALREADY_ABSENT_VERIFIED`.

## Quarantine

An `IDENTITY_UNVERIFIABLE` or repeated `REMOVAL_UNCERTAIN` resource is
quarantined: it stays `cleanup_pending`, it is reported by residue
escalation, and no automatic path retries a bare-name remove. The
backend's fail-safe is *not* to try harder deletion — it is to stop
and leave the resource named for a human.

## The MSB identity contract (RC7.6)

- Dispatch labels every sandbox `crabedence.dispatch=<nonce>`,
  `crabedence.job=<id>` at create, **and** the handle itself is
  nonce-bound: `sx-<job>-<dispatchNonce>`. The nonce tail is never
  truncated, so the name is the unforgeable deletion key — no other
  dispatch or tenant can mint it.
- Before removal, `inspect` confirms the occupant's labels match the
  persisted dispatch identity *and* the request's handle ends with
  the claimed nonce. A mismatch → `IDENTITY_MISMATCH` or
  `IDENTITY_UNVERIFIABLE`, no destructive call.
- Removal is `msb rm -f <handle>` — deletion by the nonce-bound name.
  The name the runtime resolves can only ever have been minted by
  this dispatch: the resolve→delete window cannot reach a substitute,
  because a substitute cannot occupy a name it cannot mint.
- Post-removal `inspect` independently confirms the outcome under a
  fresh bounded context — verify-then-report, not delete-then-assume;
  a hung verify reports `REMOVAL_UNCERTAIN`, never blocks forever.

## Honest limits (do not overclaim)

- The nonce-bound name makes the *name* the identity, but `msb rm`
  still resolves name→record internally before deleting: the residual
  is a runtime-internal catalog swap under an occupied name, which
  requires the dispatch nonce (never leaves dispatch identity) — i.e.
  a compromised runtime, which no CLI contract can defend. A native
  catalog-locked conditional delete (Rust SDK adapter) remains the
  tracked upgrade path.
- `IDENTITY_MISMATCH` deliberately leaves the foreign instance alone —
  destroying it is never our call, even when it "looks like" ours.
