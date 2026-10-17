# RC7.5 Quarantine and Cleanup

How resources that cannot be safely destroyed are held, and the exact
semantics of every cleanup outcome.

## Cleanup outcomes (INV-01)

| Outcome | Meaning | `cleanup_pending` cleared? |
|---|---|---|
| `REMOVED_VERIFIED` | Removed and independently confirmed absent | yes |
| `ALREADY_ABSENT_VERIFIED` | Authorized instance verifiably gone | yes |
| `IDENTITY_MISMATCH` | A *different* instance occupies the name — the substitute survives by design | **no** |
| `IDENTITY_UNVERIFIABLE` | Current identity could not be read | **no** |
| `REMOVAL_UNCERTAIN` | Remove may have landed; state unresolved | **no** |

Only `ProvesAbsent()` outcomes clear the flag. Everything else is
explicit residue — the resource stays named in the ledger until
absence is proven, not until it is assumed.

## Quarantine

An `IDENTITY_UNVERIFIABLE` or repeated `REMOVAL_UNCERTAIN` resource is
quarantined: it stays `cleanup_pending`, it is reported by residue
escalation, and no automatic path retries a bare-name remove. The
backend's fail-safe is *not* to try harder deletion — it is to stop
and leave the resource named for a human.

## The MSB identity contract

- Dispatch labels every sandbox `crabedence.dispatch=<nonce>`,
  `crabedence.job=<id>` at create.
- Before removal, `inspect` confirms the occupant's labels match the
  persisted dispatch identity. A mismatch → `IDENTITY_MISMATCH`, no
  destructive call.
- Removal is `msb rm -f --label crabedence.dispatch=<nonce> --label
  crabedence.job=<id>` — the AND-matched label selector means the
  delete itself only reaches instances carrying our nonce, not
  whatever happens to hold the name.
- Post-removal `inspect`/`list` independently confirms the outcome —
  verify-then-report, not delete-then-assume.

## Honest limits (do not overclaim)

- The label-conditioned remove is *conditional*, not a documented
  atomic primitive: an identity swap inside msb's own
  resolve→delete window is bounded by msb's transition guard but is
  not a contractual conditional-delete. Pre/post verification plus
  `REMOVAL_UNCERTAIN` is the compensating control; the Linux/KVM lane
  must exercise the real race.
- `IDENTITY_MISMATCH` deliberately leaves the foreign instance alone —
  destroying it is never our call, even when it "looks like" ours.
