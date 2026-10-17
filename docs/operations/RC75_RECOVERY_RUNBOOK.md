# RC7.5 Recovery Runbook

What the recovery machinery guarantees, and what an operator does —
and must not do — when it stops converging.

## Invariants the operator can rely on

- A recovery claimant holds a durable, leased, generation-bound claim.
  Ownership survives daemon restart; a claim's `claim_uid` is never
  reused, so a token cannot be mistaken for a later owner.
- Every protected transition (terminal state, cleanup clear, claim
  release) validates the claim in the same transaction as the write.
  A stale worker cannot commit — it gets `ErrClaimStale`.
- A VM is only destroyed bound to its dispatch nonce. Name reuse can
  never be the reason something is deleted.
- Every recovery event is hash-chained; tampering is detectable with
  `VerifyRecoveryEvents`, and signed checkpoints detect a rolled-back
  or rewritten history.

## Reading the residue

`escalateResidue` reports what did not converge. Durable answers live
in the ledger, not the log:

- `jobs.cleanup_pending = 1` with `cleanup_error` = last classified
  outcome — `IDENTITY_MISMATCH`, `IDENTITY_UNVERIFIABLE`,
  `REMOVAL_UNCERTAIN`. These are *explicit residue*: a resource the
  system refused to destroy on insufficient proof. They are for
  retry or operator action, never silent success.
- `recovery_attempts` — live claims and pacing (`next_due_ms`).
- `recovery_events` — the chained trail; `authenticated = 0` marks
  pre-v12 legacy rows honestly.

## Operator procedures

### A pending cleanup that will not clear

1. Read `cleanup_error` — it names the classification.
2. `IDENTITY_MISMATCH` → a *different* instance occupies the name. Do
   **not** force-remove by name: that is exactly the substituted-VM
   case. Confirm the occupant's labels; if foreign, escalate the
   foreign owner, leave ours pending.
3. `REMOVAL_UNCERTAIN` → the remove may have landed mid-timeout.
   Re-inspect the sandbox set before any manual `rm`: an already-absent
   authorized instance clears on the next pass.
4. `IDENTITY_UNVERIFIABLE` → identity could not be read. Quarantine,
   do not delete.

### A stalled recovery claim

Claims lease out on their own — a suspended worker loses ownership at
`claim_until_ms`; the next claimant wins cleanly. There is no manual
"steal" path by design: forcing ownership under a live worker would
violate INV-03.

### Verifying history

- Local: `VerifyRecoveryEvents` recomputes the chain and reports every
  break.
- Against custody: `CheckRecoveryCheckpoint` proves the retained
  checkpoint's committed tip is still the head of covered history.

## What an operator must never do

- Never `msb rm <name>` by bare name to "help" a pending cleanup — it
  bypasses identity binding and can destroy a substitute.
- Never delete a `recovery_attempts` row by hand to unlock a claim —
  release is claim-conditioned on purpose.
- Never treat `cleanup_pending` as cosmetic: it is a durable debt the
  system refuses to forget until absence is *proven*.
