# Durable Execution Contract

This document freezes the invariants of the Effect Fabric durable
execution store. All code in `internal/idempotency` and
`internal/reconcile` must satisfy these rules. Changes to this
document require the same review as changes to the store itself.

## 1. State vocabulary

```
PREPARED    No external dispatch has occurred.
EXECUTING   An executor owns a lease and is preparing dispatch.
IN_FLIGHT   The dispatch boundary has been crossed; external
            effects may have occurred.
UNKNOWN     The durable store cannot currently determine the
            real-world result.
COMMITTED   Durably final — the operation succeeded.
FAILED      Durably final — the operation definitively failed.
```

DENIED is a wire-level admission status, not a durable store state.
Admission denial happens in the service layer before the idempotency
envelope, so no code path persists StateDenied. The constant is
retained in `IsDurablyFinal`/`IsCallerTerminal` for backward
compatibility with any pre-existing DENIED records, but
`legalTransitions` does not include it as a reachable target.

Lifecycle:

```
Acquire (insert or reclaim)
   │
   ▼
PREPARED
   │
BeginExecution (lease holder only)
   │
   ▼
EXECUTING
   │
MarkInFlight (dispatch boundary crossed)
   │  — persists provider_id + recovery_locator atomically
   │    so a crashed execution carries the information needed
   │    for provider-specific reconciliation
   ▼
IN_FLIGHT
   │
   ├── Finalize(COMMITTED)
   ├── Finalize(FAILED)
   └── EnterRecovery
          │
          ▼
      UNKNOWN
          │
      ClaimUnknownBatch (FOR UPDATE SKIP LOCKED)
          │
          ▼
      ResolveRecovery
          ├── COMMITTED (claim fields cleared)
          ├── FAILED (claim fields cleared)
          └── UNKNOWN → ReleaseReconcileClaim (backoff)
```

## 2. Terminal predicates

```go
func IsCallerTerminal(state State) bool {
    switch state {
    case COMMITTED, FAILED, DENIED, UNKNOWN:
        return true
    }
    return false
}

func IsDurablyFinal(state State) bool {
    switch state {
    case COMMITTED, FAILED, DENIED:  // DENIED kept for backward compat
        return true
    }
    return false
}
```

`UNKNOWN` is caller-terminal (callers must not retry) but not
durably-final (reconciliation may still resolve it).

## 3. Lease ownership invariants

1.  **Lease time belongs to the store.** PostgreSQL computes
    `lease_started_at` and `lease_expires_at` using `clock_timestamp()`.
    Callers may request a duration but never set timestamps directly.

2.  **Expired leases cannot renew, transition, or finalize.** Every
    authority-bearing mutation checks `lease_expires_at > clock_timestamp()`
    inside the SQL statement. Expiry is not checked in Go alone.

3.  **Only the active lease token can mutate execution state.** Every
    transition, finalization, and renewal requires the current
    `lease_token` and `lease_generation`.

4.  **Lease tokens are unguessable.** Generated using
    `crypto/rand`, encoded as base64url.

5.  **Lease generation monotonically increases on takeover.** Each
    successful reclaim increments `lease_generation`. This functions
    as a fencing epoch: an old holder with a stale token and stale
    generation cannot mutate state even if the token were somehow
    reused.

## 4. Reclaim matrix

| State | Expired lease | Action |
|---|---|---|
| PREPARED | reclaim allowed | New caller acquires lease, generation increments |
| EXECUTING | reclaim only if dispatch boundary provably not crossed | New caller acquires lease, generation increments |
| IN_FLIGHT | reclaim forbidden | Transition to UNKNOWN / RECOVERY_REQUIRED |
| UNKNOWN | no normal dispatch | Reconciliation only |
| COMMITTED | immutable replay | Return existing terminal receipt |
| FAILED | immutable replay | Return existing terminal receipt |

**IN_FLIGHT expired → reclaim is forbidden.** The side effect may
have occurred. The record transitions to UNKNOWN for reconciliation.
This directly fixes the blind-retry defect.

## 5. Dispatch boundary

The dispatch boundary is the transition from EXECUTING to IN_FLIGHT.

- **PREPARED → EXECUTING**: lease acquired, preparing dispatch.
  No external effect has occurred. Safe to reclaim on expiry.
- **EXECUTING → IN_FLIGHT**: the provider invocation boundary has
  been crossed. `IN_FLIGHT` is persisted before the provider call.
  External effects may have occurred. Not safe to blindly retry.

## 6. Post-dispatch uncertainty

A provider error after IN_FLIGHT must not automatically become FAILED
unless the provider can prove no side effect occurred.

Handler outcomes:

```
DEFINITIVE_SUCCESS → validate evidence → COMMITTED
DEFINITIVE_FAILURE  → FAILED
AMBIGUOUS           → UNKNOWN
```

Evidence validation failure after provider success is uncertainty,
not failure:

```
provider says success
required evidence invalid/missing
→ UNKNOWN / EVIDENCE_INVALID
→ reconciliation required
```

This applies to ALL evidence validation failures after the dispatch
boundary has been crossed (IN_FLIGHT persisted), including:
- Missing evidence digest
- Invalid evidence digest format
- Wrong receipt version
- Missing provider run ID

Returning FAILED in any of these cases would allow a blind retry of
an operation that may have already executed.

## 7. Terminal finalization

### Immutability

Terminal receipts are immutable. Once a record is durably final
(COMMITTED, FAILED, DENIED), no further mutations are permitted.

### Idempotent replay

The same canonical terminal receipt may be finalized again. The
result is `ALREADY_FINALIZED` — not an error.

### Conflict detection

A different canonical terminal receipt for the same execution is a
`FINALIZATION_CONFLICT`. The original receipt is preserved.

The entire terminal receipt is compared, including:
- terminal_status
- canonical_result
- provider_id
- provider_run_id
- evidence_digest
- receipt_version

Two COMMITTED receipts with the same evidence digest but different
results or provider IDs must conflict.

### Terminal receipt digest

`terminal_receipt_sha256` is computed over the canonical terminal
receipt. This provides a simple equality test for duplicate
finalization and makes conflict detection precise.

## 8. Recovery semantics

### Recovery decisions

```go
type RecoveryDecision string

const (
    RecoveryCommitted RecoveryDecision = "COMMITTED"
    RecoveryFailed    RecoveryDecision = "FAILED"
    RecoveryUnknown   RecoveryDecision = "UNKNOWN"
    RecoveryRetryable RecoveryDecision = "RETRYABLE"
    RecoveryConflict  RecoveryDecision = "CONFLICT"
)
```

### State-specific recovery

For expired IN_FLIGHT:

```
query provider/evidence
     ↓
proven completed        → COMMITTED
proven failed (no side effect) → FAILED
cannot determine        → UNKNOWN
```

Never: cannot determine → PREPARED → retry.

### CAS for reconciliation

Reconciliation must use CAS transitions with expected state/version.
It must never overwrite a state that changed after it was read.

### Work distribution

Multiple service replicas may run reconciliation workers concurrently.
`ClaimUnknownBatch` claims a batch of UNKNOWN records using
`FOR UPDATE SKIP LOCKED`, setting `reconcile_owner` and
`reconcile_lease_expires_at`. Each record is processed by exactly one
worker per claim window.

Claimable records must satisfy:

- `state = 'UNKNOWN'`
- No active reconcile claim (`reconcile_owner IS NULL` or
  `reconcile_lease_expires_at < clock_timestamp()`)
- Not waiting for backoff (`next_reconcile_at IS NULL` or
  `next_reconcile_at <= clock_timestamp()`)

On successful resolution, `ResolveRecovery` clears all reconcile claim
fields. On failure or continued UNKNOWN, `ReleaseReconcileClaim` sets
`next_reconcile_at` with exponential backoff (30s, 1m, 2m, ..., 30m cap)
and records `last_reconcile_error`.

### NoopResolver

`NoopResolver` returns `UNKNOWN`. It must not cause retries or
terminal rewrites.

## 9. Retry policy

Retries require proof that the provider invocation boundary was never
crossed, or provider-specific idempotency semantics strong enough to
make retry safe.

Default policy:

| State | Retryable |
|---|---|
| PREPARED expired | yes |
| EXECUTING expired (before dispatch marker) | yes |
| IN_FLIGHT expired | no (without reconciliation) |
| UNKNOWN | no (by default) |

## 10. Lease configuration

```go
type LeaseConfig struct {
    DefaultDuration time.Duration
    MaxDuration     time.Duration
    RenewalWindow   time.Duration
}
```

Zero, negative, or excessive requested lease durations are rejected.
Callers may not silently accept arbitrary lease values.

## 11. Typed lease failures

```go
type LeaseError string

const (
    LeaseLost            LeaseError = "LEASE_LOST"
    LeaseExpired         LeaseError = "LEASE_EXPIRED"
    LeaseTokenMismatch   LeaseError = "LEASE_TOKEN_MISMATCH"
    LeaseGenerationMismatch LeaseError = "LEASE_GENERATION_MISMATCH"
    StateConflict        LeaseError = "STATE_CONFLICT"
    RecoveryRequired     LeaseError = "RECOVERY_REQUIRED"
)
```

These are distinguishable by callers and tests. Generic
`sql.ErrNoRows` or boolean returns are not used for lease failures.

## 12. Acquire result

```go
type AcquireResultKind string

const (
    LeaseAcquired       AcquireResultKind = "ACQUIRED"
    LeaseHeldByOther    AcquireResultKind = "HELD_BY_OTHER"
    LeaseReclaimed      AcquireResultKind = "RECLAIMED"
    TerminalReplay      AcquireResultKind = "TERMINAL_REPLAY"
    RecoveryRequired    AcquireResultKind = "RECOVERY_REQUIRED"
    IdempotencyConflict AcquireResultKind = "IDEMPOTENCY_CONFLICT"
)
```

Code must not infer semantics from state names.

## 13. Release invariants

```
CRAB-V1-017: Expired IN_FLIGHT work is never blindly redispatched.
CRAB-V1-018: Only an unexpired active lease generation may mutate
             execution state.
CRAB-V1-019: Terminal finalization is immutable and conflict-aware.
CRAB-V1-020: Post-dispatch uncertainty cannot become retryable
             without evidence.
CRAB-V1-021: Concurrent identical mutations cause at most one
             provider dispatch.
```

## 14. Acceptance conditions

The artifact is not qualified until all of the following hold:

```
expired IN_FLIGHT redispatch count = 0
100 concurrent identical MUTATION requests
    → provider executions = 1
expired token renewals = 0 successful
stale generation transitions = 0 successful
terminal conflicting overwrites = 0 successful
recovery without proof → UNKNOWN, not retry
source manifest mismatches = 0
source manifest unexpected = 0
mandatory live tests executed > 0
release admission = PASS
clean-room verifier = PASS
```
