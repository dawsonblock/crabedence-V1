# Durable Execution Contract

This document freezes the invariants of the Effect Fabric durable
execution store. All code in `internal/idempotency` and
`internal/reconcile` must satisfy these rules. Changes to this
document require the same review as changes to the store itself.

## 0. Revision-8 normative invariants

The following are requirements, not commentary. Any implementation
that violates one is defective, regardless of test results.

1.  **Frozen state graph.** The only legal transitions are:
    `PREPARED → EXECUTING`, `EXECUTING → IN_FLIGHT`,
    `IN_FLIGHT → COMMITTED | FAILED | UNKNOWN`, and
    `UNKNOWN → COMMITTED | FAILED`. `COMMITTED` and `FAILED` are
    immutable. `EnterRecovery` is legal only from `IN_FLIGHT`.

2.  **Provider observations are durable before classification.** The
    dispatcher MUST call `RecordProviderObservation` immediately after
    the provider returns, before evidence validation and before any
    terminal decision. Observation writes MUST NOT require a state
    change, MUST be accepted while `IN_FLIGHT` (lease-fenced) or
    already `UNKNOWN` (the CAS-loss race), and MUST be monotonic:
    re-recording the identical observation is idempotent, and a
    conflicting observation on the same record is rejected with a
    typed `PROVIDER_OBSERVATION_CONFLICT`. Observation persistence
    errors MUST NOT be swallowed or reported as success.

3.  **CRITICAL terminal states require authenticated evidence.**
    `COMMITTED` requires an Ed25519-signed effect receipt attesting
    outcome `COMPLETED`; `FAILED` requires a signed receipt attesting
    `NO_EFFECT`. The receipt MUST be verified against trusted signer
    fingerprints and MUST bind execution ID, capability, principal,
    request digest, provider ID, provider run ID, outcome, and
    evidence SHA-256. A syntactically valid digest alone is not proof.
    `DefinitiveFailure` is a routing hint for MUTATION; it is never
    sufficient proof for CRITICAL `FAILED`.

4.  **One terminal policy.** `Finalize` and `ResolveRecovery` MUST
    enforce identical proof requirements through a single shared
    terminal-transition policy. There is no weaker recovery path and
    no weaker normal path.

5.  **Recovery decisions are execution-specific.** A resolver MUST
    correlate the record under recovery to the specific external
    operation it caused — by durable `execution_id`, or by the
    `(principal_id, capability_id, idempotency_key)` uniqueness
    triple plus the provider operation identity. The resolver MUST
    return the original provider run ID, never a fabricated
    replacement.

6.  **Resolvers are observational.** `RecoveryResolver.Resolve` MUST
    be side-effect-free and idempotent. It may be invoked multiple
    times and concurrently; it must never cause an external effect.

7.  **Database time is authoritative.** Lease timestamps, lease
    expiry, reconcile claim expiry, and reconcile backoff are computed
    by PostgreSQL (`clock_timestamp()`), never by application clocks.

8.  **Recovery locators are provider-specific and minimal.** When a
    provider implements `RecoveryLocatorProvider`, the persisted
    locator contains only provider lookup material: provider
    idempotency token, provider operation token, resource identifier,
    request fingerprint, execution ID — never the raw request body.
    Whatever token is persisted before `IN_FLIGHT` MUST be the same
    token used in the external request. Raw arguments are a
    compatibility fallback only, subject to bounded size, redaction,
    and a retention window; `recovery_locator` is cleared on terminal
    transition and scrubbed from stale `UNKNOWN` records.

9.  **Lease and claim ownership are held until durable ownership is
    no longer required.** The execution heartbeat ends only after a
    durable terminal or recovery state is persisted, or another worker
    has definitively taken ownership. Provider return alone is not a
    stopping condition. Reconcile claims are renewed while a resolver
    runs, and resolver deadlines are enforced below the claim TTL.

10. **Expired pre-dispatch work is normalized once.** Expired
    `PREPARED`/`EXECUTING` records are reset to lease-less `PREPARED`
    in a single CAS write. They leave the expired-lease claim set
    until a caller reacquires them — reconciliation must not
    claim/release dormant work every cycle.

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
   │      — CRITICAL requires proof at store boundary
   ├── Finalize(FAILED)
   │      — CRITICAL requires proof at store boundary
   └── EnterRecovery (only from IN_FLIGHT)
          │  or EnterRecoveryWithObservation
          │  (persists provider_id/provider_run_id/evidence)
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

      Expired leases → ClaimExpiredBatch (FOR UPDATE SKIP LOCKED)
          │
          ├── PREPARED/EXECUTING → RecoverExpiredPreDispatch
          │    (normalize once to lease-less PREPARED)
          └── IN_FLIGHT → EnterRecovery → UNKNOWN
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

Concurrent identical finalization is also idempotent: if two workers
race to finalize the same execution with the same receipt, the CAS
loser re-reads the terminal state and sees the matching digest —
it returns success, not a conflict.

### CRITICAL proof enforcement

The store enforces CRITICAL proof requirements inside `Finalize()`:
both COMMITTED and FAILED require a valid SHA-256 evidence digest,
receipt_version 3, provider_id, and provider_run_id — **plus** a
signed `evidence_receipt` (ReceiptV3) verified against trusted signer
fingerprints and bound to the execution, request, provider identity,
outcome, and evidence digest. COMMITTED requires outcome `COMPLETED`;
FAILED requires outcome `NO_EFFECT`. A digest without a verified
signed receipt is rejected. This prevents a caller that bypasses
DispatchExecutor from finalizing CRITICAL with weaker evidence than
the recovery path requires — and both paths share the same policy
function (`ValidateTerminalTransition`).

### Recovery locator cleanup

`recovery_locator` is cleared to NULL on terminal finalization
(both `Finalize` and `ResolveRecovery`) and scrubbed from UNKNOWN
records older than the configured retention window. Provider-owned
locators contain only provider lookup material; raw request
arguments are a compatibility fallback subject to bounded size and
redaction, and must not persist beyond the terminal transition.

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

`EnterRecovery` enforces the legal transition matrix — only
IN_FLIGHT → UNKNOWN is permitted. Terminal states (COMMITTED,
FAILED, DENIED) and pre-dispatch states (PREPARED, EXECUTING)
cannot enter recovery.

`EnterRecoveryWithObservation` persists provider metadata
(provider_id, provider_run_id, evidence_digest, result) atomically
with the UNKNOWN transition. This is used when the provider returned
a result but finalization could not commit — the observation is
the best available evidence for the recovery resolver.

`RecordProviderObservation` persists provider response metadata
(provider_status, result, result_digest, evidence digest, receipt
version, observed-at) independently of state transitions — while
`IN_FLIGHT` under lease fencing, or on a record that already raced
to `UNKNOWN`. The write is monotonic: identical re-observation is
idempotent; conflicting provider identity, status, result, or
evidence is a typed `PROVIDER_OBSERVATION_CONFLICT`. It does not
increment `version`, so it cannot invalidate reconciliation CAS.

### CAS for reconciliation

Reconciliation must use CAS transitions with expected state/version.
It must never overwrite a state that changed after it was read.

### Work distribution

Multiple service replicas may run reconciliation workers concurrently.

**UNKNOWN resolution**: `ClaimUnknownBatch` claims a batch of UNKNOWN
records using `FOR UPDATE SKIP LOCKED`, setting `reconcile_owner` and
`reconcile_lease_expires_at`. Each record is processed by exactly one
worker per claim window.

**Expired-lease crash recovery**: `ClaimExpiredBatch` claims a batch
of PREPARED/EXECUTING/IN_FLIGHT records with expired leases using
`FOR UPDATE SKIP LOCKED`. The caller inspects each record's state:
IN_FLIGHT records enter recovery (`UNKNOWN`); expired
PREPARED/EXECUTING records are normalized once to lease-less
`PREPARED` via `RecoverExpiredPreDispatch` — the claim, lease, and
lease expiry are cleared in one CAS write so the record leaves the
expired-lease claim set until a caller reacquires it.

Claimable records must satisfy:

- `state = 'UNKNOWN'` (for ClaimUnknownBatch) or
  `state IN ('PREPARED','EXECUTING','IN_FLIGHT')` with expired lease
  (for ClaimExpiredBatch)
- No active reconcile claim (`reconcile_owner IS NULL` or
  `reconcile_lease_expires_at < clock_timestamp()`)
- Not waiting for backoff (`next_reconcile_at IS NULL` or
  `next_reconcile_at <= clock_timestamp()`)

On successful resolution, `ResolveRecovery` clears all reconcile claim
fields. On failure or continued UNKNOWN, `ReleaseReconcileClaim` sets
`next_reconcile_at` using `clock_timestamp() + backoff` (DB-owned time)
and records `last_reconcile_error`. Backoff is exponential: 30s, 1m,
2m, 4m, 8m, 16m, 30m cap — saturating, never overflowing.

`RenewReconcileClaim` extends an active claim using
`GREATEST(current, clock_timestamp() + duration)` — renewal cannot
shorten an existing claim. The reconciliation worker runs a claim
heartbeat while the resolver executes and enforces a resolver
deadline below the claim TTL; losing the claim cancels the resolver
context rather than committing under a lost claim.

`RecoveryResolver.Resolve` MUST be observational, side-effect-free,
and idempotent. Claim renewal minimizes duplicate provider queries;
the side-effect-free contract makes any residual overlap harmless.

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
CRAB-V1-022: Provider observations are durable before terminal
             classification and monotonic thereafter.
CRAB-V1-023: CRITICAL terminal transitions require authenticated
             (signed, trust- and binding-verified) evidence receipts.
CRAB-V1-024: Recovery resolvers are observational, side-effect-free,
             and execution-specific; they return the original provider
             operation identity.
CRAB-V1-025: Reconciliation claims are renewed while resolvers run;
             resolver deadlines stay below claim TTL.
CRAB-V1-026: Expired pre-dispatch records normalize once; dormant
             work does not churn.
CRAB-V1-027: Recovery locators are provider-specific, minimal,
             bounded, and cleared at terminal completion or retention.
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
provider observation conflicts accepted = 0
CRITICAL finalize/recover without verified signed receipt = 0
cross-principal/cross-capability recovery false positives = 0
expired PREPARED/EXECUTING churn cycles = 0 (normalize once)
recovery locators surviving terminal transition = 0
source manifest mismatches = 0
source manifest unexpected = 0
mandatory live tests executed > 0
mandatory live tests skipped = 0 (unless allowlisted)
release admission = PASS
clean-room verifier = PASS
```
