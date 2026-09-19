# Recovery Model

Recovery covers everything that happens after the dispatch boundary is
crossed but before (or instead of) a terminal state: post-dispatch
uncertainty, crash recovery, provider lookup, and post-restore
recovery mode. The governing rule is invariant 20 of the contract:
*post-dispatch uncertainty cannot become retryable without evidence.*

## The dispatch boundary

`EXECUTING → IN_FLIGHT` (`MarkInFlight`, T6) is the boundary. It is
persisted **before** the provider call, together with the provider
binding and a recovery locator, so a crashed execution carries what a
resolver needs to find the external operation. Before it: failures are
provably effect-free and safe to abandon or retry. After it: any
failure is `UNKNOWN` unless the provider proves otherwise.

## The mandatory post-dispatch path

When the provider returns, the executor runs a fixed persistence
sequence. Each stage derives its own bounded, caller-detached context
(`ExecutorTimeouts`), and **each budget starts when the stage starts** —
a stage that exhausts its budget can never consume the budget of the
stage that follows:

| Stage | Default budget | What it bounds | On exhaustion |
|---|---|---|---|
| Provider call | capability/deadline-specific | the external invocation | post-dispatch ambiguity → recovery |
| `ObservationPersistence` | 5s | `RecordProviderObservation` (T12) | observation error → recovery (fresh budget) |
| `Terminalization` | 5s | CRITICAL signing, lease-generation lookup, fenced `Finalize` (T7) | finalize failure → recovery (fresh budget) |
| `EmergencyRecovery` | 5s | entering `UNKNOWN` with the observation (T9) | the record is left for lease-expiry reconciliation |
| `LeaseOperation` | 3s | a single lease renewal (heartbeat) or pre-dispatch abandon | heartbeat stops; finalize fails closed on the stale lease |

Emergency recovery is deliberately **not** run on the observation or
terminalization context: those may already be exhausted by the database
operation that just failed, and recovery must still be able to persist
the provider observation. That distinction is the difference between a
record reaching `UNKNOWN` with its observation durable and one stranded
`IN_FLIGHT` with provider metadata lost.

The heartbeat is owned by the durability lifetime, not the caller: it
ends only after a durable terminal or recovery state is persisted.
Caller cancellation can never cancel mandatory post-dispatch
persistence.

## Entry paths into recovery

| Trigger | Path |
|---|---|
| Handler returned an ambiguous result after `IN_FLIGHT` | `EnterRecoveryWithObservation` (T9) |
| Provider observation write failed | `EnterRecoveryWithObservation` (T9) — the receipt must never contradict a durable observation |
| CRITICAL signing failed | `EnterRecoveryWithObservation` (T9) — no proof, no terminal state |
| `Finalize` failed (lease lost, CAS miss, store error) | `EnterRecoveryWithObservation` (T9) |
| Process crash after `IN_FLIGHT` | Expired lease → `ClaimExpiredBatch` (T15) → `EnterRecovery` (T8) |
| Restore / environment rebuild | Cluster epoch advance declares `RECOVERY_REQUIRED` (T20) |

`EnterRecovery` is legal only from `IN_FLIGHT`. Pre-dispatch states are
normalized to lease-less `PREPARED` instead (T11) — a record that
provably never dispatched must not occupy the recovery backlog.

## Recovery locators

A locator is the durable pointer to the external operation, persisted
before `IN_FLIGHT`:

- Provider-specific when the adapter implements
  `RecoveryLocatorProvider`; a metadata-only generic locator otherwise.
- Contains lookup material only: provider identity, correlation
  strategy, external operation token, resource reference, request
  digest, execution identity. Never raw request arguments.
- Bounded (`MaxRecoveryLocatorBytes`) and secret-denylisted.
- The external token persisted here **must** be the same token sent in
  the external request (`ExternalTokenFromContext` injects it into the
  dispatch context).
- Cleared on terminal transition; scrubbed after the retention window
  on unresolved `UNKNOWN` records.

## Resolution

`ResolveRecovery` (T10) shares the exact terminal policy with
`Finalize` (`ValidateTerminalTransition`) — there is no weaker recovery
path:

- `COMMITTED` requires provider-authenticated material; CRITICAL
  requires a signed `COMPLETED` receipt binding the provider run ID.
- `FAILED` requires a signed `NO_EFFECT` receipt; the evidence artifact
  must be provider bytes (or the executor's own pre-transmission proof),
  never the resolver's own assertion. A CRITICAL `FAILED` without
  artifact bytes stays `UNKNOWN`.
- The attested evidence digest is always recomputed by the attestor
  from artifact bytes — a resolver-supplied digest string is never
  signed.
- Concurrent resolvers are harmless: resolvers are observational and
  idempotent, and commits are claim-fenced CAS.

## Post-restore recovery mode

`AdvanceClusterEpoch` (T20) fences every store admitted under the old
epoch (`CLUSTER_EPOCH_MISMATCH`) and declares recovery mode: new-effect
admission closes (`CLUSTER_RECOVERY_REQUIRED`) until
`CompleteClusterRecovery` (T21) clears it. Reads, diagnostics, and
reconciliation of inherited records stay open throughout. This is what
prevents a restored database from accepting stale-world mutations.

## Crash matrix

The crash/fault matrix asserts the recovery contract at every durable
boundary (see `internal/execution/dispatch_crash_test.go`,
`dispatch_crashproc_test.go`, `external_provider_test.go`):

| Crash point | Permitted result |
|---|---|
| Before dispatch (`after_acquire`, `after_begin_execution`, `after_mark_in_flight`) | Retry safely — the provider was never invoked |
| After `IN_FLIGHT`, before a known provider result (`before_provider`, `after_provider`) | `UNKNOWN` / reconcile — never a blind retry |
| Provider committed, response lost | Discovered through reconciliation (external operation lookup by token) |
| Observation persisted, terminal commit lost (`before_observation`, `after_observation`, `before_finalize`) | Recover using the durable observation |
| Terminal commit complete (`after_finalize`) | Return / retrieve the same immutable terminal receipt |

The governing invariant: **no crash point may cause an external effect
to be automatically repeated unless the system can prove the earlier
dispatch did not occur.** The external-provider crash qualification
runs the provider as a separate process with its own durable log and
asserts provider effect count ≤ 1 across every post-dispatch kill
point.

## Invariants and their tests

| Invariant | Tests |
|---|---|
| Caller cancellation cannot cancel mandatory post-dispatch persistence | `dispatch_cancellation_test.go` |
| Each stage's exhausted budget never starves the next stage | `dispatch_budget_test.go` |
| Heartbeat renewals and abandons are bounded | `dispatch_budget_test.go` |
| Crash after dispatch never redispatches | `dispatch_crash_test.go`, `dispatch_crashproc_test.go`, `external_provider_test.go` |
| A stale lease owner can never finalize | store conformance suite |
| A stale cluster epoch can never mutate restored state | `internal/idempotency/epoch_test.go`, conformance suite |
| Terminal receipts are immutable | store conformance suite, golden vector |
