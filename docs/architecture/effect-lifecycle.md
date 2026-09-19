# Effect Lifecycle

The durable effect lifecycle is the state machine implemented by
`internal/idempotency` (PostgreSQL `Store` and embedded `SQLiteStore`)
and driven by `internal/execution`, `internal/reconcile`, and the
authority stores. The normative invariants live in
[the durable execution contract](../spec/durable-execution-contract.md)
and [ADR-002](../adr/ADR-002-durable-effect-r13-contract-freeze.md);
this document is the architecture view: every transition, its actor,
its fencing requirements, and the exact `EffectStore` method that
performs it.

## State vocabulary

| State | Meaning | Caller-terminal | Durably final |
|---|---|---|---|
| `PREPARED` | No external dispatch has occurred. | no | no |
| `EXECUTING` | An executor owns a lease and is preparing dispatch; the dispatch boundary has **not** been crossed. | no | no |
| `IN_FLIGHT` | The dispatch boundary has been crossed; the external effect may have occurred. Persisted **before** the provider call. | no | no |
| `UNKNOWN` | The real-world result cannot currently be determined. | yes (do not retry) | no (reconciliation may resolve) |
| `COMMITTED` | Durably final — the operation succeeded. | yes | yes |
| `FAILED` | Durably final — the operation definitively failed. | yes | yes |

`DENIED` is a wire-level admission status, not a durable store state:
admission denial happens in the service layer before the idempotency
envelope, so no code path persists it. The constant remains in the
terminal predicates only for backward compatibility with legacy rows.

The only legal transitions are:

```
PREPARED  → EXECUTING → IN_FLIGHT → COMMITTED | FAILED
    ↑            │            └────→ UNKNOWN → COMMITTED | FAILED
    └────────────┘
  (abandon / expired-lease normalization)
```

`COMMITTED` and `FAILED` are immutable. `EnterRecovery` is legal only
from `IN_FLIGHT`.

## Transition table

Every state-changing `EffectStore` method maps to exactly one row.
"Transaction boundary" names the atomic unit; "fence" names the
predicates evaluated inside the mutation, on database-owned time.

| # | Transition | Source → destination | Actor | Transaction boundary | Fence | Evidence written | Retry semantics | Crash semantics |
|---|---|---|---|---|---|---|---|---|
| T1 | Acquire (insert) | ∅ → `PREPARED` + lease | Any caller (executor) | Single `INSERT … ON CONFLICT` | First writer wins; no lease predicate | Execution row; authority snapshot (with `AcquireWithAuthority`) | Safe — nothing was dispatched | Crash before dispatch: lease expires, T11 normalizes once |
| T2 | Acquire (reclaim) | `PREPARED`/`EXECUTING` with expired lease → same state, new lease, generation +1 | Any caller | Single CAS `UPDATE` | Lease expiry by DB clock; state ∈ {PREPARED, EXECUTING} | New lease token/generation | Safe — pre-dispatch | Same as T1 |
| T3 | Terminal replay | `COMMITTED`/`FAILED` → replay (no transition) | Any caller | Read | — | Stored terminal receipt returned verbatim | **Never redispatch** | Replay is a read; no crash window |
| T4 | BeginExecution | `PREPARED` → `EXECUTING` | Lease holder | Single CAS `UPDATE` | Token + generation + state + version | — | Safe — pre-dispatch | Crash → expired lease → T11 → reclaimable |
| T5 | AbandonPreDispatch | `PREPARED`/`EXECUTING` → lease-less `PREPARED` | Lease holder | Single CAS `UPDATE` | Token + generation; only touches pre-dispatch states | — | Safe — retry reclaims immediately | Crash after abandon → record is lease-less `PREPARED`; next acquire is T1/T2 |
| T6 | MarkInFlight | `EXECUTING` → `IN_FLIGHT` | Lease holder | Single CAS `UPDATE` + provider binding + recovery locator, atomically | Token + generation + state + version | Recovery locator (provider lookup material, bounded, secret-denylisted) | **Not retryable** — effect may occur | Crash → expired lease → claim → T8 → `UNKNOWN` |
| T7 | Finalize | `IN_FLIGHT` → `COMMITTED`/`FAILED` | Lease holder | Single CAS `UPDATE` + receipt digest | Token + generation + expected state `IN_FLIGHT`; terminal policy (`ValidateTerminalTransition`) | Terminal receipt; CRITICAL requires a verified signed ReceiptV3 (`COMPLETED` for COMMITTED, `NO_EFFECT` for FAILED) | Terminal immutable; identical replay idempotent (`ALREADY_FINALIZED`); different receipt = typed `FINALIZATION_CONFLICT` | Crash before commit → observation is durable → recovery path; crash after commit → replay |
| T8 | EnterRecovery | `IN_FLIGHT` → `UNKNOWN` | Lease holder, or reconciler holding a claim | Single CAS `UPDATE` | Token + generation (executor) or claim + version (reconciler); expected state `IN_FLIGHT` | — | Never auto-retry | Crash → expired lease → claim → T8 retried by reconciliation |
| T9 | EnterRecoveryWithObservation | `IN_FLIGHT` → `UNKNOWN` + provider observation, atomically | Lease holder, or reconciler | Single CAS `UPDATE` + observation insert | Same as T8 | Provider observation (status, result bytes, digests) | Never auto-retry | Observation is durable with the state; a later crash cannot lose it |
| T10 | ResolveRecovery | `UNKNOWN` → `COMMITTED`/`FAILED` (or `UNKNOWN` + backoff) | Reconciler holding the claim | Single CAS `UPDATE` | Claim ownership + expected version + expected state `UNKNOWN`; same terminal policy as T7 | Terminal receipt; CRITICAL requires a verified signed receipt, recomputed from resolver artifact bytes | Definitive outcomes are immutable; `UNKNOWN` decisions release with exponential backoff | Claim loss cancels the resolver; nothing is committed under a lost claim |
| T11 | RecoverExpiredPreDispatch | Expired `PREPARED`/`EXECUTING` → lease-less `PREPARED` | Reconciler holding a claim | Single CAS `UPDATE` | Claim + version; state ∈ {PREPARED, EXECUTING} | — | Normalize **once** — the record leaves the expired-lease claim set until a caller reacquires it (no per-cycle churn) | Idempotent under concurrent workers via the claim + version CAS |
| T12 | RecordProviderObservation | Append-only; no state change | Lease holder (`IN_FLIGHT`) or reconciler (already `UNKNOWN`) | Single monotonic insert/update | Token + generation while `IN_FLIGHT`; monotonicity enforced by store-computed digests | Provider observation row; store-computed SHA-256 of the asserted bytes | Identical re-observation idempotent; conflicting identity/result/evidence = typed `PROVIDER_OBSERVATION_CONFLICT`; does not bump `version` (cannot invalidate reconciliation CAS) | Durable before classification; a crash after the write loses nothing |
| T13 | RenewLease | No state change | Lease holder | Single CAS `UPDATE` | Token + generation; expiry by DB clock | — | Bounded per call by the executor's lease-operation budget; failure stops the heartbeat (finalize then fails closed) | — |
| T14 | ClaimUnknownBatch | Claim fields on `UNKNOWN` records; no state change | Reconciler | Atomic claim (`FOR UPDATE SKIP LOCKED`; single-statement `UPDATE … RETURNING` on SQLite) | `state = UNKNOWN`, no active claim, backoff due | Claim owner + claim expiry; increments `reconcile_attempt` | One worker per record per claim window | Expired claims are reclaimable by another worker |
| T15 | ClaimExpiredBatch | Claim on expired-lease records; no state change | Reconciler | Atomic claim (same mechanism as T14) | State ∈ {PREPARED, EXECUTING, IN_FLIGHT}, lease expired, no active claim | Claim fields | One worker per record per claim window | Drives T8 (IN_FLIGHT) or T11 (pre-dispatch) |
| T16 | ReleaseReconcileClaim | Clears claim + sets backoff; no state change | Reconciler | Single CAS `UPDATE` | Claim owner + version | `next_reconcile_at` (DB time + exponential backoff 30s…30m), `last_reconcile_error` | Exponential, saturating | Stale releases no-op via version CAS |
| T17 | RenewReconcileClaim | Extends claim; no state change | Reconciler | Single CAS `UPDATE` | Claim owner + version | `reconcile_lease_expires_at = MAX(current, now + duration)` | Cannot shorten an existing claim; loss cancels the resolver | — |
| T18 | SuspendReconciliation | Dead-letter; state stays `UNKNOWN` | Reconciler | Single CAS `UPDATE` | Claim owner + version; attempt ceiling (`SetMaxAttempts`, default 15) | Claim released; `next_reconcile_at` parked far in the future | Never re-claimed; operator inspection only; an unresolvable record is never forced terminal | — |
| T19 | ScrubStaleRecoveryLocators | Clears `recovery_locator`; no state change | Reconciler / maintenance | Bulk `UPDATE` | Retention age measured from `entered_unknown_at` | — | Idempotent | — |
| T20 | AdvanceClusterEpoch | `cluster_meta` CAS bump + declares recovery mode | Operator (restore/rebuild) | Single CAS `UPDATE` | Expected epoch | New epoch; recovery-required flag + reason | Stale-epoch stores are permanently fenced (`CLUSTER_EPOCH_MISMATCH`) | New-effect admission closes until T21 |
| T21 | CompleteClusterRecovery | Clears recovery mode | Operator | Single CAS `UPDATE` | Epoch-guarded (cannot clear a newer restore's mode) | Resolution audit text | Reads and reconciliation stay open throughout; only admission is closed | — |

## Method → transition mapping

This is the acceptance artifact for the lifecycle freeze: every
state-changing method on `EffectStore` maps to exactly one transition
row above. Read-only methods (`Lookup`, `LookupByKey`, `ListUnknown`,
`ListExpiredLeases`, `ListStuck`, `ReconciliationBacklog`,
`ListEffectEvents`, `ListProviderObservations`, `ClusterEpoch`,
`ClusterRecoveryRequired`, `SchemaVersion`, `LeaseConfig`) and the
configuration setters (`SetLocatorRedactor`, `SetEvidenceVerifier`,
`SetTrustedEvidenceSigners`) are not transitions.

| `EffectStore` method | Transition | Notes |
|---|---|---|
| `Acquire` | T1 / T2 | Or a typed no-transition outcome: `TERMINAL_REPLAY` (T3), `HELD_BY_OTHER`, `RECOVERY_REQUIRED`, `IDEMPOTENCY_CONFLICT` |
| `AcquireWithAuthority` | T1 / T2 | Same outcomes; persists the immutable authority snapshot |
| `BeginExecution` | T4 | |
| `MarkInFlight` | T6 | |
| `RenewLease` | T13 | |
| `AbandonPreDispatch` | T5 | |
| `Finalize` | T7 | |
| `RecordProviderObservation` | T12 | |
| `EnterRecovery` | T8 | |
| `EnterRecoveryWithObservation` | T9 | |
| `ResolveRecovery` | T10 | |
| `RecoverExpiredPreDispatch` | T11 | |
| `ClaimUnknownBatch` | T14 | |
| `ClaimExpiredBatch` | T15 | |
| `ReleaseReconcileClaim` | T16 | |
| `RenewReconcileClaim` | T17 | |
| `SuspendReconciliation` | T18 | |
| `ScrubStaleRecoveryLocators` | T19 | |
| `AdvanceClusterEpoch` | T20 | |
| `CompleteClusterRecovery` | T21 | |

Both engines are held to the same table by the shared conformance
suite (`store_conformance_test.go`), which runs the same invariant
checks against `Store` and `SQLiteStore`.

## Related documents

- [Durable execution contract](../spec/durable-execution-contract.md) — normative invariants.
- [Durable execution operations](../spec/durable-execution-operations.md) — backend selection, backup/restore, alerting.
- [Authority model](authority-model.md)
- [Reconciliation model](reconciliation-model.md)
- [Recovery model](recovery-model.md)
- [Capability trust model](capability-trust-model.md)
