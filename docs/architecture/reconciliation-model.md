# Reconciliation Model

Reconciliation is the subsystem that resolves `UNKNOWN` records and
recovers crashed executions with expired leases. It exists because
post-dispatch uncertainty must never silently become `FAILED` and must
never be automatically repeated: a record that may have produced an
external effect is resolved only by independent evidence.

Normative rules: invariants 5, 6, 9 and section 8 of
[the durable execution contract](../spec/durable-execution-contract.md).

## Work distribution

Multiple service replicas may run reconciliation workers concurrently.
Records are distributed by atomic claims, never by cooperation:

| Claim | Target | Mechanism |
|---|---|---|
| `ClaimUnknownBatch` (T14) | `UNKNOWN` records whose backoff is due | `FOR UPDATE SKIP LOCKED` (PostgreSQL) or a single `UPDATE … WHERE id IN (SELECT … LIMIT n) RETURNING` (SQLite single-writer) |
| `ClaimExpiredBatch` (T15) | `PREPARED`/`EXECUTING`/`IN_FLIGHT` with expired leases | Same atomic claim |

Claiming sets `reconcile_owner` and `reconcile_lease_expires_at` (both
on database time) and increments `reconcile_attempt`. A record is
processed by exactly one worker per claim window.

## Claim lifecycle

- **Revalidate before resolving.** The worker synchronously renews
  (CAS) its claim before invoking a resolver. Claiming bumps `version`,
  so a stale claim fails the CAS and the resolver is never invoked for
  a record the worker no longer owns — this is what makes the attempt
  ceiling a real bound on provider lookups.
- **Heartbeat while resolving.** A claim heartbeat renews the claim
  during resolver execution, across claim-TTL windows.
- **Bounded resolver deadline.** The resolver deadline is 4× the claim
  TTL — never below one TTL, because the heartbeat exists precisely so
  resolution longer than one claim window is safe. A wedged resolver
  cannot hold the record forever.
- **Claim loss cancels the resolver.** Nothing is ever committed under
  a lost claim.
- **Batch heartbeat.** All claims in a batch are renewed while the
  batch drains, so a slow head record cannot let later claims expire.

## Outcomes and backoff

| Resolver decision | Store action | Result |
|---|---|---|
| `COMMITTED` | `ResolveRecovery` (T10) | Terminal `COMMITTED`; claim fields cleared |
| `FAILED` | `ResolveRecovery` (T10) | Terminal `FAILED`; claim fields cleared |
| `UNKNOWN` | `ReleaseReconcileClaim` (T16) | Stays `UNKNOWN`; exponential backoff 30s → 1m → 2m → 4m → 8m → 16m → 30m (saturating) |
| `RETRYABLE` / transport failure | `ReleaseReconcileClaim` (T16) | Same as `UNKNOWN` |
| Attempt ceiling exceeded | `SuspendReconciliation` (T18) | Dead-lettered: stays `UNKNOWN`, claim released, `next_reconcile_at` parked far in the future; never re-claimed |

An unresolvable record is never forced to a terminal state, and it also
never churns through the reconcile loop forever. Dead-lettered records
remain visible for operator inspection (`ListUnknown`,
`ReconciliationBacklog`).

## Conservatism: negative reads are not proof

- Finding the external operation is positive evidence for `COMMITTED`.
- **Not** finding it is only absence of positive evidence → `UNKNOWN`,
  unless the provider offers a strongly consistent operation-lookup API
  that can genuinely prove non-execution. Provider listing and search
  APIs are typically eventually consistent.
- Provider transport errors are definitive only when the request
  provably never left (connection refused, DNS failure). Resets,
  timeouts, and mid-request drops after transmission are ambiguous →
  `UNKNOWN`.
- Resolvers are observational, side-effect-free, and idempotent; they
  are execution-specific (correlate by durable `execution_id` or the
  `(principal, capability, idempotency_key)` triple plus provider
  operation identity) and return the original provider run ID.

## Crash recovery (expired leases)

| Record state at claim | Action | Result |
|---|---|---|
| `PREPARED` / `EXECUTING` | `RecoverExpiredPreDispatch` (T11) | Normalized **once** to lease-less `PREPARED`; leaves the expired-lease claim set until a caller reacquires it |
| `IN_FLIGHT` | `EnterRecovery` (T8) | `UNKNOWN` — never blind-retry a post-dispatch crash |
| anything else | Logged, claim released | Unexpected; no mutation |

## Recovery locator retention

Recovery locators carry provider lookup material (operation token,
resource reference, request fingerprint) and are bounded, secret-
denylisted, and minimal. They are cleared on terminal transition and
scrubbed from `UNKNOWN` records whose recovery condition is older than
the retention window (default 7 days), measured from
`entered_unknown_at` — never `created_at`.

## Observability

- `ReconciliationBacklog` — pending `UNKNOWN` count plus the oldest
  `entered_unknown_at`, in one query, on both engines; the two operands
  of the "UNKNOWN accumulation or age" alert. Readable under a fenced
  epoch and during recovery mode.
- Store metrics: reconcile claims/resolutions, observation writes and
  conflicts, lease-fence rejections, `reconciliation_suspended_total`,
  `effect_lease_lost_total`, `cluster_epoch_rejections_total`.
- Worker counters: cycles started/completed/failed, resolver failures,
  dead letters (`Worker.Metrics`).
- **Supervisor.** The worker runs under a `Supervisor` with an explicit
  readiness policy (`SupervisorConfig`):

  | Verdict | Rule |
  |---|---|
  | `NOT_READY` | reconciler stopped or never started; no successful cycle within `NotReadyAfterCycleAge`; `MaxConsecutiveFailures` consecutive failed cycles |
  | `DEGRADED` | no successful cycle within `DegradedAfterCycleAge`; oldest pending UNKNOWN older than `MaxUnknownAge` |
  | `READY` | otherwise |

  `Supervisor.Health` reports the verdict, the violated rules, the
  UNKNOWN backlog (pending + oldest age), and the worker counters.
  Readiness transitions are logged, so the process knows its
  reconciliation subsystem is unhealthy without an operator polling it.
  The service runs reconciliation through the supervisor with
  production defaults (5 consecutive failures, 1-hour UNKNOWN age).

## Invariants and their tests

| Invariant | Tests |
|---|---|
| Exactly one worker processes a record per claim window | `internal/reconcile/worker_test.go`, `worker_sqlite_test.go`, multi-process torture in `internal/idempotency/multiproc_live_test.go` |
| Claim revalidation precedes every resolver invocation | `internal/reconcile/worker_test.go` |
| Backoff is DB-owned, exponential, saturating | store conformance suite |
| Attempt ceiling dead-letters instead of looping | `internal/reconcile/worker_test.go` |
| Negative reads stay `UNKNOWN`; CRITICAL definitive decisions require signed evidence recomputed from artifact bytes | `internal/execution/github_adversarial_test.go`, `external_provider_test.go`, `internal/reconcile` suites |
| Expired pre-dispatch records normalize once (no churn) | `store_conformance_test.go` |
