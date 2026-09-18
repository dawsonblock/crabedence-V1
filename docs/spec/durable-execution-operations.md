# Durable Execution — Operations, Boundaries, and Threat Model

Companion to `durable-execution-contract.md`. That document defines
the semantic contract; this one defines the operational boundaries,
deployment classifications, disaster-recovery rules, and the threat
model those semantics are qualified against.

## 1. Storage backend boundaries

### SQLite — single-node backend

The embedded SQLite store (`internal/idempotency/sqlite.go`) is the
single-node durable backend. It is supported for exactly this
deployment shape:

| Supported | Not supported |
|---|---|
| One Crabedence runtime on one host | Multiple machines writing one file |
| Multiple goroutines in that runtime | Shared NFS / network filesystem DBs |
| Normal process crash and restart | HA clusters, failover pairs |
| Durable local execution | Any topology where the file can be opened by two writers at once |

SQLite is configured `journal_mode=WAL`, `synchronous=FULL`,
`busy_timeout`, `foreign_keys=ON` — verified by
`TestSQLitePragmasApplied`, not just by intent. `OpenSQLiteDB`
enforces file-system hygiene: the database directory is created or
required at `0700`, the DB file at `0600`, symlinked paths are
rejected, and existing world-accessible files are refused rather than
silently used as a sensitive execution ledger.

For anything distributed — multiple runtimes, failover, network
storage — use PostgreSQL. Do not "make SQLite work" for those cases.

### PostgreSQL — distributed backend

The PostgreSQL store is the multi-runtime backend. Lease expiry,
authority expiry, reconcile claims, and backoff are all computed by
`clock_timestamp()` — the database clock is the single time authority
for every connected writer. Operational qualification must cover:
connection drops, database restart, primary failover, transactions
aborted after a provider result, and lease expiry during an outage.
Application logic must not assume a connection survives a
transaction boundary.

Payload columns (`result`, `provider_result`, `evidence_receipt`,
`recovery_locator`) are TEXT, not JSONB: jsonb rewrites whitespace
and key order on write, which would silently alter asserted provider
bytes and break signature verification over stored evidence receipts
(schema v10). TEXT preserves the caller's exact bytes, matching
SQLite fidelity; the monotonic write guards compare
`column::jsonb` to the canonical parameter so semantic equality is
unchanged.

## 2. Release classifications

Production readiness is not one boolean. The durable execution stack
classifies deployments as:

| Class | Meaning |
|---|---|
| `DEVELOPMENT` | Local iteration; no qualification evidence required |
| `QUALIFIED_LOCAL` | Contract + race + crash suites pass on SQLite, single host |
| `QUALIFIED_SINGLE_NODE` | `QUALIFIED_LOCAL` plus restart/integrity and WAL/synchronous verification |
| `QUALIFIED_POSTGRES` | Contract + race + crash suites pass on PostgreSQL |
| `QUALIFIED_DISTRIBUTED` | `QUALIFIED_POSTGRES` plus multi-process, failover, and connection-loss qualification |
| `PRODUCTION_APPROVED` | All above plus release evidence bundle, provenance, and real-provider gates for the adapters in use |

The current tree should be treated as a **qualification candidate**:
the contract, crash, cancellation, concurrency, and property suites
exist and pass on SQLite; the PostgreSQL live suite runs via
`scripts/test-live-postgres.sh`. Promotion to `PRODUCTION_APPROVED`
requires the artifact-bound evidence bundle — not documentation
claims.

## 3. UNKNOWN is not an error budget

`UNKNOWN` means the external world is in a state this system cannot
prove. It is a semantic state, not operational debt to burn down.

- An execution MUST NOT be converted to `FAILED` because N
  reconciliation attempts elapsed, because a deadline elapsed, or
  because an operator wants the queue empty.
- Long-unresolved records are suspended (`SuspendReconciliation`) —
  an operational annotation that stops retry churn while the durable
  semantic state remains `UNKNOWN`.
- Operator intervention is evidence-driven: an operator may attach
  externally obtained evidence and resume reconciliation, but a
  CRITICAL record still requires admissible `COMPLETED` or
  `NO_EFFECT` proof. There is no `--mark-not-executed`.

## 4. Backup, restore, and the cluster epoch

A durable execution ledger restored from a backup can resurrect
records for external effects that already happened. Restoring a stale
snapshot is therefore a recovery event, not a routine operation:

1. Restored `IN_FLIGHT` records describe operations that may have
   executed after the snapshot — they must flow through lease expiry
   into `UNKNOWN` and reconcile like any crash-orphaned record.
2. Restored `PREPARED`/`EXECUTING` records are safe to reclaim.
3. Normal dispatch MUST NOT resume blindly on a restored snapshot;
   reconciliation of inherited `IN_FLIGHT`/`UNKNOWN` records comes
   first.

**Cluster epoch (implemented, schema v9):** the ledger carries a
persisted environment/cluster epoch in the single-row `cluster_meta`
table. Every `EffectStore` reads the epoch once at construction (its
*admitted* epoch) and stamps it onto each new record's
`admitted_epoch` column for forensic provenance. Every mutation
carries the epoch as a WHERE fragment — after the epoch advances, a
stale store's writes match zero rows, and the CAS-failure classifiers
return the typed `CLUSTER_EPOCH_MISMATCH` error rather than a
lease-conflict misclassification. New-record admission is fenced by
an epoch-guarded INSERT: the row is admitted only while
`cluster_meta.epoch` still equals the store's admitted epoch, so a
stale store admits nothing. On SQLite the `BEGIN IMMEDIATE` write
lock additionally freezes the epoch for the admission's duration,
making the guard airtight; on PostgreSQL the guard is statement-
snapshot consistent, and a record that commits in the microseconds
around an advance is provenance-tagged `admitted_epoch=old` and can
only ever be mutated by stores admitted under the live epoch.

`AdvanceClusterEpoch(expected, reason)` CAS-bumps the epoch by exactly
one when the current value still equals `expected` — two operators
racing the bump cannot double-advance. Run it as part of any restore
or environment rebuild, before restarting executors; every store
admitted under the old epoch is permanently fenced afterward and must
restart (a restarted executor admits under the new epoch). Epoch
rejections are counted under `cluster_epoch_rejections_total`.

## 5. Threat model and controls

| Threat | Control | Qualification |
|---|---|---|
| Malicious provider adapter returns contradictory observations | Monotonic observation columns; `PROVIDER_OBSERVATION_CONFLICT` typed error; conflict never overwrites | Property + conflict tests |
| Compromised worker forges terminal state | CRITICAL requires Ed25519 receipt verified against trusted signer fingerprints; digest recomputed from evidence bytes | Evidence golden vectors, CRITICAL gate tests |
| Stale executor mutates a reclaimed record | Lease token + generation fencing on every transition; CAS on state+version | Property test stale-fence invariant |
| Executor from a pre-restore world mutates the restored ledger | Persisted cluster epoch; every mutation carries the epoch WHERE fragment; `CLUSTER_EPOCH_MISMATCH` typed error | Stale-writer fencing conformance test (both engines) |
| Caller disconnect erases post-dispatch work | Detached bounded durability context; heartbeat owned by durability lifetime | Adversarial cancellation suite |
| Authority mutated after admission | Append-only authority generations; generation+digest bound into request digest and persisted on the record | Authority binding tests |
| Tampered/forged evidence | Receipt binds execution, digest, provider identity, outcome; unsigned digests are not proof | Receipt golden vectors, untrusted-signer tests |
| Signing-key theft / rotation breaking receipts | Key ring: retired fingerprints stay trusted for historical receipts; revocation fails closed | Rotation test |
| Database credentials stolen | Attacker still cannot mint valid signed receipts without the signer; fencing prevents blind rewrites | — |
| Clock manipulation | All lease/expiry/authority decisions on database time | DB-time expiry tests |
| Process death mid-execution | Crash points at every durable boundary; post-dispatch death → `UNKNOWN` reconcilable | SIGKILL process matrix |
| Replay / double dispatch | Atomic `(principal, capability, key)` uniqueness; lease fencing; deterministic provider idempotency key | Concurrency torture (dispatch ≤ 1) |
| Recovery-locator leakage | Locator denylist scans persisted bytes; generic locators carry metadata only; optional redactor hook | Locator denylist tests |
| SQLite file theft | `0700` dir / `0600` file enforcement, symlink rejection | Path/permission tests |

## 6. Alertable invariants

`StoreMetrics` exposes semantic counters (`Snapshot()`):
acquire/execute/in-flight/committed/failed totals, UNKNOWN entries,
lease renewals, fence rejections, observation writes and conflicts,
reconcile claims and resolutions, CRITICAL evidence rejections, and
cluster-epoch write rejections (`cluster_epoch_rejections_total` —
any nonzero value means a stale-epoch executor is still running).
High-value alerts are on the semantic signals — UNKNOWN accumulation
or age, observation conflicts, fence rejections, CRITICAL evidence
rejections — not raw request error rates.
