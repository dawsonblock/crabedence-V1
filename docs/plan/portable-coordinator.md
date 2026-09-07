# Portable Coordinator Runtime

Status: Node/PostgreSQL and Cloudflare adapters implemented. This file is the
design history and remaining scale/migration plan. For the shipped operator
guide, read [Portable Coordinator](../features/portable-coordinator.md).

Read when:

- evaluating a coordinator deployment outside Cloudflare Workers;
- separating coordinator behavior from Durable Object runtime primitives;
- planning a container, Kubernetes, or managed-service deployment.

Current behavior remains authoritative in
[Coordinator](../features/coordinator.md), [Architecture](../architecture.md),
and `worker/src/`. This document records the implemented runtime design and the
remaining deployment proof required before production cutover, horizontal
scaling, or cross-runtime migration.

## Decision

Crabbox includes a Node.js coordinator runtime backed by PostgreSQL and keeps
the existing Cloudflare Worker and Durable Object deployment as an adapter over
the same coordinator behavior.

Use:

- PostgreSQL for durable records and coordination;
- [pg-boss](https://github.com/timgit/pg-boss) for delayed maintenance,
  retries, and recurring reconciliation;
- ordinary Node WebSockets for control, WebVNC, code, and egress bridges;
- one service replica initially, with reconnectable WebSocket clients;
- PostgreSQL advisory locks when multiple replicas become necessary.

This is a smaller and more operationally conventional change than adopting an
actor platform. Provider adapters already use portable TypeScript and `fetch`;
the runtime-specific surface is concentrated in Durable Object storage, alarms,
request routing, and WebSocket lifecycle.

## Required Semantics

The portable runtime must preserve:

| Current primitive | Required behavior | Portable implementation |
| --- | --- | --- |
| Durable Object storage | durable key/value records and prefix scans | PostgreSQL JSONB key/value table |
| One Fleet Durable Object | coordinated fleet mutations and cost reservations | one replica first; advisory lock for multi-replica |
| Durable Object alarms | expiry, cleanup retry, orphan sweep | pg-boss delayed and recurring jobs |
| Hibernating WebSockets | live bidirectional bridges | in-process WebSockets with ping, reconnect, and ticket replay |
| Worker entrypoint | auth, OAuth, portal, API routing | Node HTTP server using the existing route handlers |
| Worker secrets | provider and auth credentials | service secret injection |

SSH, rsync, command execution, and output streaming remain direct between the
CLI and runner. The portable coordinator changes only the control plane.

## Runtime Boundary

Runtime-dependent operations are now behind `CoordinatorRuntime`:

```ts
interface CoordinatorRuntime {
  storage: CoordinatorStorage;
  runExclusive<T>(callback: () => Promise<T>): Promise<T>;
  createWebSocketUpgrade(): CoordinatorWebSocketUpgrade;
  getWebSockets(): Iterable<WebSocket>;
  socketAttachment<T>(socket: WebSocket): T | undefined;
  setSocketAttachment(socket: WebSocket, attachment: unknown): void;
  acceptWebSocket(/* socket, attachment, tags, handlers */): void;
  scheduleAlarm(time: number): Promise<void>;
  clearAlarm(): Promise<void>;
}
```

`runExclusive` serializes lifecycle state transitions, alarms, and control
messages. Provider provisioning and bridge data traffic run outside that queue.

The first extraction should preserve the current key format (`lease:*`,
`run:*`, ticket keys, image keys, and cleanup keys). A normalized relational
schema can follow after both runtimes pass the same contract tests.

The Cloudflare adapter wraps `DurableObjectStorage`, alarms, and hibernating
WebSockets. The Node adapter wraps PostgreSQL, pg-boss, and a WebSocket server.

## PostgreSQL Shape

Start with one compatibility table:

```sql
create table coordinator_kv (
  key text primary key,
  value jsonb not null,
  value_text text,
  value_text_updated_at timestamptz,
  updated_at timestamptz not null default now()
);

create index coordinator_kv_updated_at_idx
  on coordinator_kv (updated_at);
```

Use parameterized prefix queries. Keep pg-boss in its own schema. Do not place
provider credentials in coordinator records.

The initial single-replica runtime serializes fleet lifecycle mutations with a
process queue. Lease creation uses the same queue for reservation and
finalization while provider provisioning runs outside it. A provider call
therefore cannot stall heartbeats, releases, control messages, or proxied code
traffic, while concurrent creates still make cost reservations in order. Before
enabling multiple replicas, replace the process queue with PostgreSQL advisory
locks for each fleet mutation. Provisioning is a phased state transition:

1. lock, validate limits, and persist a `provisioning` reservation;
2. unlock and call the provider;
3. lock and finalize the lease or record cleanup-required failure state.

The lease record is persisted before the cloud API call and checked again before
finalization, so concurrent release remains recoverable without holding a
database transaction across provisioning.

## Maintenance

Use a pg-boss `maintenance` job as the alarm equivalent:

- schedule it for the earliest lease expiry, cleanup retry, or provider sweep;
- let every lease mutation recompute the next due time;
- use a recurring reconciliation job as a backstop after deploys or crashes;
- make cleanup idempotent and retain the existing retry metadata;
- acquire the fleet mutation lock before each maintenance pass.

A process restart must not lose an expiry or cleanup request. Job delivery may
repeat, so handlers must remain idempotent.

## WebSockets

WebSocket upgrade creation, attachment storage, socket enumeration, and
lifecycle handlers are behind `CoordinatorRuntime`. The Cloudflare adapter
retains hibernating sockets and the existing non-hibernating fallback.

Portable deployments must assume that proxies and service rollouts can close
long-lived connections:

- ping at least every 30-60 seconds;
- reconnect with bounded exponential backoff;
- mint short-lived, one-use bridge tickets as today;
- restore logical subscriptions after reconnect;
- treat the in-memory socket registry as disposable state.

Run one replica until bridge ownership is externalized. Multi-replica options,
in preferred order:

1. reconnect clients to the replica owning the bridge;
2. use PostgreSQL only to discover the owning replica, then relay over an
   internal service connection;
3. add a binary-capable message bus when bridge volume justifies it.

## Packaging

Produce one OCI image containing:

- the Node HTTP/WebSocket service;
- database migrations;
- health and readiness routes;
- the existing portal assets;
- no embedded credentials.

Required deployment resources:

- managed PostgreSQL 13 or newer;
- secret injection for coordinator, OAuth, and provider credentials;
- outbound access to provider APIs;
- an ingress that supports WebSocket upgrades;
- one always-on replica for the initial release.

The portal should remain served by the coordinator initially. A static-site
host can serve a later extracted frontend, but cannot replace the coordinator
API, scheduler, durable state, or WebSocket bridges.

## Alternatives

### Rivet Actors

[Rivet Actors](https://rivet.dev/docs/actors/) is the closest open-source
semantic match: durable actors, state, timers, and WebSockets, with
self-hosting on containers or Kubernetes.

It is a useful spike target, but not the default:

- it introduces a new runtime and control plane;
- the current single global Fleet object becomes a large "god actor";
- scaling well would require partitioning by lease, run, or bridge;
- PostgreSQL is already sufficient for Crabbox's control-plane volume.

Reconsider Rivet if Crabbox intentionally adopts per-lease actors or needs
actor placement and hibernation across many replicas.

### Restate, Temporal, or Dapr Actors

These are strong durable-workflow or actor systems. They do not remove the need
for a separate WebSocket service and would require a larger rewrite than the
current coordinator needs. Reconsider one when lease lifecycle becomes a
multi-service workflow with long-running compensation and audit requirements.

### workerd

[workerd](https://github.com/cloudflare/workerd) can self-host Worker APIs, but
it is not by itself a production replacement for distributed Durable Object
storage, alarms, and hibernating sockets. It helps API compatibility, not the
coordinator's durable control-plane problem.

## Implementation Status

### Phase 1: contracts

- [x] Add storage, scheduler, socket, and upgrade interfaces.
- [x] Wrap the current Durable Object implementation without changing behavior.
- [x] Run the Worker tests through the Cloudflare adapter.

### Phase 2: portable runtime

- [x] Add PostgreSQL storage and migrations.
- [x] Add Node HTTP and WebSocket entrypoints.
- [x] Add pg-boss maintenance and reconciliation jobs.
- [ ] Run every Miniflare-specific coordinator contract against PostgreSQL in
  the same test matrix. In progress: `worker/test/coordinator-parity.test.ts`
  runs a shared contract (auth, lease create/heartbeat/release, restart and
  crash-restart recovery, post-restart expiry cleanup without client traffic,
  stranded mid-provisioning reconciliation, concurrent active-lease limits,
  usage accounting, run + event recording, portal, checkpoint create/list, and
  WebVNC/code/egress ticket minting and persistence) through both the
  Cloudflare adapter and `NodeCoordinatorRuntime` via
  `worker/test/coordinator-parity-fixture.ts`.
  `worker/test/coordinator-parity-socket.test.ts` covers the Node socket path
  (ticket redeem → accepted socket → attachment → one-use → close → socket
  registry, ticket validity across restart, shutdown closing bridge sockets).
  `worker/test/coordinator-parity.live.test.ts` runs the same fixture against
  a real `CRABBOX_TEST_DATABASE_URL` PostgreSQL (real
  `PostgresCoordinatorStorage` + `pg-boss`); CI runs it against a postgres:16
  service. Still open: parameterize the remaining
  `fleet.test.ts`/`bridge-tickets.test.ts`/`checkpoints.test.ts`/
  `lease-provisioning.test.ts`/`pairing.test.ts` contracts into the shared
  fixture, and merge the `describe.each` matrix in `capacity.test.ts`.

### Remaining deployment proof

- [x] Build the OCI image locally and in CI.
- Deploy one replica with managed PostgreSQL.
- Exercise auth, lease create/heartbeat/release, restart recovery, cleanup,
  usage, portal, run recording, WebVNC, code, and egress. The in-process and
  `CRABBOX_TEST_DATABASE_URL` legs of `coordinator-parity` cover this list;
  live end-to-end against a deployed instance remains.
- Verify WebSocket reconnect during a rolling restart. The Node socket parity
  tests prove tickets survive restart, old sockets close on shutdown, and a
  new socket can connect to the replacement process; a live rolling-restart
  test against a deployed instance remains.

### Optional cutover

- [x] Add a Durable Object state export and PostgreSQL import tool:
  `worker/src/coordinator-migration.ts` implements versioned, per-entry-hashed
  export documents, validation, dry-run planning, conflict policies
  (`fail`/`skip`/`overwrite`), bounded transactional batches, and
  reconciliation via `POST /v1/admin/coordinator/export`, `/import`
  (`?dryRun=true&onConflict=…`), and `/verify` on `FleetCoordinator` — so the
  same endpoints work against both the Durable Object and Node runtimes.
  Remaining orchestration: pause mutations, run export → import → verify, then
  switch the coordinator URL.
- Pause mutations during migration, import, validate counts and active leases,
  then switch the coordinator URL.
- Keep provider cleanup reconciliation enabled throughout rollback coverage.

### Phase 5: scale only when required

- [x] Fail closed to a single coordinator replica until bridge ownership is
  externalized: `PostgresCoordinatorStorage.acquireCoordinatorLock` takes a
  session-scoped `pg_try_advisory_lock` and `NodeCoordinatorRuntime.start`
  refuses to start while another instance holds it (released on `stop()`,
  `close()`, and session death). Covered by `postgres-storage.test.ts`,
  `node-runtime.test.ts`, the node leg of `coordinator-parity.test.ts`, and a
  real-PostgreSQL contention test in `coordinator-parity.live.test.ts`.
- Add advisory-lock mutation coordination for per-request serialization across
  replicas once multi-replica operation is reintroduced.
- Partition high-volume run logs or move them to object storage.
- Externalize bridge routing before increasing replica count.

## Acceptance Criteria

- The same coordinator contract tests pass against Cloudflare and Node.
- A service restart preserves leases, runs, tickets, and scheduled cleanup.
- Expired resources are deleted after a restart without client traffic.
- Cost and active-lease limits cannot be bypassed by concurrent creates.
- WebSocket clients reconnect after proxy or replica termination.
- Provider credentials never enter PostgreSQL, logs, images, or CLI output.

## Runtime Abstraction

### Completed

- [x] Injectable `ProcessSupervisor` for Tart and Lume
  (`internal/providers/shared/process_supervisor.go`): defines
  `ProcessSupervisor.Start` → `ProcessHandle` (PID, Kill, Abort, Handoff,
  Stderr, Done) so provider backends can substitute a fake in tests without
  spawning real VMs. Tart's `startupProcess` satisfies `ProcessHandle`
  natively; Lume wraps `lumeRunOwner` + stop logic in `lumeProcessHandle`.
  Both backends accept a supervisor via `newBackendWithSupervisor`; the
  default wraps their existing `startVM`/`stopVM` so production behavior is
  unchanged.
- [x] `ProcessStartupConfirm` strategies
  (`internal/providers/shared/process_startup_confirm.go`):
  `TimeoutWindowConfirm` (Tart's survival-window readiness),
  `FileHandoffConfirm` (Lume's PID/gate/ack file protocol),
  `ProcessExitConfirm` (one-shot command exit). Each satisfies the shared
  interface so new providers can plug in their own readiness strategy.
- [x] MXC injected runtime coverage: `provider_test.go` now exercises `Run`,
  `Warmup`, `Stop`, `Status`, `List`, and option-rejection paths with a
  `fakeCommandRunner` that records calls and returns configurable results —
  no real `wxc-exec.exe` required.
- [x] `RunEvidenceV1` (`internal/cli/run_evidence.go`,
  `worker/src/types.ts`): provider-neutral, versioned, machine-verifiable
  run outcome record with SHA-256 integrity digest. Normalizes `RunResult`
  and `TimingReport` into a portable format with outcome, timing, phases,
  failure classification, and artifacts. Constructed via
  `NewRunEvidence`, `RunEvidenceFromTimingReport`, or
  `RunEvidenceFromRunResult`; verified via `VerifyRunEvidenceDigest`.
  The frozen wire contract — canonicalization, raw-hex digest, receipt v3
  binding, verification order, and size limits — is specified in
  [docs/spec/run-evidence.md](../spec/run-evidence.md), with shared
  golden fixtures (`internal/cli/testdata/evidence-golden.json`)
  validated by both Go and TypeScript. Evidence is collected for every
  completed run regardless of `--timing-json`, and the coordinator
  accepts evidence only with a fully verified v3 receipt binding.
- [x] `RunEvidenceV1` wired into the CLI run path: evidence is constructed
  from the finalized `TimingReport` in the deferred cleanup, emitted to
  stderr alongside timing JSON when `--timing-json` is set, and passed to
  `CoordinatorClient.FinishRun` via a new `evidence` parameter. The worker
  `RunFinishRequest` and `RunRecord` now accept `evidence?: RunEvidenceV1`,
  and `finishRun` stores it on the `RunRecord`.
- [x] Tart `startVM` migrated to use `ProcessStartupConfirm` internally:
  `confirmStartup` delegates to `shared.TimeoutWindowConfirm.Wait` using
  the caller's context and a new `exitedErr` channel fed by the reaper.
  The legacy `observe` method is retained as a compatibility wrapper.
- [x] Lume `startVM` migrated to use `shared.FileHandoffConfirm` and
  `shared.TimeoutWindowConfirm` internally: the owner/ack handoff waits
  and the final survival window select are all routed through shared
  strategies. The legacy `waitForLaunchHandoff` is retained as a
  compatibility wrapper.
- [x] Tart `Acquire` migrated to use `ProcessHandle` methods exclusively:
  `startSupervisedVM` returns `shared.ProcessHandle` (not `*startupProcess`),
  and `Acquire` uses `handle.Context()`, `handle.Abort()`, and
  `handle.Handoff()` instead of reaching into private struct fields.
  `ProcessHandle` gained a `Context() context.Context` method that returns
  the process's lifecycle context (cancelled when the process exits).

### Remaining

- External provider plugin architecture.
