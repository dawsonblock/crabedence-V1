# ADR-003: NEMO runtime transfer — one distribution, two trust domains

Status: Accepted
Date: 2026-09-29

Implementation: in progress. The vendoring (Phase 0) and the bridge (Phase 1)
have landed under `runtimes/nemo-relay/`; the trust-enforcement and
conformance phases are partial. See the
[transfer plan](../plan/nemo-runtime-transfer.md) for the current state and
the findings recorded during implementation.

## Context

Two systems exist and are to become one distribution:

- **NEMO** (NeMo Relay, Rust core with Python and Node.js bindings) is a
  multi-language agent runtime: scopes, middleware, plugins, an isolated
  native plugin host, LLM wrapping and routing, a worker protocol, and
  observability. It ships its own partial implementations of kernel
  responsibilities — `crates/authority`, `crates/ledger`,
  `crates/executor`, `crates/effect-runtime`,
  `crates/effect-qualification`.
- **Crabedence** is the trusted execution kernel in this repository:
  capability truth (`internal/capability`), authority
  (`internal/authority`), admission, durable idempotency
  (`internal/idempotency`), the Effect Fabric, evidence and receipts
  (`internal/evidence`), and UNKNOWN reconciliation
  (`internal/reconcile`).

The transfer must not produce two ledgers, two authority systems, two
execution-class systems, or two pieces of software that both believe
they own idempotency. NEMO's overlapping subsystems are not defective;
they are simply not the authority once the two runtimes share a
distribution.

The `nemo/` TypeScript package was a compatibility kernel, and it served as
the executable specification this transfer was checked against: it spoke the
capability invocation ABI (`docs/spec/capability-invocation-abi.md`),
verified the registry envelope, and carried cross-language conformance tests
against the Go kernel. **That kernel has since been retired** — its catalog,
route table, schema validator, and execution harness are deleted. What
remains is the ABI contracts and their validator, the registry-snapshot
loader (`nemo/registry-snapshot/snapshot.ts`), and the Crabedence adapter and
client. The transfer plan records what replaced each removed behavior.

## Decision

### 1. One distribution, two trust domains

NEMO decides how to run, reason, and route. Crabedence decides whether
consequential work is authorized and how it is committed. Neither
delegates its trust responsibility to the other.

The ownership matrix below is a repository invariant: a component that
owns a concern in this table may not also own its counterpart, and a
change that moves a concern from one column to the other is an
architecture change, not a refactor.

| Concern | Owner |
| --- | --- |
| LLM / model abstraction | NEMO |
| Middleware and interceptors | NEMO |
| Plugin lifecycle | NEMO |
| Native plugin isolation | NEMO |
| Python / Node / Rust bindings | NEMO |
| PII / DLP middleware | NEMO |
| Capability discovery and catalog | NEMO (consumes it) |
| Capability truth | Crabedence |
| Execution classification | Crabedence |
| Authorization | Crabedence |
| Approval requirements | Crabedence |
| Idempotency | Crabedence |
| Effect state machine | Crabedence |
| Dispatch | Crabedence |
| Fencing and leases | Crabedence |
| Receipts and evidence | Crabedence |
| Reconciliation | Crabedence |
| Provider integrations | Crabedence |
| Recovery and disaster recovery | Crabedence |

The invariant that follows from the matrix:

> No NEMO component can independently produce a MUTATION or CRITICAL
> external effect.

It is asserted by tests in CI, not merely documented here; see
[Phase 2](../plan/nemo-runtime-transfer.md) for the current enforcement
status.

### 2. The capability invocation ABI is the only seam

The semantic contract in `docs/spec/capability-invocation-abi.md` is
frozen and is the only boundary between the two. The request crossing
that boundary carries capability, arguments, authority material, an
idempotency key, and a deadline. It never carries execution route,
provider or adapter selection, assurance profile, approval
requirements, retry policy, or receipt requirements. A caller-supplied
`execution_class` is at most an advisory assertion that Crabedence
checks against its registry and denies on mismatch.

The transport is the existing length-prefixed JSON Unix-socket binding
(4-byte big-endian length, 4 MiB maximum). The transport is
replaceable; the semantic contract is not.

### 3. Capability truth flows one way

Crabedence constructs the authoritative registry and writes its
verifiable envelope (`capabilities.json`, 0600, crash-durable atomic
write) next to the socket. NEMO verifies SHA-256 over the decoded
canonical payload and only then parses it; a snapshot whose payload
does not match its digest fails startup closed. NEMO never maintains an
independent definition of any capability's execution class.

Server-side authority is unaffected by what NEMO believes: even a
compromised NEMO that asserts a downgraded class is refused by
Crabedence's registry resolution, and route selection is never read
from the caller.

### 4. Import boundaries

| NEMO component | Disposition |
| --- | --- |
| `core`, `types`, `adaptive` | Import |
| `plugin`, `plugin-protocol`, `plugin-proto` | Import |
| `plugin-host` | Import |
| `native-abi` | Import |
| `native-loader` | Import; host process only |
| `worker`, `worker-proto` | Import |
| `pii-redaction` | Import |
| CLI / gateway, Python, Node, FFI bindings | Import |
| Framework integrations | Import |
| `authority` | Not authoritative |
| `ledger` | Not used as a production ledger |
| `executor` | Must not own consequential execution |
| `effect-runtime` | Replaced by Crabedence |
| `effect-qualification` | Reconciled with Crabedence qualification; no competing truth |
| `dlp` | Optional contract/middleware |
| `isolation` | Kept where useful; not confused with Crabedence authority |

### 5. Native plugin isolation invariant

A plugin must never be able to register a consequential local callback
and bypass the kernel:

- `PURE` may execute in the NEMO plugin host.
- `READ` may use the approved read path.
- `MUTATION` and `CRITICAL` must cross Crabedence.

`native-loader` stays in the plugin host process and is never linked
into the Crabedence kernel process.

### 6. The uncertainty model is preserved end to end

NEMO's execution contract already carries the vocabulary
(`DispatchState`, `OutcomeCertainty`, `state_for_error` in
`crates/executor`); the bridge maps Crabedence outcomes onto it without
inventing certainty:

| Crabedence outcome | NEMO result |
| --- | --- |
| Connection refused before dispatch | `FAILED`, safe to retry |
| Request accepted, dispatch uncertain | `UNKNOWN`, never retried |
| Confirmed provider failure | `FAILED` |
| Confirmed successful effect | `SUCCEEDED` with evidence |
| Authority rejection | `DENIED` |
| `IN_FLIGHT` at the client boundary | `UNKNOWN` |

`UNKNOWN` is terminal-pending at the NEMO boundary. The bridge does not
implement NEMO's `ReconciliationProvider` against today's socket ABI,
because reconciliation is owned by Crabedence's internal engine and the
socket exposes no reconciliation call. Resolving UNKNOWN through an
additive ABI extension is a future option gated on a real nonterminal
polling need, never on a retry convenience.

### 7. CI invariant

No execution path from NEMO can produce an external `MUTATION` or
`CRITICAL` effect without entering Crabedence's execution kernel. This
is asserted by a test in CI, not documented as an intention.

### 8. Migration sequence

The TypeScript compatibility kernel is retired. It was retained as the
executable specification until the behaviors it owned were shown to be
covered: the duplicated admission checks by the Go service's own tests
(`TestExpiredDeadline`, `TestInvalidDeadline`,
`TestExecutionServiceMissingIdempotencyKey`,
`TestExecutionServiceExecutionClassMismatch`,
`TestExecutionClassRequiresIdempotencyKey`), the CRITICAL evidence contract by
the Rust bridge's `map_outcome(requires_evidence)`, and route resolution by
the registry on both sides. The one behavior with no counterpart —
result-schema validation — was inert in production, because a result schema
never travels in the registry snapshot.

The lightweight TypeScript client and the registry-snapshot loader are
retained, because Node applications still need a way to invoke Crabedence and
to verify the envelope it publishes.

## Consequences

- The repository carries two release surfaces in one distribution. The
  vendored NEMO tree stays intact under `runtimes/nemo-relay/` so
  upstream NEMO updates remain pullable; the bridge is the only new
  code that touches it.
- The bridge is deliberately tiny. Any logic that classifies, routes,
  authorizes, retries, or reconciles belongs to one side or the other,
  never to the bridge.
- NEMO's `authority`, `ledger`, `executor`, and `effect-runtime` crates
  remain in the tree for compilation and non-consequential use, but no
  production path may treat them as authoritative. Their status is
  recorded here so a later reader does not "restore" them.
- The release gate in the migration plan must pass before the transfer
  is declared complete, including capability snapshot tampering,
  class-downgrade and route-override attempts, and both-restart
  recovery.

See the executable plan in [NEMO runtime transfer](../plan/nemo-runtime-transfer.md).
