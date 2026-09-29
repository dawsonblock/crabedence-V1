# ADR-001: Durable Effect Contract architecture is frozen

Status: Accepted
Date: 2026-09-17

## Context

The crabedence durable Effect Fabric has been through its architectural
iteration. The current structure — the `idempotency.EffectStore`
abstraction, the frozen state machine, the SQLite/PostgreSQL backend
split, UNKNOWN reconciliation semantics, lease fencing, and the
CRITICAL Ed25519 evidence model — is sound and does not need another
redesign.

The remaining defects are contract violations, missing hardening, and
unproven semantics — not architectural gaps.

## Decision

The following are architecture-frozen. Changes to them require the
same review as changes to `docs/spec/durable-execution-contract.md`:

1. **The `EffectStore` interface** is the persistence boundary.
   `DispatchExecutor` and `reconcile.Worker` consume the interface;
   no third persistence abstraction will be added.

2. **The state graph is frozen:**

   ```
   PREPARED → EXECUTING → IN_FLIGHT → COMMITTED | FAILED | UNKNOWN
                                          UNKNOWN → COMMITTED | FAILED
   ```

   `EXECUTING → PREPARED` (AbandonPreDispatch) is the only reverse
   edge and exists because the dispatch boundary was not crossed.
   No new states and no new edges — in particular, nothing may make
   `UNKNOWN` automatically retryable.

3. **The dispatch boundary is the ownership boundary.** Once provider
   dispatch might have happened, automatic retry is forbidden until
   reconciliation establishes what actually happened, and all
   mandatory persistence runs on a caller-independent, bounded
   durability context.

4. **Two storage engines, one contract.** SQLite (embedded,
   single-node) and PostgreSQL (distributed) both implement
   `EffectStore` and must pass the same conformance suite. SQLite is
   not replaced; PostgreSQL is not redesigned.

5. **CRITICAL terminal states require authenticated Ed25519
   evidence** bound to execution identity. Resolvers interpret
   evidence; they never manufacture it.

6. **Authority is immutable and generation-scoped.** Grant reissue
   appends generations; the resolved generation + grant digest are
   bound into the request digest.

## Consequences

- Future work is contract hardening: adversarial testing, crash
  qualification, migration safety, observability, and release
  evidence — not redesign.
- No new persistence abstraction, no executor rewrite, no new
  terminal-state shortcuts.
- Any proposal that adds a state, a retry path out of `UNKNOWN`, or a
  way to finalize `CRITICAL` without signed evidence is rejected by
  definition.
