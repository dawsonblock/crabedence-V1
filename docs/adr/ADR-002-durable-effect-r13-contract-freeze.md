# ADR-002: Revision-13 repair contract freeze

Status: Accepted
Date: 2026-09-17

## Context

Revision 13 of the durable Effect Fabric landed the right architecture —
`EffectStore`, SQLite and PostgreSQL backends, the
PREPARED/EXECUTING/IN_FLIGHT state machine with UNKNOWN reconciliation,
fenced leases, the CRITICAL evidence model, provider capabilities, and
detached post-dispatch persistence. ADR-001 froze that architecture.

The r13 audit then identified repair items that are contract violations
and hardening gaps, not architectural defects: exponent parsing through
`int64` in request canonicalization, `SELECT MAX(generation)+1`
authority issuance, ambiguous revocation semantics, nanosecond
timestamps entering digest inputs, mutable provider-result storage,
and a recovery CAS race.

The repair is a controlled hardening release. The risk it must not
introduce is architecture churn — a "repair" that quietly becomes
another redesign and invalidates the architecture that already works.

## Decision

The following invariants are frozen for the r13 repair. Any change that
violates one is rejected by definition, the same review bar as
`docs/spec/durable-execution-contract.md`:

1. **UNKNOWN can never automatically redispatch.** Recovery is
   evidence-driven; no code path may retry a possibly-executed
   external effect without reconciliation.
2. **IN_FLIGHT means the external effect may have occurred.** Every
   post-IN_FLIGHT path must treat the side effect as potentially
   real until evidence proves otherwise.
3. **Caller cancellation cannot cancel mandatory post-dispatch
   persistence.** Once the dispatch boundary is crossed, durability
   work runs on a caller-independent bounded context.
4. **Terminal states cannot regress.** COMMITTED, FAILED, and DENIED
   are sealed; no transition, replay, or fence failure may mutate
   them or their receipts.
5. **CRITICAL COMMITTED requires COMPLETED evidence.** A definitive
   commit without verified completion evidence is rejected.
6. **CRITICAL FAILED requires NO_EFFECT evidence.** A definitive
   failure without verified no-effect evidence is rejected.
7. **Resolver assertion is not evidence.** A resolver may interpret
   provider-returned evidence; it may never manufacture the digest or
   receipt it attests.
8. **Authority used for execution is immutable and digest-bound.**
   The resolved generation and grant digest are bound into the
   request digest; reissue mints a new generation, never mutates an
   admitted grant.
9. **Provider observations are immutable.** The first recorded
   observation is forensic fact; conflicting observations are
   rejected, never silently overwritten.
10. **SQLite and PostgreSQL implement identical logical EffectStore
    semantics.** Backend-specific behavior is a defect unless the
    contract explicitly allows it.

The components frozen by ADR-001 (the `EffectStore` interface, both
backends, the state machine, UNKNOWN reconciliation, fenced leases,
the CRITICAL evidence model, the provider capability model, and
detached post-dispatch work) remain frozen and are not rewritten by
this repair.

## Consequences

- Repair work proceeds in the r13 order: P0 numeric canonicalization
  first (the request-identity ABI), then authority serialization and
  the stable authority ABI, then the immutable forensic record, then
  hardening, then qualification. No qualification work validates an
  ABI that is still wrong.
- New persistence (observation ledger, reconciliation events,
  authority heads) is append-only or head-locked; it extends the
  frozen model rather than replacing it.
- The numeric canonicalization change is a deliberate request-digest
  ABI change; the frozen vectors in
  `internal/idempotency/testdata/digest-vectors.json` are regenerated
  exactly once for it, then frozen again.
