# RC6 Promotion Criteria

This document defines the mandatory criteria for promoting
`release/crabedence-v1-rc6-qualified-execution` to a release candidate.

**Do not promote until ALL criteria are verified.**

## Release Integrity

- [ ] Source archive exactly matches source manifest
- [ ] Zero unlisted source files
- [ ] Zero hash mismatches
- [ ] Standalone verifier works without `.git`
- [ ] Qualification schema genuinely validates (not a jq no-op)
- [ ] Gate aggregate values independently recomputed from individual gates
- [ ] PostgreSQL live tests actually execute (not skipped)
- [ ] NEMO dependencies installed reproducibly (`npm ci --prefix nemo`)
- [ ] NEMO typecheck passes
- [ ] All NEMO tests pass
- [ ] Stale release evidence removed from source tree
- [ ] Evidence generated to `dist/release-evidence/` (not committed)

## Execution Boundary

- [ ] Fake READ success removed from `crabbox exec`
- [ ] Fake UNKNOWN for undispatched operations removed
- [ ] `crabbox exec` returns `FAILED` + `CAPABILITY_UNIMPLEMENTED`
- [ ] Go capability registry is authoritative (`internal/capability/`)
- [ ] Execution class pinned by Go registry (caller assertion only)
- [ ] Mismatch between caller assertion and registry = `DENIED`
- [ ] Authority (principal + grant_id) checked by Go
- [ ] Typed error vocabulary: `INVALID_REQUEST`, `UNAUTHORIZED`,
      `CAPABILITY_NOT_FOUND`, `CAPABILITY_UNIMPLEMENTED`,
      `ADMISSION_DENIED`, `EXECUTION_FAILED`, `EXECUTION_UNKNOWN`,
      `IN_FLIGHT`, `INTERNAL_ERROR`, `IDEMPOTENCY_CONFLICT`
- [ ] `crabbox serve-execution` starts persistent Go service
- [ ] No per-call subprocess spawn for execution

## Durable Idempotency

- [ ] Durable idempotency implemented (`internal/idempotency/`)
- [ ] PostgreSQL-backed `execution_requests` table
- [ ] States: `RESERVED`, `DISPATCHING`, `IN_FLIGHT`, `SUCCEEDED`,
      `FAILED`, `DENIED`, `UNKNOWN`, `RECONCILIATION_REQUIRED`
- [ ] Atomic reservation via `INSERT ON CONFLICT`
- [ ] Same key + different digest = `IDEMPOTENCY_CONFLICT` (never re-execute)
- [ ] Idempotency survives process restart
- [ ] UNKNOWN survives process restart
- [ ] Canonical JSON digest (sorted keys, property order independent)
- [ ] Digest binds: protocol version, principal, capability, canonical
      arguments, grant identity, authoritative execution class

## Dispatch Semantics

- [ ] PRE_DISPATCH vs POST_DISPATCH state tracking
- [ ] Pre-dispatch failures return `FAILED` (safe)
- [ ] Post-dispatch failures return `UNKNOWN` (may have executed)
- [ ] Persistence failure after dispatch returns `UNKNOWN`, not `FAILED`
- [ ] Reconciliation subsystem implemented (`internal/reconcile/`)

## Protocol

- [ ] Runtime wire response validation (not `JSON.parse(...) as T`)
- [ ] Invalid status values rejected as `PROTOCOL` errors
- [ ] Evidence digest format validated (64-char hex)
- [ ] CRITICAL requires valid V3 evidence (receipt_version == 3)
- [ ] Strict RFC3339 deadline validation (matches Go's `time.Parse`)
- [ ] Shared wire protocol across Go and TypeScript

## Real Capabilities

- [ ] `system.echo` (PURE) executes end-to-end
- [ ] `test.counter.increment` (MUTATION) executes with idempotency
- [ ] Real adapter invocation (not fake success)
- [ ] Evidence generation for CRITICAL operations

## Adversarial Matrix

- [ ] Unicode request and response
- [ ] Maximum frame size boundary
- [ ] Oversized frame rejected
- [ ] Malformed JSON rejected
- [ ] Invalid status rejected
- [ ] Expired deadline rejected
- [ ] Invalid deadline rejected
- [ ] Missing authority rejected
- [ ] Execution class downgrade rejected
- [ ] Concurrent identical mutations
- [ ] Socket close before response
- [ ] Same key different request (conflict)
- [ ] Same key different grant (conflict)
- [ ] Canonical JSON reorder (same digest)

## Clean-Room Qualification

- [ ] Qualification starts from exact commit
- [ ] No untracked files
- [ ] No prior `node_modules`
- [ ] No cached generated qualification
- [ ] All gates execute from scratch
- [ ] Final archive independently verifies
- [ ] External attestation binds artifact to commit

## Gate Closure

Expected gates (approximate — derive actual count dynamically):

1. go-test
2. go-race
3. go-vet
4. gofmt
5. worker-typecheck
6. worker-lint
7. worker-tests
8. worker-build
9. postgres-fencing
10. postgres-parity
11. cross-language-conformance
12. provider-tests
13. evidence-tests
14. receipt-tests
15. source-manifest
16. artifact-verifier
17. nemo-typecheck
18. nemo-tests
19. go-capability-tests
20. go-execution-tests

Promotion rule:
```
mandatory_failed == 0
mandatory_skipped == 0
mandatory_not_run == 0
source_mismatch == 0
artifact_mismatch == 0
```

## Planner Independence

- [ ] Crabedence core has no dependency on NEMO
- [ ] Crabedence core has no dependency on Hermes
- [ ] Capability ABI has a generic conformance suite
- [ ] Two independent clients pass the same conformance suite
- [ ] `crabbox invoke` (generic CLI client) executes capabilities successfully
- [ ] NEMO adapter executes the same capabilities successfully
- [ ] Caller cannot control execution class (advisory only; registry is authoritative)
- [ ] Caller cannot control authority policy (resolved by Crabedence)
- [ ] Caller cannot bypass durable mutation semantics (fail closed without store)
- [ ] Provider selection remains server-controlled (adapter policy in registry)
- [ ] `authority_ref` is accepted (not just `grant_id`)
- [ ] `execution_class` is optional in the wire request
