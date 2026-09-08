# Crabedence v1 Hardening — Qualification Matrix

**Branch:** `release/crabedence-v1-hardening`
**Source commit:** `ad20b9bd434ca551e27fa3404f2af10624944ba8`
**Date:** 2026-09-07

## Gate Results

| Gate | Status | Details |
|------|--------|---------|
| `go vet` | PASS | evidence/receipt/tart/lume/shared packages |
| Go evidence/receipt tests | PASS | 7.8s |
| Go race tests | PASS | evidence/receipt/tart/lume with race detector |
| Go tart provider tests | PASS | 81.3s |
| Go lume provider tests | PASS | 1.6s |
| Go shared provider tests | PASS | 1.0s |
| Worker typecheck (`tsc --noEmit`) | PASS | |
| Worker tests (Vitest) | PASS | 2845 passed, 11 skipped (2856) |
| Worker format (`oxfmt --check`) | PASS | |
| Worker lint (`oxlint`) | PASS | 0 errors, 0 warnings |
| Worker build (`wrangler dry-run`) | PASS | |
| PostgreSQL authority fencing (live) | PASS | 3 tests, real PostgreSQL with `pg_terminate_backend` |
| PostgreSQL coordinator parity (live) | PASS | 4 tests, real PostgreSQL restart parity |
| Cross-language conformance | PASS | Go and TypeScript share fixtures; 94 TS conformance tests |

## Release Invariants

1. **Authority fencing (linearizable drain):** Only one coordinator can mutate authoritative state. Mutations admitted before coordinator-session loss may complete while holding the global mutation fence; no mutation admitted by a replacement coordinator can execute until those transactions complete. New mutations from the old coordinator fail closed after authority loss. See `docs/features/portable-coordinator.md` § Coordinator authority and fencing.
2. **Startup evidence:** Provider startup confirmation produces structured evidence for success, timeout, early exit, cancellation, handoff failure, and acquisition failure.
3. **Cross-language determinism:** Go and TypeScript canonicalization produce identical SHA-256 digests for shared fixtures.
4. **Receipt binding:** Every V3 terminal receipt is evidence-bound (`evidence_sha256` required), Ed25519-signed, millisecond-precision, and self-verified before persistence. V2 receipts are legacy and cannot bind evidence.
5. **Immutable finalization:** Successful remote execution cannot be retroactively changed to failed by local write or coordinator commit failures.
6. **Capability interfaces:** Providers advertise only lifecycle capabilities they possess (Tart: ExitObservable; Lume: DetachedProcess only).
