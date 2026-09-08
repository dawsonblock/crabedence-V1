# Crabedence V1 Hardening — Qualification Matrix

**Branch:** `release/crabedence-v1-hardening`
**Source commit:** `a8d2cda3348a1744bf9e40e0ab5411721770005d`
**Git tree:** `2f4949028ebb80f5f369f2fba69fa714ea60438f`
**Date:** 2026-09-08T23:30:23Z
**Release status:** PASS (16/16 gates passed)

## Toolchains

| Tool | Version |
|------|---------|
| Go | go version go1.26.5 darwin/arm64 |
| Node | v22.22.3 |

## Gate Results

| Gate | Status | Log |
|------|--------|-----|
| `source_manifest` | PASS | `source-manifest-verify.log` |
| `go-vet` | PASS | `go-vet.log` |
| `go-evidence-tests` | PASS | `go-evidence-tests.log` |
| `go-tart-tests` | PASS | `go-tart-tests.log` |
| `go-lume-tests` | PASS | `go-lume-tests.log` |
| `go-shared-tests` | PASS | `go-shared-tests.log` |
| `go-race-evidence` | PASS | `go-race-evidence.log` |
| `go-race-providers` | PASS | `go-race-providers.log` |
| `postgres-fencing` | PASS | `postgres-fencing.log` |
| `postgres-parity` | PASS | `postgres-parity.log` |
| `cross-language-conformance` | PASS | `cross-language-conformance.log` |
| `worker-typecheck` | PASS | `worker-typecheck.log` |
| `worker-tests` | PASS | `worker-tests.log` |
| `worker-format` | PASS | `worker-format.log` |
| `worker-lint` | PASS | `worker-lint.log` |
| `worker-build` | PASS | `worker-build.log` |

## Release Invariants

- **CRAB-V1-001:** V3 receipt always binds evidence_sha256
- **CRAB-V1-002:** V2 receipt can never contain evidence_sha256
- **CRAB-V1-003:** receipt evidence digest equals canonical RunEvidenceV1 SHA-256
- **CRAB-V1-004:** Go and TypeScript produce identical canonical evidence
- **CRAB-V1-005:** Go and TypeScript accept/reject identical receipt/evidence domains
- **CRAB-V1-006:** startup confirmation failure evidence survives to RunEvidenceV1
- **CRAB-V1-007:** detached providers never advertise exit observability
- **CRAB-V1-008:** persistence failure cannot alter FinalRunOutcome
- **CRAB-V1-009:** new mutations fail after coordinator authority loss
- **CRAB-V1-010:** replacement mutations cannot overlap pre-admitted old-coordinator mutations
- **CRAB-V1-011:** qualified source tree equals packaged source tree
- **CRAB-V1-012:** every mandatory qualification gate was executed and passed

## Provenance

- Commit: `a8d2cda3348a1744bf9e40e0ab5411721770005d`
- Tree: `2f4949028ebb80f5f369f2fba69fa714ea60438f`
- Branch: `release/crabedence-v1-hardening`
- Dirty: false (clean working tree required)

## Verification

To verify this release artifact:

```bash
./scripts/verify-release-artifact.sh
```

To check release admission:

```bash
./scripts/check-release-admission.sh
```
