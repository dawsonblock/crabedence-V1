# Crabedence v0.52 RC Promotion Policy

Machine-readable release policy is authoritative.

## Authoritative sources

The release decision is defined entirely by these machine-readable
artifacts and the scripts that consume them:

- `schemas/qualification.schema.json` — the qualification record contract.
- `scripts/lib/qualification-gates.sh` — the single gate-semantics
  validator, shared by release admission and the standalone verifier.
- `scripts/check-release-admission.sh` — release admission.
- `scripts/verify-release-artifact.sh` — standalone artifact verification.
- `.github/workflows/release-rc.yml` — the RC build/verify/publish workflow.

## Human promotion sequence

```
source freeze
  → qualification
  → build
  → evidence finalization
  → clean-room verification
  → attestation
  → publication
  → public reverification
```

## Execution state vocabulary

The durable execution state machine uses exactly these states:

- `PREPARED`
- `IN_FLIGHT`
- `COMMITTED`
- `FAILED`
- `UNKNOWN`
- `RECONCILING`

## Authority terminology

- `authority_ref` — the server-resolved reference binding a request to an
  authority record.
- **authority generation** — the monotonic generation that must match the
  resolved authority; caller-supplied generations are ignored.
- `CLOSE` — closes an authority reference to new generations; the existing
  generation remains resolvable.
- `REVOKE` — revokes the authority; existing authority is denied.

## Normative status

This document is explanatory. Machine-readable qualification and release
policy is normative. Where this document and the machine-readable policy
disagree, the machine-readable policy decides.
