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

- `PREPARED` — no external dispatch has occurred.
- `EXECUTING` — an executor owns the lease and is preparing dispatch;
  the dispatch boundary has not been crossed.
- `IN_FLIGHT` — the dispatch boundary has been crossed and the effect
  may have occurred.
- `COMMITTED` — the operation durably succeeded.
- `FAILED` — the operation definitively failed.
- `UNKNOWN` — the durable store cannot currently determine the
  real-world result; caller-terminal but not durably final.
- `DENIED` — admission denied the request before dispatch.

`RECONCILING` is not a durable execution state. Reconciliation is
expressed through claims and metadata on an `UNKNOWN` record — never a
distinct state, and never a silent retry of the mutation.

## Authority terminology

- `authority_ref` — an unguessable bearer reference resolved by the
  server-side authority store. Possession of the reference is the
  authorization proof; it must never be logged or exposed to untrusted
  parties. The server resolves the reference to immutable authority
  material — caller-supplied generation or digest values never override
  the resolved values. `grant_id` is the backward-compatible alias.
- **authority generation** — the monotonic generation that must match the
  resolved authority; caller-supplied generations are ignored.
- **authority constraints** — optional resource caveats bound into the
  grant digest (for example `repo=owner/name`). A constrained grant
  admits only the listed resources for each bound dimension.
- `CLOSE` — closes an authority reference to new generations; the existing
  generation remains resolvable.
- `REVOKE` — revokes the authority; existing authority is denied.

## Normative status

This document is explanatory. Machine-readable qualification and release
policy is normative. Where this document and the machine-readable policy
disagree, the machine-readable policy decides.
