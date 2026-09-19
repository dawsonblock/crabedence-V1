# Capability Trust Model

There is exactly one authoritative capability definition in Crabedence:
the resolved descriptor in the Go capability registry
(`internal/capability/registry.go`). Planners — NEMO, Hermes, the
OpenAI Agents SDK, custom runtimes — are outside the trust path: they
choose *what* to invoke, never *how* it is classified, routed, assured,
or authorized.

Normative boundary: the
[capability invocation ABI](../spec/capability-invocation-abi.md).

## Three orthogonal dimensions

Every capability pins three independent dimensions at registration
time, plus its argument schema and authority policy:

| Dimension | Values | Meaning |
|---|---|---|
| Effect class | `PURE`, `READ`, `MUTATION`, `CRITICAL` | Side-effect semantics |
| Assurance profile | `NONE`, `STANDARD`, `DURABLE`, `HIGH_ASSURANCE` | Admission, durability, evidence requirements |
| Execution route | `LOCAL`, `DIRECT`, `CRABEDENCE` | Dispatch mechanism |

The dimensions are resolved and frozen by `Resolve()` at registration.
The active registry contains only `ResolvedDescriptor` values — no
runtime inference, no defaults at execution time.

## Registration-time invariants (fail the registry, not the request)

`ValidateDescriptorCompatibility` rejects, at registration:

- `LOCAL` route unless effect is `PURE` **and** assurance is `NONE`.
- `DIRECT` route for `MUTATION`/`CRITICAL` effects, and for
  `DURABLE`/`HIGH_ASSURANCE` assurance.
- Unknown values for any dimension; empty capability ID; duplicate IDs.

The hard invariant **`MUTATION`/`CRITICAL` ⇒ durable route** is
therefore enforced by construction: a mutation cannot be registered on
a route that cannot provide its durability guarantees.

## Planner-facing request vs server-resolved policy

The caller sends:

```json
{
  "capability": "github.issue.create",
  "arguments": { "…": "…" },
  "authority": { "principal": "user-123", "authority_ref": "grant-456" },
  "idempotency_key": "…",
  "deadline": "…"
}
```

The caller must **not** send — and the service ignores if sent:
`execution_class` (advisory assertion only, checked against the
registry), `assurance_profile`, `execution_route`, `authority_policy`,
`authority_generation`, `authority_digest`, `provider`/`adapter`,
`schema`, `receipt_version`, `evidence`.

The resolved dimensions are bound into the request digest
(server-assigned), so the same arguments under different classification,
assurance, routing, or authority material are different execution
identities. A policy change is never invisible to idempotency.

## Routing

| Route | Intended semantics | Status |
|---|---|---|
| `LOCAL` | Deterministic / contained functions in the caller's process — no socket hop, no durability, no admission. Bound to `PURE` + `NONE`. | Declared and validated; execution subsystem **not yet implemented** (v0.52 Function Hooks work) |
| `DIRECT` | Observational external operations with admission, schema validation, authority, timeouts, and audit — but without the durable mutation ledger. Bound to `READ` + `STANDARD`. | Declared and validated; **no DIRECT provider yet** (v0.52 work) |
| `CRABEDENCE` | The durable execution kernel: authority, idempotency, dispatch, evidence, reconciliation. Required for `MUTATION`/`CRITICAL` and for `DURABLE`/`HIGH_ASSURANCE`. | Implemented (`crabbox serve-execution`) |

Until `LOCAL` and `DIRECT` land, every registered capability uses the
`CRABEDENCE` route and the registry's compatibility rules prevent
registering anything the service cannot actually dispatch.

## The planner boundary

```
planner (untrusted)
   │  capability + arguments + principal (+ optional authority_ref)
   ▼
registry lookup → trusted ResolvedDescriptor
   ▼
admission (class assertion check, authority policy, idempotency key, deadline)
   ▼
schema validation (exact-number JSON Schema model)
   ▼
route dispatch (descriptor.execution_route)
   ▼
signed / auditable execution
```

NEMO's TS kernel historically maintained a parallel capability catalog
and hand-rolled schema validator. That duplication is being deleted in
v0.52: the kernel must resolve descriptors from the authoritative
registry and route on the trusted `execution_route`, never on a
separately maintained classification.

## Architectural laws (invariant tests)

| ID | Law | Where enforced |
|---|---|---|
| INV-001 | A `MUTATION` can never execute through `LOCAL`. | `ValidateDescriptorCompatibility`; `routing_conformance_test.go` |
| INV-002 | A `CRITICAL` operation can never execute without `HIGH_ASSURANCE`. | Same |
| INV-003 | An unrecognized capability can never reach a provider. | `Admit()` → `CAPABILITY_NOT_FOUND`; admission tests |
| INV-004 | Caller-supplied execution class cannot influence routing. | Registry is authoritative; class mismatch → `ADMISSION_DENIED` |
| INV-005 | Caller-supplied authority generation is ignored/rejected. | Service overwrite; `authority_binding_test.go` |
| INV-011 | A registry-policy change changes request identity. | Resolved class/assurance/route bound into the request digest |
| INV-012 | A failed qualification cannot publish an RC. | Release workflows (see `docs/RELEASING.md`) |

Additional laws (INV-006…INV-010) are enforced in the effect fabric:
see [recovery-model.md](recovery-model.md) and
[effect-lifecycle.md](effect-lifecycle.md).

## Open items for v0.52 (tracked here as they land)

- Canonical descriptor schema + descriptor digest (registry-versioned
  capability identity bound into request identity).
- Registry invariant scan at startup, registry SHA-256 digest, and a
  startup report; the digest appears in runtime identity, qualification
  evidence, and release artifacts.
- NEMO consuming the authoritative registry (deleting its parallel
  catalog and hand-rolled validator).
- `LOCAL` Function Hooks and a real `DIRECT` read provider.
