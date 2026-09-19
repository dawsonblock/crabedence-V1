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
| `LOCAL` | Deterministic / contained functions in the caller's process — no socket hop, no durability, no admission. Bound to `PURE` + `NONE`. | Implemented: `FunctionHookRegistry` executes hooks in-process under the LOCAL contract (PURE-only, input validation, bounded runtime, bounded payload, well-formed JSON results, audit record). Hooks receive data only — no store, dispatcher, or effect-fabric client — so `PURE` is an execution boundary, not an assertion. |
| `DIRECT` | Observational external operations with admission, schema validation, authority, timeouts, and audit — but without the durable mutation ledger. Bound to `READ` + `STANDARD`. | Implemented: `DirectReadRegistry` executes reads under the in-process contract (READ-only, argument validation, bounded runtime, bounded payload, projected results, audit record). First real capability: `github.issue.get`. A failed read is a safe `FAILED`, never `UNKNOWN`. |
| `CRABEDENCE` | The durable execution kernel: authority, idempotency, dispatch, evidence, reconciliation. Required for `MUTATION`/`CRITICAL` and for `DURABLE`/`HIGH_ASSURANCE`. | Implemented (`crabbox serve-execution`) |

`RouteDispatcher` is the single dispatch point: it reads
`descriptor.execution_route` (never a caller value), re-checks the
class/route invariant at dispatch time as defense in depth (a
`MUTATION`/`CRITICAL` on a non-durable route is denied even if a
registry bug produced the descriptor), and fails closed on an unknown
route. Until the `DIRECT` leg lands, `READ` capabilities that declare
it fail with `CAPABILITY_UNAVAILABLE` rather than silently taking a
different path.

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
| INV-013 | A `LOCAL` capability can never require a grant. | `Resolve`; whole-registry scan; NEMO envelope loader |
| INV-014 | Provider availability cannot modify capability security classification. | `Availability` is derived and never written into descriptors; `invariants_test.go` |
| INV-015 | No model-generated field may determine trusted execution classification. | Wire request carries no policy fields; registry is authoritative; `invariants_test.go` |

Additional laws (INV-006…INV-010) are enforced in the effect fabric:
see [recovery-model.md](recovery-model.md) and
[effect-lifecycle.md](effect-lifecycle.md).

## Registry export and verification

The service writes a **verifiable envelope** next to its socket
(`capabilities.json`, 0600, crash-durable atomic write):

```json
{ "registry_sha256": "<hex>", "canonical_payload": "<base64>" }
```

The payload is the exact canonical descriptor bytes the digest covers.
A consumer (NEMO) verifies `SHA-256(payload) == registry_sha256` and
only then parses the verified bytes. That makes the descriptors a
planner routes on provably the bytes the authoritative registry
digested — a rewritten capability with a stale digest fails closed.

Cross-language canonicalization deliberately never enters this
boundary: the canonical bytes are produced once, by the authoritative
Go implementation, and travel with the digest. There is no second
serializer whose number representation, key ordering, or escaping could
disagree with Go's.

The production kernel accepts only a `VerifiedCapabilityCatalog`, which
is produced solely by the envelope loader; hand-built catalogs are
confined to tests via `createTestKernel`/`createTestCatalog`. The
snapshot file lives in the same trust domain as the socket (0600 inside
a 0700 directory owned by the service user); signing the envelope
becomes relevant only if it is ever transported or read by a different
principal.

## Release evidence closure (v0.52)

- The registry digest is bound into the authenticated release evidence:
  `artifact.json` carries `registry_sha256` (produced by
  `cmd/registry-digest`) and the standalone verifier refuses a bundle
  without it.
- `artifact.json` is inside the final evidence manifest. The release
  workflow runs `scripts/finalize-release-evidence.sh` after the archive
  and artifact binding exist, regenerating `SHA256SUMS` (which now covers
  `artifact.json`) and `evidence-manifest.json`; the verifier fails a
  bundle whose checksum manifest does not cover the artifact binding.
- The attestation terminates the chain: its subject is the final
  `evidence-manifest.json` and its predicate carries the manifest digest
  (`evidence_sha256`), which the verifier cross-checks. An attestation of
  a superseded manifest fails closed.
- Clean-room verification runs BEFORE publication: `release-rc.yml`
  builds and stages the archive and evidence, the clean room verifies the
  staged bytes standalone, and only then does the publish job tag and
  create the release — re-verifying the staged archive digest first.
- Publication is followed by a distribution-integrity reverify: the
  published archive digest must equal the qualified digest, the published
  `artifact.json`/`evidence-manifest.json`/`SHA256SUMS` must be
  byte-identical to the qualified bundle, and the published bytes must
  pass the standalone `--mode release` verifier and attestation check.

Typed release gates remain open; see the release-engineering findings.
