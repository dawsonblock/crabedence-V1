# Adding a capability

The capability registry is the release's complete policy surface — its
digest is the identity a runtime verifies before it serves. A capability
is not a function: it is a frozen policy decision (class, assurance,
route, schema, authority, adapter) plus an adapter that honors that
decision. This recipe is the checklist for adding one so every dimension
stays true.

## 1. Choose the execution class first

Class decides what the capability is allowed to *mean*, and everything
else follows:

| Class | Semantics | Required route | Evidence |
|---|---|---|---|
| `PURE` | no external effect | `LOCAL` (assurance `NONE`) | audit record only |
| `READ` | observational, no effect | `DIRECT` (assurance `STANDARD`) | audit record, bounded projection |
| `MUTATION` | external effect | `CRABEDENCE` (durable ledger) | receipt + recovery locator |
| `CRITICAL` | consequential effect | `CRABEDENCE` (`HIGH_ASSURANCE`) | signed evidence |

`Resolve` enforces the legal combinations (`ValidateDescriptorCompatibility`):
`LOCAL` refuses anything that is not `PURE`+`NONE`; `DIRECT` refuses
`MUTATION`/`CRITICAL` classes and `DURABLE`/`HIGH_ASSURANCE` assurance;
`CRITICAL` refuses anything but `HIGH_ASSURANCE`. A capability that does
not fit an existing class has no recipe — changing the class lattice is
a trust-model change, not a capability addition.

The caller never chooses any of this. The descriptor in the registry
decides; the wire carries only the capability ID and arguments.

## 2. Write the descriptor

Register through the catalog builder (`RegisterBuiltinCapabilities`) so
the service, `cmd/registry-digest`, and the qualification harness all
see the same surface:

```go
capability.CapabilityDescriptor{
    ID:             "provider.verb.object",     // namespaced, stable forever
    ExecutionClass: capability.ClassMutation,   // the policy decision
    AdapterID:      "github",                   // the provider adapter
    AuthorityPolicy: capability.AuthorityPolicy{
        ID:            "github.issue",          // the grant scope identity
        GrantRequired: true,
        ResourceArguments: map[string]string{
            "repo": "repo",                     // grant dimension → request arg
        },
    },
    Schema: json.RawMessage(`{...}`),
}
```

Rules the registry enforces (failing them refuses startup):

- **Schema is a contract, not a hint.** `additionalProperties: false`,
  every field typed and bounded (`maxLength`, `minimum`/`maximum`,
  `enum` where the set is closed). The schema is validated at admission;
  the adapter validates semantically too — both places, always.
- **`ResourceArguments` binds only string arguments** to grant
  constraint dimensions. An integer arg (`number`) cannot carry a
  dimension — the least-privilege scope is the string arg it nests
  under (`repo`).
- **`GrantRequired` on `LOCAL` is a registration error** — LOCAL never
  reaches the authority resolver, so a grant requirement there would be
  silently unenforced.
- **A `DIRECT` read behind a service credential is not public.** If the
  adapter attaches a token that sees more than the anonymous world, the
  capability requires a grant like the mutation leg.

## 3. Implement the adapter contract for the route

`LOCAL` — a function hook: validated args in, bounded JSON out. No
authority, no ledger.

`DIRECT` — a `DirectReadRegistry` handler `(ctx, CallContext) (json.RawMessage, error)`:

- Project a **bounded field set** — never the raw provider payload, and
  never echo response bodies or credentials in errors.
- Bound the provider response bytes (`maxDirectReadBytes`) and honor
  caller bounds (`limit`) with a server-side ceiling.
- Failure is a safe `FAILED` — a read has no effect to reconcile.

`CRABEDENCE` — the durable contract (`Execute` + two recovery roles):

- `Execute`: embed the external-operation token (`ExternalTokenFromContext`)
  in the provider request so the durable ledger and the external object
  share one operation identity. Report `DefinitiveFailure` only when the
  request provably never left (connection refused, DNS) — resets,
  timeouts, and mid-stream drops are `UNKNOWN`.
- `PrepareRecovery`: persist a *minimal* locator — operation token,
  resource coordinates, metadata. Never raw arguments.
- `Resolve`: strictly observational (GET only), paginates to exhaustion
  with same-origin `next` links only (the bearer never leaves the
  configured API origin), marker-found → `COMMITTED` with the original
  provider run ID, exhausted → `UNKNOWN` — absence of positive evidence
  is not proof of no effect.

When one `AdapterID` fronts several capabilities, route inside the
adapter (`githubAdapter.handlerFor`) and fail closed on an unknown
capability — never fall through to a sibling handler.

## 4. Wire it

- `builtin_capabilities.go`: add the registration — unconditional;
  deployment config never decides registry membership.
- `serve.go`: construct the adapter under its deployment gate, add it
  to the `handlers` map (or the adapter mux), and for MUTATION register
  the reconciliation resolver (`worker.RegisterResolver`).
- `DIRECT` reads also bind in `RegisterXxxReads` against the
  `DirectReadRegistry` — an unbound DIRECT capability fails closed with
  `CAPABILITY_UNAVAILABLE`, and that is correct: the registry advertises
  policy, the deployment binds availability.

## 5. Prove it

The minimum coverage, per route:

- Registry: the descriptor resolves to the intended class/route/assurance
  tuple; the serve-time snapshot lists it unconditionally
  (`serve_test.go`).
- `DIRECT`: projection correctness against a mock provider, auth header
  sent, failure is `FAILED`, body bound enforced, defaults applied.
- `CRABEDENCE`: commit binds the marker + evidence artifact; invalid
  args fail definitively; transport ambiguity table
  (`ECONNREFUSED`/`DNS` definitive, reset/timeout `UNKNOWN`); resolver
  paginates and never false-negatives; locator carries no raw arguments.
- Mux: unknown capability under a shared adapter fails closed.

## 6. Publication discipline

Adding a capability changes `registry_sha256` — the release identity.
That is the point: a different catalog is a different release. The
envelope is regenerated by the assembler (`registry-digest -envelope`);
update the catalog listing in `docs/architecture/capability-registry-semantics.md`
and the changelog. Do not hand-maintain the digest anywhere.
