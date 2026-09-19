# Capability Registry Semantics

This document resolves the registry's identity permanently:
**`registry_sha256` identifies the complete policy-defined capability
catalog shipped by a release.** It does not identify which capabilities
happen to have configured adapters on a particular machine.

## registry = the release's capability surface

The registry contains every capability the release ships and
recognizes — including capabilities whose adapters are not configured in
a given deployment:

```
system.echo
system.info
test.counter.increment
github.issue.get
github.issue.create
qualification.critical.commit
qualification.critical.query
...
```

The registry digest is identical on two machines running the same
qualified release, whether or not GitHub credentials exist. Deployment
configuration never enters the registry, the registry digest, or any
descriptor digest.

## Four different states

| State | Question | Decided by | Failure code |
|---|---|---|---|
| `KNOWN` | Does this release recognize the capability? | The built-in catalog (compiled into the build) | `CAPABILITY_NOT_FOUND` when no |
| `AVAILABLE` | Can this deployment currently execute it? | Adapter wiring / health (runtime state) | `CAPABILITY_UNAVAILABLE` when no |
| `AUTHORIZED` | Does the principal hold authority for it? | Grant resolution at admission | `UNAUTHORIZED` when no |
| `EXECUTABLE` | Is this specific request admitted right now? | Admission (class assertion, schema, idempotency key, deadline) | `ADMISSION_DENIED` / `INVALID_REQUEST` when no |

These are orthogonal. A capability can be `KNOWN` but not `AVAILABLE`
(GitHub not configured), `AVAILABLE` but not `AUTHORIZED` (no grant),
or `AUTHORIZED` but not `EXECUTABLE` (missing idempotency key, expired
deadline). Each failure is reported with its own code; they are never
collapsed into each other.

Availability values (`internal/capability/availability.go`):

```
AVAILABLE
ADAPTER_NOT_CONFIGURED
ADAPTER_UNHEALTHY
FEATURE_DISABLED
```

## Availability is runtime state, never policy

Availability lives beside the registry, never inside it:

- It is not written into `ResolvedDescriptor` and never changes a
  descriptor's `execution_class`, `execution_route`,
  `assurance_profile`, authority policy, schemas, or digest.
- An unavailable adapter fails closed at dispatch. It never becomes a
  routing change, a `LOCAL`/`DIRECT` fallback, or a class downgrade.
- Enabling an integration does not change the security catalog.

**INV-014**: provider availability cannot modify capability security
classification.

## registry_sha256 vs runtime_configuration_sha256

Two identities, deliberately distinct:

| Identity | Covers | Changes when |
|---|---|---|
| `registry_sha256` | Descriptors sorted by ID, canonicalized: id, descriptor version, policy revision, class, assurance, route, schema, authority policy, adapter binding | The release's capability policy changes |
| `runtime_configuration_sha256` | Safe, normalized deployment identity: schema version, release, registry digest, effect-store backend, enabled adapters | The deployment's configuration changes |

`runtime_configuration_sha256` is computed over non-secret identity
only. API keys, passwords, OAuth tokens, cookies, private keys,
database credentials, and raw environment variables are excluded by
construction — the structure has no field for them.

Runtime identity is therefore:

```
release identity + registry identity + configuration identity
```

without leaking secrets, and without configuration contaminating the
policy identity.

## Three-way registry verification

Release qualification establishes, and the release evidence binds, one
value three ways:

```
registry generated from the exact qualified source
        ↓  registry_sha256 = ABC
artifact.json binds          registry_sha256 = ABC
runtime serves               registry_sha256 = ABC
```

`cmd/registry-digest` computes the digest from the same built-in
registration path the service uses at startup, so qualified policy =
released policy = runtime policy is checkable, not asserted.

## Where this is enforced

| Rule | Enforcement |
|---|---|
| Complete built-in catalog registered unconditionally | `internal/execution/serve.go`; `cmd/registry-digest` |
| Availability separate from policy | `internal/capability/availability.go`; `Registry.Availability` |
| Unavailable ≠ unknown | `CAPABILITY_UNAVAILABLE` + `ADAPTER_NOT_CONFIGURED` reason |
| No routing/class fallback | `RouteDispatcher`; `MultiHandler` |
| Digest covers policy only | `internal/capability/registry_digest.go` |
| Runtime identity excludes secrets | `internal/execution/runtime_identity.go` |
