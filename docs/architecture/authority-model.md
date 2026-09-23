# Authority Model

Authority answers one question at admission: *which principal is
allowed to invoke this capability, under which grant material?* This
document is the architecture view; the normative rules are invariants
3 and 11 of
[the durable execution contract](../spec/durable-execution-contract.md)
and the [capability invocation ABI](../spec/capability-invocation-abi.md).

## Where authority sits

```
planner (untrusted)
    │  authority: { principal, authority_ref? }
    ▼
execution service (crabbox serve-execution)
    │  1. registry lookup → descriptor.authority_policy
    │  2. grant required?  ── no ──▶ grant-free admission
    │                      └ yes ──▶ resolver.Resolve(ref, principal)
    │  3. bind generation + grant digest (server-assigned)
    ▼
EffectStore.AcquireWithAuthority(…, AuthorityBinding{Ref, Generation, Digest}, …)
```

The planner supplies an identity (`principal`) and an opaque reference
(`authority_ref`). It never supplies policy, generation, or digest.

## `authority_ref` is bearer authority

The current model is deliberately a bearer model: possession of an
unguessable `authority_ref`, together with a `principal` matching the
resolved material, is the complete authorization proof. The service
does not independently authenticate `principal` — it is a claimed
attribute verified only against the grant the reference resolves to.

Two controls carry the trust boundary:

- References are credentials. Issued grant IDs carry 96 bits of random
  entropy, and references must never appear in logs, receipts,
  metrics, or error text.
- The transport boundary restricts presentation — a `0600` Unix socket
  today. Deployments can additionally authenticate the principal
  itself: `CRABEDENCE_PEER_PRINCIPALS` maps Unix peer UIDs
  (`SO_PEERCRED`/`LOCAL_PEERCRED`) to principals, and the claim must
  match the mapping — see *Peer authentication* below.

## Peer authentication (optional strict mode)

`CRABEDENCE_PEER_PRINCIPALS` upgrades the claimed `principal` into an
authenticated one. When set — a comma-separated `uid:principal` map —
the service reads the caller's kernel-supplied UID from the Unix socket
(`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on BSD/macOS) before
admission:

- an unmapped UID, missing peer credentials, or a principal claim that
  disagrees with the mapping is denied before admission;
- a `uid:*` entry marks a trusted local caller that may claim any
  principal (e.g. an orchestrator that proxies authenticated
  principals upstream);
- on success the authenticated principal **replaces** the claim for
  admission, grant resolution, and the durable execution identity.

Unset, the bearer model above applies unchanged. The map is parsed at
startup; malformed entries refuse startup rather than silently
weakening the boundary. A peer map only authenticates the *local*
caller — a deployment that fronts the socket with a proxy needs that
proxy to authenticate its own upstream identity instead.

## Grant material is immutable and generation-scoped

- Grants are never updated in place. Reissuing a `grant_id` appends a
  new immutable generation row carrying a `grant_digest` over its
  material (grant ID, generation, principal, sorted capabilities,
  constraints, issuance time, expiry), and the latest generation
  supersedes all earlier ones for admission — an older still-valid
  generation never resurfaces after a reissue.
- Grants may carry **constraints**: resource caveats per dimension
  (for example `repo: ["example-org/my-app"]`). A capability's
  authority policy maps each dimension it binds to a request argument;
  admission denies the request unless the argument's value is listed
  (or the grant lists `"*"`). A dimension absent from the grant is
  unconstrained — least-privilege deployments issue constrained
  grants.
  grants. Constraints are part of the immutable material bound into
  the digest, so narrowing or widening scope is a new generation with
  a new execution identity.
- Revocation marks every generation while preserving the rows as
  forensic snapshots. `RevokeGeneration` revokes one immutable
  generation; revoking after admission never invalidates an
  already-admitted execution.
- **CLOSE and REVOKE are different lifecycle operations, deliberately.**
  `CloseAuthorityRef` retires the reference: no new generation may ever
  be issued for that `grant_id`, while the existing generation keeps
  resolving until it is revoked or expires — closing is not revocation,
  so continuity of already-issued authority is preserved. `RevokeGrant`
  (or `RevokeGeneration`) invalidates existing authority: the latest
  generation stops admitting anyone at admission. An operator who needs
  an atomic "close and revoke everything" performs both operations; the
  distinction is exercised by the live qualification test
  `TestLiveCriticalQualificationClosedAuthoritySemantics`.
- Expiry is evaluated by the authority store's own database clock
  (`expires_at > NOW()` / `unixepoch`), never the application clock.
  Resolvers that own the clock declare `ExpiryIsAuthoritative`, and
  the service skips its application-time veto for them.
- Issuance is serialized through a per-reference `authority_heads` row
  locked during issue, so concurrent issuers produce strictly
  increasing generations instead of racing `MAX(generation)+1`.

## Admission policy is descriptor-owned

`AuthorityPolicy.GrantRequired` on the resolved capability descriptor
decides whether authority material is required:

| `grant_required` | Caller sends `authority_ref` | Outcome |
|---|---|---|
| `false` | absent | Admitted grant-free. No generation/digest binding (zero values mean unversioned authority). |
| `false` | present | Ignored by policy — grant-free capabilities never resolve or bind a grant. |
| `true` | absent | `UNAUTHORIZED` — `missing grant_id`. |
| `true` | present, resolves, valid | Admitted; generation + digest bound into the execution identity. |
| `true` | present, not found / revoked / expired / wrong principal / wrong capability / outside resource constraints | `UNAUTHORIZED`; the resolver's reason is recorded, never the material. |

A capability is grant-free by policy, not by accident: the policy is
pinned in the registry at registration time and is not caller-visible
or caller-editable.

## Binding into execution identity

The service overwrites any caller-supplied `authority_generation` /
`authority_digest` and assigns them from the resolved grant. They are
inputs to the request digest, so the same `grant_id` under different
immutable authority material is a different execution identity — and
the durable record proves which authority admitted it
(`AcquireWithAuthority` persists the snapshot). Reissuing authority
can therefore never silently reinterpret a durable record or
idempotency key.

## Failure vocabulary

| Failure | Meaning |
|---|---|
| `UNAUTHORIZED` | Missing principal, missing required grant, or resolution denied (not found, revoked, expired, wrong principal/capability). |
| `ADMISSION_DENIED` | Registry-level rejection (unknown capability, class mismatch, missing idempotency key for a mutation, expired deadline). |
| `CAPABILITY_NOT_FOUND` | Capability is not registered. |
| `CAPABILITY_UNAVAILABLE` | Registered but no adapter is wired. |

## Invariants and their tests

| Invariant | Enforced by | Tests |
|---|---|---|
| Caller-supplied generation/digest is ignored and rejected as identity input | Service overwrite before dispatch | `internal/execution/authority_binding_test.go` |
| A revoked/expired/closed grant never admits | Resolver + DB-clock expiry | `internal/authority/sqlite_test.go`, `store_live_test.go` |
| Generation reuse and cross-principal/cross-capability reuse are denied | Resolver `HasCapability` + generation supersession | `internal/capability/registry_test.go`, authority suites |
| Grant-free capabilities never require or bind authority | `AuthorityPolicy.GrantRequired` | `internal/capability/admission` tests, `internal/execution/e2e_test.go` |
| Authority metrics never expose material | `internal/authority/metrics.go` (counters only) | `metrics_test.go` |
| With `CRABEDENCE_PEER_PRINCIPALS` set, an unmapped UID or a principal claim that disagrees with the kernel-authenticated mapping is denied before admission | `PeerPrincipalMap` + `SO_PEERCRED`/`LOCAL_PEERCRED` | `internal/execution/peer_auth_test.go`, `qualification_deployed_test.go` |

The metrics surface (`authority_grants_issued_total`,
`authority_generations_revoked_total`, `authority_grants_revoked_total`,
`authority_refs_closed_total`, `authority_resolves_total`,
`authority_resolve_denials_total`) reports outcomes, never identifiers
or material.
