# Governed Capability Packs

Status: Draft — proposed direction, not yet scheduled. This file is the
design record for turning the execution kernel's narrow built-in catalog
into an extensible platform without weakening the trust boundary.

Read when:

- adding a provider family or deciding whether one belongs in the kernel;
- changing registry loading, adapter dispatch, reconciliation resolvers,
  or evidence classification;
- deciding what runs inside the trusted kernel versus outside it.

Current behavior remains authoritative in
[Adding a capability](../architecture/adding-a-capability.md),
[Capability Trust Model](../architecture/capability-trust-model.md), and
`internal/capability/registry.go`. This document records the target
architecture and the ordered work required to reach it.

## Problem

The kernel is ahead of the catalog. Adding a capability today is trusted
code: a `CapabilityDescriptor` compiled into `RegisterBuiltinCapabilities`,
a Go adapter wired in `serve.go`, a reconciliation resolver, evidence
handling, and a rebuild (the recipe in `adding-a-capability.md`). The result
is a sophisticated governed execution kernel whose real external surface is
GitHub plus a counter — every new provider repeats the full
trusted-code cycle.

The fix is not a looser plugin path. Native plugins are deliberately
middleware/observability only, and that stays true: anything that produces
external effects must cross the same admission → authority → dispatch →
reconciliation → evidence path the built-ins do. The fix is making that
path consumable by artifacts the kernel did not compile.

## The invariant

A capability pack may supply implementation. It may never supply truth.

The kernel continues to decide, for every invocation and every installed
capability:

- is this capability recognized, and is its descriptor legal
  (`Resolve`/`ValidateDescriptorCompatibility` — the class/assurance/route
  lattice is not negotiable by a pack);
- does this principal hold authority, and is the resource inside the grant;
- which route may execute it (a pack cannot name `DIRECT` for a `MUTATION`);
- whether dispatch is certain, ambiguous, or definitively refused —
  `DispatchState`/`OutcomeCertainty` stay kernel vocabulary;
- whether an `UNKNOWN` record may be committed — attribution evidence is
  verified by the kernel's rules, not the pack's claim;
- what evidence binds the terminal receipt.

A pack that disagrees with any of these is refused at install, admission,
or dispatch — whichever boundary catches it first.

## Pack contents

A pack is a signed bundle. The manifest is the declaration the kernel
verifies; everything else is what the declaration binds by digest.

| Component | Role | Kernel treatment |
| --- | --- | --- |
| `identity` + `version` + signature | who built this and which build | verified at install; install record binds the digest |
| capability descriptors | `ID`, class, assurance, adapter binding, schema, authority policy | re-resolved through `capability.Resolve`; illegal combinations refuse install |
| `authority` | grant scope identity, `ResourceArguments` mapping | resolved server-side, exactly as today — the pack's own approval is never authoritative |
| `adapter` artifact + `isolation` | provider transport/serialization code | runs confined under the plugin-host model, never in-process |
| `dispatch` | how the provider expresses uncertain delivery | declared per capability; `UNKNOWN`-on-ambiguity is mandatory, not optional |
| `idempotency` | provider-side dedup hints | advisory only — kernel namespacing (per principal) and ledger fencing are not pack-configurable |
| `attribution` | how a resolver proves *this* request caused the observed state | declared mechanism, conformance-tested |
| `evidence` | extraction from provider responses to canonical evidence | declared field mapping; kernel recomputes digests and signs |
| `dlp` | fields allowed to leave, provider allowlist, payload ceilings | intersected with the kernel's outbound policy — a pack can narrow, never widen |
| `network.allow` | origins the adapter may reach | enforced at the confined boundary |
| conformance suite | outcome vectors, fault injection, resolver fixtures | must pass before the pack is admitted — qualification is admission |

Two fields deserve emphasis because they are where a naive SDK silently
breaks the kernel's guarantees.

**Dispatch semantics.** `on_uncertain_delivery: UNKNOWN` is the only legal
value for `MUTATION`/`CRITICAL`. The provider-specific part is *which*
responses are uncertain — that is declared as a classification table and
held against the shared outcome corpus
(`internal/execution/testdata/outcome-conformance/vectors.json` is the
existing cross-language version of this idea; packs get the same shape:
classified fixtures the kernel runs, not a callback the kernel trusts).

**Attribution.** Recovery today binds the *requested* effect, not any
matching observed state: marker-carrying writes hide an operation token in
the request (with schema headroom carved out of the provider's own limit —
`body` caps at 65473 because the marker is appended after validation),
`issue.close`/`issue.update` require the provider transition timestamp to
fall inside the record's lifetime, and `pr.merge` proves `merge` by
two-parent topology while `squash`/`rebase` stay `UNKNOWN`. A pack must
declare which attribution mechanism it uses and prove it under fault
injection; `absence of evidence → UNKNOWN` is non-negotiable — no effect
may commit on "I looked and didn't see it."

## Where packs execute

The adapter is the part that parses provider bytes, and a parser that
decides "this response means committed" is truth-adjacent. Two properties
contain that:

1. **The adapter never emits a verdict.** It emits structured evidence —
   status, provider request/run id, observed resource state, timestamps.
   The kernel maps evidence to outcome through the pack's declared
   classification table, verified at install against the conformance suite.
2. **The adapter runs confined.** The plugin-host substrate already built
   for this — process separation, restricted-Linux namespaces/Landlock/
   seccomp, staged digest verification, fd-passed kernel channel
   (`crates/plugin-host`, `crates/native-loader/.../linux_sandbox.rs`) —
   is the execution model. A pack adapter is a confined artifact speaking
   the invocation ABI; the network allowlist is enforced at that boundary,
   not asked of the code.

## Governance

Installing a pack grants authority to *declare* capabilities — including,
potentially, `CRITICAL` ones. Pack install, upgrade, and removal are
therefore themselves governed operations: grant-required, durable,
evidence-bound, and reconciled like any other consequential effect.
Removal while records reconcile to `UNKNOWN` under that pack's
capabilities must refuse or explicitly fence, never strand ambiguity.

## Prerequisites that are not optional

- **Outbound DLP as an enforcement boundary.** The vendored runtime's
  `OUTBOUND_DLP_ENABLED = false` is tolerable while the catalog is GitHub;
  it is not tolerable once arbitrary providers can receive arbitrary
  arguments. Field allowlists, provider allowlists, secret stripping, and
  payload ceilings are the admission condition for opening the ecosystem.
- **Authenticated runtime provenance.** `RequestMediation` is currently
  caller-attested — bound into durable identity but not independently
  verified. A signed runtime attestation closes that gap before
  third-party packs are accepted; otherwise a compromised runtime can
  claim legitimate mediation digests.
- **Local caller identity beyond shared UID.** Peer-credential auth
  (`internal/execution/peer_auth.go`) treats same-UID processes as one
  trust zone. Fine for a desktop tool; insufficient before packs widen
  what a hostile local process can reach.

## Ordered work

| Phase | Deliverable | Exit test |
| --- | --- | --- |
| 0 — externalize | pack manifest schema + verification tooling; descriptor serialization of today's catalog with zero registry-digest change | the built-in catalog round-trips through the manifest format byte-identical |
| 1 — reference pack | GitHub extracted into a pack: same descriptors, same adapter contract, same resolvers, driven through the confined boundary | the existing qualification suite passes with GitHub loaded as a pack; registry digest unchanged |
| 2 — second family | filesystem or database — deliberately a family where `UNKNOWN` means crash-consistency, not network partition | recovery proofs hold without a transport ambiguity source |
| 3 — breadth | one cloud provider + one SaaS family | real reconciliation at provider scale; DLP enforced per pack |
| 4 — hard evidence | browser/API automation | unstructured evidence classified correctly |

GitHub first is not a demotion — it is the correctness check. The existing
adapter family (hidden markers, timestamp-bound resolvers, topology
proofs, the 65473 headroom rule) is the most demanding contract in the
catalog; an abstraction that can express it without behavior change can
express the easier families. One that cannot is the wrong abstraction.

## Non-goals

- Smarter planning. The bottleneck is the governed surface, not the model.
- In-process pack code. Convenience is not worth a TCB expansion.
- Pack-declared grants, self-approval, or pack-controlled reconciliation
  verdicts — all remain kernel-side by construction.
- Turning middleware plugins into callable capabilities. The middleware
  boundary stays observational; effects stay behind the registry.

## Open questions

- **Revocation.** Uninstalling a pack while its records sit `UNKNOWN`
  needs a defined fence — refuse, drain, or hand reconciliation to the
  operator.
- **Signing trust root.** Which keys may sign packs for which namespaces;
  how revocation propagates to already-installed catalogs.
- **Resource-constraint language.** `repo/*`-style string matching is the
  current grant dimension; whether packs need a richer constraint grammar
  is undecided — start restrictive.
- **Descriptor versioning.** Descriptor digests already pin each
  capability exactly; the `RegistryExtensionRecord` pattern (base digest +
  extension digests) is the natural shape for "release catalog + packs".
- **ABI stability.** Pack adapters speak the invocation ABI; versioning it
  is a spec change (`docs/spec/capability-invocation-abi.md`), not a pack
  concern.
