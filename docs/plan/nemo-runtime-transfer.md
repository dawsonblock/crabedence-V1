# NEMO Runtime Transfer

Status: Accepted and in progress. Phase 0 (vendoring) and Phase 1 (the bridge)
are implemented and verified; Phases 2 and 3 are partially implemented; Phase 4
has not started. This file is the executable plan and the decision record for
the transfer described in
[ADR-003](../adr/ADR-003-nemo-runtime-transfer-boundary.md).

Read when:

- integrating the full NEMO runtime into this repository;
- changing `runtimes/nemo-relay/`, the NEMO↔Crabedence bridge, or the
  capability snapshot handshake;
- retiring or preserving the TypeScript `nemo/` compatibility kernel;
- reasoning about which side owns authority, idempotency, or reconciliation.

Current behavior remains authoritative in
[Capability Trust Model](../architecture/capability-trust-model.md),
[Capability Invocation ABI](../spec/capability-invocation-abi.md), and
`internal/capability/registry.go`. This document records the target
architecture and the ordered work required to reach it.

## Where things stand (verified)

| Fact | Evidence |
| --- | --- |
| Crabedence already exports a verifiable registry envelope | `Registry.Envelope()` in `internal/capability/registry_digest.go`; `serve-exec` writes `capabilities.json` (0600, atomic) next to the socket (`internal/execution/serve.go`) |
| The ABI and its strict parsing rules are frozen | `docs/spec/capability-invocation-abi.md` |
| A cross-language conformance corpus exists | `internal/execution/testdata/invocation-abi-conformance/vectors.json` |
| A TypeScript compatibility kernel exists and is the executable spec | `nemo/reference-kernel/snapshot.ts` (verify-then-parse), `nemo/adapters/crabedence/` |
| NEMO's backend seam already matches the kernel's vocabulary | `crates/executor/src/lib.rs`: `ExecutionBackend`, `ExecutionRequest`, `ExecutionResult`, `EffectExecutionError`, `state_for_error`, `ReconciliationProvider` (feature `unstable-hardening`) |
| NEMO's `ExecutionClass` is identical to Crabedence's | `Pure/Read/Mutation/Critical` in both |
| No reconciliation call exists over the socket | `internal/reconcile/` is the kernel's internal engine; the socket ABI exposes invocation only |
| Neither repository references the other yet | no `crabedence` string in the NEMO tree; no `bridges/` directory here |

Sizes, for planning: the NEMO working copy is 2.0 GB dominated by a 2.0 GB
`target/` directory; the source (`crates/`) is 19 MB. The vendored tree
excludes `target/`, caches, `node_modules`, and editor state.

## Implementation status

| Phase | State | Evidence |
| --- | --- | --- |
| 0 — vendor | Done | `runtimes/nemo-relay/` (1438 source files, no build artifacts); a recursive diff against the source copy reports exactly two differing files (`Cargo.toml`, `Cargo.lock`); provenance and fingerprint in `runtimes/nemo-relay/TRANSFER-PROVENANCE.md` |
| 1 — bridge | Done | `runtimes/nemo-relay/bridges/nemo-crabedence/`: `abi.rs`, `transport.rs`, `capability_snapshot.rs`, `outcome_mapping.rs`, `execution_port.rs`; 56 unit tests, 1 corpus conformance test, 5 schema-binding tests, 5 env-gated live tests |
| 2 — trust enforcement | Partial | Bridge-level invariants enforced and tested (unregistered capability, class mismatch, route mismatch, no policy field on the wire), and the bridge's tests, lints, and formatting now run in CI (`nemo-bridge` job in `.github/workflows/ci.yml`). The end-to-end CI invariant still needs NEMO's `BackendRouter` wiring, which is not done |
| 3 — conformance | Partial | The Rust validator matches the shared corpus exactly (11 accepted, 32 rejected) and the live kernel's refusal phrases match the Rust validator's word-for-word. The full release-gate scenario list is not complete |
| — reference kernel | Done | `nemo/kernel/` renamed to `nemo/reference-kernel/` with a README stating its role and the known divergence; export key and all references updated; 155 TypeScript tests pass |
| — canonical schema | Done | `schemas/capability-invocation-v1.json` describes the frozen wire contract; Go, TypeScript, and Rust each carry a test that binds their implementation to it, so a field added on one side and not the others fails CI |
| — effect router | Done at the routing layer | `runtimes/nemo-relay/bridges/nemo-effect-router/`: `EffectRouter` resolves the path from the verified **route** (not the class, which is what NeMo Relay's own router uses), fails closed on an unwired read path, and holds the effect-isolation invariant. 7 routing tests and 6 isolation tests, including one that runs against a live registry |
| 4 — retire the TS kernel | Not started | `nemo/reference-kernel/` is retained as the executable specification |

Verification actually run:

```sh
cd runtimes/nemo-relay && cargo test -p nemo-crabedence-bridge -p nemo-effect-router
cd runtimes/nemo-relay && cargo clippy -p nemo-crabedence-bridge -p nemo-effect-router --all-targets -- -D warnings
cd runtimes/nemo-relay && cargo fmt -p nemo-crabedence-bridge -p nemo-effect-router -- --check
cd runtimes/nemo-relay && NEMO_CRABEDENCE_LIVE_SOCKET=<socket> \
  NEMO_CRABEDENCE_LIVE_GRANT=<grant> \
  cargo test -p nemo-crabedence-bridge -p nemo-effect-router -- --nocapture
go test ./internal/execution/ -count=1
go test ./internal/cli/ -run 'TestExec' -count=1
go test ./cmd/nemo-runtime-digest/ -count=1
node --test scripts/generate-release-evidence.test.js scripts/release-adversarial.test.js
npm test --prefix nemo
scripts/check-docs.sh
```

`go run ./cmd/nemo-runtime-digest` prints the shipped runtime identity, and
`go run ./cmd/nemo-runtime-digest -envelope` prints it with the inputs it
covers and the version the workspace declares.

The live run drove the real kernel end to end: the bridge verified the
service's own `capabilities.json`, refused a tampered copy of it, refused a
locally-routed capability without a socket hop, received the kernel's
`UNAUTHORIZED` denial for a grant-requiring mutation, and — with an issued
grant — committed a mutation with `SUCCEEDED` and receipt version 3 evidence.

## Findings recorded during implementation

1. **`FAILED` without `definitive_failure` is not a failure.** The kernel's own
   post-dispatch table maps bare `FAILED` to `UNKNOWN`. The NEMO TypeScript
   compatibility layer maps bare `FAILED` to `FAILED`, which claims more
   certainty than the kernel does. The bridge follows the kernel; the
   TypeScript layer should be corrected so the two planners agree about the
   same effect.
2. **`crabbox exec` was permissive where the socket is strict.** The stdin
   bridge used a plain `json.Unmarshal`, which silently drops unknown fields,
   keeps the last duplicate key, and — because its local authority type only
   declared `grant_id` — discarded the stable `authority_ref` spelling
   entirely. A planner could send a route override and be told `UNAUTHORIZED`
   instead of "unknown field", and a valid `authority_ref` was lost. Fixed:
   the bridge now parses with the shared strict parser
   (`execution.ParseInvocationRequest`), and regression tests cover the
   refusal and the stable field.
3. **No grant-issuing path for the SQLite backend.** `cmd/issue-grant` opens
   PostgreSQL only, while the default single-host backend is SQLite
   (`authority.NewSQLiteStore`). Exercising any grant-required capability
   locally therefore needs a helper that uses the store directly.
4. **The built-in registry cannot exercise every gate scenario.** It carries no
   CRITICAL capability, and only one CRABEDENCE-routed mutation
   (`test.counter.increment`); `system.echo` and `system.info` are pinned
   `LOCAL` and `DIRECT`. The "NEMO → Crabedence PURE / READ / CRITICAL" gate
   scenarios need registry entries pinned to the `CRABEDENCE` route.
5. **The sketched ABI additions would be a breaking change.** The consolidation
   sketch proposes a request carrying `abi_version` and `request_id` with
   `principal` and `authority_ref` at the top level. The frozen contract has no
   `abi_version` field — `docs/spec/capability-invocation-abi.md` says so
   explicitly — and nests identity under `authority`. Because the parser
   refuses unknown fields rather than ignoring them, a request carrying
   `abi_version` is **rejected**, not tolerated: every existing client would
   break at once, and the conformance corpus would fail. The frozen contract's
   stability guarantee permits additive changes only. If those fields are
   wanted, they are a v2 decision requiring a new schema, a new corpus, and
   coordinated changes in all three implementations; the schema published here
   describes v1 as it runs.
6. **NeMo Relay's `BackendRouter` cannot carry consequential execution.** The
   kernel's authority path is NeMo-Relay-shaped, and every one of its outcomes
   either requires NeMo Relay to hold the authority or refuses:
   `Granted` needs a `VerifiedGrant` that passes `verify_grant` and
   `grant.binds()` (plus an `approval_reference` for CRITICAL);
   `Deferred` is an **error** — `pending_after_authority_failure`, the
   invocation does not proceed (`crates/core/src/kernel.rs:1526`); `Denied`
   and `Modify` cancel the action. Only `FastPath` — `PURE` and `READ` — runs
   without authority (`:1400`, `:710`).

   So composing the bridge into the kernel's `effect_fabric` slot with a
   "deferring authority shim" does not work: a deferring shim blocks every
   consequential invocation, and a shim that fabricates a `VerifiedGrant` to
   let requests through makes NeMo Relay the authority — precisely what the
   ownership matrix forbids.

   The composition point is therefore **above** the kernel: `EffectRouter` is
   the entry point, NeMo Relay's kernel serves the local path, and no
   consequential invocation reaches the kernel's authority path at all. This
   is the design the router already implements; it is recorded here because
   the obvious composition (put the port in the kernel's effect slot) is the
   wrong one.
7. **NeMo Relay forwarded cloud credentials into MCP subprocesses — fixed.**
   The containment argument for plugins ("credentials live behind Crabedence's
   provider processes") was not true of the tree. `crates/cli/src/mcp_environment.rs`
   forwarded credential material two ways: `prefix_allowed` includes `AWS_`, so
   *any* ambient `AWS_*` variable reached a subprocess, and
   `BASE_MCP_ENV_VARS` listed the credential names explicitly —
   `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, the
   shared credentials and config files, the web-identity token file, and the
   container credential endpoints. The base allowlist also bypassed the
   blocklist, so `BLOCKED_MCP_ENV_VARS` could not have stopped it.

   The patch removes those names from the allowlist, adds them — plus the
   Crabedence, GitHub, and OpenComputer credential names — to
   `BLOCKED_MCP_ENV_VARS`, and makes the blocklist authoritative over the base
   allowlist. Region and endpoint configuration still flows. A checked-in
   manifest (`integrations/coding-agents/codex/.mcp.json`) is regenerated to
   match, because a test asserts the two agree.

   Verified: `scripts/check-nemo-credential-isolation.sh` asserts the plugin
   path is silent *and* that the blocklist covers every credential name; the
   module's unit tests pin the behavior; and the crate's full library suite
   passes (1338 tests).

   Two limits, stated rather than implied. `HOME` is still forwarded, so a
   subprocess can read `~/.aws/credentials` if the operator has one there —
   closing that is a deployment property. And
   `crates/core/src/observability/plugin_component.rs` (the S3 observability
   destination) still reads an operator-configured credential: that is an
   explicit deployment choice for a NeMo Relay feature, the same shape as
   Crabedence reading its own store credential, not ambient inheritance into a
   plugin. Removing it would remove the exporter.

## Consolidation roadmap

The transfer is one part of a larger consolidation. This table maps the
consolidation phases onto the state of this repository. The ordering principle
is integrate → prove equivalence → prune: nothing is deleted before its
replacement is proven.

| Consolidation phase | State |
| --- | --- |
| 0 — freeze architectural ownership | Done: the ownership matrix is a repository invariant in ADR-003 §1 |
| 1 — repository layout | Done for the transfer: `runtimes/nemo-relay/` with its Cargo workspace intact and the Go module untouched. The root-level `bridges/` directory does not exist; the bridge lives inside the NEMO workspace because Cargo refuses a workspace member outside the workspace root (see Packaging decision) |
| 2 — freeze the TS NEMO as the reference implementation | Done: `nemo/reference-kernel/` |
| 3 — freeze one capability invocation ABI | Done for the frozen contract: `schemas/capability-invocation-v1.json`, bound by tests in all three implementations. The sketched additions are a breaking change — see finding 5 |
| 4 — Rust bridge | Done |
| 5 — preserve uncertainty semantics | Done |
| 6 — make the registry authoritative | Done |
| 7 — route NEMO execution by effect class | Done: `EffectRouter` resolves the path from the verified route rather than the class, so a `READ` pinned to `CRABEDENCE` crosses the kernel instead of taking the local path, and an unwired read path fails closed. The router is the composition point; composing into the kernel's authority path is not merely unwired but wrong — see finding 6 |
| 8 — native plugin isolation and credential containment | Done for the inheritance path: the MCP environment allowlist no longer forwards credential material, and the plugin host, native loader, and integration crates are credential-free — both asserted in CI. Limits are recorded in finding 7 |
| 9 — demote the overlapping NEMO subsystems | Done for the dependency graph, which is the step that must come first: `nemo-relay`, `types`, `adaptive`, `plugin`, `plugin-protocol`, `plugin-proto`, `plugin-host`, `native-abi`, `worker`, `worker-proto`, and `pii-redaction` depend on none of `authority`, `ledger`, `executor`, `effect-runtime`, or `effect-qualification`. `scripts/check-nemo-runtime-dependencies.sh` enforces it in CI and fails closed (verified by falsification). The integration crates do depend on `executor` — and therefore `ledger` — because the `ExecutionBackend` seam lives there; that exception is deliberate and recorded. Marking the crates deprecated, moving their interoperability tests, and deleting them is the follow-up |
| 10 — one authority chain for qualification | Not started |
| 11 — remove the TS mini-kernel | Not started, and correctly gated. The reference kernel carries 150 tests covering catalog resolution, schema validation, framing, snapshot verification, and adversarial cases; the Rust path covers the ABI, the snapshot, framing, and outcome mapping, but not the kernel's catalog and schema behavior. Deleting it now would delete the specification rather than a duplicate |
| 12–13 — provider SDK and generated code | Not started. This is a refactor of ~80 provider packages under `internal/providers/` and cannot be completed without changing provider dispatch semantics; the plan's own caution ("do not force providers into one generic abstraction where semantics differ") is the reason to do it incrementally |
| 14 — shrink the trusted computing base | Not started (measurement) |
| 15 — cross-language golden vectors | Partial: the invocation corpus, the schema binding, and the outcome corpus are shared and enforced in all three languages; the receipt, digest, and snapshot vector families are not |
| 16–17 — adversarial bypass and boundary-failure tests | Partial: the bypass tests exist at the bridge and router level (class downgrade, route override, unregistered capability, unwired read path, effect isolation), the live kernel checks pass, and the duplicate-effect property is verified across a restart; the wider crash, partition, and late-response matrix does not exist on the NEMO side |
| 18–19 — shadow mode and progressive cutover | Not started, gated on 11 and 17 |
| 20–23 — delete dead architecture, unify tooling and CI, platform profiles | Not started, gated on 18–19 |

## Release blockers

The consolidation's own completion criteria, against the current state:

| # | Blocker | State |
| --- | --- | --- |
| 1 | Full Rust NEMO consumes the digested capability snapshot | Met: `capability_snapshot.rs`, verified against the live service's own `capabilities.json`, tamper-refused |
| 2 | Rust NEMO talks through the frozen invocation ABI | Met: `transport.rs` + `abi.rs`, corpus-exact |
| 3 | NEMO cannot authoritatively select class or provider route | Met: the wire carries neither, the schema refuses them, and the kernel denies a mismatch |
| 4 | Post-dispatch ambiguity becomes `UNKNOWN` | Met: `outcome_mapping.rs`, including bare `FAILED` |
| 5 | All mutations pass through Crabedence | Met at the routing layer: `EffectRouter` + the effect-isolation invariant, which passes against the live registry |
| 6 | Native plugins cannot directly reach provider credentials | Met for the inheritance path: the MCP environment allowlist no longer forwards credential material (finding 7), the plugin host, native loader, and integration crates are credential-free, and both halves are asserted in CI. Two limits are stated rather than implied: `HOME` still permits reading `~/.aws/credentials`, and NeMo Relay's own S3 observability exporter holds an operator-configured credential |
| 7 | NEMO and Crabedence share protocol golden vectors | Met for invocation, schema, and outcomes: the ABI corpus, the schema binding, and the outcome corpus are all shared and enforced across Go, TypeScript, and Rust. Receipt and digest vector families are still uncovered |
| 8 | Restart and crash tests prove no duplicate consequential effects | Met for the property that matters: a repeated idempotency key replays rather than duplicating, verified against the live kernel across a full service restart with a fresh planner process. The wider crash and partition matrix is still not exercised from the NEMO side |
| 9 | The old TypeScript kernel is no longer required | Not met, deliberately: it is still the only executable specification for kernel catalog and schema behavior |
| 10 | NEMO's duplicate runtime is absent from the production dependency graph | Met: asserted in CI |
| 11 | Provider common infrastructure has begun moving into a shared SDK | Not met |
| 12 | A CI assertion proves no consequential bypass path exists | Met: `tests/effect_isolation.rs` and `tests/routing.rs` run in the `NEMO integration` job |
| 13 | Release artifacts identify exact NEMO and Crabedence source revisions | Met: the release evidence generator runs `cmd/nemo-runtime-digest` and writes `nemo-runtime.json` and `nemo-runtime.sha256` into the bundle, which `SHA256SUMS`, the manifest digest, and the attestation already cover. The Crabedence revision is bound by the source commit and the registry digest; the NEMO revision is now bound too. The frozen gate registry is untouched — the digest is evidence, not a new gate |
| 14 | Security qualification passes for the shipping binaries | Not a NEMO-transfer deliverable, and stated as such rather than left ambiguous. The repository's shipping binaries are Go, and their security qualification is the existing typed release-gate set (`scripts/lib/qualification-gates.sh`, `release-qualification.yml`), which is frozen and managed by the repository's own release process — not something the transfer should extend by inventing gates. What the transfer contributes is the NEMO-side security assertions, which run in CI (`tests/effect_isolation.rs`, `tests/routing.rs`, the credential and dependency-graph checks) and are now bound into release evidence by blocker 13. Wiring those checks into the typed gate set is a release-engineering change, gated by that process |

## Target layout

```text
crabedence/
├── cmd/                      # unchanged
├── internal/                 # unchanged (kernel, registry, effect fabric)
├── nemo/                     # TS compatibility kernel — retained until Phase 4
├── runtimes/
│   ├── aws-lambda-microvm/   # unchanged
│   └── nemo-relay/           # FULL NEMO, upstream tree preserved
│       ├── crates/           # core, plugin, plugin-host, native-abi,
│       │                     # native-loader, adaptive, worker, ...
│       ├── bridges/
│       │   └── nemo-crabedence/   # the bridge (workspace member)
│       ├── python/
│       ├── integrations/
│       └── security/
└── worker/                   # unchanged
```

### Packaging decision and a verified constraint

The bridge is a member of NEMO's Cargo workspace, which fixes its location:
**`runtimes/nemo-relay/bridges/nemo-crabedence/`**.

A crate at a repository-root `bridges/nemo-crabedence/` cannot be a member of
the workspace rooted at `runtimes/nemo-relay/Cargo.toml`. Cargo refuses it in
both mechanisms, verified with cargo 1.95.0:

- `members = ["../../bridges/nemo-crabedence"]` fails with
  *"workspace member is not hierarchically below the workspace root"*;
- `workspace = "../../runtimes/nemo-relay"` in the bridge's own manifest fails
  with *"current package believes it's in a workspace when it's not"*, and the
  suggested fix (adding it to `members`) hits the first error.

The root-level `bridges/` directory from the original layout sketch is
therefore realized inside the vendored tree. If a second, non-NEMO bridge ever
appears, it can live at the repository root as a standalone crate; the
NEMO bridge cannot.

Upstream NEMO updates remain a pull: the vendored tree differs from upstream
only by the `bridges/nemo-crabedence` entry in the workspace `members` list and
that new directory. Re-applying both after an upstream refresh is the
documented update procedure.

## Phase 0 — vendor the NEMO runtime (done)

Deliverable: `runtimes/nemo-relay/` containing the full NEMO source, workspace
intact, no build artifacts.

- Copy with exclusions: `target/`, `.git/`, `node_modules/`, `.venv/`,
  `.uv-cache/`, `dist/`, editor and OS state.
- Preserve the workspace: `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`,
  `justfile`, `crates/`, `python/`, `go/`, `integrations/`, `docs/`,
  `qualification/`, `security/`, `scripts/`.
- Do not scatter crates. Nothing outside `runtimes/nemo-relay/` imports a NEMO
  crate except the bridge.
- Record provenance: the upstream commit or tag the copy came from, in
  `runtimes/nemo-relay/TRANSFER-PROVENANCE.md`.

Verification:

```sh
ls runtimes/nemo-relay
test ! -d runtimes/nemo-relay/target
cd runtimes/nemo-relay && cargo metadata --format-version 1 --no-deps >/dev/null
cd runtimes/nemo-relay && just test-rust   # upstream suite still green
```

## Phase 1 — the bridge (done)

Deliverable: `runtimes/nemo-relay/bridges/nemo-crabedence/`, a deliberately
tiny crate. One responsibility per module:

| Module | Responsibility |
| --- | --- |
| `abi.rs` | The strict invocation-ABI scanner (rules R1–R8), a Rust mirror of the Go parser and the NEMO TypeScript validator. Added beyond the original sketch because the transport must refuse to emit a request the kernel would refuse, and because the conformance corpus is only meaningful when all three implementations scan it. |
| `transport.rs` | Length-prefixed JSON client for the Unix socket: 4-byte big-endian length, 4 MiB cap, canonical default socket resolution matching `crabbox serve-exec`/`crabbox invoke`. A failure before the request frame is fully transmitted is a definitive pre-dispatch failure; a lost or late response after transmission is `UNKNOWN`. |
| `capability_snapshot.rs` | Envelope loader: read `capabilities.json`, base64-decode, SHA-256, constant-time compare, and only then parse descriptors. Fail closed on any mismatch. Rust mirror of `nemo/reference-kernel/snapshot.ts`. |
| `execution_port.rs` | `NemoCrabedenceExecutionPort` implementing `nemo_relay_executor::unstable::ExecutionBackend`. Maps `ExecutionRequest` → ABI request; deliberately drops `route_digest`, `registration_digest`, policy material, and never sends route/provider/assurance/receipt fields. |
| `outcome_mapping.rs` | Response → `ExecutionResult` / `EffectExecutionError` per the table in ADR-003 §6, so `state_for_error` classifies identically to the kernel. `IN_FLIGHT` maps to `UNKNOWN`. |

The bridge does not implement `ReconciliationProvider`: the socket ABI exposes
no reconciliation call, and Crabedence owns reconciliation. UNKNOWN is
terminal-pending at the NEMO boundary.

Verification:

```sh
cd runtimes/nemo-relay && cargo test -p nemo-crabedence-bridge
```

plus the env-gated live suite (`tests/live_socket.rs`), which runs against a
real `crabbox serve-exec`: it verifies the service's own snapshot, refuses a
tampered copy, refuses a locally-routed capability, maps the kernel's
`UNAUTHORIZED` denial, and — with an issued grant — commits a mutation.

## Phase 2 — trust enforcement (partial)

Deliverable: NEMO routes on the verified catalog and cannot bypass the kernel.

- NEMO startup loads and verifies the snapshot before any routing decision; a
  digest mismatch fails startup.
- NEMO's routing metadata is derived from the verified descriptors — it never
  defines an execution class itself.
- Class-downgrade refusal: a request asserting `PURE` for a `MUTATION`
  capability is denied by the kernel (server-side) and surfaced as `DENIED`,
  never executed.
- Route-override refusal: no bridge code path can place a route, provider, or
  assurance field on the wire.
- Plugin invariant: a plugin cannot register a consequential local callback.
  `MUTATION`/`CRITICAL` requests from plugin code must cross the bridge;
  `native-loader` is never linked into the kernel process.
- The CI invariant test: **no execution path from NEMO can produce an external
  MUTATION or CRITICAL effect without entering Crabedence's execution kernel.**

Verification:

```sh
cd runtimes/nemo-relay && cargo test -p nemo-crabedence-bridge
go test ./internal/execution/... ./internal/capability/...
```

## Phase 3 — conformance and release gate (partial)

Deliverable: the Rust bridge and the TypeScript compatibility kernel accept and
reject identically, and the release gate passes.

- Run `internal/execution/testdata/invocation-abi-conformance/vectors.json`
  against the Rust bridge's request construction and response parsing; a
  vector accepted by one runtime and rejected by the other is a failure.
- Bind the registry digest into release evidence as the TS layer already does.
- The release gate scenarios, all required before the transfer is complete:

```text
NEMO → Crabedence PURE / READ / MUTATION / CRITICAL
plugin host crash, hang, malformed plugin reply
plugin registration rejection
class downgrade attempt, route override attempt
invalid authority, expired authority
duplicate idempotency key, concurrent duplicate action
pre-dispatch disconnect, post-dispatch disconnect
UNKNOWN reconciliation
receipt tampering, capability snapshot tampering
registry digest mismatch
provider crash
Crabedence restart, NEMO restart, both restarted
```

## Phase 4 — retire the TypeScript kernel (not started)

Only after the full NEMO runtime passes the same behavioral tests:

- Delete `nemo/reference-kernel/` and the adapter's kernel-side duplication.
- Retain the lightweight TypeScript client: Node applications still need to
  invoke Crabedence, and the client is not the kernel.

## Verification for this document

```sh
scripts/check-docs.sh
```

## Open decisions

1. **Upstream sync cadence** for `runtimes/nemo-relay/` — a pinned upstream
   tag refreshed deliberately, or a tracked branch. The provenance file must
   record whichever is chosen.
2. **Reconciliation ABI** — whether NEMO ever needs a nonterminal status or
   reconciliation call over the socket. Additive only, and only when a real
   polling need exists (ADR-003 §6).
3. **NEMO's `authority`/`ledger` crates** — keep compiling (recorded in
   ADR-003 as non-authoritative) or delete once no build target references
   them. Deletion is a follow-up, not part of this transfer.
4. **The TypeScript layer's `FAILED` mapping** (finding 1) — correct it to
   honor `definitive_failure`, so both planners classify the same effect
   identically. Leaving it makes the compatibility layer the weaker of the
   two.
5. **Grant issuance on SQLite** (finding 3) — extend `cmd/issue-grant` to the
   default backend, or document the helper path. Without one of these, the
   grant-required gate scenarios cannot be exercised on a single-host
   deployment.
6. **Registry coverage for the gate** (finding 4) — the PURE/READ/CRITICAL
   "NEMO → Crabedence" scenarios need capabilities pinned to the `CRABEDENCE`
   route; the built-in registry has none outside one mutation.
