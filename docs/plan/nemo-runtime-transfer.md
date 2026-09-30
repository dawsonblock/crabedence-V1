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
| The TypeScript compatibility kernel was the executable spec, and is now retired | what remains: `nemo/registry-snapshot/snapshot.ts` (verify-then-parse), `nemo/contracts/`, `nemo/adapters/crabedence/` |
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
| 2 — trust enforcement | Partial, and advanced. Bridge-level invariants enforced and tested (unregistered capability, class mismatch, route mismatch, no policy field on the wire), the effect-isolation invariant holds at the router, and both run in CI. A **runtime instance** now exists: `bridges/nemo-crabedence-runtime` is a process that verifies the snapshot, resolves the class and route from it, and dispatches through `EffectRouter` — verified end to end (PURE routed locally, MUTATION committed through the kernel with evidence, a missing grant refused as non-retryable, an unregistered capability refused before any socket hop, and a tampered snapshot refused before routing). What is *still* absent is the plugin host: `crates/plugin-host` is not wired to this runtime, so a plugin cannot yet reach the router, which is why the plugin-host gate scenarios remain open. This row previously named NEMO's `BackendRouter` wiring as the remainder, which finding 6 corrected: that composition is not merely unwired, it is the wrong one |
| 3 — conformance | Partial | The Rust validator matches the shared invocation corpus exactly (11 accepted, 32 rejected), the live kernel's refusal phrases match word-for-word, and the outcome corpus is shared across Go, TypeScript, and Rust. Covered against the live kernel from the NEMO side: a LOCAL-route refusal, a MUTATION commit with evidence, missing authority (`UNAUTHORIZED`), an unresolvable authority reference (`UNAUTHORIZED`, definitive and non-retryable), an expired authority reference (`UNAUTHORIZED`, definitive and non-retryable), a lost response mapping to `UNKNOWN`, snapshot tampering, same-key replay, and a CRITICAL commit carrying evidence. Two of these need orchestration the Rust test cannot own, so scripts hold the timing and the tests assert only the outcome: `scripts/test-nemo-expired-authority.sh` issues a short-lived grant, lets it lapse, then asserts the refusal; `scripts/test-nemo-restart-idempotency.sh` dispatches twice, restarts the kernel on the same store, dispatches twice again with the same key, and asserts one effect. Neither test sleeps on a clock. Not covered, and each for a stated reason: plugin host crash, hang, malformed reply, and registration rejection have no NEMO plugin host in the integration path — a runtime instance now routes through `EffectRouter`, but `crates/plugin-host` is not wired to it, so there is nothing hosting a plugin to crash or hang; provider crash is qualified Go-side by the kernel's own crash-point matrix, which SIGKILLs real provider processes; CRITICAL is now covered end to end by `scripts/test-nemo-critical-path.sh`, which wires the qualification provider so the bridge's evidence rule meets a real commit; the PURE and READ crossings are not, because the qualification extension adds only CRITICAL and no capability is pinned to the `CRABEDENCE` route for those classes — see finding 4 |
| — reference kernel | Retired | Renamed to `nemo/registry-snapshot/`, decoupled from the loader, then deleted once the suite passed without it; the README now records where each removed behavior lives |
| — canonical schema | Done | `schemas/capability-invocation-v1.json` describes the frozen wire contract; Go, TypeScript, and Rust each carry a test that binds their implementation to it, so a field added on one side and not the others fails CI |
| — effect router | Done at the routing layer | `runtimes/nemo-relay/bridges/nemo-effect-router/`: `EffectRouter` resolves the path from the verified **route** (not the class, which is what NeMo Relay's own router uses), fails closed on an unwired read path, and holds the effect-isolation invariant. 7 routing tests and 6 isolation tests, including one that runs against a live registry |
| 4 — retire the TS kernel | Done | The kernel is deleted. `nemo/` holds the ABI contracts and validator, the registry-snapshot loader, and the adapter and client. 119 tests across 9 files pass |

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
3. **No grant-issuing path for the SQLite backend — fixed.** `cmd/issue-grant`
   opened PostgreSQL only, while the default single-host backend is SQLite
   (`authority.NewSQLiteStore`), so exercising any grant-required capability
   locally needed a helper that used the store directly. The tool now selects
   its backend from the environment — `CRABEDENCE_DATABASE_URL` for PostgreSQL,
   `CRABEDENCE_STORE_PATH` for SQLite, PostgreSQL winning when both are set —
   which mirrors how `serve-exec` is started, so a grant issued here is
   resolvable by the service started the same way. Verified end to end: a grant
   issued by the tool against SQLite was accepted by a running service and
   committed a mutation through the Rust bridge.
4. **The built-in registry cannot exercise every gate scenario — CRITICAL is
   now covered, PURE/READ are not.** The release registry carries no CRITICAL
   capability and only one CRABEDENCE-routed mutation
   (`test.counter.increment`); `system.echo` and `system.info` are pinned
   `LOCAL` and `DIRECT`.

   **Correction.** This finding previously claimed the qualification registry was
   digest-only with no runtime gate, and that closing CRITICAL would need a new
   qualification mode on the service. That was wrong. The gate already exists:
   `CRABEDENCE_QUAL_PROVIDER_URL` wires the external qualification provider
   (`cmd/qual-provider`) and registers `qualification.critical.commit` as an
   explicit extension of the release registry, failing closed if the provider is
   unreachable. `scripts/test-nemo-critical-path.sh` starts that provider and a
   service using it, issues a grant, and dispatches the CRITICAL capability
   through the Rust bridge — which is the only check that exercises the bridge's
   `requires_evidence` rule against a real commit rather than a fixture. It
   passes, with a real evidence digest.

   **A third correction, and it shrinks the gap.** "NEMO → Crabedence PURE" is
   not an uncovered scenario — it is an invalid one. The frozen ABI spec states
   it outright: "PURE capabilities do not cross the Crabedence execution
   boundary. They execute in the planner or function hooks layer. PURE is part
   of the capability vocabulary but not a Crabedence execution path"
   (`docs/spec/capability-invocation-abi.md`). The gate list carried it as a
   scenario to satisfy, which no registry entry could ever do; the list is
   corrected. Only "NEMO → Crabedence READ" remains genuinely uncovered, and it
   mirrors a real deployment shape (`READ` + `HIGH_ASSURANCE` → `CRABEDENCE`,
   the `gmail.message.read` example in the trust model).

   On that remaining one — **a second correction**: an earlier revision of this
   finding called it
   "a registry-coverage gap of one or two descriptors, not a service change".
   Reading the surface shows otherwise. The qualification extension is
   deliberately *singular*: `QualificationRegistryExtensionID` is one constant,
   `RegisterQualificationCapabilities` refuses to register anything that would
   replace a release descriptor, and `QualificationRegistryExtensions` returns a
   one-element record that `cmd/registry-digest` writes into
   `qualification-registry-extensions.json`. That record is bound into release
   evidence and validated by the release gates, so adding PURE and READ
   descriptors would change a release-evidence artifact and the qualification
   registry digest. It is a qualification-policy decision, not a fixture.

   It is also a smaller hole than the gate list implies. The property those
   scenarios exist to prove — that the **route**, not the class, chooses the
   path — is already covered at the layer that decides it: `tests/routing.rs`
   pins a `READ` capability pinned to `CRABEDENCE` crossing the kernel, and a
   `PURE` capability pinned `LOCAL` staying home. What is absent is a live
   capability to dispatch those two classes over the wire, which is why the gap
   is stated rather than closed.
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

8. **The reference kernel derived execution routes locally, and its comment
   claimed a parity that did not hold.** `defaultExecutionRoute(executionClass)`
   was documented as mirroring the Go registry's `DefaultExecutionRoute` — "the
   same policy function". It does not. The Go table is keyed on the *assurance
   profile* (`NONE` → LOCAL, `STANDARD` → DIRECT, `DURABLE` and
   `HIGH_ASSURANCE` → CRABEDENCE); the TypeScript one was keyed on the
   *execution class* (`PURE` → LOCAL, `READ` → DIRECT, otherwise CRABEDENCE).
   For a `READ` + `HIGH_ASSURANCE` capability they disagree outright: the
   registry routes it to the kernel, and the local table routed it to the
   direct path.

   Latent in production, because a verified snapshot always carries a pinned
   route — but reachable through `CapabilityCatalog`, and precisely what the
   trust model forbids: "the kernel must resolve descriptors from the
   authoritative registry and route on the trusted `execution_route`, never on
   a separately maintained classification."

   Fixed by deletion rather than correction. `defaultExecutionRoute` and the
   `??` fallback are gone, and `register` refuses a descriptor that declares no
   route. There is no second classification left to drift, and the Rust
   `EffectRouter` already behaves this way — an unregistered capability or an
   unpinned route fails closed — so the two sides now agree by construction.
   Seventeen test descriptors were given explicit routes (four in
   `kernel.test.ts`, five in `schema.test.ts`, eight in `adversarial.test.ts`),
   and the test that asserted the old fallback now asserts the refusal.

## Consolidation roadmap

The transfer is one part of a larger consolidation. This table maps the
consolidation phases onto the state of this repository. The ordering principle
is integrate → prove equivalence → prune: nothing is deleted before its
replacement is proven.

| Consolidation phase | State |
| --- | --- |
| 0 — freeze architectural ownership | Done: the ownership matrix is a repository invariant in ADR-003 §1 |
| 1 — repository layout | Done for the transfer: `runtimes/nemo-relay/` with its Cargo workspace intact and the Go module untouched. The root-level `bridges/` directory does not exist; the bridge lives inside the NEMO workspace because Cargo refuses a workspace member outside the workspace root (see Packaging decision) |
| 2 — freeze the TS NEMO as the reference implementation | Done: `nemo/registry-snapshot/` |
| 3 — freeze one capability invocation ABI | Done for the frozen contract: `schemas/capability-invocation-v1.json`, bound by tests in all three implementations. The sketched additions are a breaking change — see finding 5 |
| 4 — Rust bridge | Done |
| 5 — preserve uncertainty semantics | Done |
| 6 — make the registry authoritative | Done |
| 7 — route NEMO execution by effect class | Done: `EffectRouter` resolves the path from the verified route rather than the class, so a `READ` pinned to `CRABEDENCE` crosses the kernel instead of taking the local path, and an unwired read path fails closed. The router is the composition point; composing into the kernel's authority path is not merely unwired but wrong — see finding 6 |
| 8 — native plugin isolation and credential containment | Done for the inheritance path: the MCP environment allowlist no longer forwards credential material, and the plugin host, native loader, and integration crates are credential-free — both asserted in CI. Limits are recorded in finding 7 |
| 9 — demote the overlapping NEMO subsystems | Done for the dependency graph, which is the step that must come first: `nemo-relay`, `types`, `adaptive`, `plugin`, `plugin-protocol`, `plugin-proto`, `plugin-host`, `native-abi`, `worker`, `worker-proto`, and `pii-redaction` depend on none of `authority`, `ledger`, `executor`, `effect-runtime`, or `effect-qualification`. `scripts/check-nemo-runtime-dependencies.sh` enforces it in CI and fails closed (verified by falsification). The integration crates do depend on `executor` — and therefore `ledger` — because the `ExecutionBackend` seam lives there; that exception is deliberate and recorded. Marking the crates deprecated, moving their interoperability tests, and deleting them is the follow-up |
| 10 — one authority chain for qualification | Not started |
| 11 — remove the TS mini-kernel | Done: the kernel is deleted and the suite is green. What remains under `nemo/` is the ABI contracts and their validator, the registry-snapshot loader, and the Crabedence adapter and client — the "lightweight TypeScript packages where they are useful as clients" this phase asked to keep |
| 12–13 — provider SDK and generated code | Largely already met, and narrower than this row claimed. `internal/providers/shared` (28 source files, 5,858 lines) is the SDK and all 81 providers import it; the 102 raw `&http.Client{}` constructions are legitimate per-provider transport configuration. What remains is the redirect-hardening duplication — sixteen implementations in four categories, three of which **must not** be migrated — and generated code, neither started. See the blocker-11 classification |
| 14 — shrink the trusted computing base | Not started (measurement) |
| 15 — cross-language golden vectors | Partial: the invocation corpus, the schema binding, and the outcome corpus are shared and enforced in all three languages; the receipt, digest, and snapshot vector families are not |
| 16–17 — adversarial bypass and boundary-failure tests | Partial: the bypass tests exist at the bridge and router level (class downgrade, route override, unregistered capability, unwired read path, effect isolation), the live kernel checks pass, and the duplicate-effect property is verified across a restart; the wider crash, partition, and late-response matrix does not exist on the NEMO side |
| 18–19 — shadow mode and progressive cutover | Not started. The earlier gate (11 and 17) is partly cleared — the TypeScript kernel is retired — and a runtime instance now routes through `EffectRouter`. What still gates this is the plugin host being wired to that instance and the boundary-failure matrix |
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
| 7 | NEMO and Crabedence share protocol golden vectors | Met. Three families are shared and enforced across Go, TypeScript, and Rust: the invocation ABI corpus (43 vectors), the published schema binding, and the outcome corpus (12 vectors). The receipt and digest families this row used to list as uncovered turn out not to apply to the bridge: it consumes only the evidence *reference* — `evidence.digest`, validated as 64-hex, and `receipt_version`, required to be 3 for CRITICAL — and never the receipt structure, because Crabedence owns receipts and the bridge sets `receipt: None`. Both of those reference fields are already pinned by the outcome corpus (`evidence-digest-not-hex` rejected, `succeeded-with-evidence` accepted, and the CRITICAL evidence rule). The full receipt structure is Go↔TS conformance and Rust is deliberately not a party to it |
| 8 | Restart and crash tests prove no duplicate consequential effects | Met for the property that matters: a repeated idempotency key replays rather than duplicating, and `scripts/test-nemo-restart-idempotency.sh` proves it across a full kernel restart with a fresh planner process — dispatch twice, restart on the same store, dispatch twice again with the same key, and assert a single increment (observed value 1 in both phases, where a second effect would read 2). The NEMO side's failure surface is the transport boundary, and every class of it is classified and tested: pre-dispatch versus post-dispatch versus protocol, a response timeout, a lost response, and a truncated frame, with `UNKNOWN` kept distinct from `FAILED` throughout. The wider crash and partition matrix is the kernel's, qualified Go-side by its crash-point matrix. What is not exercised from the NEMO side is a plugin-host failure — see blocker 2, which has no plugin host in the path to fail |
| 9 | The old TypeScript kernel is no longer required | Met: the kernel is deleted. `kernel.ts`, `schema.ts`, and `testing.ts` are gone along with their two test files; the loader survives as `nemo/registry-snapshot/`, verifies on its own, and returns descriptors rather than a catalog. The suite went from 168 tests across 11 files to 119 across 9, and the difference is exactly the removed kernel behavior plus its duplicated admission tests — every one of which the Go suite covers by name |
| 10 | NEMO's duplicate runtime is absent from the production dependency graph | Met: asserted in CI |
| 11 | Provider common infrastructure has begun moving into a shared SDK | Substantially met. `internal/providers/shared` (28 source files, 5,858 lines) is that SDK and every provider except the `all` aggregator imports it — all 81. The 102 raw `&http.Client{}` constructions are legitimate per-provider transport configuration and should not be collapsed. Sixteen providers implement redirect handling themselves; reading each one showed four distinct categories, three of which **must not** be migrated to `shared.SecureHTTPClient` — one refuses all redirects, two follow none, three need their deliberate error unwrapping preserved, and one pins at the transport layer. Of the seven that are structurally equivalent, `azuredynamicsessions` is migrated: its body was a byte-for-byte copy of the helper's, and it now calls it, with the package's tests passing. The other six are the same shape and the same treatment |
| 12 | A CI assertion proves no consequential bypass path exists | Met: `tests/effect_isolation.rs` and `tests/routing.rs` run in the `NEMO integration` job |
| 13 | Release artifacts identify exact NEMO and Crabedence source revisions | Met: the release evidence generator runs `cmd/nemo-runtime-digest` and writes `nemo-runtime.json` and `nemo-runtime.sha256` into the bundle, which `SHA256SUMS`, the manifest digest, and the attestation already cover. The Crabedence revision is bound by the source commit and the registry digest; the NEMO revision is now bound too. The frozen gate registry is untouched — the digest is evidence, not a new gate |
| 14 | Security qualification passes for the shipping binaries | Not a NEMO-transfer deliverable, and stated as such rather than left ambiguous. The repository's shipping binaries are Go, and their security qualification is the existing typed release-gate set (`scripts/lib/qualification-gates.sh`, `release-qualification.yml`), which is frozen and managed by the repository's own release process — not something the transfer should extend by inventing gates. What the transfer contributes is the NEMO-side security assertions, which run in CI (`tests/effect_isolation.rs`, `tests/routing.rs`, the credential and dependency-graph checks) and are now bound into release evidence by blocker 13. Wiring those checks into the typed gate set is a release-engineering change, gated by that process |

## Target layout

```text
crabedence/
├── cmd/                      # unchanged
├── internal/                 # unchanged (kernel, registry, effect fabric)
├── nemo/                     # ABI contracts, snapshot loader, adapter and client
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
| `capability_snapshot.rs` | Envelope loader: read `capabilities.json`, base64-decode, SHA-256, constant-time compare, and only then parse descriptors. Fail closed on any mismatch. Rust mirror of `nemo/registry-snapshot/snapshot.ts`. |
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

Deliverable: the Rust bridge and the TypeScript implementations accept and
reject identically, and the release gate passes.

- Run `internal/execution/testdata/invocation-abi-conformance/vectors.json`
  against the Rust bridge's request construction and response parsing; a
  vector accepted by one runtime and rejected by the other is a failure.
- Bind the registry digest into release evidence as the TS layer already does.
- The release gate scenarios, all required before the transfer is complete:

```text
NEMO → Crabedence READ / MUTATION / CRITICAL
  (PURE does not cross: "PURE capabilities do not cross the Crabedence
   execution boundary ... not a Crabedence execution path"
   — docs/spec/capability-invocation-abi.md)
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

- Delete `nemo/registry-snapshot/` and the adapter's kernel-side duplication.
- Retain the lightweight TypeScript client: Node applications still need to
  invoke Crabedence, and the client is not the kernel.

## Verification for this document

```sh
scripts/check-docs.sh
```

## The two remaining blockers, resolved

Both were investigated against the code, and both came out smaller than the
plan claimed. Blocker 9 is **done** — the kernel is deleted and the suite is
green. Blocker 11 is **substantially already met**; what remains is one bounded
assessment.

### Blocker 9 — retired

Status: **done.** `kernel.ts`, `schema.ts`, and `testing.ts` are deleted, along
with `kernel.test.ts` and `schema.test.ts`; `snapshot.ts` survives and was
renamed with its directory to `nemo/registry-snapshot/`. The suite went from
168 tests across 11 files to 119 across 9, and the difference is exactly the
removed kernel behavior and its duplicated admission tests.

The work was sequenced as agreed: the loader was decoupled first and the suite
verified green *without* the kernel in the path, and only then were the files
removed. The loader now verifies on its own — `loadRegistrySnapshot` returns
verified descriptors rather than a catalog, so nothing downstream can derive a
route from it.

Why it was safe, kept as the record of the decision:

| Behavior | Cover after deletion |
| --- | --- |
| Capability lookup | Go service (`CAPABILITY_NOT_FOUND`) and the Rust router, which fails closed |
| Execution-class immutability | Go admission denies a mismatch; the Rust port refuses locally too |
| Idempotency key for MUTATION/CRITICAL | The Go service requires it at admission |
| Authority principal required | Go admission (`missing grant_id` → `UNAUTHORIZED`) |
| Deadline format and expiry | The Rust bridge emits only RFC3339; the service denies after expiry |
| Argument schema validation | Authoritative server-side; the NEMO-side check was defense in depth |
| Route resolution | Registry-only on both sides (finding 8) |
| CRITICAL evidence contract | The Rust `map_outcome(requires_evidence)`, against the shared outcome corpus |
| Result-schema validation | Removed with the kernel, and inert in production — `resultSchema` never travels in the registry snapshot, so it could only fire for a hand-built test catalog |

The Go tests that carry the admission behavior are named in the
[registry snapshot loader README](../../nemo/registry-snapshot/README.md).

What remains a *feature* question, not a port: if local execution is ever to
enforce result contracts, the contract has to travel in the registry snapshot
first. That is independent of the kernel's existence and is not in scope.

### Blocker 11 — the inventory exists, and the SDK is already there

The sketch proposes `internal/providerkit/`. That package already exists under
another name: **`internal/providers/shared`** — 28 source files plus tests,
5,858 lines, imported 256 times. Every provider except the `all` aggregator and
`shared` itself imports it, so all 81 real providers are already on it.

It covers the sketch's concerns almost exactly:

| Sketch concern | Existing home |
| --- | --- |
| lifecycle | `delegated.go`, `direct.go`, `process_supervisor.go`, `process_startup_confirm.go` |
| observation | `observer.go`, `status.go`, `resource_identity.go` |
| auth / config | `claim.go`, `claim_scope.go`, `claim_touch.go`, `metadata.go` |
| errors | `httpresponse.go`, `httpredirect.go`, `operationlock.go` |
| receipts / identity | `tag_labels.go`, `naming.go`, `resource_identity.go` |
| redaction | `redact.go` |
| conformance | `doctor.go`, plus per-capability tests |

And the provider contract is deliberately finer-grained than the sketch:
`internal/cli/provider_backend.go` declares `Provider` plus dozens of opt-in
capability interfaces, each documenting why it is separate — for example
`ReleaseLeaseOutcomeBackend` exists only for providers "with retained or
asynchronous release semantics". Collapsing that into one `Provider` interface
would make every provider implement operations it does not have.

So blocker 11 is **substantially already met**, and the remainder is now
specific. The 102 raw `&http.Client{}` constructions were assessed: they are
legitimate per-provider transport configuration, not boilerplate — a
control-plane client with a timeout beside a data-plane client without one, or
a custom transport. They should not be collapsed.

The duplication that *is* real is next to them. `shared/httpredirect.go`
exports `SecureHTTPClient`, which "returns a copy of source whose
`CheckRedirect` refuses redirects leaving the trusted origin, preserves
source's `CheckRedirect`, and applies net/http's default 10-redirect cap".
**Sixteen providers implement redirect handling themselves** rather than call it:

```text
awslambdamicrovm, azuredynamicsessions, blaxel, boxd,
cloudflaredynamicworkers, fastapicloud, githubcodespaces, islo, morph,
nomad, opensandbox, ovh, ... (17 total)
```

Redirect hardening written seventeen times is seventeen chances to get it
subtly wrong, and a fix to one does not reach the others. The shared helper
already accepts a provider-specific refusal error via `newError`, so the
provider-specific parts have a home.

**Migrating them is not mechanical, and a bulk pass would be wrong.** Each site
was read, and the population falls into four categories:

| Category | Providers | Why migration is not a drop-in |
| --- | --- | --- |
| Drop-in as written | `azuredynamicsessions` (**migrated**) | Its origin comparison already delegated to `shared.SameOrigin` and its body matched the helper's, so it needed no new option |
| Sentinel contracts — **migrated** once the helper could express them | `nomad`, `ovh` (**migrated**) | Each defines a redirect-limit sentinel that a consumer matches on (`errors.Is`). The helper's cap message was fixed, so migrating as it stood would have replaced a matched sentinel with a different value. `WithRedirectLimitError` closes that gap, and both now pass their sentinel in |
| Richer redirect policy | `unikraftcloud`, `scaleway` | `unikraftcloud` additionally enforces path containment (`withinUnikraftCloudAPIPath`) and refuses a method change on a mutation — checks the helper does not make, so migrating would silently drop them. `scaleway` reads a marker header its own transport sets and distinguishes three sentinels (`CrossOrigin`, `Invalid`, `Limit`), then threads a hop count through the request context |
| Host comparison differs | `sprites` (**migrated**) | `sprites` compares hosts through `canonicalSpritesHostname` (which strips IPv6 zone identifiers) and its own port helper, not `shared.SameOrigin`. `WithHostComparator` closes that gap, so it now passes its own comparison in, and its refusal text — asserted by a test — is preserved through `newError` |
| **Cap evaluated before the hook** | `islo` | Its guard checks the origin, then the cap, then the preserved hook. The helper does origin, then the hook, then the cap — so a caller-supplied hook wins over the cap there, and migrating would **loosen** islo's cap whenever a caller supplies a redirect hook. Its comparison (a normalized origin string) and its typed errors were both expressible; the ordering is what stops it |
| **Pinned to the request chain** | `awslambdamicrovm`, `blaxel` | Neither pins to a configured trusted origin. `awslambdamicrovm` compares against `via[0].URL` — the original request — and refuses when `via` is empty; `blaxel` checks the cap first and then compares against the previous hop. Both were missing from an earlier revision of this table, which named fourteen providers and called them sixteen |
| Deliberately stricter | `boxd`, `cloudflaredynamicworkers`, `githubcodespaces` | `boxd` refuses every redirect ("boxd API redirects are not allowed"); the other two return `http.ErrUseLastResponse` and follow none. Migrating would **weaken** them by permitting same-origin redirects |
| Origin-pinned with deliberate unwrapping | `fastapicloud`, `morph`, `railway` | Each unwraps its typed error at the call site, with the comment "net/http wraps CheckRedirect failures with the untrusted Location URL" — they deliberately avoid surfacing the untrusted destination. Migration must preserve that unwrapping |
| Pinned at the transport | `opensandbox` | `openSandboxRedirectTransport` intercepts the 3xx response and parses `Location` itself. A different mechanism, arguably stronger, and not a `CheckRedirect` site at all |

So the earlier claim that this is "bounded and mechanical" was wrong, and the
correction matters: a bulk migration would weaken three providers, **break the
error contracts of two**, silently drop redirect policy in two more, and change
error identity in the rest. The real duplication is smaller than the file count
suggests — **exactly one provider, not sixteen, is drop-in**, and it is
migrated.

The finding that mattered was about the helper rather than the providers:
`SecureHTTPClient` was **under-parameterized**. It could not express a
provider-specific redirect-limit error (its cap message was fixed), nor a
provider-specific host comparison (it always used `shared.SameOrigin`), and two
of the categories above existed precisely because of those two gaps.

**That is now fixed.** The helper gained `WithRedirectLimitError` and
`WithHostComparator` — variadic options, so the seven existing callers are
untouched, and covered by their own tests (defaults unchanged, a sentinel
survives, a comparator decides, the original hook still wins, the source client
is not mutated). With those in place the three providers whose only gaps were
those two are migrated: `nomad` and `ovh` pass their sentinels,
`sprites` passes its stricter host comparison. All four packages build, vet, and
test clean.

**Four of sixteen are consolidated.** What remains is not a migration backlog:
`unikraftcloud` and `scaleway` enforce redirect policy the helper does not model
(path containment, a method change on a mutation, a transport-set marker header,
three distinct sentinels), `islo` evaluates its cap before its hook where the
helper does the reverse, `awslambdamicrovm` and `blaxel` pin to the request
chain rather than a configured origin, three are deliberately stricter, three
unwrap their errors on purpose, and one pins at the transport layer. Every one
of the sixteen is now accounted for.

This is the same mistake as finding 4, made twice: classifying by the *shape* of
the code rather than by the *contract* its callers depend on. The bodies looked
alike; what differs is which sentinels something matches on and what extra
policy each provider enforces.

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
4. **The TypeScript layer's `FAILED` mapping** (finding 1) — **resolved.** The
   adapter honors `definitive_failure`, and the shared outcome corpus pins the
   rule for the TypeScript adapter and the Rust bridge alike.
5. **Grant issuance on SQLite** (finding 3) — **resolved.** `cmd/issue-grant`
   selects PostgreSQL or the embedded SQLite store from the environment, so the
   grant-required gate scenarios can be exercised on a single-host deployment
   without a helper.
6. **Registry coverage for the gate** (finding 4) — the PURE/READ/CRITICAL
   "NEMO → Crabedence" scenarios need capabilities pinned to the `CRABEDENCE`
   route; the built-in registry has none outside one mutation.
