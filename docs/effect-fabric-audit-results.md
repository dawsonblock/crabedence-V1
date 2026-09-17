# Effect Fabric Audit Results — Durable Store and Provider-Proof Hardening

Status document for `feat/effect-fabric-durable-store-contracts`
(PR https://github.com/dawsonblock/crabedence-V1/pull/3), base
`release/crabedence-v1-rc6-qualified-execution`.

Scope: the durable execution store (`internal/idempotency`), dispatch
executor (`internal/execution`), reconciliation worker
(`internal/reconcile`), GitHub provider adapter, and release-evidence
scripts. ~11.7k insertions across 35 files at review time.

## Review passes

Three structured review passes ran against the branch (Codex
`gpt-5.6-sol`, high reasoning; mandatory TruffleHog pre-send scan):

| Pass | Threshold | Findings | Outcome |
|------|-----------|----------|---------|
| P0   | release-blocking | 0 | scoped-clean, both bundle passes "patch is correct" (0.91 / 0.96) |
| P2   | high      | 11 (5 P1, 6 P2) | all verified against code, fixed in `c147e35` |
| P3   | all       | 8 (7 P2, 1 P3) | all verified against code, fixed in `d439d57` |

Every reported finding was re-verified against the actual code before
editing; no finding was applied blindly.

## P2 batch (`c147e35`)

- **Dispatch.** `DefinitiveFailure` can no longer fabricate signed
  `NO_EFFECT` evidence — only executor-proven pre-transmission failures
  (expired deadline before handler invocation) may synthesize an
  attestable artifact. A handler-claimed flag is a routing hint;
  CRITICAL records fail closed to `UNKNOWN`. Provider-observation write
  failures on a terminal path route to `UNKNOWN` instead of committing
  a contradicting receipt. `RecoveryRequired` now reports
  `StatusUnknown` + `FAILURE_EXECUTION_UNKNOWN` (was `StatusInFlight`,
  which invited callers to wait/retry a record under reconciliation).
- **GitHub resolver.** The silent 50-page pagination cap (markers
  beyond page 50 were unreachable) is replaced with visited-URL cycle
  detection; cycles resolve `UNKNOWN` via `pagination_truncated`.
- **Reconcile.** The claim heartbeat is bounded by the resolver
  deadline — a wedged resolver can no longer hold its claim forever.
  A resolver's `RecoveryFailed` + `Result` payload is no longer
  promoted into signed `NO_EFFECT` evidence.
- **Store.** `ensureSchema` reads the schema version through its
  already-held connection, fixing a deadlock under `MaxOpenConns(1)`.
- **Release scripts.** `go-race-*`, `provider-*`, and
  `cross-language-conformance` gates are now classified as test gates
  in both `check-release-admission.sh` and manifest aggregation;
  `tests_executed` no longer counts `SKIP` results, and
  `TOTAL_TESTS_SKIPPED` is actually computed.

## P3 batch (`d439d57`)

- **Observation monotonicity on recovery.** `ResolveRecovery` previously
  overwrote `provider_id`/`provider_run_id` unconditionally — a resolver
  could silently replace a durable provider identity. The update is now
  guarded: contradictory identity rejects with
  `PROVIDER_OBSERVATION_CONFLICT`; empty resolver fields preserve stored
  values via `COALESCE`. Result/evidence payloads stay resolver-owned —
  recovery legitimately produces a different evidence capture than the
  dispatch-time observation (listing object vs. create response), which
  the `crash_during_finalize_recovers` live test proves.
- **Pre-dispatch abandon.** Every failure before the dispatch boundary
  (`BeginExecution`, locator preparation/marshal/size, `MarkInFlight`)
  now calls `AbandonPreDispatch` — the record returns to lease-less
  `PREPARED` and retries reacquire immediately instead of stranding an
  `EXECUTING` lease until expiry.
- **Deadline preflight before `MarkInFlight`.** An already-expired
  request is abandoned to `PREPARED` with a definitive FAILED — a crash
  between the old `MarkInFlight` and the deadline check could strand a
  provably-never-dispatched record in `UNKNOWN`. The in-dispatch check
  remains for the residual race window.
- **Counter recovery replays the execution's own value.**
  `CounterExecution.Value` stores the post-increment value at execution
  time; `Resolve` returns it instead of the live aggregate, so a later
  increment no longer changes an older execution's recovered result.
- **Strict trailing-JSON rejection.** `canonicalizeJSON` requires
  `io.EOF` after the first value — `Decoder.More()` reported
  end-of-input at `]`/`}`, accepting malformed input like `{"a":1}}`.
- **Schema-scoped invalid-index detection.** `ensureValidIndex` joins
  `pg_namespace` and filters on `current_schema()` — a same-named index
  in another schema can no longer mask an invalid one.
- **Batch-wide reconcile claim heartbeat.** `reconcileAll` renews every
  claimed record's lease for the batch duration — a slow head resolver
  can no longer let queued claims expire and be stolen mid-batch.
- **Exact attempt ceiling.** `reconcileOne` suspends a record claimed
  past `maxAttempts` *before* invoking the resolver, and the record
  suspends once the last allowed attempt ran — `maxAttempts=N` now
  bounds provider lookups to at most N.

## Verification

- `gofmt` / `go vet` clean on all touched packages.
- `go test -race -count=1` — `internal/idempotency`,
  `internal/reconcile`, `internal/execution` all pass.
- `./scripts/test-live-postgres.sh` (ephemeral local PostgreSQL,
  initdb fallback) — all four live suites pass under `-race`:
  `internal/idempotency`, `internal/reconcile`, `internal/execution`,
  `internal/authority`.
- `node --test scripts/test-live-postgres.test.js` — 4/4 (Docker
  fallback, existing-URL passthrough, default command).

## Regression coverage added this pass

- Trailing-JSON table test (`{"a":1}}`, `1]`, second values, garbage).
- Per-execution counter recovery value (A resolves to its own
  post-increment value after B advances the same counter).
- `ResolveRecovery` observation conflict + field preservation.
- Expired-deadline abandon to `PREPARED` + successful retry.
- Pre-dispatch locator-failure abandon + successful retry.
- Exact claim-ceiling enforcement (resolver never invoked past the
  bound; invoked exactly on the last allowed claim).
- Batch-heartbeat protection against mid-batch claim stealing.
- Schema-scoped invalid-index repair.

## Known gaps / not yet done

- **Blacksmith remote verification** — `.crabbox.yaml` targets the
  `blacksmith-testbox` provider, but the Blacksmith GitHub App is not
  installed on `dawsonblock/crabedence-V1`, so dispatched testboxes
  queue forever. Install the app, then:
  `crabbox run --provider blacksmith --blacksmith-ref feat/effect-fabric-durable-store-contracts -- ./scripts/test-live-postgres.sh`
- **Real GitHub integration gate** — `TestRealGitHubAPI` needs
  `CRABBOX_GITHUB_TEST_TOKEN`/`CRABBOX_GITHUB_TEST_REPO`.
- **`dist/release-evidence/`** — release qualification evidence has not
  been generated for this branch.

## Commits

- `5883952` — residual provider-truth, evidence, reconcile-churn gaps
- `c147e35` — evidence-fabrication and reconciliation gaps (P2)
- `c9a536c` — `scripts/test-live-postgres.sh` ephemeral live-test DB
- `d439d57` — pre-dispatch, observation-monotonicity, claim-lifecycle (P3)
