# RC7.5 Qualification Report

**Candidate:** `0.54.0-rc.7.5-dev` — **development** build. Not
qualified. The `qualified` name and tag are reserved until every
mandatory gate below reads verified on this exact tree.

## Gate ledger

| Gate | Criterion | Result | Evidence |
|---|---|---|---|
| 0 | Baseline identity, call sites, invariants | **PASS** | `rc75-evidence/` baseline snapshot; `docs/security/RC75_INVARIANTS.md` |
| 1 | No production cleanup path destroys by reusable name; substituted-VM test passes against the real mechanism | **PASS** | `cleanup_identity_test.go` — substitution, wrong-nonce, missing-identity, transport-uncertain, reopen, independence all green |
| 2 | Stale claimants cannot commit protected state or unapproved effects | **PASS** | `recovery_fence_test.go` — 50-claimant race, takeover-mid-flight, stale release/transition/extend, `TestStaleClaimCannotClearCleanup` |
| 3 | Invalid evidence cannot normalize into a pass | **PASS** | `go-test-case-evidence.test.js` — 60 tests, 16 fixtures; fabricated-valid stream accepted structurally, rejected as evidence |
| 4 | Committed recovery history has verifiable continuity; retained checkpoints detect rollback/tampering | **PASS (local) / custody NOT_RUN** | `recovery_event_chain_test.go` — modify/delete/reorder/rollback/forge/atomic/migration all detected; external custody lane unexercised |
| 5 | Clean verifier can establish package identity + qualification without trusting the workspace | **PASS** | `verify-rc75-release.test.py` — 12/12; dev package manifest+attest+fresh-extract verify PASS (4263 entries) |
| 6 | Mandatory platform + custody lanes verified | **NOT_RUN (partial)** | Go race gate PASS (699s); Linux/KVM, Rust, live-macOS, real custody = NOT_RUN blockers |
| 7 | Docs, packaging, final digest | **PENDING** | docs written; final zip/manifest/digest produced only after gates 4–6 close |

## What is verified on this tree

- `go build ./...` and `go vet ./...` — clean.
- `go test -race -timeout=20m ./...` — **full repository PASS**, all
  packages green (`internal/cli` 1161.2s, `internal/sandboxexecutor`
  699.3s under `-race`).
- `scripts/go-test-case-evidence.test.js` — 60/60, all 16 fixtures.
- `scripts/verify-rc75-release.test.py` — 12/12.
- Development package `NEMO-CONTROL-v0.54.0-rc7.5-development.zip`
  built from `git ls-files` membership (4263 entries), manifest
  embedded, sidecar attestation issued, fresh-extraction `verify`
  PASS. The released archive's SHA-256 is
  `796437dd80667b0febe63f1c272a4d45c655524081d3e1aefc23b89e0a31f6c0`
  (18,420,025 bytes) — bound by the external attestation
  (`NEMO-CONTROL-v0.54.0-rc7.5-development.zip.attestation.json`),
  which is the authoritative record. An in-archive report cannot bind
  its own container's digest; a previously cited value here
  (`6001dd98…`) named a superseded candidate build, not the released
  archive — this correction is D-RC75-10.

## Explicit blockers (must close before `qualified`)

1. **Linux/KVM lane** — live microVM dispatch/cleanup/fault injection
   is `NOT_RUN` on this Darwin host; remote Crabbox required.
2. **Independent custody destination** — the recovery-checkpoint
   custody path is implemented but never exercised against a real
   independently-controlled daemon; Gate 4's external half stays open.
3. **Rust toolchain lane** — `cargo`/`rustc` unavailable locally.
4. **Live macOS virtualization lane** — CLI-fake coverage only; no
   live `msb` VM boot this pass.
5. **Full-tree package verification** — verifier proven on synthetic
   packages; the real RC7.5 archive manifest+verify lands at packaging.

## Non-claims (do not read as weakness-shopping)

- Label-conditioned `msb rm` is not represented as atomic conditional
  delete.
- The recovery fence is enforced at every commit boundary; backend-side
  enforcement is bounded by label conditioning, honestly stated.
- No RC7.4 result is carried forward.

## RC7.6 repair addendum (branch `fix/rc7.6-defect-repair`)

This tree carries the RC7.6 correctness repairs over the frozen RC7.5
source (`main` = `67bacdb3`). The defects they close are the register
entries D-RC75-1, -2, -4, -5, -6, -7, -8, -9 and the record-keeping
half of -10. Repairs, not qualification: no gate above is re-opened by
this branch and no admission is claimed.

- **D-RC75-1 (recovery convergence):** a recovery claim issued by an
  older ledger epoch no longer blocks takeover — the flock the new
  epoch holds conclusively proves the claimant dead, so its lease is
  residue, not authority. Backoff still paces retries; crash-looping
  daemons get no free pass. `TestDaemonCrashPreservesAcknowledgedJobs`
  settles in <1s against the fake runtime (previously blocked past the
  20s window by the dead claimant's ~90s lease).
- **D-RC75-2 (test timing):** the ambiguous-dispatch test holds the
  fake backend's `Wait` behind an explicit gate and asserts a single
  dispatch, so DISPATCH_AMBIGUOUS is asserted under synchronization,
  not a <15ms race.
- **D-RC75-4 (dispatch refusal):** a failed/uncertain create now runs
  the real identity-bound `Cleanup` instead of best-effort
  `destroyDispatch`; when absence cannot be proven the dispatch returns
  `ErrAmbiguousDispatch` *with* its identity, so the cleanup obligation
  stays durable.
- **D-RC75-5 (destroy atomicity):** sandbox handles are nonce-bound
  (`sx-<job>-<dispatchNonce>`) and `msb rm` deletes by that handle —
  the name is itself unforgeable identity, so the resolve→delete window
  can only ever name this dispatch's record. The label check remains as
  the pre-delete authorization gate and post-verify is unchanged.
  Honest residual: a runtime-internal catalog swap under an occupied
  name needs the nonce, which never leaves dispatch identity; a native
  catalog-locked conditional delete remains the upgrade path.
- **D-RC75-6 (retention semantics):** `KeepSandboxes` now returns
  `RETAINED_BY_POLICY`, which discharges the cleanup obligation without
  claiming absence; `ProvesAbsent()` was not weakened.
- **D-RC75-7 (unbounded verify):** post-removal verification runs under
  a fresh 15s timeout derived from `context.WithoutCancel`; expiry is
  `REMOVAL_UNCERTAIN`.
- **D-RC75-8 (custody boundary):** the recovery-custody drain and
  archive finalization now verify the acknowledgement's signature and
  payload/sequence binding at the generic recording boundary — adapter
  checks are defense in depth, not the sole enforcement. Unsigned or
  forged acks are rejected before any durable state releases.
- **D-RC75-9 (verifier bypass):** `verify-rc75-release.py` now extracts
  the embedded manifest and compares schema/version, entry_count,
  root_hash and the full entry list against the attested external
  manifest. The reproduced tamper package (zeroed embedded root_hash,
  attacker-regenerated manifest+attestation) fails with exit 1; the
  real package still verifies.
- **D-RC75-10 (records):** the stale `6001dd98…` cite above is
  corrected; the external `RELEASE_MANIFEST.json` now binds the shipped
  RC7.5 bytes instead of RC7.4.

**Not yet established (still open for RC7.6 qualification):** live
re-verification of the repaired paths on both real virtualization
lanes; an independently controlled external custodian; a full release
admission workflow with all mandatory gates green.
