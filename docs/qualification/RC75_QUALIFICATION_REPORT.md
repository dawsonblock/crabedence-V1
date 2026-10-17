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
  PASS. Archive SHA-256:
  `796437dd80667b0febe63f1c272a4d45c655524081d3e1aefc23b89e0a31f6c0`

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
