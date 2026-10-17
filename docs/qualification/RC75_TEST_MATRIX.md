# RC7.5 Qualification Matrix

What each mandatory scenario claims, which test enforces it, and its
verified status. Status values are honest: `PASS` means the named test
ran green on this tree; `NOT_RUN` means the lane is unavailable in
this environment and the gate stays open as a blocker — never a pass.

Every claim maps to a test that exists in this tree. A renamed or
deleted test must turn its row red, not quietly weaken the gate.

## End-to-end scenarios

| # | Scenario | Enforced by | Lane | Status |
|---|----------|-------------|------|--------|
| A | Normal execution: authorized task completes, terminal evidence commits, exact sandbox instance removed | `internal/sandboxexecutor` server+dispatch tests; `TestMSBCleanupRemovesSandbox` (backend_msb_test.go) | Go (unit+integration) | PASS |
| B | Unauthorized execution: policy rejects before a privileged effect | admission/authority tests (`internal/authority`, executor admission tests) | Go | PASS |
| C | Lost launch acknowledgement: dispatch stays ambiguous, never replayed | `TestMSBDispatchAmbiguousCreateLeaksNothing`, `TestMSBDispatchCancelledAfterAdmissionIsAmbiguous`, `TestMSBWaitVanishedSandboxIsUnobserved` (backend_msb_test.go); server reconcile tests | Go | PASS |
| D | VM substitution: replacement VM survives stale cleanup | `TestCleanupSubstitutedVMSurvives`, `TestCleanupReusedNameWrongNonce`, `TestCleanupSubstitutionInsideRemovalWindow`, `TestCleanupWrongJobLabel`, `TestCleanupMissingIdentityFailsClosed` (cleanup_identity_test.go) | Go, live-MSB fake | PASS |
| E | Recovery takeover: stale claimant cannot overwrite or destroy after ownership transfer | `recovery_fence_test.go` (50-claimant race, stale release, expiry-during-op) | Go, `-race` | PASS |
| F | Process crash: durable recovery resumes without duplicating the action | crash/reopen tests (`recovery_test.go`, ledger reopen, `TestAdmitJobClaimsDispatchAtomically`) | Go | PASS |
| G | Evidence tampering: verification detects altered records, refuses qualification | `recovery_event_chain_test.go` (modify/delete/reorder/rollback/forge); `go-test-case-evidence` 16-fixture corpus | Go + Node + Python | PASS |
| H | Artifact substitution: release verification rejects executables/archives inconsistent with approved source | `verify-rc75-release.test.py` (substitution, traversal, symlink, missing/extra member, forged attestation, version drift, recursion) | Python | PASS |

## Platform lanes

| Lane | Coverage | Status |
|------|----------|--------|
| Go toolchain (locked) | `go build ./...`, `go vet ./...`, `go test -race -timeout=20m ./...` (full repository) | PASS |
| Rust toolchain | Microsandbox runtime checks | NOT_RUN — no Rust toolchain on this host (`cargo: command not found`); remote lane required |
| Node.js (locked deps) | `scripts/go-test-case-evidence.test.js` — 60 tests, 16 fixtures | PASS |
| Python | `scripts/verify-rc75-release.test.py` — 11 tests; `go-test-case-evidence.py` strict validation | PASS |
| Linux + KVM | Actual microVM execution + fault injection | NOT_RUN — Darwin/arm64 host cannot provide KVM; remote Crabbox lane required |
| macOS virtualization | Platform-specific live sandbox tests | NOT_RUN — live `msb` VM boot not exercised in this pass; CLI-fake coverage only |
| Fresh installation | Package closure + startup | PARTIAL — `verify-rc75-release.py verify` does fresh-extraction closure on synthetic packages; full-tree package verification is a Phase 7 deliverable |
| Independent custody destination | Checkpoint publication + verification | PARTIAL — `DrainRecoveryCustody` covered against a scripted custodian; a real independent custody integration has NOT been exercised and must not be claimed |

## Evidence fixtures

| Corpus | Count | Purpose |
|--------|-------|---------|
| `tests/evidence_fixtures/` | 16 | Strict `go test -json` stream validation: 15 negative cases rejected, `15-valid-empty-package` accepted, `16-fabricated-no-provenance` accepted as *structurally* valid only — provenance is a separate gate |
| `scripts/verify-rc75-release.test.py` adversarial cases | 11 | Archive substitution, tampered member, path traversal, zip symlink, missing/extra member, forged attestation, version drift, missing lockfile, manifest recursion |

## Rules this matrix enforces on itself

- A row may only read `PASS` when the named artifact ran on this
  exact source tree during the RC7.5 campaign.
- `NOT_RUN` is a blocker, not a footnote: qualification cannot be
  claimed with mandatory lanes unverified.
- No RC7.4 result carries forward — every row re-earns its status.
