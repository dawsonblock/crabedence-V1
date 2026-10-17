# RC7.5 Platform Requirements

The mandatory coverage matrix and what each lane must produce before
qualification is claimable. A lane that cannot run in the development
environment keeps its gate open as `NOT_RUN` — absence of a platform
is a blocker, never an implicit pass.

## Lane inventory

| Environment | Required coverage | How it is exercised | Local status |
|---|---|---|---|
| Go toolchain (project lock, go1.26.5) | Unit, integration, race and concurrency | `go build ./...`, `go vet ./...`, `go test -race -timeout=20m ./internal/sandboxexecutor/` (package suite), plus targeted adversarial tests | Available locally (Darwin/arm64) |
| Rust toolchain (project lock) | Microsandbox/runtime checks | `cargo`/`rustc` builds and runtime pins verification | **Not available** — `cargo: command not found`; remote lane required |
| Node.js (locked dependencies) | Evidence and release tooling | `scripts/go-test-case-evidence.test.js` (60 tests / 16 fixtures) | Available (v24.16.0, npm 11.13.0) |
| Python | Parsing and evidence validation | `scripts/verify-rc75-release.test.py`, `scripts/go-test-case-evidence.py` validation paths | Available (3.12.0) |
| Linux with KVM | Actual microVM execution and fault injection | Live `msb` dispatch/cleanup/wait on KVM-backed VMs; substitution and kill-fault injection | **Not available** — Darwin host has no KVM; remote Crabbox lane required |
| macOS virtualization platform | Platform-specific live sandbox tests | Live `msb` operations on the macOS virtualization backend | **Not exercised** — `msb doctor` is healthy but no live VM boot was run in this pass; CLI-fake coverage only |
| Fresh installation environment | Package closure and startup | `verify-rc75-release.py verify` on the built ZIP; first-run smoke | Tooling ready; full-tree package verification lands with Phase 7 packaging |
| Independent custody destination | Checkpoint publication + verification | `DrainRecoveryCustody` → `SocketCustodian.WitnessRecoveryCheckpoint` → sandboxcustody daemon | Code path implemented and covered by scripted custodian; **a real independent custody integration has not been exercised** — gate remains `NOT_RUN` for qualification purposes |

## Remote qualification (Crabbox)

Lanes that cannot run locally must run on the remote Crabbox
environment with evidence captured back to the release record:

1. Linux + KVM: live dispatch → terminal observe → identity-bound
   cleanup → crash/resume fault injection against real microVMs.
2. Rust toolchain: build and runtime-pin verification of the pinned
   `msb` 0.7.8 toolchain surface.
3. Independent custody: a custody daemon under separate control
   acknowledging `recovery_outbox` checkpoints, with ack
   verification, sequence continuity, and competing-head rejection.

Until those lanes return evidence, the RC7.5 candidate is
`development`-suffixed only — the `qualified` artifact name is not
used.
