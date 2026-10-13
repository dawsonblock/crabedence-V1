# Sandbox executor

Read this when you need to:

- deploy `sandbox-executord` and understand the posture it refuses to run without;
- submit a signed job contract and verify the result independently;
- recover from a daemon crash, an interrupted observation or an unresolved run;
- review what the executor proves about a run — and what it does not.

`sandbox-executord` is the isolated execution sidecar for untrusted code. It
accepts job submissions only from kernel-verified peer identities carrying the
shared submission token, admits only Ed25519-signed contracts, runs each job in
a fresh, exclusively created microVM, and emits signed evidence for every
terminal outcome. It holds no authority keys: it can attest that work ran, never
authorize it.

## What the executor proves

Every dispatch compiles the signed contract and the operator's mandatory
restrictions into one canonical, hashed **effective policy**
(`EffectivePolicyV1`). Before any guest command starts, the booted VM must match
that policy exactly, in both the persisted `config` and the resolved
`active_config`:

- the image manifest digest, the security profile, the deployment profile and
  the strict external-mount policy;
- the guest environment — the contract's entries plus the pinned image's own
  config environment, with **nothing extra** and no duplicate keys;
- the runtime's execution defaults — the command shell, and the pinned image's
  own command, entrypoint, user and working directory — so nothing about how
  the guest starts is left to a default nobody authorized;
- resources, the VM's own `--max-duration` (contract timeout plus the fixed
  observation grace), the workdir and the authorized mounts (including
  read-only intent);
- the network policy rule-for-rule, with no interface bindings or published
  ports;
- the absence of initialization hooks, rootfs patches, runtime script bindings
  and sandbox-level rlimits; no pending configuration changes; a running,
  non-recovering VM;
- the dispatch identity labels that bind this VM to this contract.

A mismatch destroys the VM before the guest command runs.

**Runtime identity.** A qualified runtime manifest (JSON with `version`,
`msb_sha256`, `libkrunfw_sha256` and an optional `components` map) is required.
Startup verifies the version, hashes the executable and the firmware the
runtime's own prerequisite report names, and verifies every shared component
the pinned version ships under `<install>/lib/v<version>/` against the
manifest — an unpinned, substituted or missing component refuses. A binary that
reports the right version but carries different bytes refuses. The effective
policy binds the same digests, so the signed evidence names the runtime the
result was produced on.

**Execution identity.** Every dispatch records the runtime-owned job id, the VM
boot generation (read from the pinned runtime's state and cross-checked against
the runtime's own job record), the dispatch nonce and the effective-policy
digest. The generation is persisted (ledger schema v4) and every later
observation must carry it — a job record naming a different generation refuses
at launch, in the monitor, and in recovery. A sandbox re-created under the same
name is a substituted VM instance and is never adopted.

**Result authenticity.** Guest outcomes are observed from the runtime's own
durable job record, never from a CLI process exit code: `exited` with the
guest's code (0 = verified success, any other code = verified failure),
`timed_out` (the runtime killed the command at the contract deadline — no exit
code is invented), `failed` (the guest rejected the command before it started),
`lost` or unreachable (unobserved). An unobserved outcome becomes
`DISPATCH_AMBIGUOUS` with no receipt, and is never retried blind.

**Artifacts.** Captured output is read from the runtime's retained job log,
bounded by the contract's `max_output_bytes`, and published durably: a private
temp file, fsync, close, atomic rename, directory sync, then a read-back SHA-256
that must equal the digest computed while streaming. An exit observed but not
artifact-finalized leaves the job unresolved ("result not fully verified"),
never terminal without its evidence. The runtime's log store bounds retention
and normalizes invalid UTF-8 in its rendered view, so the artifact is exactly
the retained bytes — a durable, hashed record rather than a claim of
byte-completeness beyond what the runtime kept.

## Deploying

The daemon refuses to start without the posture it needs. Required:

```sh
sandbox-executord \
  -socket-dir /run/crabedence-executor \
  -peer-uids "$(id -u):crabedence" \
  -token-file /etc/crabedence/executor-token \
  -job-pubkey-file /etc/crabedence/authority-keys \
  -backend microsandbox \
  -msb-bin "$HOME/.microsandbox/bin/msb" \
  -runtime-manifest /etc/crabedence/runtime-manifest.json \
  -msb-version 0.7.8 \
  -msb-deployment-profile single-tenant \
  -msb-pull never \
  -pool-vms 4 -pool-submitter-vms 2 \
  -pool-cpus 8 -pool-memory-mb 8192 -pool-disk-mb 40960 -pool-output-bytes 67108864 \
  -evidence-dir /var/lib/crabedence/executor-evidence \
  -ledger /var/lib/crabedence/executor-ledger.db
```

- **Aggregate bounds are mandatory**: a configured backend requires every pool
  dimension to be a positive bound, and a bounded dimension requires every
  admitted contract to declare it. "Unbounded" is not a posture an
  untrusted-code executor may take.
- **Custody**: copy each published checkpoint (and the receipts log) to storage
  outside the executor's directory and off its host as it appears —
  `sandbox-evidence-verify` accepts any retained checkpoint path, and custody
  only counts as independent when the bytes outlive the executor's
  administrative control.
- The startup report prints the runtime identity, the host-confinement verdict,
  the effective profile, the fence epoch and the evidence signer fingerprint an
  operator should pin for verifiers.

## Submitting and verifying

Sign a contract with the authority key and submit it over the socket:

```sh
sandbox-job-sign -key-file authority.pem -contract contract.json > envelope.json
sandbox-submit -socket /run/crabedence-executor/executor.sock -envelope envelope.json
```

Verify the evidence independently — the ledger is opened read-only, and the
verifier trusts only the signer fingerprint you pin:

```sh
sandbox-evidence-verify \
  -ledger /var/lib/crabedence/executor-ledger.db \
  -evidence-dir /var/lib/crabedence/executor-evidence \
  -trusted-signer <evidence-signer-fingerprint>
```

The verifier checks, from the durable records alone: every terminal job's signed
receipt (bound to the contract hash, the outcome, the artifact digest and the
composed execution identity — run id, boot generation, policy digest); the
checkpoint's coverage of the terminal enumeration and its chain; each artifact's
re-hashed digest against the ledger, the result's size and the contract's
declared bound; and the result's execution identity against the row. It does not
recompute the policy digest itself: the operator's inputs (runtime manifest,
profile, pool) are deployment configuration, not ledger rows — pin them out of
band and compare the digest the receipts attest.

## Recovery

The durable state machine never guesses:

| State | Meaning |
| --- | --- |
| `RECORDED` | admitted and persisted; no backend has been asked to run it |
| `DISPATCHING` | durable intent to launch, fence written |
| `RUNNING` | the backend acknowledged the launch |
| `SUCCEEDED` / `FAILED` / `DISPATCH_FAILED` | terminal; receipt emitted before the transition |
| `DISPATCH_AMBIGUOUS` | the outcome is unknown — may still be live; never auto-retried |
| `INTERRUPTED` | was `RUNNING` when the daemon stopped cleanly |

On startup the executor reconciles what the runtime can still prove: unresolved
rows are **resumed** through the runtime's own job record — a terminal run
reaches the same receipt, artifact and terminal state a live monitor would have
produced, and a run whose identity was lost with the crash is adopted from the
runtime's job list only when exactly one record matches the authorized argv.
Recovery is authorization, not command matching: before adopting anything the
executor re-inspects the discovered VM, recomputes the policy the dispatch was
approved under (from the stored contract and the current operator
configuration), requires the VM's booted configuration to still equal it, and
requires the VM to present the dispatch's own nonce label and boot generation.
A substituted instance, a rewritten nonce, a rewritten policy digest or a
changed operator configuration all refuse; zero matches or several matches stay
unresolved with a liveness audit. Nothing is ever re-dispatched and nothing is
auto-destroyed — an uncertain launch leaves its VM for reconciliation.

Cleanup is tracked separately from the result: the terminal write records
cleanup intent, the sandbox removal runs after, and a failure is recorded as
`cleanup_pending` (with the reason) and retried at the next startup. A cleanup
failure never rewrites the observed result, and the VM's own contract bound is
the backstop.

## Qualification and boundaries

- `CRABBOX_MSB_LIVE=1 go test -race -timeout=900s -run 'TestMSBLive' ./internal/sandboxexecutor/`
  qualifies real microVMs (policy enforcement, isolation, artifact integrity,
  monitor interruption, substituted-VM refusal, recovery). It runs on Apple
  Silicon and on Linux with KVM; a skipped live test is not a pass.
- The repo-local job `live-microvm` (`.crabbox.yaml`) wraps that lane for a
  remote host and fails closed when the pinned runtime is absent:

  ```sh
  crabbox job run --dry-run live-microvm
  crabbox job run live-microvm --provider ssh --static-host <kvm-host>
  ```

- **Linux KVM lane.** Nested KVM is not a managed-provider feature, so the lane
  needs an operator-prepared host: bare metal, or an instance family with nested
  virtualization enabled and `/dev/kvm` exposed. Install the pinned runtime
  (the `msb-linux-<arch>` and `libkrunfw-linux-<arch>.so` assets of the pinned
  microsandbox release, or `msb update` on the host), then prove the host with
  the runtime's own check before qualifying:

  ```sh
  "$HOME/.microsandbox/bin/msb" --version      # must be the pinned version
  "$HOME/.microsandbox/bin/msb" self doctor    # must report host setup ready
  ```

  The executor refuses a host its runtime's prerequisite check rejects, and the
  runtime manifest is built from the hashes of that qualified install, so the
  Linux lane pins exactly the bytes it proved.
- The adversarial fault matrix measures the release targets instead of
  asserting them: 33 scenarios across dispatch, policy and adoption boundaries
  report zero false `NO_EFFECT` receipts, zero unauthorized adoptions, zero
  duplicate dispatches and zero accepted forbidden policy changes.
- The crash-consistency lane is qualified by SIGKILL rather than assertion:
  `TestDaemonCrashPreservesAcknowledgedJobs` kills the real daemon mid-job and
  requires the acknowledged job, its pre-persisted authorization and its single
  runtime record to survive, with recovery settling the run from the runtime's
  own record afterwards.
- The executor's macOS artifacts follow this fork's declared unsigned contract;
  the rc lane publishes source bundles, SBOM and release evidence, not compiled
  binaries.
- The executor refuses a runtime it was not qualified against, a host its
  runtime's prerequisite check rejects, and any contract that widens what the
  operator permitted.
