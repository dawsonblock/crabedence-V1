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
  own command, entrypoint, user and working directory — compared as **ordered
  sequences**, because for a program the order *is* the meaning: `["/bin/sh",
  "-c"]` and `["-c","/bin/sh"]` run different things, so a reordered hook
  refuses rather than passing as an equivalent spelling;
- resources and their **ceilings** — the runtime must boot with exactly the
  authorized cpus, memory and disk, and no headroom above the budget the
  contract and the aggregate pool accounted for — plus the VM's own
  `--max-duration` (contract timeout plus the fixed observation grace), a
  lifecycle that is neither ephemeral nor idle-reaped, and the workdir;
- the authorized mounts, including read-only intent in both directions, every
  **hardening option the contract declared** (`nodev`, `nosuid`, `noexec` — a
  silently dropped one boots a mount nobody authorized), and the renderings that
  decide what the guest can observe about the host: **host permissions** and
  **file-stat virtualization** must be the confined values, and a mount must not
  follow host root symlinks;
- the network policy rule-for-rule, with no interface bindings or published
  ports;
- the absence of initialization hooks, rootfs patches, runtime script bindings
  and sandbox-level rlimits; no pending configuration changes; a running,
  non-recovering VM;
- the dispatch identity labels that bind this VM to this contract.

A mismatch destroys the VM before the guest command runs.

The comparison is a **closure at every level, not only at the top**. Every field
the pinned runtime's resolved configuration carries must be one the policy was
qualified against, and the schema is taken from the pinned runtime's own output;
a field it does not define refuses by name and by path, so a capability the
pinned runtime grows, or one a substituted runtime invents, can never ride along
unverified inside a nested object. Closing only the top level left a whole
surface invisible while the policy claimed to check the booted VM exactly, so
the security-relevant nested fields are verified on their own terms as well:
**injected secrets**, **TLS interception** and an **interception certificate
authority**, upstream CA pinning, **host CA trust**, a non-strict network, a
**DNS nameserver override**, and **host-root-symlink following** on a mount each
refuse, whatever the rest of the configuration says. A **guest-to-host `vsock`
route** refuses in its own right even when every other field matches exactly — a
host channel is reachability, and a host local-IPC endpoint, that the policy
never authorizes. The `msb create` command is derived from the compiled policy
alone, so no operator-supplied flag can add a setting the verification does not
cover.

Every field the schema admits has a stated disposition, so "not checked" is a
decision a reviewer can challenge rather than a gap: a field is either verified
against the policy, or recorded as deliberately unpinned with the reason it is
not a policy dimension (a field that only reports on something already verified,
or one that narrows rather than widens). Fields whose reason stops holding
belong in verification instead — the mount hardening options and the
host-identity renderings were exactly that, and moved.

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
digest. All of it is persisted in the ledger's dispatch-authorization columns
before any VM exists, and every later observation must carry the same identity
— a job record naming a different generation refuses at launch, in the monitor,
and in recovery. A sandbox re-created under the same name is a substituted VM
instance and is never adopted.

**Result authenticity.** Guest outcomes are observed from the runtime's own
durable job record, never from a CLI process exit code: `exited` with the
guest's code (0 = verified success, any other code = verified failure),
`timed_out` (the runtime killed the command at the contract deadline — no exit
code is invented), `failed` (the guest rejected the command before it started),
`lost` or unreachable (unobserved). An unobserved outcome becomes
`DISPATCH_AMBIGUOUS` with no receipt, and is never retried blind.

A no-effect claim is only ever made from positive evidence, never from absence
and never from a generic failure. What proves the workload produced no effect is
the runtime's own record of a typed failure at a **pre-execution stage**
(`Command::spawn`), with no pid and no start timestamp — every signal must
agree, and the stage is bound into the result and re-checked when the outcome is
classified, so the receipt names the proof rather than asserting it. A bare
`failed` state, a failure the runtime did not type as pre-execution, or a record
showing a started process demonstrates nothing about whether the workload ran
and is left unresolved instead. Likewise a launch that failed before the runtime
admitted anything leaves no record at all, and an absent record is not proof
that nothing executed — that outcome stays `DISPATCH_AMBIGUOUS`, its VM is left
for reconciliation rather than destroyed under a workload that may be running,
and no receipt is emitted.

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
  -state-dir /var/lib/crabedence/executor-artifacts \
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
That proof is **mandatory**: a row carrying no persisted policy digest or nonce
— a legacy row, or one whose authorization never reached disk — is never adopted
from the runtime's record, because a matching command, or a sandbox found under
the expected name, is not authority. Such a row stays unresolved for an
operator. A substituted instance, a rewritten nonce, a rewritten policy digest
or a changed operator configuration all refuse; zero matches or several matches
stay unresolved with a liveness audit. The startup pass walks **every**
unresolved row and every pending cleanup through a keyset cursor, so a candidate
is never omitted for having fallen outside the newest page. Nothing is ever
re-dispatched and nothing is auto-destroyed — an uncertain launch leaves its VM
for reconciliation.

Cleanup is tracked separately from the result: the terminal write records
cleanup intent, the sandbox removal runs after, and a failure is recorded as
`cleanup_pending` (with the reason) and retried at the next startup and on the
maintenance cadence below. A cleanup
failure never rewrites the observed result, and the VM's own contract bound is
the backstop. Until the removal is verified the job **keeps its pool
reservation**: the guest process finishing is not the microVM ceasing to exist,
so capacity is not released because the workload completed.

A reservation ends in exactly two ways, and only the first is verification.
**Verified cleanup** — the removal succeeded and the ledger cleared
`cleanup_pending` — ends it outright. The second is the VM's own
runtime-enforced `--max-duration`, which the backend pins to the contract
timeout plus the observation grace: once that bound plus the caller's grace has
certainly elapsed the VM cannot exist, and the reservation is released even
though the row stays unresolved for the operator's audit. That bound is not
verification of anything — it rests on the pinned runtime honouring
`--max-duration`, which is part of what the runtime identity is pinned by digest
to guarantee. It is deliberately conservative (the caller's grace exceeds the
VM's own, and a terminal row's last transition is always later than the VM's
creation), and a row whose contract cannot be parsed or that declares no timeout
is never released this way: the bound cannot be established, so the reservation
is held rather than guessed away.

## Registry archival

The registry bound counts **active** work — jobs whose outcome or cleanup could
still change — not history. A settled row (terminal sequence assigned, signed
receipt bound, cleanup verified) may move to the ledger's immutable archive:
the full payload is copied into `jobs_archive` inside one transaction under a
content-addressed `archive_segments` record, and the operational row is deleted.
The job's identity never archives — `job_identities` keeps every admitted
`job_id`/`contract_hash`/`seq` for the registry's whole life, so replay
protection survives the row's operational deletion. `Get`, `List`, the terminal
enumeration that checkpoints commit to, and the read-only verifier all span the
active table plus the archive, so evidence coverage is complete whether or not a
row has moved. When the active registry reaches the bound, admission archives
settled rows and recounts rather than refusing on stale history; only a registry
still full of live or unresolved work refuses. `VerifyArchiveSegments`
re-derives each segment's digest from the archive contents, so a rewrite of
archived bytes is detectable tampering.

### External custody

With `ArchiveCustodian` configured (`-archive-custody-socket` on
`sandbox-executord`), archival hands the segment's canonical payload to a
separate custody daemon — `sandbox-custodyd` — before the operational rows
release. The witness is an independent attestor with its own key and store:

- It stores the payload content-addressed under `segments/<sha256>` only after
  re-deriving the digest from the bytes it received — a payload that digests
  otherwise, carries the wrong row count, or strays outside the claimed
  terminal range is refused and nothing is stored.
- Each acknowledgement is appended to `acks.jsonl` as a signed record chained
  to the previous one (`prev_ack_sha256` is the digest of the previous raw
  line), signed with the witness's own Ed25519 key — a key the executor never
  holds.
- Custody is idempotent on the digest: a retried handoff re-verifies the held
  bytes and returns the original acknowledgement, so the crash window between
  the executor's archive commit and the operational release resumes without
  double-witnessing. A retry whose declared identity disagrees with the
  recorded acknowledgement is a conflicting custody claim, not a retry.
- `sandbox-custodyd -verify -custody-dir <dir>` re-derives the whole store
  independently — chain links, signatures, payload digests, and orphaned
  payloads — from the durable bytes alone; `-trust-file` additionally flags
  acknowledgements by witnesses the operator never approved.

The response carries the complete signed acknowledgement (record type
`archive-custody-ack/v2`), and the executor independently verifies it before
any row may leave: the record must bind this exact segment (sequence,
terminal range, row count, payload digest, and the request's own
`created_at`), carry a signer identity consistent with its embedded public
key, hold a valid Ed25519 signature over the versioned custody domain — and
the signer must be an approved witness. Witness trust is explicit
configuration, never learned from a response: `-archive-custody-trust-file`
loads a trust root of approved witness public keys (owner-only file;
rotations require the incumbent's signed key-transition record), and
`-archive-custody-signer` pins a single witness fingerprint. A configured
custody socket without an approved witness refuses startup — an unpinned
witness is a self-declared identity, not custody. The verified
acknowledgement reference is persisted on the segment
(`archive_segments.custody_ack`) in the same transaction that releases the
operational rows.

Payload files and the ack chain are committed at durability boundaries: file
sync plus directory sync at every rename and acknowledgement append, so a
power loss cannot lose the name under which the acknowledgement or payload
was committed. The custody socket obeys the same discipline as the
executor's: the directory is owner-only on a local filesystem, an existing
occupant is cleared only when it is a stale socket (a live listener refuses
startup rather than losing its socket), and shutdown unlinks only the exact
object the daemon bound.

If the custodian cannot be reached or refuses, the archive rows and the
pending segment are durable but the operational rows are never released; the
handoff retries on every later archive pass and across restarts, idempotent on
the segment digest.

## Continuous recovery

Startup reconciliation fixes what a previous lifetime left, but a daemon that
runs forever also leaves residue mid-lifetime — a driver that dies between
recording a job and claiming its dispatch intent, a cleanup that keeps failing,
an unresolved run whose backend settles an hour later. A maintenance scheduler
re-drives each category on a bounded cadence (`MaintenanceInterval`, default 60s,
negative disables the periodic passes):

- **Stranded `RECORDED` rows.** An admission crash or a record-only deployment
  can leave a durable row with no dispatch intent. The scheduler re-checks the
  contract — an expired or unreadable one terminates as `DISPATCH_FAILED` with a
  `NO_EFFECT` receipt, which is sound precisely because `RECORDED` proves no
  backend was ever asked — re-checks the pool under the admission lock, claims
  the row through the same `RECORDED`→`DISPATCHING` CAS the live path uses, and
  drives it through the shared dispatch pipeline. Live admission itself is
  atomic (`AdmitJob` writes the row already `DISPATCHING`), so the stranded set
  only ever contains pre-existing residue.
- **Stale `DISPATCHING` rows.** Every context on the dispatch drive is bounded
  (prepare plus the dispatch timeout), so a `DISPATCHING` row older than both
  bounds has no live driver. The sweep marks it `DISPATCH_AMBIGUOUS` —
  uncertain, never retried, never claimed dead — where the reconcile walk and
  the escalation see it.
- **Unresolved re-observation.** `DISPATCH_AMBIGUOUS`/`INTERRUPTED` rows are
  re-resumed through the backend on a per-row backoff (`ResumeBackoff`, default
  2m), exactly as at startup.
- **Cleanup retries.** `cleanup_pending` removals retry on their own backoff
  (`CleanupBackoff`, default 5m).
- **Archival.** Settled rows move to the archive each pass; capacity relief
  does not wait for the registry to fill.
- **Residue escalation.** Rows that persist unresolved or cleanup-pending are
  audited as an `ESCALATION` line — immediately when the residue shape changes,
  then on a throttle — so an operator learns the residue exists rather than
  discovering it at the next restart. Nothing is re-dispatched blind and
  nothing is auto-destroyed.

The scheduler's pacing is itself durable (ledger `recovery_attempts`, schema
v9): a retry claimed recently stays claimed across a restart, so a daemon
reopened inside a backoff window keeps waiting instead of re-attempting every
unresolved row on every open — a crash loop cannot hammer a wedged backend with
its own recovery — while downtime longer than the backoff still makes the next
pass due immediately, because the world may have changed while the daemon was
down. The same durability covers the escalation throttle, and every claim,
marking, termination, and escalation lands in `recovery_events`: the durable
recovery trail `InspectLedger` can read back after the audit log is gone.
Because the pacing is durable, a backoff configured long also delays the first
post-restart attempt — `ResumeBackoff` and `CleanupBackoff` tune both windows
for deployments whose backends recover slower or faster than the defaults.

## Platform qualification

Microsandbox runs on two independent virtualization implementations, and
evidence from one never qualifies the other:

| Lane | Host | Prerequisite | Proves |
| --- | --- | --- | --- |
| `apple-hypervisor-framework` | Apple Silicon (`darwin/arm64`) | `sysctl -n kern.hv_support` is `1` | policy enforcement, isolation, artifacts and recovery on HVF |
| `linux-kvm` | Linux (`arm64` or `x86-64`) | `/dev/kvm` present | the same properties on KVM |

- `TestMSBLivePlatformIdentity` names the lane a host provides and is
  deliberately ungated: the lane belongs in every qualification record.
- `TestMSBLiveLinuxKVM` is the Linux lane's entry point — it runs the real
  microVM suite on a Linux host with KVM and skips as **unsupported**
  everywhere else. A release that claims Linux support requires this lane's
  own passing evidence; a macOS HVF pass is not Linux evidence, and a Linux
  KVM lane is never "failed" because it ran on a Mac.
- The executor refuses an unsupported host on its own: startup runs the
  runtime's prerequisite check (`msb doctor`), so a host with neither HVF nor
  KVM cannot execute anything.
- **Two runners**: keep the Mac as the primary development and HVF
  qualification machine, and add a dedicated Linux KVM runner. The repo-local
  job takes the host explicitly, e.g.
  `crabbox job run live-microvm --provider ssh --static-host <kvm-host>`.

## Qualification and boundaries

- `CRABBOX_MSB_LIVE=1 go test -race -timeout=900s -run 'TestMSBLive' ./internal/sandboxexecutor/`
  qualifies real microVMs (policy enforcement, isolation, artifact integrity,
  monitor interruption, substituted-VM refusal, recovery). It runs on Apple
  Silicon and on Linux with KVM; a skipped live test is not a pass.
- That lane is also a release gate: `live-microvm` is registered in
  `dist/release-evidence` only on a host that can boot microVMs (the pinned
  runtime present, `msb doctor` green). On a host that cannot, the gate is
  not registered at all — the portable gate set makes no lane claim rather
  than recording a skip that reads like a pass.
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
