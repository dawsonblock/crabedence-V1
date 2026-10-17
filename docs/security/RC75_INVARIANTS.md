# RC7.5 Security Invariants

These invariants are the release contract for `0.54.0-rc.7.5`. They are
normative: an implementation that cannot satisfy one of them is a
qualification blocker, never a rationale for weakening the invariant.

Every invariant names the failure it exists to prevent, the mechanism
that enforces it, and the evidence that proves the mechanism works.

## INV-01 — Identity-safe destruction

**A resource may be automatically destroyed only when the operation is
bound to the exact resource instance authorized for destruction.**

A reusable name is not an identity. A sandbox handle can be deleted and
recreated by another actor under the same name; a destructive operation
keyed on the name alone can then destroy a resource that was never
authorized for destruction. Every automatic cleanup must therefore be
conditioned on an identity the substitute cannot carry: the per-dispatch
nonce the instance was created with, verified against the persisted
dispatch authorization — and where the backend exposes one, the
instance's own immutable identity (its runtime boot generation and its
persistent instance id).

- An empty or unverifiable identity field is never a wildcard: a cleanup
  request that cannot name the dispatch it authorizes fails closed and
  the resource is quarantined for an operator, not removed.
- Verify-then-delete that is not serialized against substitution is not
  proof of ownership. The deletion condition must be evaluated by the
  runtime against the instance identity at the destructive operation
  itself; where the backend cannot serialize selection and deletion, the
  residual window is documented in the threat model and bounded by the
  runtime's own transition guard, and post-deletion verification
  confirms the authorized instance is absent and reports any
  contradicting evidence.
- An unverifiable destructive outcome is `REMOVAL_UNCERTAIN`, never a
  silent success: the cleanup stays pending and is retried, because an
  uncertain destroy is indistinguishable from a live one.

## INV-02 — Ambiguous effects

**An unresolved execution must never be automatically replayed or
considered terminated.**

A dispatch whose outcome is uncertain may have launched a workload that
is still running. Replaying it duplicates the workload; declaring it
dead fabricates an outcome. The only honest states are the ones the
system can prove.

- `ErrAmbiguousDispatch` and `ErrExecutionUnobserved` leave the ledger
  row unresolved (`DISPATCH_AMBIGUOUS`, `INTERRUPTED`); only an explicit
  `ErrDispatchRefused` may support a no-effect claim.
- A canceled observation means the monitor stopped watching — it says
  nothing about the workload, which may still be live.
- An unresolved row's resources are never automatically destroyed: the
  workload under them may be running the authorized job. They are held
  for operator reconciliation, and the VM's own `--max-duration` bound
  is the backstop.
- Recovery re-observes through the runtime's own record; it never
  re-dispatches an unresolved intent.

## INV-03 — Recovery ownership

**Only the currently authorized recovery claimant may commit recovery
state transitions or consequential effects.**

A recovery claim is a fencing token, not a hint. It is granted
atomically in the ledger, carries the owner's fence epoch and a lease,
and is verified at both the operation boundary and the commit boundary.

- The full `RecoveryClaim` — job, action, attempt ordinal, owner epoch,
  claim time, lease expiry — propagates to every operation that runs
  under it; it is never reduced to a boolean at a protected effect
  boundary.
- Every claim-conditioned write validates the expected claim generation
  in the same transaction as its write: conditional updates with
  affected-row checks, never check-then-write.
- A stale claim — wrong epoch, wrong attempt, expired lease, or a claim
  generation superseded by a newer claimant — cannot commit a state
  transition, and its release cannot erase the current owner's claim.

## INV-04 — Fenced external operations

**Losing a recovery lease must not permit a stale worker to destroy or
modify resources through a delayed external operation.**

Database fencing serializes commits; it cannot recall an external
effect already issued. The external effect boundary therefore carries
the fence too: the operation validates the claim before issue, the
effect itself is bound to the authorized resource instance (INV-01 —
an identity-bound effect cannot reach a resource it does not name), and
the result commits only while the claim is still valid.

- A claimant whose lease expired mid-flight cannot commit the outcome.
- The identity-bound effect limits a stale action's blast radius to the
  instance its own dispatch created — it can never destroy a resource
  that now belongs to another job's authority.
- Where a backend cannot enforce the fence at the external boundary,
  irreversible operations are gated on lease validity immediately before
  issue and the commit is conditioned on the claim afterward; the
  residual is bounded and documented, and observation-only operations
  may carry weaker fencing because a stale observation cannot overwrite
  authoritative state.

## INV-05 — Evidence integrity

**Every mandatory recovery transition must have a durable,
cryptographically verifiable commitment.**

A recovery event that commits without evidence never happened for
qualification purposes, and a history that can be silently rewritten
proves nothing.

- The state transition and its recovery-event record commit in the same
  ledger transaction — an unauditable transition does not commit.
- Every committed recovery event is bound into a hash chain:
  `event_hash = SHA256(domain_separator || canonical_event)`, where the
  canonical event includes the digest of its predecessor. Modification,
  deletion, reordering, duplication and truncation are independently
  detectable.
- Signed checkpoints bind the committed sequence range, the chain head,
  the schema identity, and the signer — a checkpoint's signature is
  verified against a configured trust root, never self-declared.
- Events written before the chain existed are marked legacy
  unauthenticated evidence; migration never retroactively claims they
  were authenticated.

## INV-06 — Evidence authenticity

**A successful qualification record must correspond to an identified
test invocation, not merely syntactically plausible JSON.**

A well-formed event stream is necessary but not sufficient: a fabricated
stream parses exactly like a real one. Qualification evidence binds the
invocation that produced it.

- Streams are strictly validated: package and test identity are
  required, lifecycle transitions are enforced, and malformed or
  implausible values (negative or non-numeric elapsed times, NaN,
  Infinity, missing terminals, contradictory outcomes) reject.
- The qualified record binds the controlled test-runner invocation:
  source revision and tree digest, the exact command, toolchain version,
  process exit code, the raw stream's SHA-256, runner identity and
  attestation, and the applicable policy.
- A record whose provenance cannot be verified is rejected at the
  release gate regardless of how plausible its JSON is.

## INV-07 — Release binding

**Qualification must apply to the exact distributed source and
executable artifacts.**

A green report about different bytes qualifies nothing. The release
evidence chain binds reviewed source → approved dependencies → build
environment → binary output → test evidence → qualification decision →
final package.

- Manifests are generated from the finalized distributable tree: every
  regular file's SHA-256, sizes, types, symlink targets, and the
  manifest's own schema identity.
- The final archive digest is computed over the delivered bytes and
  published in an independently signed sidecar attestation — never
  inside the artifact it describes.
- Verification runs against a fresh extraction, not the developer's
  working tree: entry safety, manifest closure, source hashes, symlink
  targets, version consistency, dependency locks, build reproduction,
  and attestation verification.
- Historical results never qualify a changed tree: any source
  modification after a gate passes rebuilds the affected evidence.

---

## Gate mapping

| Invariant | Primary enforcement | Qualification evidence |
|---|---|---|
| INV-01 | `CleanupRequest`/`CleanupResult` contract; label-conditioned removal through the runtime's guarded path; boot-generation binding | `cleanup_identity_test.go`, `backend_msb_test.go` substituted-VM adversarial cases |
| INV-02 | Explicit dispatch classes; unresolved states never auto-destroyed; no blind retry | dispatch/resume adversarial tests, `DISPATCH_AMBIGUOUS` handling |
| INV-03 | Atomic claim upsert; claim validated at operation and commit; ownership-conditioned release | `recovery_fence_test.go`, `maintenance_test.go`, `recovery_test.go` concurrency cases |
| INV-04 | Fence carried to effect boundary; identity-bound effects; conditional commit | delayed-effect and lease-expiry tests |
| INV-05 | Transactional transition+event commits; hash-chained events; signed checkpoints | `recovery_event_chain_test.go` tampering cases |
| INV-06 | Shared lifecycle validator; numeric/identity checks; provenance binding at the gate | `go-test-case-evidence` adversarial fixtures, release-gate verification |
| INV-07 | Source/build/distribution/artifact manifests; sidecar attestation; fresh-extraction verification | `verify-rc75-release.py`, `tests/release_adversarial/` |
