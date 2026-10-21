# RC7.5 Threat Model

Adversaries and attacks the RC7.5 hardening is designed against, the
control that answers each, and the residual risk honestly left open.
This document pairs with `RC75_INVARIANTS.md`: every control below is
the enforcement of an invariant; every residual is an explicit
blocker, not an absorbed assumption.

## Assets

- The job ledger: durable identity of every admitted execution.
- The backend fleet: VMs and sandbox instances a job's identity maps to.
- Recovery authority: which claimant may act on unresolved work.
- Evidence: recovery history, test evidence, release attestations.
- The distributed package: source + artifacts a verifier runs.

## Threats and controls

### T1 — Sandbox substitution under a reusable name

*Attack.* A sandbox name is freed and re-created by a foreign actor
(or a retry) between dispatch and cleanup; name-only destruction
removes the substitute — destroying someone else's VM or masking the
original leak.

*Control (INV-01).* Destruction is bound to the dispatch identity.
Sandbox handles are minted nonce-bound (`sx-<job>-<nonce>`, 128-bit
random per dispatch), so the name the runtime resolves can only ever
have been issued by this dispatch — a substitute cannot mint an
unforgeable name, and a re-used job name under another nonce is a
different name entirely. Before issue, inspection verifies the
occupant's `crabedence.dispatch=<nonce>` / `crabedence.job=<id>`
labels — a foreign occupant is refused, never destroyed. Removal is
then name-scoped (`msb rm -f <handle>`); post-removal inspection
independently confirms absence vs. surviving-substitute vs.
unverifiable. Cleanup stays pending on any non-proven outcome.

*Residual.* An unforgeable name is not an atomic conditional delete:
msb resolves the name to a catalog record inside its own process, and
a swap of that record between the executor's inspect and msb's
resolve is unobservable from the CLI. Closing that window by
construction therefore requires a **stated deployment assumption —
exclusive namespace ownership**: no principal other than this
executor may create, rename, or replace sandboxes under its `sx-`
prefix (and nothing else may learn the dispatch nonces, which are
exposed through process argv, logs, and sandbox listings — secrecy
of the nonce is a hardening measure, not the invariant). Under that
assumption the name can only ever have resolved to this dispatch's
instance. The stronger primitive — a runtime-native catalog-locked
conditional delete binding the immutable instance ID — remains the
upgrade path (D-RC75-5 register entry) and is required before the
executor may run in a shared sandbox namespace. Post-verify
classification already detects reoccupation and reports the
substitute rather than claiming clean absence.

### T2 — Ambiguous effects replayed

*Attack.* A lost dispatch acknowledgement is retried, double-launching
a non-idempotent action.

*Control (INV-02).* Ambiguous dispatch is a first-class state; it is
reconciled, never silently rerun. `RECORDED` intents are claimed
once, atomically.

### T3 — Stale recovery claimant commits state

*Attack.* Claimant A is suspended mid-operation; B takes over; A wakes
and commits a terminal transition or clears B's cleanup debt.

*Control (INV-03).* Every protected write validates the full claim —
job, action, attempt, owner epoch, **claim generation (claim_uid)**,
lease — inside the same transaction as the write. `claim_uid` is
monotonic and never reused across row delete/recreate, so a token
that outlived its generation can never match. Stale releases are
refused; stale clears are refused; stale transitions are refused.

### T4 — Delayed external operation after lease loss

*Attack.* A claimant's external call (a sandbox remove, a dispatch)
lands after its lease expired — a fenced-out worker still modifying
resources.

*Control (INV-04).* The claim is re-validated at the commit boundary
*and* the fence is carried to the backend as `RecoveryFence` on the
cleanup request, so a backend capable of enforcing it can refuse a
stale effect outright. Leases are extended before long observations.

*Residual.* The fence is *presented* to the backend; msb's CLI has no
fencing-token enforcement. Protection at the commit boundary is
complete; protection inside the backend's own operation is bounded
by label conditioning (T1) — a stale claimant's remove still only
reaches instances labeled with *its* job's nonce, never another
job's.

### T5 — Rewritten or rolled-back recovery history

*Attack.* The local recovery_events table is modified, deleted,
reordered, truncated, or wholesale re-computed to hide what happened.

*Control (INV-05).* Every event is hash-chained
(`prev_event_sha256`/`event_sha256` over a domain-separated canonical
form) inside the same transaction as the state change. Signed
recovery checkpoints commit to the chain head and covered range —
a recomputed chain fails the retained checkpoint; a truncated one
loses the committed tip. The custody outbox makes replication
durable and detects competing checkpoint heads.

*Residual.* A hash chain is only as strong as an *independently
retained* checkpoint: until the external custody lane runs, the
chain detects tampering at read time but the "rewritten whole"
case is proven only against a checkpoint that has actually left
the host. That lane is `NOT_RUN` and remains a qualification
blocker.

### T6 — Fabricated or malformed qualification evidence

*Attack.* A syntactically valid `go test -json` stream is fabricated,
or a malformed stream is normalized into a pass.

*Control (INV-06).* Strict lifecycle validation (package/test
identity, ordering, terminal states, numeric finiteness) rejects
every malformed shape — the 16-fixture corpus is the gate.
Structural validity is kept deliberately separate from runner
provenance: a fabricated-but-valid stream is *accepted as
structurally valid* and *rejected as evidence* — the release gate
binds the controlled runner invocation, not arbitrary JSON.

### T7 — Artifact/source substitution in distribution

*Attack.* The shipped archive or executable differs from the reviewed
source — swapped bytes, injected member, traversal entry, forged
attestation, recursive manifest hiding its own hash.

*Control (INV-07).* Canonical manifest (path, type, size, SHA-256,
symlink target, exec bit, schema) + sidecar attestation binding the
exact archive bytes + fresh-extraction verification in a clean dir.
No manifest recursion; the outer digest covers the container the
manifest cannot cover.

## Out of scope (stated, not assumed)

- Compromise of the executor's own evidence-signing key — checkpoints
  then lie with a valid signature; key custody is an operational
  control, not a code invariant.
- A malicious `msb` runtime — the runtime is pinned, but a replaced
  binary is a supply-chain matter covered by T7's artifact binding,
  not by runtime behavior.
- Exclusive sandbox-namespace ownership is a *stated deployment
  assumption*, not a proven property: until a native conditional
  delete lands, the executor must be the only principal able to
  create or replace sandboxes under its handle prefix. A shared
  namespace makes T1's residual reachable; qualification is scoped
  to the exclusive-ownership posture.
- Custody acknowledgements are verified at the recording boundary
  under an operator-administered trust root (separately configured
  from the custodian adapter) and bound to the ledger's durable
  deployment scope (v3 records sign the request's deployment_id, so
  an ack minted for one ledger is evidence for no other); an adapter
  that declares its own trust root is not the authority — but the
  *deployment* of an independently administered custodian remains an
  operational control the code cannot supply.
