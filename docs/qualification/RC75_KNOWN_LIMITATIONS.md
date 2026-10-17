# RC7.5 Known Limitations

Stated plainly so they are never mistaken for absorbed assumptions.
Each is either a deliberate residual with a compensating control, or
an explicit `NOT_RUN` blocker.

## Compensating (not native) controls

- **`msb rm --label` is a conditioned remove, not an atomic
  conditional-delete.** Microsandbox's CLI resolves labels to names
  then deletes by name; the identity-checked `remove_identified`
  primitive exists only in the Rust SDK, unreachable from the CLI.
  Compensation: label conditioning at the remove itself, identity
  verification before it, independent inspection after it, and honest
  `REMOVAL_UNCERTAIN` on any unresolved window. A Rust shim exposing
  `remove_identified` is the proper fix and is not built.
- **The recovery fence is enforced at every commit boundary, not
  inside the backend.** `RecoveryFence` is *presented* to the backend
  on consequential requests, but msb has no fencing-token
  enforcement. A stale claimant's external op is still bounded by
  label conditioning (it can only ever reach its own job's nonce),
  and its commit is refused — but the fence is not natively enforced
  mid-flight inside msb.
- **External custody is wired but unexercised.** The outbox, drain,
  ack-verification, and competing-head detection are implemented and
  covered by a scripted custodian — a *real* independently-controlled
  custody destination has not acknowledged a checkpoint. Gate 4's
  external half stays `NOT_RUN`.

## Explicitly unrun lanes (blockers)

| Lane | Why not run | Required to close |
|---|---|---|
| Linux + KVM microVM | No KVM on Darwin host | Remote KVM-capable runner (`.crabbox.yaml` `live-microvm` job) |
| Rust toolchain | `cargo`/`rustc` not installed | Remote or toolchain install |
| Live macOS virtualization | No live `msb` VM boot this pass | `CRABBOX_MSB_LIVE=1` on a capable host |
| Independent verifier rerun | Dev package built and `verify`ed here | A *clean-room* rerun on a second host is the intended fresh-install proof |

## Behavioral non-claims

- Pre-v12 recovery events are `authenticated = 0` permanently — bound
  into the chain for tamper-evidence, never called signed history.
- `IDENTITY_MISMATCH` leaves a foreign occupant untouched even when it
  looks like ours — destroying it is never our call.
- An evidence-signing-key compromise is an operational, not code,
  concern — checkpoints then lie with a valid signature.
