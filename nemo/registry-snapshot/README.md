# Registry snapshot loader

This directory holds one thing: the TypeScript registry-envelope loader
(`snapshot.ts`). The reference kernel that used to live here — the capability
catalog, the route table, the schema validator, and the execution harness — has
been removed.

## What it does

`loadRegistrySnapshot` verifies the envelope the service writes next to its
socket and returns the descriptors it covers:

```text
base64-decode → SHA-256 → constant-time compare → only then parse
```

A payload that does not match its digest fails closed, so the descriptors
returned are provably the bytes the authoritative registry digested.

It returns **descriptors, not a catalog**. A catalog would be a second
classification, and the kernel that built one derived routes from it — see
finding 8 in `docs/plan/nemo-runtime-transfer.md`.

## Why the rest went

| Behavior the kernel owned | Where it lives now |
| --- | --- |
| Capability lookup, class immutability, idempotency key, principal, deadline, argument schema | The Go service, at admission — `TestExpiredDeadline`, `TestInvalidDeadline`, `TestExecutionServiceMissingIdempotencyKey`, `TestExecutionServiceExecutionClassMismatch`, `TestExecutionClassRequiresIdempotencyKey` |
| CRITICAL evidence contract | The Rust bridge's `map_outcome(requires_evidence)`, against the shared outcome corpus |
| Route resolution | The registry, on both sides; the Rust `EffectRouter` fails closed rather than deriving one |
| Result-schema validation | Removed with the kernel, and inert in production: `resultSchema` never travels in the registry snapshot, so it could only fire for a hand-built test catalog |

## What still must agree

| Behavior | TypeScript | Rust |
| --- | --- | --- |
| Invocation ABI scanning (R1–R8) | `../contracts/invocation-abi.ts` | `runtimes/nemo-relay/bridges/nemo-crabedence/src/abi.rs` |
| Envelope verification | `snapshot.ts` | `.../capability_snapshot.rs` |
| Length-prefixed framing | `../adapters/crabedence/adapter.ts` | `.../transport.rs` |
| Outcome and uncertainty mapping | `../adapters/crabedence/adapter.ts` | `.../outcome_mapping.rs` |

All four are held to shared corpora under `internal/execution/testdata/`, and
all four are exercised in CI. The adapter's mapping includes the rule that a
`FAILED` response without `definitive_failure: true` is `UNKNOWN`, not `FAILED`
— the kernel's own post-dispatch table, which the outcome corpus pins for both
implementations.
