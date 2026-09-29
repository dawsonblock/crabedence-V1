# Reference kernel

This is the TypeScript reference kernel: the **executable specification** for
the Rust NEMO integration, not a shipping runtime.

It predates the Rust runtime and is retained deliberately. Where the two paths
disagree, this one is not automatically right — but a disagreement is a
finding that must be resolved before either side is trusted, and the shared
conformance corpus
(`internal/execution/testdata/invocation-abi-conformance/vectors.json`) is what
makes the comparison mechanical.

## What must agree

| Behavior | Reference implementation | Rust counterpart |
| --- | --- | --- |
| Invocation ABI scanning (R1–R8) | `../contracts/invocation-abi.ts` | `runtimes/nemo-relay/bridges/nemo-crabedence/src/abi.rs` |
| Registry envelope verification | `snapshot.ts` | `.../capability_snapshot.rs` |
| Length-prefixed framing | `../adapters/crabedence/adapter.ts` | `.../transport.rs` |
| Outcome and uncertainty mapping | `../adapters/crabedence/adapter.ts` | `.../outcome_mapping.rs` |

## Divergence resolved

The adapter previously mapped a bare `FAILED` response to `FAILED`. The
kernel's own post-dispatch table (`classifyPostDispatch`) maps `FAILED`
**without** `definitive_failure: true` to `UNKNOWN`, because after the dispatch
boundary it cannot prove no effect occurred. Reporting `FAILED` claimed more
certainty than the kernel did, and a caller treating it as definitive could
retry an effect that already happened.

The adapter now applies the kernel's rule, and the Rust bridge does the same.
The shared outcome corpus
(`internal/execution/testdata/outcome-conformance/vectors.json`) holds both to
it.

## Exit condition

This kernel is deleted once the Rust path passes the same behavioral tests.
The lightweight TypeScript client is not part of the kernel and is retained:
Node applications still need a way to invoke Crabedence.
