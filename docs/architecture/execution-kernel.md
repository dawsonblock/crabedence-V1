# Architecture: Planner-Agnostic Execution Kernel

## Core Principle

Crabedence is a trusted execution kernel, not an agent runtime.

It does not plan, reason, decompose tasks, manage memory, or decide
what the next action is. It executes capability invocations with
authoritative admission, durable idempotency, and cryptographic evidence.

Any planner can sit above it. The planner is replaceable; the execution
kernel is durable.

## System Responsibilities

| System        | Responsibility                                              |
|---------------|-------------------------------------------------------------|
| Hermes        | Agent loop, planning, reasoning, memory, workflow state     |
| NEMO          | Optional specialized reasoning/research component           |
| Function Hooks| Fast capability-call ABI / local dispatch optimization      |
| Crabedence    | Trusted execution kernel (admission, authority, dispatch)   |
| Crabbox       | Isolated/remote worker substrate                           |
| MCP/APIs      | External capability providers                               |

## Architecture

```
                     HERMES
              Agent / Planner / Memory
                       |
                       |
             capability invocation
             (see: capability-invocation-abi.md)
                       |
                       v
               FUNCTION HOOKS
                fast call ABI
                       |
              +--------+--------+
              |                 |
            PURE              external
              |                 |
              v                 v
         local functions    CRABEDENCE
                            execution kernel
                                |
                +---------------+---------------+
                |               |               |
               MCP             API           CRABBOX
                |               |               |
             Gmail / HA      cloud         VM/workers
```

## Why This Separation

### The reasoning engine is replaceable

Hermes may improve. OpenAI's runtime may improve. Another open-source
agent may surpass both. The planner can be swapped without touching
the execution infrastructure.

### The execution kernel is the durable asset

The capability registry, authority policies, idempotency guarantees,
evidence generation, and provider bindings are stable. They don't
change when the planner changes. They are the trust boundary.

### Better failure model

If the planner crashes mid-workflow, Crabedence retains the execution
state. On planner restart:

```
execution abc: SUCCEEDED
execution def: UNKNOWN → reconciliation
execution ghi: DENIED
```

The planner reasons about what to do next. Crabedence does not.

### No runtime lock-in

You don't need to win the agent-runtime race. You build the execution
substrate that every runtime can use.

## Execution Path Differentiation

Crabedence supports different execution paths based on the
registry-pinned execution class:

```
PURE
  → local runtime (no socket hop, no durability)
  → fast function calls

READ
  → lightweight admitted execution
  → authority verified, schema validated
  → no durable idempotency needed (no side effects)

MUTATION
  → durable execution
  → PostgreSQL-backed idempotency
  → exactly-once semantics
  → fail closed if durable store unavailable

CRITICAL
  → durable execution + evidence
  → PostgreSQL-backed idempotency
  → V3 receipt with evidence_sha256 binding
  → Ed25519 signature
  → reconciliation on ambiguity
  → fail closed if durable store unavailable
```

This preserves the original concern: function calls remain fast.
PURE capabilities don't pay the durability tax. Only MUTATION and
CRITICAL operations require the durable path.

## What Crabedence Owns

- Capability registry (authoritative execution classes)
- Argument schema validation
- Authority verification (grant resolution)
- Durable idempotency (PostgreSQL)
- Provider dispatch
- Terminal outcome determination
- Evidence generation (RunEvidenceV1)
- V3 receipt signing (Ed25519)
- Reconciliation (UNKNOWN → definitive state)

## What Crabedence Does NOT Own

- Planning or task decomposition
- Reasoning loops
- Memory or workflow state
- Model routing
- Tool selection
- Agent personality or policies
- Reflection or self-evaluation

## The Stable Boundary

The capability invocation ABI (see [capability-invocation-abi.md](capability-invocation-abi.md))
is the frozen boundary between any planner and Crabedence.

It is intentionally minimal:

```json
{
  "capability": "gmail.message.send",
  "arguments": {"to": "bob@example.com", "body": "..."},
  "principal": "user@example.com",
  "grant_id": "mail-send-grant",
  "idempotency_key": "send-001"
}
```

Security-relevant properties (execution class, authority policy,
provider binding, schema) are pinned inside Crabedence's registry,
not sent by the planner.

## NEMO's Role

NEMO is repositioned from "parent runtime" to "optional specialized
component." It is not required for the execution path.

Current NEMO role:
- Thin adapter to Crabedence's Unix socket
- Test client for the execution service
- Optional reasoning/research service that a planner may call

NEMO does not own:
- Provider semantics
- Authority truth
- Execution-class truth
- Durable idempotency
- Receipts
- Reconciliation

Those are Crabedence's responsibilities.

## Hermes Integration (Future)

Hermes (or any planner) connects to Crabedence through the capability
invocation ABI. The integration is:

1. Hermes plans a workflow.
2. Hermes determines which capability to invoke.
3. Hermes sends a capability invocation to Crabedence.
4. Crabedence admits, dispatches, and returns a typed outcome.
5. Hermes reasons about the outcome and plans the next step.

No Crabedence code needs to change for Hermes integration.
The ABI is already frozen.
