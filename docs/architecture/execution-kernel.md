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
                HERMES / OTHER PLANNER
             reasoning / planning / memory
                        |
                        v
                Capability Invocation
                        |
                        v
                  FUNCTION HOOKS
            capability registry + dispatch
                        |
          +-------------+-------------+
          |                           |
     FAST PATH                     GUARDED PATH
          |                           |
     LOCAL / DIRECT                CRABEDENCE
          |                           |
     local functions              authority
     safe reads                   idempotency
                                  evidence
                                  reconciliation
                                       |
                        +--------------+--------------+
                        |              |              |
                       MCP            APIs         Crabbox
                        |              |              |
                   Gmail / HA       cloud       workers / VMs
```

### How routing works

The planner asks: `invoke("email.send", args)`

Function Hooks looks up the capability descriptor:

```
email.send
  effect_class = CRITICAL
  assurance_profile = HIGH_ASSURANCE
  execution_route = CRABEDENCE
```

Therefore: route to Crabedence.

The planner never gets to say "this email is low security, execute
it directly." That decision is pinned in the descriptor, not in the
request.

For local, deterministic work, Function Hooks executes immediately:

```
math.calculate
  effect_class = PURE
  assurance_profile = NONE
  execution_route = LOCAL
→ execute locally, no socket hop
```

For low-risk READs where the descriptor permits it:

```
weather.current
  effect_class = READ
  assurance_profile = STANDARD
  execution_route = DIRECT
→ execute via direct adapter with admission, no durable kernel
```

For sensitive operations:

```
gmail.message.read
  effect_class = READ
  assurance_profile = HIGH_ASSURANCE
  execution_route = CRABEDENCE
→ route through Crabedence trusted execution kernel
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

Crabedence supports different execution paths based on three
orthogonal dimensions pinned in the capability descriptor:

| Dimension          | Values                                    |
|--------------------|-------------------------------------------|
| Effect class       | PURE, READ, MUTATION, CRITICAL            |
| Assurance profile  | NONE, STANDARD, DURABLE, HIGH_ASSURANCE   |
| Execution route    | LOCAL, DIRECT, CRABEDENCE                 |

```
PURE     → NONE           → LOCAL      (no socket hop, no durability)
READ     → STANDARD       → DIRECT     (admission, no durable kernel)
READ     → HIGH_ASSURANCE → CRABEDENCE (authority-verified read)
MUTATION → DURABLE        → CRABEDENCE (PostgreSQL idempotency, exactly-once)
CRITICAL → HIGH_ASSURANCE → CRABEDENCE (durable + V3 evidence + receipts)
```

The registry decides all three dimensions. The dispatch layer
(Function Hooks) reads `execution_route` from the descriptor to
decide routing. The planner cannot override the route.

This preserves the original concern: function calls remain fast.
LOCAL and DIRECT capabilities don't pay the durability tax. Only
CRABEDENCE-routed operations require the durable path.

## What Crabedence Owns

- Capability registry (authoritative execution classes, assurance profiles, execution routes)
- Argument schema validation
- Authority verification (grant resolution via `authority_ref`)
- Durable idempotency (PostgreSQL)
- Provider dispatch (server-controlled adapter policy)
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
  "authority_ref": "mail-send-grant",
  "idempotency_key": "send-001"
}
```

Security-relevant properties (execution class, assurance profile,
execution route, authority policy, provider binding, schema) are
pinned inside Crabedence's registry, not sent by the planner.

## Function Hooks

Function Hooks is the fast capability-dispatch layer. It is optional
but recommended — it provides the low-latency path for LOCAL and
DIRECT capabilities while routing CRABEDENCE operations to the
trusted execution kernel.

Function Hooks does not decide what is "safe." It reads the
`execution_route` from the capability descriptor (pinned in
Crabedence's registry) and dispatches accordingly. The planner
cannot override the route.

The stable Crabedence ABI does not depend on Function Hooks. Any
client can connect directly to Crabedence's Unix socket. Function
Hooks is an optimization layer, not a mandatory hop.

## NEMO's Role

NEMO is optional. It is not between every user request and every
planner simply because it exists. That would create another mandatory
runtime layer without a clear security responsibility.

If NEMO has useful routing/reasoning technology, use it as a component
inside or beside the planner:

```
Hermes
  |
  +--> NEMO for model routing / reasoning optimization
  |
  +--> Capability invocation → Function Hooks → Crabedence
```

Current NEMO role:
- Thin adapter to Crabedence's Unix socket
- Test client for the execution service
- Optional reasoning/research service that a planner may call

NEMO does not own:
- Provider semantics
- Authority truth
- Execution-class truth
- Execution-route decisions
- Durable idempotency
- Receipts
- Reconciliation

Those are Crabedence's responsibilities, pinned in the registry.

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
