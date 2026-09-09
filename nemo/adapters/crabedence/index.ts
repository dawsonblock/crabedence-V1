// Production exports: the thin NEMO → Crabedence Go execution adapter.
// This is the only execution path that should be used in production.
export { CrabedenceClient, CrabedenceExecutionAdapter, TransportError } from "./adapter";
export type { CapabilityInvocationRequest, CrabedenceExecutionResponse } from "./adapter";

// ─── Legacy/test-only exports ──────────────────────────────────────────
// These are exported for testing and backward compatibility only.
// They are NOT part of the production execution path.
//
// - createCrabedenceBridge: spawns `crabbox exec` per request (legacy)
// - ExecutionApiServer: TypeScript execution server (test reference)
//
// Production code should use CrabedenceExecutionAdapter, which connects
// to the persistent Go execution service via Unix socket.

/** @deprecated Use CrabedenceExecutionAdapter instead. Spawns a subprocess per request. */
export { createCrabedenceBridge } from "./bridge";
/** @deprecated Use CrabedenceExecutionAdapter instead. TypeScript test server, not production. */
export type { BridgeOptions } from "./bridge";

/** @deprecated Use CrabedenceExecutionAdapter instead. TypeScript test server, not production. */
export { ExecutionApiServer } from "./server";
/** @deprecated Use CrabedenceExecutionAdapter instead. TypeScript test server, not production. */
export type {
  ExecutionApiRequest,
  ExecutionApiResponse,
  ExecutionHandler,
  IdempotencyStore,
} from "./server";
