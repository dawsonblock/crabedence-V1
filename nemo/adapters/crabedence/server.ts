/**
 * Crabedence execution API server (Unix socket) — test/local bridge.
 *
 * @deprecated This server is for testing only. Production execution
 * uses the Go `crabbox serve-execution` service, which owns authority,
 * idempotency, dispatch, evidence, and receipts.
 *
 * This bridge does:
 *   1. Accepts framed requests over a Unix domain socket
 *   2. Validates required request field presence (not authority truth)
 *   3. Reserves idempotency keys atomically (prevents concurrent duplicates)
 *   4. Delegates to an injected handler
 *   5. Persists execution state (including UNKNOWN)
 *   6. Returns typed outcomes
 *
 * What this bridge does NOT do:
 *   - Authority grant verification (only presence check; Crabedence verifies)
 *   - JSON-schema argument validation (Crabedence core)
 *   - Authority-policy matching (Crabedence core)
 *   - Provider dispatch (Crabedence core)
 *   - V3 receipt signing (Crabedence core)
 *   - Evidence generation (Crabedence core)
 *   - PostgreSQL fencing (Crabedence core)
 *
 * The injected ExecutionHandler is the bridge to that machinery.
 */

import { createServer, type Server, type Socket } from "node:net";
import { unlinkSync, existsSync, mkdirSync, chmodSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir, tmpdir } from "node:os";

// ─── Wire types (shared with adapter) ─────────────────────────────────

export interface ExecutionApiRequest {
  readonly capability: string;
  readonly arguments: unknown;
  readonly authority: {
    readonly principal: string;
    readonly authority_ref?: string;
    readonly grant_id?: string;
  };
  readonly execution_class?: string;
  readonly idempotency_key?: string;
  readonly deadline?: string;
}

export interface ExecutionApiResponse {
  readonly status: "SUCCEEDED" | "FAILED" | "DENIED" | "UNKNOWN";
  readonly result?: unknown;
  readonly error?: string;
  readonly evidence?: {
    readonly digest: string;
    readonly receipt_version?: number;
  };
  readonly execution?: {
    readonly provider: string;
    readonly run_id: string;
  };
}

// ─── Handler interface ───────────────────────────────────────────────

/**
 * Request handler. In production this bridges to Crabedence's Go core
 * for provider lifecycle, evidence generation, receipt signing, and
 * authority verification. In tests, a mock handler is injected.
 */
export type ExecutionHandler = (
  request: ExecutionApiRequest,
) => Promise<ExecutionApiResponse>;

// ─── Observation ──────────────────────────────────────────────────────

/**
 * Per-request observability record for the idempotency path.
 *
 * A concurrency failure has two very different shapes, and only
 * observation can tell them apart:
 *   - two external executions (two `dispatched` records for one key)
 *   - one execution, but a caller observed the wrong state
 *
 * The record carries the request fingerprint (canonical digest), the
 * admission outcome (reservation state), leader/follower status
 * (`dispatched`), the wire status returned, and arrival order/timing.
 * (Effect IDs, provider operation tokens, and terminal receipt IDs are
 * owned by the durable Go kernel; this bridge is a transport-level test
 * double and has no such identifiers to report.)
 */
export interface ExecutionObservation {
  /** Idempotency key. */
  readonly key: string;
  /** Canonical request digest — the request fingerprint. */
  readonly requestDigest: string;
  /** Reservation outcome observed by this request. */
  readonly reservation: "NEW" | "EXISTING" | "IN_FLIGHT" | "CONFLICT";
  /** True only for the request that crossed into provider dispatch. */
  dispatched: boolean;
  /** Wire status returned to the caller, once sent. */
  status?: string;
  /** Monotonic arrival order on this server. */
  readonly sequence: number;
  /** Arrival time (ms since epoch). */
  readonly at: number;
}

// ─── Protocol constants ────────────────────────────────────────────────

const MAX_MESSAGE_BYTES = 4 * 1024 * 1024;
const IO_TIMEOUT_MS = 30_000;

// ─── Execution state ──────────────────────────────────────────────────

/**
 * Durable execution record state.
 *
 * IN_FLIGHT   — request dispatched to provider, awaiting outcome
 * SUCCEEDED   — provider confirmed success
 * FAILED      — provider confirmed failure
 * DENIED      — authority rejected before dispatch
 * UNKNOWN     — dispatched but outcome could not be confirmed
 *
 * For MUTATION/CRITICAL operations, once a key is IN_FLIGHT or has
 * reached any terminal state, a retry with the same key MUST return
 * the existing record, not re-invoke the provider.
 */
type ExecutionState =
  | "IN_FLIGHT"
  | "SUCCEEDED"
  | "FAILED"
  | "DENIED"
  | "UNKNOWN";

interface ExecutionRecord {
  readonly key: string;
  readonly requestDigest: string;
  state: ExecutionState;
  response?: ExecutionApiResponse;
}

// ─── Idempotency store ───────────────────────────────────────────────

/**
 * Idempotency store with atomic reservation.
 *
 * In production this is backed by PostgreSQL with INSERT ... ON CONFLICT.
 * For testing, an in-memory implementation is used.
 *
 * Key invariants:
 *   1. Concurrent requests with the same key + digest converge on one
 *      execution record (atomic reservation).
 *   2. A key bound to a different request digest is a hard conflict.
 *   3. UNKNOWN is persisted (not discarded) so retries retrieve the
 *      existing record instead of re-invoking the provider.
 *   4. IN_FLIGHT records block concurrent duplicates until the first
 *      execution completes.
 */
export interface IdempotencyStore {
  /**
   * Atomically reserve a key. Returns:
   *   - { state: "NEW" } if the key was not present (caller should execute)
   *   - { state: "EXISTING", response } if the key has a terminal record
   *   - { state: "IN_FLIGHT" } if the key is reserved but not yet complete
   *   - { state: "CONFLICT" } if the key exists with a different digest
   */
  reserve(
    key: string,
    requestDigest: string,
  ): Promise<{
    state: "NEW" | "EXISTING" | "IN_FLIGHT" | "CONFLICT";
    response?: ExecutionApiResponse;
  }>;

  /** Store the outcome for a reserved key. */
  settle(
    key: string,
    response: ExecutionApiResponse,
  ): Promise<void>;
}

/**
 * In-memory idempotency store with atomic reservation.
 *
 * The reservation critical section is synchronous: JavaScript runs it to
 * completion before any other request handler can observe the store, so
 * two concurrent reservations for one key can never both see "absent" and
 * both return NEW. A waiter must never inherit the leader's outcome —
 * returning NEW to a second caller would dispatch the provider twice,
 * which is exactly the invariant this store exists to protect.
 */
class InMemoryIdempotencyStore implements IdempotencyStore {
  private readonly records = new Map<string, ExecutionRecord>();

  async reserve(
    key: string,
    requestDigest: string,
  ): Promise<{
    state: "NEW" | "EXISTING" | "IN_FLIGHT" | "CONFLICT";
    response?: ExecutionApiResponse;
  }> {
    const record = this.records.get(key);
    if (!record) {
      // New reservation — the caller owns the dispatch.
      this.records.set(key, {
        key,
        requestDigest,
        state: "IN_FLIGHT",
      });
      return { state: "NEW" as const };
    }

    // Key exists — check digest
    if (record.requestDigest !== requestDigest) {
      return { state: "CONFLICT" as const };
    }

    if (record.state === "IN_FLIGHT") {
      return { state: "IN_FLIGHT" as const };
    }

    return {
      state: "EXISTING" as const,
      response: record.response,
    };
  }

  async settle(
    key: string,
    response: ExecutionApiResponse,
  ): Promise<void> {
    const record = this.records.get(key);
    if (!record) {
      return;
    }
    // Map response status to execution state
    const state: ExecutionState =
      response.status === "SUCCEEDED"
        ? "SUCCEEDED"
        : response.status === "FAILED"
          ? "FAILED"
          : response.status === "DENIED"
            ? "DENIED"
            : "UNKNOWN";
    record.state = state;
    record.response = response;
  }
}

// ─── Request digest ──────────────────────────────────────────────────

/**
 * Compute a canonical digest of the request for idempotency binding.
 * Binds the full admitted operation identity:
 *   - principal
 *   - grant_id
 *   - capability
 *   - execution_class
 *   - canonical arguments (sorted keys)
 *
 * The same key with different arguments, authority, or class is a conflict.
 * Uses canonical JSON (sorted keys at all levels) so property insertion
 * order does not affect the digest.
 */
async function computeRequestDigest(
  request: ExecutionApiRequest,
): Promise<string> {
  const canonical = canonicalJSONStringify({
    principal: request.authority.principal,
    authority_ref: request.authority.authority_ref ?? request.authority.grant_id,
    capability: request.capability,
    execution_class: request.execution_class ?? "",
    arguments: request.arguments,
  });
  const encoder = new TextEncoder();
  const data = encoder.encode(canonical);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Canonical JSON: sorted keys at every nesting level, no whitespace.
 * This ensures the same object produces the same string regardless of
 * property insertion order.
 */
function canonicalJSONStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJSONStringify).join(",") + "]";
  }
  const keys = Object.keys(value as object).sort();
  const pairs = keys.map(
    (k) => JSON.stringify(k) + ":" + canonicalJSONStringify((value as Record<string, unknown>)[k]),
  );
  return "{" + pairs.join(",") + "}";
}

// ─── Server ──────────────────────────────────────────────────────────

export class ExecutionApiServer {
  private server: Server | null = null;
  private readonly idempotency: IdempotencyStore;
  private readonly activeConnections = new Set<Socket>();
  private readonly observationLog: ExecutionObservation[] = [];
  private sequence = 0;

  constructor(
    private readonly handler: ExecutionHandler,
    private readonly socketPath: string,
    idempotency?: IdempotencyStore,
  ) {
    this.idempotency = idempotency ?? new InMemoryIdempotencyStore();
  }

  /**
   * Per-request observation records for the idempotency path, in arrival
   * order. Test/local diagnostics: the concurrency invariant is "exactly
   * one dispatched record per key, and no caller observes a different
   * terminal outcome".
   */
  observations(): ExecutionObservation[] {
    return this.observationLog.map((observation) => ({ ...observation }));
  }

  private observe(
    key: string,
    requestDigest: string,
    reservation: ExecutionObservation["reservation"],
  ): ExecutionObservation {
    const observation: ExecutionObservation = {
      key,
      requestDigest,
      reservation,
      dispatched: false,
      sequence: this.sequence++,
      at: Date.now(),
    };
    this.observationLog.push(observation);
    return observation;
  }

  async start(): Promise<void> {
    // Ensure the socket directory exists with 0700 permissions.
    // Don't bind in a shared /tmp location without a private subdirectory.
    const dir = dirname(this.socketPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    chmodSync(dir, 0o700);

    if (existsSync(this.socketPath)) {
      unlinkSync(this.socketPath);
    }

    this.server = createServer((socket: Socket) => {
      this.activeConnections.add(socket);
      socket.on("close", () => {
        this.activeConnections.delete(socket);
      });
      this.handleConnection(socket);
    });

    return new Promise((resolve) => {
      this.server!.listen(this.socketPath, () => {
        // Restrict socket access to owner only
        try {
          chmodSync(this.socketPath, 0o600);
        } catch {
          // Best effort — some platforms may not support this
        }
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    if (this.server) {
      // Destroy all active connections before closing
      for (const socket of this.activeConnections) {
        try {
          socket.destroy();
        } catch {
          // ignore
        }
      }
      this.activeConnections.clear();

      await new Promise<void>((resolve) => {
        this.server!.close(() => resolve());
      });
      this.server = null;
    }
    if (existsSync(this.socketPath)) {
      unlinkSync(this.socketPath);
    }
  }

  private handleConnection(socket: Socket): void {
    const chunks: Buffer[] = [];
    let request: ExecutionApiRequest | null = null;
    let expectedLen = 0;
    let processed = false;

    // I/O timeout
    const timer = setTimeout(() => {
      if (!processed) {
        try {
          socket.destroy();
        } catch {
          // ignore
        }
      }
    }, IO_TIMEOUT_MS);

    socket.on("data", async (chunk: Buffer) => {
      if (processed) {
        // Reject trailing data after a complete frame
        this.sendResponse(socket, {
          status: "FAILED",
          error: "unexpected trailing data after frame",
        });
        try {
          socket.destroy();
        } catch {
          // ignore
        }
        return;
      }

      chunks.push(chunk);
      const buf = Buffer.concat(chunks);

      if (request === null && buf.length >= 4) {
        expectedLen = buf.readUInt32BE(0);
        if (expectedLen > MAX_MESSAGE_BYTES) {
          this.sendResponse(socket, {
            status: "FAILED",
            error: `frame length ${expectedLen} exceeds maximum ${MAX_MESSAGE_BYTES}`,
          });
          try {
            socket.destroy();
          } catch {
            // ignore
          }
          return;
        }
      }

      if (request === null && buf.length >= 4 + expectedLen) {
        const body = buf.subarray(4, 4 + expectedLen).toString("utf-8");
        try {
          request = JSON.parse(body) as ExecutionApiRequest;
        } catch {
          this.sendResponse(socket, {
            status: "FAILED",
            error: "invalid JSON request",
          });
          return;
        }
        processed = true;
        clearTimeout(timer);
        // Process asynchronously
        this.processRequest(socket, request);
      }
    });

    socket.on("error", () => {
      clearTimeout(timer);
    });

    socket.on("close", () => {
      clearTimeout(timer);
    });
  }

  private async processRequest(
    socket: Socket,
    request: ExecutionApiRequest,
  ): Promise<void> {
    try {
      // Validate required fields
      if (!request.capability) {
        this.sendResponse(socket, {
          status: "FAILED",
          error: "missing capability",
        });
        return;
      }
      const authRef = request.authority?.authority_ref ?? request.authority?.grant_id;
      if (!request.authority?.principal || !authRef || !authRef.trim()) {
        this.sendResponse(socket, {
          status: "DENIED",
          error: "missing authority",
        });
        return;
      }

      // Idempotency handling for mutations
      if (request.idempotency_key) {
        const digest = await computeRequestDigest(request);
        const reservation = await this.idempotency.reserve(
          request.idempotency_key,
          digest,
        );
        const observation = this.observe(
          request.idempotency_key,
          digest,
          reservation.state,
        );

        if (reservation.state === "CONFLICT") {
          observation.status = "DENIED";
          this.sendResponse(socket, {
            status: "DENIED",
            error: "idempotency key bound to different request",
          });
          return;
        }

        if (reservation.state === "IN_FLIGHT") {
          // Another request with this key is in progress.
          // Return UNKNOWN — the caller should retrieve the result later.
          observation.status = "UNKNOWN";
          this.sendResponse(socket, {
            status: "UNKNOWN",
            error: "execution in flight for this idempotency key",
          });
          return;
        }

        if (reservation.state === "EXISTING") {
          // Return the existing terminal response (including UNKNOWN).
          // This is the critical fix: UNKNOWN is persisted and returned
          // for the same key, NOT re-invoked.
          const replay: ExecutionApiResponse = reservation.response ?? {
            // EXISTING but no response — inconsistent state. Fail closed
            // into UNKNOWN/reconciliation, never re-execute.
            status: "UNKNOWN",
            error: "execution record exists but has no terminal response (reconciliation required)",
          };
          observation.status = replay.status;
          this.sendResponse(socket, replay);
          return;
        }

        // state === "NEW" — this request owns the reservation and is the
        // only request permitted to cross into provider dispatch.
        observation.dispatched = true;
        let response: ExecutionApiResponse;
        try {
          response = await this.handler(request);
        } catch (handlerErr) {
          // Handler crashed after dispatch. The side effect may have
          // occurred. Return UNKNOWN, not FAILED, and persist it.
          response = {
            status: "UNKNOWN",
            error: `handler error after dispatch: ${(handlerErr as Error).message}`,
          };
        }

        // Persist the outcome (including UNKNOWN) so retries retrieve
        // it instead of re-invoking the provider.
        try {
          await this.idempotency.settle(request.idempotency_key, response);
        } catch (settleErr) {
          // Persistence failed. The side effect may have occurred.
          // Return UNKNOWN, not FAILED.
          observation.status = "UNKNOWN";
          this.sendResponse(socket, {
            status: "UNKNOWN",
            error: `execution completed but persistence failed: ${(settleErr as Error).message}`,
          });
          return;
        }

        observation.status = response.status;
        this.sendResponse(socket, response);
        return;
      }

      // No idempotency key — execute directly
      let response: ExecutionApiResponse;
      try {
        response = await this.handler(request);
      } catch (handlerErr) {
        // Handler crash without idempotency key — still return the
        // typed error. For mutations this is a problem, but without
        // a key there's no reservation to protect.
        response = {
          status: "FAILED",
          error: `handler error: ${(handlerErr as Error).message}`,
        };
      }
      this.sendResponse(socket, response);
    } catch (err) {
      this.sendResponse(socket, {
        status: "FAILED",
        error: `internal error: ${(err as Error).message}`,
      });
    }
  }

  private sendResponse(socket: Socket, response: ExecutionApiResponse): void {
    const payload = Buffer.from(JSON.stringify(response), "utf-8");
    const length = Buffer.alloc(4);
    length.writeUInt32BE(payload.byteLength, 0);
    socket.write(length);
    socket.write(payload);
    socket.end();
  }
}
