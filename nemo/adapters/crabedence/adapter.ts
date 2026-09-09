/**
 * Crabedence execution adapter.
 *
 * Implements NEMO's ExecutionPort by calling the Crabedence execution
 * kernel over a Unix domain socket. This adapter is intentionally thin —
 * it maps NEMO request types to the Crabedence wire format (defined in
 * docs/spec/capability-invocation-abi.md) and maps the response back.
 *
 * The adapter is a transport layer. It does not own:
 *   - provider semantics
 *   - authority truth (grant resolution is Crabedence's job)
 *   - execution-class truth (Crabedence's registry is authoritative)
 *   - durable idempotency
 *   - receipts or evidence
 *   - reconciliation
 *
 * Any planner (Hermes, OpenAI SDK, custom) can target the same ABI
 * directly without going through NEMO. NEMO is optional.
 *
 * Dependency direction:
 *
 *   NEMO contracts (ExecutionPort)
 *       ↑ implements
 *   CrabedenceExecutionAdapter
 *       ↓ calls
 *   Crabedence execution kernel (Unix socket)
 */

import { connect, type Socket } from "node:net";

import type {
  ExecutionPort,
  KernelExecutionOutcome,
  KernelExecutionRequest,
} from "../../contracts/index";

// ─── Wire protocol ────────────────────────────────────────────────────

/**
 * Capability invocation request (Capability Invocation ABI).
 * See docs/spec/capability-invocation-abi.md for the frozen specification.
 *
 * execution_class is optional/advisory — Crabedence's registry is
 * authoritative. If present, it is checked against the registry.
 * If absent, the registry's pinned class is used.
 *
 * authority_ref is an opaque reference to authority material — today
 * a grant ID, tomorrow a capability token or workload identity.
 * grant_id is accepted for backward compatibility.
 */
export interface CapabilityInvocationRequest {
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

/** @deprecated Use CapabilityInvocationRequest */
export type CrabedenceExecutionRequest = CapabilityInvocationRequest;

/**
 * Crabedence execution API response.
 */
export interface CrabedenceExecutionResponse {
  readonly status: "SUCCEEDED" | "FAILED" | "DENIED" | "UNKNOWN" | "IN_FLIGHT";
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

// ─── Protocol constants ────────────────────────────────────────────────

/** Maximum message size (4 MiB). Rejects oversized frames. */
const MAX_MESSAGE_BYTES = 4 * 1024 * 1024;

/** Default connect + I/O timeout in milliseconds. */
const DEFAULT_TIMEOUT_MS = 30_000;

// ─── Transport errors ─────────────────────────────────────────────────

/**
 * Transport errors are typed to distinguish:
 *   - PRE_DISPATCH: the request never reached the server (safe to retry)
 *   - POST_DISPATCH: the request was sent but no response was received
 *     (the side effect may have occurred — caller must treat as UNKNOWN)
 *   - PROTOCOL: the server responded but the frame was malformed
 */
export class TransportError extends Error {
  constructor(
    message: string,
    public readonly kind: "PRE_DISPATCH" | "POST_DISPATCH" | "PROTOCOL",
  ) {
    super(message);
    this.name = "TransportError";
  }
}

// ─── Framing helpers ──────────────────────────────────────────────────

/**
 * Encode a value as a length-prefixed frame using UTF-8 byte length
 * (not string length, which counts UTF-16 code units).
 */
function encodeFrame(value: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(value), "utf-8");
  if (payload.byteLength > MAX_MESSAGE_BYTES) {
    throw new TransportError(
      `message exceeds maximum size: ${payload.byteLength} > ${MAX_MESSAGE_BYTES}`,
      "PRE_DISPATCH",
    );
  }
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.byteLength, 0);
  return Buffer.concat([header, payload]);
}

/**
 * Read a single length-prefixed frame from accumulated buffer data.
 * Returns { frame, consumed } if a complete frame is available,
 * or { frame: null, consumed: 0 } if more data is needed.
 */
function readFrame(buf: Buffer): { frame: Buffer | null; consumed: number } {
  if (buf.length < 4) {
    return { frame: null, consumed: 0 };
  }
  const len = buf.readUInt32BE(0);
  if (len > MAX_MESSAGE_BYTES) {
    throw new TransportError(
      `frame length ${len} exceeds maximum ${MAX_MESSAGE_BYTES}`,
      "PROTOCOL",
    );
  }
  if (buf.length < 4 + len) {
    return { frame: null, consumed: 0 };
  }
  return { frame: buf.subarray(4, 4 + len), consumed: 4 + len };
}

// ─── Client ───────────────────────────────────────────────────────────

/**
 * Low-level Unix socket client for the Crabedence execution API.
 * Sends a length-prefixed JSON request (UTF-8 byte length) and reads
 * a single JSON response.
 *
 * Transport failures are typed:
 *   - Connection failure before write → PRE_DISPATCH (safe to retry)
 *   - Connection failure after write → POST_DISPATCH (may be UNKNOWN)
 *   - Malformed response → PROTOCOL
 */
export class CrabedenceClient {
  constructor(
    private readonly socketPath: string,
    private readonly timeoutMs: number = DEFAULT_TIMEOUT_MS,
  ) {}

  async execute(
    request: CrabedenceExecutionRequest,
  ): Promise<CrabedenceExecutionResponse> {
    return new Promise((resolve, reject) => {
      let dispatched = false;
      let settled = false;
      const socket = connect(this.socketPath);
      const chunks: Buffer[] = [];
      let timer: ReturnType<typeof setTimeout> | null = null;

      const cleanup = () => {
        if (timer) {
          clearTimeout(timer);
          timer = null;
        }
        socket.removeAllListeners();
        try {
          socket.destroy();
        } catch {
          // ignore
        }
      };

      const fail = (err: TransportError) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(err);
      };

      const succeed = (response: CrabedenceExecutionResponse) => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(response);
      };

      // Timeout
      timer = setTimeout(() => {
        const kind = dispatched ? "POST_DISPATCH" : "PRE_DISPATCH";
        fail(new TransportError(`timeout after ${this.timeoutMs}ms`, kind));
      }, this.timeoutMs);

      socket.on("connect", () => {
        try {
          const frame = encodeFrame(request);
          dispatched = true;
          socket.write(frame);
        } catch (err) {
          fail(err as TransportError);
        }
      });

      socket.on("data", (chunk: Buffer) => {
        chunks.push(chunk);
        const buf = Buffer.concat(chunks);
        try {
          const { frame, consumed } = readFrame(buf);
          if (frame) {
            // Consume the frame
            if (consumed < buf.length) {
              // Reject trailing data after a complete frame
              fail(
                new TransportError(
                  `unexpected trailing data after frame (${buf.length - consumed} bytes)`,
                  "PROTOCOL",
                ),
              );
              return;
            }
            try {
              const raw = JSON.parse(frame.toString("utf-8"));
              const response = validateWireResponse(raw);
              succeed(response);
            } catch (err) {
              if (err instanceof TransportError) {
                fail(err);
              } else {
                fail(
                  new TransportError("invalid JSON in response", "PROTOCOL"),
                );
              }
            }
          }
        } catch (err) {
          fail(err as TransportError);
        }
      });

      socket.on("error", (err: Error) => {
        const kind = dispatched ? "POST_DISPATCH" : "PRE_DISPATCH";
        fail(new TransportError(`socket error: ${err.message}`, kind));
      });

      socket.on("close", () => {
        if (!settled) {
          const kind = dispatched ? "POST_DISPATCH" : "PRE_DISPATCH";
          fail(
            new TransportError(
              dispatched
                ? "socket closed before response received"
                : "socket closed before request dispatched",
              kind,
            ),
          );
        }
      });
    });
  }
}

// ─── Adapter ─────────────────────────────────────────────────────────

/** Valid status values from the wire protocol. */
const VALID_WIRE_STATUSES = new Set([
  "SUCCEEDED",
  "FAILED",
  "DENIED",
  "UNKNOWN",
  "IN_FLIGHT",
]);

/**
 * Validate and map Crabedence wire status to NeMo execution status.
 * Rejects unknown status values at runtime — a malformed peer cannot
 * inject arbitrary status strings.
 */
function mapStatus(status: unknown): string {
  if (typeof status !== "string" || !VALID_WIRE_STATUSES.has(status)) {
    throw new TransportError(
      `invalid wire status: ${JSON.stringify(status)}`,
      "PROTOCOL",
    );
  }
  return status;
}

/**
 * Runtime validation of a Crabedence wire response.
 * Rejects malformed responses at the protocol boundary.
 */
function validateWireResponse(raw: unknown): CrabedenceExecutionResponse {
  if (typeof raw !== "object" || raw === null) {
    throw new TransportError("response is not an object", "PROTOCOL");
  }
  const obj = raw as Record<string, unknown>;

  // status is required and must be a valid enum
  const status = mapStatus(obj.status);

  // error must be a string if present
  if (obj.error !== undefined && typeof obj.error !== "string") {
    throw new TransportError("response.error must be a string", "PROTOCOL");
  }

  // evidence must have a valid digest if present
  let evidence: CrabedenceExecutionResponse["evidence"];
  if (obj.evidence !== undefined) {
    if (typeof obj.evidence !== "object" || obj.evidence === null) {
      throw new TransportError("response.evidence must be an object", "PROTOCOL");
    }
    const ev = obj.evidence as Record<string, unknown>;
    if (typeof ev.digest !== "string" || !/^[0-9a-f]{64}$/.test(ev.digest)) {
      throw new TransportError(
        "response.evidence.digest must be a 64-character hex string",
        "PROTOCOL",
      );
    }
    evidence = {
      digest: ev.digest,
      ...(typeof ev.receipt_version === "number" && {
        receipt_version: ev.receipt_version,
      }),
    };
  }

  // execution must have provider and run_id if present
  let execution: CrabedenceExecutionResponse["execution"];
  if (obj.execution !== undefined) {
    if (typeof obj.execution !== "object" || obj.execution === null) {
      throw new TransportError("response.execution must be an object", "PROTOCOL");
    }
    const ex = obj.execution as Record<string, unknown>;
    if (typeof ex.provider !== "string" || typeof ex.run_id !== "string") {
      throw new TransportError(
        "response.execution must have provider and run_id strings",
        "PROTOCOL",
      );
    }
    execution = { provider: ex.provider, run_id: ex.run_id };
  }

  return {
    status: status as CrabedenceExecutionResponse["status"],
    ...(obj.result !== undefined && { result: obj.result }),
    ...(obj.error !== undefined && { error: obj.error as string }),
    ...(evidence && { evidence }),
    ...(execution && { execution }),
  };
}

/**
 * CrabedenceExecutionAdapter implements NeMo's ExecutionPort by
 * forwarding requests to the Crabedence execution API.
 *
 * For MUTATION/CRITICAL operations, a POST_DISPATCH transport failure
 * (request sent, no response) is converted to UNKNOWN rather than
 * thrown, because the side effect may have already occurred.
 */
export class CrabedenceExecutionAdapter implements ExecutionPort {
  constructor(
    private readonly client: CrabedenceClient,
    private readonly timeoutMs: number = DEFAULT_TIMEOUT_MS,
  ) {}

  async execute(
    request: KernelExecutionRequest,
  ): Promise<KernelExecutionOutcome> {
    const wireRequest: CapabilityInvocationRequest = {
      capability: request.capabilityId,
      arguments: request.arguments,
      authority: {
        principal: request.authority.principal,
        authority_ref: request.authority.grantId,
      },
      // execution_class is optional/advisory — only send if the caller
      // explicitly asserts it. Crabedence's registry is authoritative.
      ...(request.executionClass && { execution_class: request.executionClass }),
      ...(request.idempotencyKey && { idempotency_key: request.idempotencyKey }),
      ...(request.deadline && { deadline: request.deadline }),
    };

    try {
      const response = await this.client.execute(wireRequest);

      // IN_FLIGHT is a valid wire status but not a terminal NEMO status.
      // The operation is in progress — the outcome is unknown to the caller.
      // Convert to UNKNOWN at the NEMO boundary.
      const nemoStatus: KernelExecutionOutcome["status"] =
        response.status === "IN_FLIGHT" ? "UNKNOWN" : (response.status as KernelExecutionOutcome["status"]);

      return {
        status: nemoStatus,
        ...(response.result !== undefined && { result: response.result }),
        ...(response.error !== undefined && { error: response.error }),
        ...(response.evidence && {
          evidence: {
            digest: response.evidence.digest,
            ...(response.evidence.receipt_version !== undefined && {
              receiptVersion: response.evidence.receipt_version,
            }),
          },
        }),
        ...(response.execution && {
          execution: {
            provider: response.execution.provider,
            runId: response.execution.run_id,
          },
        }),
      };
    } catch (err) {
      // For mutations, POST_DISPATCH failure means the request was sent
      // but the response was lost. The side effect may have occurred.
      // Convert to UNKNOWN instead of throwing.
      if (
        err instanceof TransportError &&
        err.kind === "POST_DISPATCH" &&
        (request.executionClass === "MUTATION" ||
          request.executionClass === "CRITICAL")
      ) {
        return {
          status: "UNKNOWN",
          error: `transport failure after dispatch: ${err.message}`,
        };
      }
      throw err;
    }
  }
}
