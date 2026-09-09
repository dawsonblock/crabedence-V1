/**
 * Crabedence execution adapter.
 *
 * Implements NeMo's ExecutionPort by calling the Crabedence execution
 * API over a Unix domain socket. This adapter is intentionally thin —
 * it maps NeMo request types to Crabedence wire format and maps the
 * response back. If this file grows beyond a few hundred lines, the
 * boundary is wrong.
 *
 * Dependency direction:
 *
 *   NeMo contracts (ExecutionPort)
 *       ↑ implements
 *   CrabedenceExecutionAdapter
 *       ↓ calls
 *   Crabedence execution API (Unix socket)
 */

import { connect, type Socket } from "node:net";

import type {
  ExecutionPort,
  KernelExecutionOutcome,
  KernelExecutionRequest,
} from "../../contracts/index";

// ─── Wire protocol ────────────────────────────────────────────────────

/**
 * Crabedence execution API request (POST /v1/executions).
 * This is the wire format. NeMo's types map to this.
 */
export interface CrabedenceExecutionRequest {
  readonly capability: string;
  readonly arguments: unknown;
  readonly authority: {
    readonly principal: string;
    readonly grant_id: string;
  };
  readonly execution_class: string;
  readonly idempotency_key?: string;
  readonly deadline?: string;
}

/**
 * Crabedence execution API response.
 */
export interface CrabedenceExecutionResponse {
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
              const response = JSON.parse(
                frame.toString("utf-8"),
              ) as CrabedenceExecutionResponse;
              succeed(response);
            } catch {
              fail(
                new TransportError("invalid JSON in response", "PROTOCOL"),
              );
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

/**
 * Maps Crabedence wire status to NeMo execution status.
 * Identity mapping — the wire protocol uses the same status names.
 */
function mapStatus(status: CrabedenceExecutionResponse["status"]): string {
  return status;
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
    const wireRequest: CrabedenceExecutionRequest = {
      capability: request.capabilityId,
      arguments: request.arguments,
      authority: {
        principal: request.authority.principal,
        grant_id: request.authority.grantId,
      },
      execution_class: request.executionClass ?? "CRITICAL",
      ...(request.idempotencyKey && { idempotency_key: request.idempotencyKey }),
      ...(request.deadline && { deadline: request.deadline }),
    };

    try {
      const response = await this.client.execute(wireRequest);

      return {
        status: mapStatus(response.status) as KernelExecutionOutcome["status"],
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
