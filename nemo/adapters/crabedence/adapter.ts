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

import { connect } from "node:net";

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
interface CrabedenceExecutionRequest {
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
interface CrabedenceExecutionResponse {
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

// ─── Client ───────────────────────────────────────────────────────────

/**
 * Low-level Unix socket client for the Crabedence execution API.
 * Sends a length-prefixed JSON request and reads a single JSON response.
 */
export class CrabedenceClient {
  constructor(private readonly socketPath: string) {}

  async execute(
    request: CrabedenceExecutionRequest,
  ): Promise<CrabedenceExecutionResponse> {
    return new Promise((resolve, reject) => {
      const socket = connect(this.socketPath);
      const chunks: Buffer[] = [];
      let body: string | null = null;

      socket.on("connect", () => {
        const json = JSON.stringify(request);
        const length = Buffer.alloc(4);
        length.writeUInt32BE(json.length, 0);
        socket.write(length);
        socket.write(json);
      });

      socket.on("data", (chunk: Buffer) => {
        chunks.push(chunk);
        // Try to parse once we have the full response.
        const buf = Buffer.concat(chunks);
        if (body === null && buf.length >= 4) {
          const respLen = buf.readUInt32BE(0);
          if (buf.length >= 4 + respLen) {
            body = buf.subarray(4, 4 + respLen).toString("utf-8");
            socket.end();
          }
        }
      });

      socket.on("error", (err: Error) => {
        reject(new Error(`crabedence socket error: ${err.message}`));
      });

      socket.on("close", () => {
        if (body === null) {
          reject(new Error("crabedence socket closed before response"));
          return;
        }
        try {
          resolve(JSON.parse(body) as CrabedenceExecutionResponse);
        } catch (err) {
          reject(
            new Error(
              `crabedence response parse error: ${(err as Error).message}`,
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
 */
export class CrabedenceExecutionAdapter implements ExecutionPort {
  constructor(private readonly client: CrabedenceClient) {}

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
  }
}
