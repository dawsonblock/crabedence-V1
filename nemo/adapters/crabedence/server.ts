/**
 * Crabedence execution API server.
 *
 * Listens on a Unix domain socket and accepts execution requests from
 * NeMo's CrabedenceExecutionAdapter. This is the server side of the
 * boundary between NeMo (reasoning) and Crabedence (execution).
 *
 * The server:
 *   1. Validates the request schema
 *   2. Verifies authority
 *   3. Checks idempotency (deduplicates mutations)
 *   4. Routes to the appropriate provider
 *   5. Captures evidence
 *   6. Returns a typed outcome with UNKNOWN as first-class
 *
 * In production this connects to Crabedence's Go core for provider
 * lifecycle, evidence generation, and receipt signing. For testing
 * and local development, handlers can be injected.
 */

import { createServer, type Server, type Socket } from "node:net";
import { unlinkSync, existsSync } from "node:fs";

// ─── Wire types (shared with adapter) ─────────────────────────────────

export interface ExecutionApiRequest {
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
 * Request handler. In production this bridges to Crabedence's Go core.
 * In tests, a mock handler is injected.
 */
export type ExecutionHandler = (
  request: ExecutionApiRequest,
) => Promise<ExecutionApiResponse>;

// ─── Idempotency store ───────────────────────────────────────────────

/**
 * In-memory idempotency store. In production this is backed by
 * PostgreSQL. For each idempotency key, the first response is cached
 * and returned for subsequent requests with the same key.
 */
class IdempotencyStore {
  private readonly cache = new Map<string, ExecutionApiResponse>();

  async get(key: string): Promise<ExecutionApiResponse | undefined> {
    return this.cache.get(key);
  }

  async put(key: string, response: ExecutionApiResponse): Promise<void> {
    this.cache.set(key, response);
  }
}

// ─── Server ──────────────────────────────────────────────────────────

export class ExecutionApiServer {
  private server: Server | null = null;
  private readonly idempotency = new IdempotencyStore();

  constructor(
    private readonly handler: ExecutionHandler,
    private readonly socketPath: string,
  ) {}

  async start(): Promise<void> {
    // Clean up stale socket
    if (existsSync(this.socketPath)) {
      unlinkSync(this.socketPath);
    }

    this.server = createServer((socket: Socket) => {
      this.handleConnection(socket);
    });

    return new Promise((resolve) => {
      this.server!.listen(this.socketPath, () => {
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    if (this.server) {
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

    socket.on("data", async (chunk: Buffer) => {
      chunks.push(chunk);
      const buf = Buffer.concat(chunks);

      if (request === null && buf.length >= 4) {
        expectedLen = buf.readUInt32BE(0);
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
        // Process asynchronously
        this.processRequest(socket, request);
      }
    });

    socket.on("error", () => {
      // Socket errors are expected on close; ignore
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
      if (!request.authority?.principal || !request.authority?.grant_id) {
        this.sendResponse(socket, {
          status: "DENIED",
          error: "missing authority",
        });
        return;
      }

      // Idempotency check for mutations
      if (request.idempotency_key) {
        const cached = await this.idempotency.get(request.idempotency_key);
        if (cached) {
          this.sendResponse(socket, cached);
          return;
        }
      }

      // Execute
      const response = await this.handler(request);

      // Cache idempotent responses
      if (request.idempotency_key && response.status !== "UNKNOWN") {
        await this.idempotency.put(request.idempotency_key, response);
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
    const json = JSON.stringify(response);
    const length = Buffer.alloc(4);
    length.writeUInt32BE(json.length, 0);
    socket.write(length);
    socket.write(json);
    socket.end();
  }
}
