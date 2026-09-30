/**
 * Regression tests from build 4 audit.
 *
 * These tests cover edge cases identified in the build 4 audit that
 * were not previously tested:
 *   - Oversized response rejected by client
 *   - Socket permissions (0600 socket, 0700 directory)
 *   - Execution class absent at adapter boundary
 *   - Malformed authority reference (empty, whitespace)
 *   - Non-ASCII evidence/provider/error fields
 */

import { mkdtempSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type {
  ExecutionApiRequest,
  ExecutionApiResponse,
} from "../adapters/crabedence/index";
import {
  CrabedenceClient,
  CrabedenceExecutionAdapter,
  ExecutionApiServer,
} from "../adapters/crabedence/index";

function makeTempSocket(): string {
  const dir = mkdtempSync(join(tmpdir(), "nemo-audit-"));
  return join(dir, "crabedence.sock");
}

function cleanupSocket(socketPath: string): void {
  rmSync(socketPath, { recursive: true, force: true });
}

const wireAuth = { principal: "alice@example.com", grant_id: "grant_123" };
const kernelAuth = { principal: "alice@example.com", grantId: "grant_123" };

describe("Audit regression: oversized response rejected", () => {
  let socketPath: string;
  let server: ExecutionApiServer;

  beforeEach(() => {
    socketPath = makeTempSocket();
  });

  afterEach(async () => {
    if (server) await server.stop();
    cleanupSocket(socketPath);
  });

  it("rejects response exceeding MAX_MESSAGE_BYTES", async () => {
    const hugePayload = "x".repeat(5 * 1024 * 1024); // 5 MiB > 4 MiB limit
    const handler = async (): Promise<ExecutionApiResponse> => ({
      status: "SUCCEEDED",
      result: { data: hugePayload },
    });

    server = new ExecutionApiServer(handler, socketPath);
    await server.start();

    const client = new CrabedenceClient(socketPath, 5000);
    await expect(
      client.execute({
        capability: "test.huge",
        arguments: {},
        authority: wireAuth,
      }),
    ).rejects.toThrow();
  });
});

describe("Audit regression: socket permissions", () => {
  it("creates socket with 0600 permissions", async () => {
    const socketPath = makeTempSocket();
    cleanupSocket(socketPath);

    const handler = async (): Promise<ExecutionApiResponse> => ({
      status: "SUCCEEDED",
    });
    const srv = new ExecutionApiServer(handler, socketPath);
    await srv.start();

    try {
      const stat = statSync(socketPath);
      const mode = stat.mode & 0o777;
      expect(mode).toBe(0o600);
    } finally {
      await srv.stop();
      cleanupSocket(socketPath);
    }
  });

  it("creates directory with 0700 permissions", async () => {
    const dir = mkdtempSync(join(tmpdir(), "nemo-perm-"));
    const socketPath = join(dir, "subdir", "crabedence.sock");

    const handler = async (): Promise<ExecutionApiResponse> => ({
      status: "SUCCEEDED",
    });
    const srv = new ExecutionApiServer(handler, socketPath);
    await srv.start();

    try {
      const stat = statSync(join(dir, "subdir"));
      const mode = stat.mode & 0o777;
      expect(mode).toBe(0o700);
    } finally {
      await srv.stop();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("Audit regression: execution class absent at adapter", () => {
  let socketPath: string;
  let server: ExecutionApiServer;

  beforeEach(() => {
    socketPath = makeTempSocket();
  });

  afterEach(async () => {
    if (server) await server.stop();
    cleanupSocket(socketPath);
  });

  it("adapter does not invent execution class when absent", async () => {
    let receivedClass: string | undefined;
    const handler = async (req: ExecutionApiRequest): Promise<ExecutionApiResponse> => {
      receivedClass = req.execution_class;
      return { status: "SUCCEEDED" };
    };

    server = new ExecutionApiServer(handler, socketPath);
    await server.start();

    const client = new CrabedenceClient(socketPath, 5000);
    const adapter = new CrabedenceExecutionAdapter(client);

    await adapter.execute({
      capabilityId: "test.read",
      arguments: {},
      authority: kernelAuth,
      // executionClass intentionally omitted
    });

    // The server should NOT have received an execution_class
    expect(receivedClass).toBeUndefined();
  });
});

describe("Audit regression: malformed authority reference", () => {
  let socketPath: string;
  let server: ExecutionApiServer;

  beforeEach(() => {
    socketPath = makeTempSocket();
  });

  afterEach(async () => {
    if (server) await server.stop();
    cleanupSocket(socketPath);
  });

  it("rejects empty authority_ref", async () => {
    const handler = async (): Promise<ExecutionApiResponse> => ({
      status: "SUCCEEDED",
    });

    server = new ExecutionApiServer(handler, socketPath);
    await server.start();

    const client = new CrabedenceClient(socketPath, 5000);

    // Empty authority_ref should be rejected by the server
    const response = await client.execute({
      capability: "test.read",
      arguments: {},
      authority: { principal: "alice", authority_ref: "" },
    });
    expect(response.status).toBe("DENIED");
  });

  it("rejects whitespace-only authority_ref", async () => {
    const handler = async (): Promise<ExecutionApiResponse> => ({
      status: "SUCCEEDED",
    });

    server = new ExecutionApiServer(handler, socketPath);
    await server.start();

    const client = new CrabedenceClient(socketPath, 5000);

    const response = await client.execute({
      capability: "test.read",
      arguments: {},
      authority: { principal: "alice", authority_ref: "   " },
    });
    expect(response.status).toBe("DENIED");
  });
});

describe("Audit regression: non-ASCII fields", () => {
  let socketPath: string;
  let server: ExecutionApiServer;

  beforeEach(() => {
    socketPath = makeTempSocket();
  });

  afterEach(async () => {
    if (server) await server.stop();
    cleanupSocket(socketPath);
  });

  it("round-trips Unicode in provider and run_id fields", async () => {
    const unicodeProvider = "提供者-🙂";
    const unicodeRunId = "run-你好-1234";

    const handler = async (): Promise<ExecutionApiResponse> => ({
      status: "SUCCEEDED",
      execution: {
        provider: unicodeProvider,
        run_id: unicodeRunId,
      },
    });

    server = new ExecutionApiServer(handler, socketPath);
    await server.start();

    const client = new CrabedenceClient(socketPath, 5000);
    const response = await client.execute({
      capability: "test.read",
      arguments: {},
      authority: wireAuth,
    });

    expect(response.status).toBe("SUCCEEDED");
    expect(response.execution?.provider).toBe(unicodeProvider);
    expect(response.execution?.run_id).toBe(unicodeRunId);
  });

  it("round-trips Unicode in error field", async () => {
    const unicodeError = "失败原因：连接超时 🚫";

    const handler = async (): Promise<ExecutionApiResponse> => ({
      status: "FAILED",
      error: unicodeError,
    });

    server = new ExecutionApiServer(handler, socketPath);
    await server.start();

    const client = new CrabedenceClient(socketPath, 5000);
    const response = await client.execute({
      capability: "test.read",
      arguments: {},
      authority: wireAuth,
    });

    expect(response.status).toBe("FAILED");
    expect(response.error).toBe(unicodeError);
  });
});
