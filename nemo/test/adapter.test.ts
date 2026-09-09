import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type {
  ExecutionApiRequest,
  ExecutionApiResponse,
} from "../adapters/crabedence/index";
import {
  CrabedenceClient,
  CrabedenceExecutionAdapter,
  ExecutionApiServer,
} from "../adapters/crabedence/index";
import type { KernelExecutionOutcome } from "../contracts/index";

// ─── Test helpers ─────────────────────────────────────────────────────

function makeTempSocket(): string {
  const dir = mkdtempSync(join(tmpdir(), "nemo-test-"));
  return join(dir, "crabedence.sock");
}

function cleanupSocket(socketPath: string): void {
  rmSync(socketPath, { recursive: true, force: true });
}

const auth = { principal: "alice@example.com", grantId: "grant_123" };
const wireAuth = { principal: "alice@example.com", grant_id: "grant_123" };

// ─── Tests ────────────────────────────────────────────────────────────

describe("CrabedenceExecutionAdapter (Unix socket)", () => {
  let socketPath: string;
  let server: ExecutionApiServer;

  beforeEach(() => {
    socketPath = makeTempSocket();
  });

  afterEach(async () => {
    if (server) {
      await server.stop();
    }
    cleanupSocket(socketPath);
  });

  async function startServer(
    handler: (req: ExecutionApiRequest) => Promise<ExecutionApiResponse>,
  ): Promise<void> {
    server = new ExecutionApiServer(handler, socketPath);
    await server.start();
  }

  // ─── Round-trip: SUCCEEDED with evidence ──────────────────────────

  it("returns SUCCEEDED with evidence for CRITICAL", async () => {
    await startServer(async (req) => ({
      status: "SUCCEEDED",
      result: { message_id: "msg_001" },
      evidence: {
        digest: "abc123def456",
        receipt_version: 3,
      },
      execution: {
        provider: "gmail",
        run_id: "run_001",
      },
    }));

    const adapter = new CrabedenceExecutionAdapter(
      new CrabedenceClient(socketPath),
    );

    const outcome: KernelExecutionOutcome = await adapter.execute({
      capabilityId: "email.send",
      arguments: { to: "bob@example.com", body: "Hello" },
      authority: auth,
      executionClass: "CRITICAL",
      idempotencyKey: "req_001",
    });

    expect(outcome.status).toBe("SUCCEEDED");
    expect(outcome.result).toEqual({ message_id: "msg_001" });
    expect(outcome.evidence).toEqual({
      digest: "abc123def456",
      receiptVersion: 3,
    });
    expect(outcome.execution).toEqual({
      provider: "gmail",
      runId: "run_001",
    });
  });

  // ─── UNKNOWN is preserved ────────────────────────────────────────

  it("returns UNKNOWN when handler loses connectivity", async () => {
    await startServer(async () => ({
      status: "UNKNOWN" as const,
      error: "lost connectivity after provider call",
    }));

    const adapter = new CrabedenceExecutionAdapter(
      new CrabedenceClient(socketPath),
    );

    const outcome = await adapter.execute({
      capabilityId: "email.send",
      arguments: { to: "bob@example.com" },
      authority: auth,
      executionClass: "CRITICAL",
      idempotencyKey: "req_unknown",
    });

    expect(outcome.status).toBe("UNKNOWN");
    expect(outcome.error).toContain("lost connectivity");
  });

  // ─── DENIED is preserved ─────────────────────────────────────────

  it("returns DENIED when authority is insufficient", async () => {
    await startServer(async () => ({
      status: "DENIED" as const,
      error: "authority grant revoked",
    }));

    const adapter = new CrabedenceExecutionAdapter(
      new CrabedenceClient(socketPath),
    );

    const outcome = await adapter.execute({
      capabilityId: "email.send",
      arguments: { to: "bob@example.com" },
      authority: auth,
      executionClass: "CRITICAL",
      idempotencyKey: "req_denied",
    });

    expect(outcome.status).toBe("DENIED");
  });

  // ─── Idempotency: duplicate key returns cached response ─────────

  it("deduplicates requests with same idempotency key", async () => {
    let callCount = 0;
    await startServer(async (req) => {
      callCount++;
      return {
        status: "SUCCEEDED" as const,
        result: { message_id: `msg_${callCount}` },
        execution: {
          provider: "gmail",
          run_id: `run_${callCount}`,
        },
      };
    });

    const client = new CrabedenceClient(socketPath);

    // First request
    const resp1 = await client.execute({
      capability: "email.send",
      arguments: { to: "bob@example.com" },
      authority: wireAuth,
      execution_class: "CRITICAL",
      idempotency_key: "idem_001",
    });

    // Second request with same key — should return cached
    const resp2 = await client.execute({
      capability: "email.send",
      arguments: { to: "bob@example.com" },
      authority: wireAuth,
      execution_class: "CRITICAL",
      idempotency_key: "idem_001",
    });

    expect(resp1.status).toBe("SUCCEEDED");
    expect(resp2.status).toBe("SUCCEEDED");
    // Same message_id — handler only called once
    expect(resp1.result).toEqual(resp2.result);
    expect(callCount).toBe(1);
  });

  // ─── UNKNOWN is not cached ──────────────────────────────────────

  it("does not cache UNKNOWN responses for idempotency", async () => {
    let callCount = 0;
    await startServer(async (req) => {
      callCount++;
      if (callCount === 1) {
        return {
          status: "UNKNOWN" as const,
          error: "first attempt lost connectivity",
        };
      }
      return {
        status: "SUCCEEDED" as const,
        result: { message_id: "msg_retry" },
      };
    });

    const client = new CrabedenceClient(socketPath);

    const resp1 = await client.execute({
      capability: "email.send",
      arguments: {},
      authority: wireAuth,
      execution_class: "CRITICAL",
      idempotency_key: "idem_unknown",
    });

    const resp2 = await client.execute({
      capability: "email.send",
      arguments: {},
      authority: wireAuth,
      execution_class: "CRITICAL",
      idempotency_key: "idem_unknown",
    });

    expect(resp1.status).toBe("UNKNOWN");
    expect(resp2.status).toBe("SUCCEEDED");
    expect(callCount).toBe(2);
  });

  // ─── Missing authority → DENIED ─────────────────────────────────

  it("rejects missing authority", async () => {
    await startServer(async () => ({
      status: "SUCCEEDED" as const,
    }));

    const client = new CrabedenceClient(socketPath);

    const resp = await client.execute({
      capability: "email.send",
      arguments: {},
      authority: { principal: "", grant_id: "" },
      execution_class: "CRITICAL",
    });

    expect(resp.status).toBe("DENIED");
  });

  // ─── Missing capability → FAILED ────────────────────────────────

  it("rejects missing capability", async () => {
    await startServer(async () => ({
      status: "SUCCEEDED" as const,
    }));

    const client = new CrabedenceClient(socketPath);

    const resp = await client.execute({
      capability: "",
      arguments: {},
      authority: wireAuth,
      execution_class: "CRITICAL",
    });

    expect(resp.status).toBe("FAILED");
  });
});
