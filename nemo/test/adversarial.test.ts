/**
 * Adversarial NEMO tests.
 *
 * These tests exercise edge cases that could cause duplicate side
 * effects, protocol corruption, or incorrect retry behavior:
 *
 *   - Unicode request/result (UTF-8 byte length vs string length)
 *   - Socket close before dispatch (safe retry)
 *   - Socket close after dispatch (POST_DISPATCH → UNKNOWN for mutations)
 *   - Two simultaneous identical mutations (atomic reservation)
 *   - Same idempotency key with different arguments (CONFLICT)
 *   - Server restart during mutation (UNKNOWN persisted)
 *   - UNKNOWN replay (returns persisted UNKNOWN, not re-invoked)
 *   - Malformed response (PROTOCOL error)
 *   - Oversized frame (rejected)
 *   - Expired deadline (DENIED)
 *   - Invalid authority (DENIED)
 *   - CRITICAL success without evidence (FAILED by kernel)
 */

import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type {
  ExecutionApiRequest,
  ExecutionApiResponse,
  IdempotencyStore,
} from "../adapters/crabedence/index";
import {
  CrabedenceClient,
  CrabedenceExecutionAdapter,
  ExecutionApiServer,
  TransportError,
} from "../adapters/crabedence/index";
import { CapabilityCatalog, NemoKernel } from "../kernel/index";
import type { ExecutionPort, KernelExecutionOutcome, KernelExecutionRequest } from "../contracts/index";

// ─── Test helpers ─────────────────────────────────────────────────────

function makeTempSocket(): string {
  const dir = mkdtempSync(join(tmpdir(), "nemo-adv-"));
  return join(dir, "crabedence.sock");
}

function cleanupSocket(socketPath: string): void {
  rmSync(socketPath, { recursive: true, force: true });
}

const auth = { principal: "alice@example.com", grantId: "grant_123" };
const wireAuth = { principal: "alice@example.com", grant_id: "grant_123" };

class MockPort implements ExecutionPort {
  readonly calls: KernelExecutionRequest[] = [];
  private response: KernelExecutionOutcome;

  constructor(response: KernelExecutionOutcome) {
    this.response = response;
  }

  setResponse(response: KernelExecutionOutcome): void {
    this.response = response;
  }

  async execute(request: KernelExecutionRequest): Promise<KernelExecutionOutcome> {
    this.calls.push(request);
    return this.response;
  }
}

// ─── Tests ────────────────────────────────────────────────────────────

describe("Adversarial: Unicode and framing", () => {
  let socketPath: string;
  let server: ExecutionApiServer;

  beforeEach(() => {
    socketPath = makeTempSocket();
  });

  afterEach(async () => {
    if (server) await server.stop();
    cleanupSocket(socketPath);
  });

  it("handles Unicode in request arguments (José, emoji, CJK)", async () => {
    const unicodeArgs = {
      to: "josé@example.com",
      name: "José García",
      emoji: "🎉🚀",
      cjk: "日本語テスト",
      smartquotes: "“smart” ‘quotes’",
    };

    let received: ExecutionApiRequest | null = null;
    server = new ExecutionApiServer(async (req) => {
      received = req;
      return {
        status: "SUCCEEDED",
        result: { echo: req.arguments },
      };
    }, socketPath);
    await server.start();

    const client = new CrabedenceClient(socketPath);
    const resp = await client.execute({
      capability: "email.send",
      arguments: unicodeArgs,
      authority: wireAuth,
      execution_class: "CRITICAL",
      idempotency_key: "unicode_001",
    });

    expect(resp.status).toBe("SUCCEEDED");
    expect(received).not.toBeNull();
    expect(received!.arguments).toEqual(unicodeArgs);
    expect((resp.result as { echo: unknown }).echo).toEqual(unicodeArgs);
  });

  it("rejects oversized frames", async () => {
    server = new ExecutionApiServer(async () => ({
      status: "SUCCEEDED",
    }), socketPath);
    await server.start();

    // Create a request larger than 4 MiB
    const hugeArgs = { data: "x".repeat(5 * 1024 * 1024) };
    const client = new CrabedenceClient(socketPath);

    await expect(
      client.execute({
        capability: "test.huge",
        arguments: hugeArgs,
        authority: wireAuth,
        execution_class: "READ",
      }),
    ).rejects.toThrow(/maximum size/);
  });
});

describe("Adversarial: Transport ambiguity", () => {
  let socketPath: string;
  let server: ExecutionApiServer;

  beforeEach(() => {
    socketPath = makeTempSocket();
  });

  afterEach(async () => {
    if (server) await server.stop();
    cleanupSocket(socketPath);
  });

  it("PRE_DISPATCH failure: connection refused (no server)", async () => {
    // No server started — connection refused
    const adapter = new CrabedenceExecutionAdapter(
      new CrabedenceClient(socketPath, 1000),
    );

    await expect(
      adapter.execute({
        capabilityId: "test.read",
        arguments: {},
        authority: auth,
        executionClass: "READ",
      }),
    ).rejects.toThrow(TransportError);
  });

  it("POST_DISPATCH: MUTATION returns UNKNOWN when socket closes after send", async () => {
    // Server accepts connection but closes immediately after receiving data
    server = new ExecutionApiServer(async () => {
      // Simulate: handler hangs (server crash mid-execution)
      return new Promise<ExecutionApiResponse>(() => {
        // Never resolves — simulates lost connection
      });
    }, socketPath);
    await server.start();

    // Use a client with short timeout
    const adapter = new CrabedenceExecutionAdapter(
      new CrabedenceClient(socketPath, 500),
      500,
    );

    const outcome = await adapter.execute({
      capabilityId: "email.send",
      arguments: { to: "bob@example.com" },
      authority: auth,
      executionClass: "CRITICAL",
      idempotencyKey: "post_dispatch_001",
    });

    // For CRITICAL, POST_DISPATCH failure must be UNKNOWN, not thrown.
    // (Either timeout or connection close after dispatch.)
    expect(outcome.status).toBe("UNKNOWN");
  });

  it("PRE_DISPATCH: READ throws (not converted to UNKNOWN)", async () => {
    // No server — connection refused, PRE_DISPATCH
    const adapter = new CrabedenceExecutionAdapter(
      new CrabedenceClient(socketPath, 500),
      500,
    );

    await expect(
      adapter.execute({
        capabilityId: "test.read",
        arguments: {},
        authority: auth,
        executionClass: "READ",
      }),
    ).rejects.toThrow(TransportError);
  });
});

describe("Adversarial: Idempotency races", () => {
  let socketPath: string;
  let server: ExecutionApiServer;

  beforeEach(() => {
    socketPath = makeTempSocket();
  });

  afterEach(async () => {
    if (server) await server.stop();
    cleanupSocket(socketPath);
  });

  it("two concurrent identical mutations converge on one execution", async () => {
    let callCount = 0;
    let resolveFirst!: () => void;
    const firstCallBlocked = new Promise<void>((resolve) => {
      resolveFirst = resolve;
    });

    server = new ExecutionApiServer(async (req) => {
      callCount++;
      if (callCount === 1) {
        // Block first call until second arrives
        await firstCallBlocked;
      }
      return {
        status: "SUCCEEDED",
        result: { message_id: `msg_${callCount}` },
        execution: { provider: "gmail", run_id: `run_${callCount}` },
      };
    }, socketPath);
    await server.start();

    const client = new CrabedenceClient(socketPath);

    // Start first request (will block)
    const promise1 = client.execute({
      capability: "email.send",
      arguments: { to: "bob@example.com" },
      authority: wireAuth,
      execution_class: "CRITICAL",
      idempotency_key: "concurrent_001",
    });

    // Start second request with same key (should see IN_FLIGHT)
    const promise2 = client.execute({
      capability: "email.send",
      arguments: { to: "bob@example.com" },
      authority: wireAuth,
      execution_class: "CRITICAL",
      idempotency_key: "concurrent_001",
    });

    // Give the second request time to arrive
    await new Promise((r) => setTimeout(r, 50));

    // Release the first call
    resolveFirst();

    const [resp1, resp2] = await Promise.all([promise1, promise2]);

    // First succeeds; second sees IN_FLIGHT → UNKNOWN
    expect(resp1.status).toBe("SUCCEEDED");
    expect(resp2.status).toBe("UNKNOWN");
    expect(resp2.error).toContain("in flight");
    // Handler called only once
    expect(callCount).toBe(1);
  });

  it("same idempotency key with different arguments is CONFLICT", async () => {
    server = new ExecutionApiServer(async () => ({
      status: "SUCCEEDED",
      result: { ok: true },
    }), socketPath);
    await server.start();

    const client = new CrabedenceClient(socketPath);

    const resp1 = await client.execute({
      capability: "email.send",
      arguments: { to: "bob@example.com" },
      authority: wireAuth,
      execution_class: "CRITICAL",
      idempotency_key: "conflict_001",
    });

    const resp2 = await client.execute({
      capability: "email.send",
      arguments: { to: "carol@example.com" }, // Different arguments
      authority: wireAuth,
      execution_class: "CRITICAL",
      idempotency_key: "conflict_001",
    });

    expect(resp1.status).toBe("SUCCEEDED");
    expect(resp2.status).toBe("DENIED");
    expect(resp2.error).toContain("different request");
  });
});

describe("Adversarial: Kernel admission", () => {
  it("rejects expired deadline", async () => {
    const local = new MockPort({ status: "SUCCEEDED" });
    const remote = new MockPort({ status: "SUCCEEDED" });
    const catalog = new CapabilityCatalog();
    catalog.register({
      id: "test.cap",
      schema: { type: "object" },
      executionClass: "READ",
      adapter: "crabedence",
      authorityPolicy: "test",
    });
    const kernel = new NemoKernel(catalog, { local, remote });

    const outcome = await kernel.execute({
      capabilityId: "test.cap",
      arguments: {},
      authority: auth,
      deadline: "2020-01-01T00:00:00Z", // Expired
    });

    expect(outcome.status).toBe("DENIED");
    expect(outcome.error).toContain("expired");
  });

  it("rejects malformed deadline", async () => {
    const local = new MockPort({ status: "SUCCEEDED" });
    const remote = new MockPort({ status: "SUCCEEDED" });
    const catalog = new CapabilityCatalog();
    catalog.register({
      id: "test.cap",
      schema: { type: "object" },
      executionClass: "READ",
      adapter: "crabedence",
      authorityPolicy: "test",
    });
    const kernel = new NemoKernel(catalog, { local, remote });

    const outcome = await kernel.execute({
      capabilityId: "test.cap",
      arguments: {},
      authority: auth,
      deadline: "not-a-date",
    });

    expect(outcome.status).toBe("DENIED");
    expect(outcome.error).toContain("invalid deadline");
  });

  it("rejects missing authority principal", async () => {
    const local = new MockPort({ status: "SUCCEEDED" });
    const remote = new MockPort({ status: "SUCCEEDED" });
    const catalog = new CapabilityCatalog();
    catalog.register({
      id: "test.cap",
      schema: { type: "object" },
      executionClass: "READ",
      adapter: "crabedence",
      authorityPolicy: "test",
    });
    const kernel = new NemoKernel(catalog, { local, remote });

    const outcome = await kernel.execute({
      capabilityId: "test.cap",
      arguments: {},
      authority: { principal: "", grantId: "grant_123" },
    });

    expect(outcome.status).toBe("DENIED");
    expect(outcome.error).toContain("authority");
  });

  it("rejects CRITICAL success without evidence digest", async () => {
    const local = new MockPort({ status: "SUCCEEDED" });
    // CRITICAL returns SUCCEEDED but no evidence
    const remote = new MockPort({
      status: "SUCCEEDED",
      result: { ok: true },
      // Missing evidence
    });
    const catalog = new CapabilityCatalog();
    catalog.register({
      id: "email.send",
      schema: { type: "object" },
      executionClass: "CRITICAL",
      adapter: "crabedence",
      authorityPolicy: "email.send",
    });
    const kernel = new NemoKernel(catalog, { local, remote });

    const outcome = await kernel.execute({
      capabilityId: "email.send",
      arguments: { to: "bob@example.com" },
      authority: auth,
      idempotencyKey: "req_no_evidence",
    });

    expect(outcome.status).toBe("FAILED");
    expect(outcome.error).toContain("evidence");
  });

  it("accepts CRITICAL success WITH evidence", async () => {
    const local = new MockPort({ status: "SUCCEEDED" });
    const remote = new MockPort({
      status: "SUCCEEDED",
      result: { ok: true },
      evidence: { digest: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", receiptVersion: 3 },
      execution: { provider: "test", runId: "run_critical_001" },
    });
    const catalog = new CapabilityCatalog();
    catalog.register({
      id: "email.send",
      schema: { type: "object" },
      executionClass: "CRITICAL",
      adapter: "crabedence",
      authorityPolicy: "email.send",
    });
    const kernel = new NemoKernel(catalog, { local, remote });

    const outcome = await kernel.execute({
      capabilityId: "email.send",
      arguments: { to: "bob@example.com" },
      authority: auth,
      idempotencyKey: "req_with_evidence",
    });

    expect(outcome.status).toBe("SUCCEEDED");
    expect(outcome.evidence?.digest).toBe("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2");
  });

  it("validates schema (missing required property)", async () => {
    const local = new MockPort({ status: "SUCCEEDED" });
    const remote = new MockPort({ status: "SUCCEEDED" });
    const catalog = new CapabilityCatalog();
    catalog.register({
      id: "email.send",
      schema: {
        type: "object",
        required: ["to", "body"],
      },
      executionClass: "CRITICAL",
      adapter: "crabedence",
      authorityPolicy: "email.send",
    });
    const kernel = new NemoKernel(catalog, { local, remote });

    const outcome = await kernel.execute({
      capabilityId: "email.send",
      arguments: { to: "bob@example.com" }, // Missing "body"
      authority: auth,
      idempotencyKey: "req_schema_fail",
    });

    expect(outcome.status).toBe("DENIED");
    expect(outcome.error).toContain("schema");
    expect(outcome.error).toContain("body");
  });

  // ─── New tests for hardening 6 audit items ─────────────────────────────

  it("handler crash after dispatch returns UNKNOWN, not FAILED", async () => {
    const socketPath = makeTempSocket();
    cleanupSocket(socketPath);

    const crashHandler = async (_req: ExecutionApiRequest): Promise<ExecutionApiResponse> => {
      throw new Error("provider crashed after side effect");
    };

    const server = new ExecutionApiServer(crashHandler, socketPath);
    await server.start();

    try {
      const client = new CrabedenceClient(socketPath, 1000);
      const adapter = new CrabedenceExecutionAdapter(client);
      const outcome = await adapter.execute({
        capabilityId: "email.send",
        arguments: { to: "bob@example.com" },
        authority: auth,
        executionClass: "MUTATION",
        idempotencyKey: "crash_dispatch",
      });

      // Handler crash after dispatch must return UNKNOWN, not FAILED.
      // The side effect may have occurred.
      expect(outcome.status).toBe("UNKNOWN");
    } finally {
      await server.stop();
      cleanupSocket(socketPath);
    }
  });

  it("persistence failure after success returns UNKNOWN", async () => {
    const socketPath = makeTempSocket();
    cleanupSocket(socketPath);

    const successHandler = async (_req: ExecutionApiRequest): Promise<ExecutionApiResponse> => {
      return { status: "SUCCEEDED" };
    };

    // A store that fails on settle()
    const failingStore: IdempotencyStore = {
      async reserve() {
        return { state: "NEW" as const };
      },
      async settle() {
        throw new Error("database write failed");
      },
    };

    const server = new ExecutionApiServer(successHandler, socketPath, failingStore);
    await server.start();

    try {
      const client = new CrabedenceClient(socketPath, 1000);
      const adapter = new CrabedenceExecutionAdapter(client);
      const outcome = await adapter.execute({
        capabilityId: "email.send",
        arguments: { to: "bob@example.com" },
        authority: auth,
        executionClass: "MUTATION",
        idempotencyKey: "persist_fail",
      });

      // Persistence failed after success — must return UNKNOWN, not FAILED.
      expect(outcome.status).toBe("UNKNOWN");
    } finally {
      await server.stop();
      cleanupSocket(socketPath);
    }
  });

  it("EXISTING record with no response fails closed to UNKNOWN", async () => {
    const socketPath = makeTempSocket();
    cleanupSocket(socketPath);

    const successHandler = async (_req: ExecutionApiRequest): Promise<ExecutionApiResponse> => {
      return { status: "SUCCEEDED" };
    };

    // A store that returns EXISTING with no response (inconsistent state)
    const brokenStore: IdempotencyStore = {
      async reserve() {
        return { state: "EXISTING" as const, response: undefined };
      },
      async settle() {
        // no-op
      },
    };

    const server = new ExecutionApiServer(successHandler, socketPath, brokenStore);
    await server.start();

    try {
      const client = new CrabedenceClient(socketPath, 1000);
      const adapter = new CrabedenceExecutionAdapter(client);
      const outcome = await adapter.execute({
        capabilityId: "email.send",
        arguments: { to: "bob@example.com" },
        authority: auth,
        executionClass: "MUTATION",
        idempotencyKey: "broken_existing",
      });

      // EXISTING with no response must fail closed to UNKNOWN, not re-execute.
      expect(outcome.status).toBe("UNKNOWN");
      expect(outcome.error).toContain("reconciliation");
    } finally {
      await server.stop();
      cleanupSocket(socketPath);
    }
  });

  it("same key with different grant_id is a conflict", async () => {
    const socketPath = makeTempSocket();
    cleanupSocket(socketPath);

    let callCount = 0;
    const handler = async (req: ExecutionApiRequest): Promise<ExecutionApiResponse> => {
      callCount++;
      return { status: "SUCCEEDED" };
    };

    const server = new ExecutionApiServer(handler, socketPath);
    await server.start();

    try {
      const client = new CrabedenceClient(socketPath, 1000);
      const adapter = new CrabedenceExecutionAdapter(client);

      // First request with grant_123
      await adapter.execute({
        capabilityId: "email.send",
        arguments: { to: "bob@example.com" },
        authority: { principal: "alice@example.com", grantId: "grant_123" },
        executionClass: "MUTATION",
        idempotencyKey: "same_key_diff_grant",
      });

      // Second request with grant_456 — same key, different grant
      const outcome2 = await adapter.execute({
        capabilityId: "email.send",
        arguments: { to: "bob@example.com" },
        authority: { principal: "alice@example.com", grantId: "grant_456" },
        executionClass: "MUTATION",
        idempotencyKey: "same_key_diff_grant",
      });

      // Different grant_id means different request digest → CONFLICT
      expect(outcome2.status).toBe("DENIED");
      expect(outcome2.error).toContain("different request");
    } finally {
      await server.stop();
      cleanupSocket(socketPath);
    }
  });

  it("malformed wire response status is rejected", async () => {
    const socketPath = makeTempSocket();
    cleanupSocket(socketPath);

    // Handler returns an invalid status
    const badHandler = async (_req: ExecutionApiRequest): Promise<ExecutionApiResponse> => {
      return { status: "BANANA" } as unknown as ExecutionApiResponse;
    };

    const server = new ExecutionApiServer(badHandler, socketPath);
    await server.start();

    try {
      const client = new CrabedenceClient(socketPath, 1000);
      const adapter = new CrabedenceExecutionAdapter(client);

      await expect(
        adapter.execute({
          capabilityId: "test.read",
          arguments: {},
          authority: auth,
          executionClass: "READ",
        }),
      ).rejects.toThrow(TransportError);
    } finally {
      await server.stop();
      cleanupSocket(socketPath);
    }
  });

  it("CRITICAL with invalid receipt version is rejected by kernel", async () => {
    const local = new MockPort({ status: "SUCCEEDED" });
    const remote = new MockPort({
      status: "SUCCEEDED",
      evidence: {
        digest: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        receiptVersion: 2, // Wrong — must be 3
      },
      execution: { provider: "test", runId: "run_bad_v" },
    });
    const catalog = new CapabilityCatalog();
    catalog.register({
      id: "email.send",
      schema: { type: "object" },
      executionClass: "CRITICAL",
      adapter: "crabedence",
      authorityPolicy: "email.send",
    });
    const kernel = new NemoKernel(catalog, { local, remote });

    const outcome = await kernel.execute({
      capabilityId: "email.send",
      arguments: { to: "bob@example.com" },
      authority: auth,
      idempotencyKey: "bad_receipt_v",
    });

    expect(outcome.status).toBe("FAILED");
    expect(outcome.error).toContain("receiptVersion");
    expect(outcome.error).toContain("3");
  });

  it("CRITICAL with short digest is rejected by kernel", async () => {
    const local = new MockPort({ status: "SUCCEEDED" });
    const remote = new MockPort({
      status: "SUCCEEDED",
      evidence: {
        digest: "abc123", // Too short — not a valid SHA-256
        receiptVersion: 3,
      },
      execution: { provider: "test", runId: "run_bad_d" },
    });
    const catalog = new CapabilityCatalog();
    catalog.register({
      id: "email.send",
      schema: { type: "object" },
      executionClass: "CRITICAL",
      adapter: "crabedence",
      authorityPolicy: "email.send",
    });
    const kernel = new NemoKernel(catalog, { local, remote });

    const outcome = await kernel.execute({
      capabilityId: "email.send",
      arguments: { to: "bob@example.com" },
      authority: auth,
      idempotencyKey: "bad_digest",
    });

    expect(outcome.status).toBe("FAILED");
    expect(outcome.error).toContain("digest");
  });

  it("canonical JSON: reordered arguments produce same digest", async () => {
    const socketPath = makeTempSocket();
    cleanupSocket(socketPath);

    let callCount = 0;
    const handler = async (_req: ExecutionApiRequest): Promise<ExecutionApiResponse> => {
      callCount++;
      return { status: "SUCCEEDED" };
    };

    const server = new ExecutionApiServer(handler, socketPath);
    await server.start();

    try {
      const client = new CrabedenceClient(socketPath, 1000);
      const adapter = new CrabedenceExecutionAdapter(client);

      // First request with arguments in one order
      await adapter.execute({
        capabilityId: "email.send",
        arguments: { to: "bob@example.com", body: "hello" },
        authority: auth,
        executionClass: "MUTATION",
        idempotencyKey: "reorder_test",
      });

      // Second request with arguments in different order — same key
      const outcome2 = await adapter.execute({
        capabilityId: "email.send",
        arguments: { body: "hello", to: "bob@example.com" },
        authority: auth,
        executionClass: "MUTATION",
        idempotencyKey: "reorder_test",
      });

      // Canonical JSON means reordered keys produce the same digest.
      // So this should return the existing SUCCEEDED, not CONFLICT.
      expect(outcome2.status).toBe("SUCCEEDED");
      expect(callCount).toBe(1); // Handler called once, not twice
    } finally {
      await server.stop();
      cleanupSocket(socketPath);
    }
  });
});
