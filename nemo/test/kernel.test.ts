import { describe, expect, it, vi } from "vitest";

import type {
  ExecutionPort,
  KernelExecutionOutcome,
  KernelExecutionRequest,
} from "../contracts/index";
import { CapabilityCatalog, NemoKernel } from "../kernel/index";

// ─── Test helpers ─────────────────────────────────────────────────────

/** A recording mock port that returns canned responses. */
class MockPort implements ExecutionPort {
  readonly calls: KernelExecutionRequest[] = [];
  private readonly response: KernelExecutionOutcome;

  constructor(response: KernelExecutionOutcome) {
    this.response = response;
  }

  async execute(
    request: KernelExecutionRequest,
  ): Promise<KernelExecutionOutcome> {
    this.calls.push(request);
    return this.response;
  }
}

/** A port that simulates UNKNOWN (lost connectivity after invocation). */
class UnknownPort implements ExecutionPort {
  async execute(): Promise<KernelExecutionOutcome> {
    return {
      status: "UNKNOWN",
      error: "lost connectivity after provider call",
    };
  }
}

/** A port that simulates authority denial. */
class DenyPort implements ExecutionPort {
  async execute(): Promise<KernelExecutionOutcome> {
    return {
      status: "DENIED",
      error: "authority grant revoked",
    };
  }
}

/** Build a kernel with the given local and remote ports. */
function makeKernel(
  local: ExecutionPort,
  remote: ExecutionPort,
  capabilities: Parameters<CapabilityCatalog["register"]>[0][],
) {
  const catalog = new CapabilityCatalog();
  for (const cap of capabilities) {
    catalog.register(cap);
  }
  return new NemoKernel(catalog, { local, remote });
}

const pureCap = {
  id: "math.add",
  schema: { type: "object" },
  executionClass: "PURE" as const,
  adapter: "local",
  authorityPolicy: "math.compute",
};

const readCap = {
  id: "calendar.search",
  schema: { type: "object" },
  executionClass: "READ" as const,
  adapter: "crabedence",
  authorityPolicy: "calendar.read",
};

const mutationCap = {
  id: "calendar.create",
  schema: { type: "object" },
  executionClass: "MUTATION" as const,
  adapter: "crabedence",
  authorityPolicy: "calendar.write",
};

const criticalCap = {
  id: "email.send",
  schema: { type: "object" },
  executionClass: "CRITICAL" as const,
  adapter: "crabedence",
  authorityPolicy: "communications.email.send",
};

const auth = { principal: "alice@example.com", grantId: "grant_123" };

// ─── Tests ────────────────────────────────────────────────────────────

describe("NemoKernel", () => {
  // Step 13: Test PURE locally
  it("routes PURE capabilities to local port", async () => {
    const local = new MockPort({ status: "SUCCEEDED", result: 42 });
    const remote = new MockPort({ status: "SUCCEEDED" });
    const kernel = makeKernel(local, remote, [pureCap]);

    const outcome = await kernel.execute({
      capabilityId: "math.add",
      arguments: { a: 2, b: 40 },
      authority: auth,
    });

    expect(outcome.status).toBe("SUCCEEDED");
    expect(outcome.result).toBe(42);
    expect(local.calls).toHaveLength(1);
    expect(remote.calls).toHaveLength(0);
  });

  // Step 14: Test READ through Crabedence
  it("routes READ capabilities to remote port", async () => {
    const local = new MockPort({ status: "SUCCEEDED" });
    const remote = new MockPort({
      status: "SUCCEEDED",
      result: [{ title: "Meeting", start: "2026-09-10T14:00:00Z" }],
    });
    const kernel = makeKernel(local, remote, [readCap]);

    const outcome = await kernel.execute({
      capabilityId: "calendar.search",
      arguments: { date: "2026-09-10" },
      authority: auth,
    });

    expect(outcome.status).toBe("SUCCEEDED");
    expect(local.calls).toHaveLength(0);
    expect(remote.calls).toHaveLength(1);
  });

  // Step 15: Test MUTATION
  it("routes MUTATION capabilities to remote port", async () => {
    const local = new MockPort({ status: "SUCCEEDED" });
    const remote = new MockPort({
      status: "SUCCEEDED",
      result: { eventId: "evt_abc" },
      execution: { provider: "google-calendar", runId: "run_001" },
    });
    const kernel = makeKernel(local, remote, [mutationCap]);

    const outcome = await kernel.execute({
      capabilityId: "calendar.create",
      arguments: { title: "Sync", start: "2026-09-10T14:00:00Z" },
      authority: auth,
      idempotencyKey: "req_001",
    });

    expect(outcome.status).toBe("SUCCEEDED");
    expect(outcome.result).toEqual({ eventId: "evt_abc" });
    expect(outcome.execution).toEqual({
      provider: "google-calendar",
      runId: "run_001",
    });
  });

  // Step 16: Test CRITICAL with durable evidence
  it("routes CRITICAL capabilities to remote port with evidence", async () => {
    const local = new MockPort({ status: "SUCCEEDED" });
    const remote = new MockPort({
      status: "SUCCEEDED",
      result: { messageId: "msg_123" },
      evidence: { digest: "abc123", receiptVersion: 3 },
      execution: { provider: "gmail", runId: "run_002" },
    });
    const kernel = makeKernel(local, remote, [criticalCap]);

    const outcome = await kernel.execute({
      capabilityId: "email.send",
      arguments: { to: "bob@example.com", body: "I'll be there at 2." },
      authority: auth,
      idempotencyKey: "req_002",
    });

    expect(outcome.status).toBe("SUCCEEDED");
    expect(outcome.evidence).toEqual({ digest: "abc123", receiptVersion: 3 });
  });

  // Step 17: Test UNKNOWN
  it("preserves UNKNOWN as first-class terminal state", async () => {
    const local = new MockPort({ status: "SUCCEEDED" });
    const remote = new UnknownPort();
    const kernel = makeKernel(local, remote, [criticalCap]);

    const outcome = await kernel.execute({
      capabilityId: "email.send",
      arguments: { to: "bob@example.com", body: "test" },
      authority: auth,
      idempotencyKey: "req_003",
    });

    expect(outcome.status).toBe("UNKNOWN");
    // NeMo must NOT retry UNKNOWN for CRITICAL capabilities.
    expect(outcome.error).toContain("lost connectivity");
  });

  // Step 18: Test authority rejection
  it("passes DENIED through from remote port", async () => {
    const local = new MockPort({ status: "SUCCEEDED" });
    const remote = new DenyPort();
    const kernel = makeKernel(local, remote, [criticalCap]);

    const outcome = await kernel.execute({
      capabilityId: "email.send",
      arguments: { to: "bob@example.com", body: "test" },
      authority: auth,
      idempotencyKey: "req_004",
    });

    expect(outcome.status).toBe("DENIED");
    expect(outcome.error).toContain("revoked");
  });

  // Step 19: Test idempotency requirement
  it("rejects MUTATION without idempotency key", async () => {
    const local = new MockPort({ status: "SUCCEEDED" });
    const remote = new MockPort({ status: "SUCCEEDED" });
    const kernel = makeKernel(local, remote, [mutationCap]);

    const outcome = await kernel.execute({
      capabilityId: "calendar.create",
      arguments: { title: "test" },
      authority: auth,
      // No idempotencyKey
    });

    expect(outcome.status).toBe("DENIED");
    expect(outcome.error).toContain("idempotency key required");
    expect(remote.calls).toHaveLength(0);
  });

  it("rejects CRITICAL without idempotency key", async () => {
    const local = new MockPort({ status: "SUCCEEDED" });
    const remote = new MockPort({ status: "SUCCEEDED" });
    const kernel = makeKernel(local, remote, [criticalCap]);

    const outcome = await kernel.execute({
      capabilityId: "email.send",
      arguments: { to: "bob@example.com" },
      authority: auth,
    });

    expect(outcome.status).toBe("DENIED");
    expect(outcome.error).toContain("idempotency key required");
  });

  // Execution class immutability
  it("rejects execution class downgrade attempts", async () => {
    const local = new MockPort({ status: "SUCCEEDED" });
    const remote = new MockPort({ status: "SUCCEEDED" });
    const kernel = makeKernel(local, remote, [criticalCap]);

    const outcome = await kernel.execute({
      capabilityId: "email.send",
      arguments: { to: "bob@example.com" },
      authority: auth,
      executionClass: "READ", // Attempt to downgrade
      idempotencyKey: "req_005",
    });

    expect(outcome.status).toBe("DENIED");
    expect(outcome.error).toContain("execution class mismatch");
    expect(outcome.error).toContain("CRITICAL");
  });

  it("does not require idempotency for PURE", async () => {
    const local = new MockPort({ status: "SUCCEEDED", result: 1 });
    const remote = new MockPort({ status: "SUCCEEDED" });
    const kernel = makeKernel(local, remote, [pureCap]);

    const outcome = await kernel.execute({
      capabilityId: "math.add",
      arguments: {},
      authority: auth,
    });

    expect(outcome.status).toBe("SUCCEEDED");
  });

  it("does not require idempotency for READ", async () => {
    const local = new MockPort({ status: "SUCCEEDED" });
    const remote = new MockPort({ status: "SUCCEEDED", result: [] });
    const kernel = makeKernel(local, remote, [readCap]);

    const outcome = await kernel.execute({
      capabilityId: "calendar.search",
      arguments: {},
      authority: auth,
    });

    expect(outcome.status).toBe("SUCCEEDED");
  });

  // Unknown capability
  it("rejects unknown capability", async () => {
    const local = new MockPort({ status: "SUCCEEDED" });
    const remote = new MockPort({ status: "SUCCEEDED" });
    const kernel = makeKernel(local, remote, [pureCap]);

    await expect(
      kernel.execute({
        capabilityId: "nonexistent.capability",
        arguments: {},
        authority: auth,
      }),
    ).rejects.toThrow("unknown capability");
  });

  // Capability immutability
  it("prevents duplicate capability registration", () => {
    const catalog = new CapabilityCatalog();
    catalog.register(pureCap);
    expect(() => catalog.register(pureCap)).toThrow("already registered");
  });

  // Step 20: Test NeMo restart while execution is running
  it("kernel restart does not affect in-flight Crabedence execution", async () => {
    const local = new MockPort({ status: "SUCCEEDED" });
    const remote = new MockPort({
      status: "SUCCEEDED",
      evidence: { digest: "def456", receiptVersion: 3 },
      execution: { provider: "gmail", runId: "run_persisted" },
    });
    const kernel1 = makeKernel(local, remote, [criticalCap]);

    // Start execution
    const promise = kernel1.execute({
      capabilityId: "email.send",
      arguments: { to: "bob@example.com" },
      authority: auth,
      idempotencyKey: "req_restart",
    });

    // "Restart" kernel — create a new instance with same catalog
    const kernel2 = makeKernel(local, remote, [criticalCap]);

    // The first execution should still complete
    const outcome = await promise;
    expect(outcome.status).toBe("SUCCEEDED");
    expect(outcome.execution?.runId).toBe("run_persisted");

    // New kernel can execute independently
    const outcome2 = await kernel2.execute({
      capabilityId: "email.send",
      arguments: { to: "carol@example.com" },
      authority: auth,
      idempotencyKey: "req_restart_2",
    });
    expect(outcome2.status).toBe("SUCCEEDED");
  });
});
