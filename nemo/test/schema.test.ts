import { describe, expect, it } from "vitest";

import type {
  ExecutionPort,
  KernelExecutionOutcome,
  KernelExecutionRequest,
} from "../contracts/index";
import {
  CapabilityCatalog,
  NemoKernel,
  SchemaCompilationError,
  SchemaValidator,
} from "../kernel/index";

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

const validator = new SchemaValidator();

function check(
  schema: object,
  value: unknown,
  direction: "argument" | "result" = "argument",
): string | null {
  const compiled = validator.compile("test.capability", schema, undefined);
  return validator.validate(compiled.input, value, direction);
}

describe("SchemaValidator", () => {
  it("distinguishes null from an object", () => {
    const schema = { type: "object", properties: { a: { type: "string" } }, required: ["a"] };
    expect(check(schema, null)).toMatch(/argument schema validation failed/);
    expect(check(schema, { a: "x" })).toBeNull();
  });

  it("distinguishes an array from an object", () => {
    const objectSchema = { type: "object", properties: {} };
    expect(check(objectSchema, [])).toMatch(/must be object/);
    const arraySchema = { type: "array", items: { type: "number" } };
    expect(check(arraySchema, [])).toBeNull();
    expect(check(arraySchema, {})).toMatch(/must be array/);
    expect(check(arraySchema, [1, "x"])).toMatch(/must be number/);
  });

  it("distinguishes an integer from a number", () => {
    const integerSchema = { type: "integer" };
    expect(check(integerSchema, 3)).toBeNull();
    expect(check(integerSchema, 3.5)).toMatch(/must be integer/);
    expect(check({ type: "number" }, 3.5)).toBeNull();
  });

  it("enforces required fields", () => {
    const schema = { type: "object", properties: { a: { type: "string" } }, required: ["a", "b"] };
    expect(check(schema, { a: "x" })).toMatch(/required/);
    expect(check(schema, { a: "x", b: "y" })).toBeNull();
  });

  it("enforces additionalProperties", () => {
    const schema = {
      type: "object",
      properties: { a: { type: "string" } },
      additionalProperties: false,
    };
    expect(check(schema, { a: "x" })).toBeNull();
    expect(check(schema, { a: "x", extra: 1 })).toMatch(/additional propert/);
  });

  it("enforces enum values", () => {
    const schema = { type: "object", properties: { mode: { type: "string", enum: ["fast", "safe"] } } };
    expect(check(schema, { mode: "fast" })).toBeNull();
    expect(check(schema, { mode: "slow" })).toMatch(/allowed values/);
  });

  it("validates nested arrays", () => {
    const schema = { type: "array", items: { type: "array", items: { type: "integer" } } };
    expect(check(schema, [[1, 2], [3]])).toBeNull();
    expect(check(schema, [[1], ["x"]])).toMatch(/must be integer/);
  });

  it("validates nested objects", () => {
    const schema = {
      type: "object",
      properties: {
        user: {
          type: "object",
          properties: { id: { type: "integer" } },
          required: ["id"],
          additionalProperties: false,
        },
      },
      required: ["user"],
    };
    expect(check(schema, { user: { id: 7 } })).toBeNull();
    expect(check(schema, { user: {} })).toMatch(/required/);
    expect(check(schema, { user: { id: 7, role: "admin" } })).toMatch(/additional propert/);
  });

  it("enforces string length bounds", () => {
    const schema = { type: "string", minLength: 2, maxLength: 4 };
    expect(check(schema, "abc")).toBeNull();
    expect(check(schema, "a")).toMatch(/fewer than 2 characters/);
    expect(check(schema, "abcde")).toMatch(/more than 4 characters/);
  });

  it("enforces array size bounds", () => {
    const schema = { type: "array", items: { type: "integer" }, maxItems: 2 };
    expect(check(schema, [1, 2])).toBeNull();
    expect(check(schema, [1, 2, 3])).toMatch(/more than 2 items/);
  });

  it("fails closed on a malformed schema", () => {
    expect(() => validator.compile("bad.capability", { required: "not-an-array" }, undefined)).toThrow(
      SchemaCompilationError,
    );
    expect(() => validator.compile("bad.capability", { type: 42 }, undefined)).toThrow(
      SchemaCompilationError,
    );
    expect(() => validator.compile("bad.capability", true, undefined)).toThrow(
      /must be a JSON Schema object/,
    );
    expect(() => validator.compile("bad.capability", undefined, ["not", "a", "schema"])).toThrow(
      /result schema must be a JSON Schema object/,
    );
  });

  it("fails closed on an unsupported schema keyword", () => {
    expect(() =>
      validator.compile("bad.capability", { type: "object", frobnicate: true }, undefined),
    ).toThrow(/does not compile/);
  });

  it("validates deeply nested input without unbounded recursion", () => {
    let nested: Record<string, unknown> = { leaf: true };
    for (let depth = 0; depth < 500; depth += 1) {
      nested = { child: nested };
    }
    expect(check({ type: "object" }, nested)).toBeNull();
  });

  it("does not let __proto__ input pollute prototypes", () => {
    const hostile = JSON.parse('{"__proto__": {"polluted": true}}');
    expect(check({ type: "object" }, hostile)).toBeNull();
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it("handles oversized input without crashing", () => {
    const oversizedString = "a".repeat(200_000);
    expect(check({ type: "string", maxLength: 16 }, oversizedString)).toMatch(/more than 16 characters/);

    const oversizedArray = new Array(50_000).fill(1);
    expect(check({ type: "array", items: { type: "integer" }, maxItems: 8 }, oversizedArray)).toMatch(
      /more than 8 items/,
    );
  });
});

describe("CapabilityCatalog schema loading", () => {
  it("refuses a capability whose schema does not compile", () => {
    const catalog = new CapabilityCatalog();
    expect(() =>
      catalog.register({
        id: "broken.capability",
        schema: { type: "object", frobnicate: true },
        executionClass: "PURE",
        adapter: "local",
        authorityPolicy: "broken",
      }),
    ).toThrow(SchemaCompilationError);
    expect(catalog.has("broken.capability")).toBe(false);
  });

  it("compiles result schemas at registration", () => {
    const catalog = new CapabilityCatalog();
    catalog.register({
      id: "math.add",
      schema: { type: "object", properties: { a: { type: "number" }, b: { type: "number" } }, required: ["a", "b"] },
      resultSchema: { type: "number" },
      executionClass: "PURE",
      adapter: "local",
      authorityPolicy: "math.compute",
    });
    expect(catalog.validateArguments("math.add", { a: 1, b: 2 })).toBeNull();
    expect(catalog.validateArguments("math.add", { a: 1 })).toMatch(/required/);
    expect(catalog.validateResult("math.add", 3)).toBeNull();
    expect(catalog.validateResult("math.add", "three")).toMatch(/result schema validation failed/);
  });

  it("compiles from the frozen copy, so later mutation cannot weaken enforcement", () => {
    const catalog = new CapabilityCatalog();
    const schema: Record<string, unknown> = {
      type: "object",
      properties: { a: { type: "string" } },
      required: ["a"],
    };
    catalog.register({
      id: "frozen.capability",
      schema,
      executionClass: "PURE",
      adapter: "local",
      authorityPolicy: "frozen",
    });
    // Mutate the caller's original object after registration.
    delete schema.required;
    schema.properties = {};
    expect(catalog.validateArguments("frozen.capability", {})).toMatch(/required/);
  });
});

describe("NemoKernel trust boundaries", () => {
  const pureCap = {
    id: "math.add",
    schema: { type: "object", properties: { a: { type: "number" }, b: { type: "number" } }, required: ["a", "b"] },
    resultSchema: { type: "number" },
    executionClass: "PURE" as const,
    adapter: "local",
    authorityPolicy: "math.compute",
  };

  const mutationCap = {
    id: "calendar.create",
    schema: { type: "object", properties: { title: { type: "string" } }, required: ["title"] },
    resultSchema: { type: "object", properties: { eventId: { type: "string" } }, required: ["eventId"] },
    executionClass: "MUTATION" as const,
    adapter: "crabedence",
    authorityPolicy: "calendar.write",
  };

  function makeKernel(local: ExecutionPort, remote: ExecutionPort, capabilities: Parameters<CapabilityCatalog["register"]>[0][]) {
    const catalog = new CapabilityCatalog();
    for (const capability of capabilities) {
      catalog.register(capability);
    }
    return new NemoKernel(catalog, { local, remote });
  }

  it("accepts a grant-free invocation (principal only)", async () => {
    const local = new MockPort({ status: "SUCCEEDED", result: 3 });
    const remote = new MockPort({ status: "SUCCEEDED" });
    const kernel = makeKernel(local, remote, [pureCap]);

    const outcome = await kernel.execute({
      capabilityId: "math.add",
      arguments: { a: 1, b: 2 },
      authority: { principal: "alice@example.com" },
    });

    expect(outcome.status).toBe("SUCCEEDED");
    expect(local.calls).toHaveLength(1);
  });

  it("still requires a principal", async () => {
    const local = new MockPort({ status: "SUCCEEDED", result: 3 });
    const remote = new MockPort({ status: "SUCCEEDED" });
    const kernel = makeKernel(local, remote, [pureCap]);

    const outcome = await kernel.execute({
      capabilityId: "math.add",
      arguments: { a: 1, b: 2 },
      authority: { principal: "" },
    });

    expect(outcome.status).toBe("DENIED");
    expect(outcome.error).toContain("missing authority principal");
    expect(local.calls).toHaveLength(0);
  });

  it("rejects arguments that violate the compiled schema before routing", async () => {
    const local = new MockPort({ status: "SUCCEEDED", result: 3 });
    const remote = new MockPort({ status: "SUCCEEDED" });
    const kernel = makeKernel(local, remote, [pureCap]);

    const outcome = await kernel.execute({
      capabilityId: "math.add",
      arguments: { a: 1 },
      authority: { principal: "alice@example.com" },
    });

    expect(outcome.status).toBe("DENIED");
    expect(outcome.error).toMatch(/required/);
    expect(local.calls).toHaveLength(0);
  });

  it("fails a PURE result that violates its declared result schema", async () => {
    const local = new MockPort({ status: "SUCCEEDED", result: "not-a-number" });
    const remote = new MockPort({ status: "SUCCEEDED" });
    const kernel = makeKernel(local, remote, [pureCap]);

    const outcome = await kernel.execute({
      capabilityId: "math.add",
      arguments: { a: 1, b: 2 },
      authority: { principal: "alice@example.com" },
    });

    expect(outcome.status).toBe("FAILED");
    expect(outcome.error).toMatch(/result schema validation failed/);
  });

  it("treats a dispatched result that violates its contract as UNKNOWN", async () => {
    const local = new MockPort({ status: "SUCCEEDED" });
    const remote = new MockPort({ status: "SUCCEEDED", result: { ok: true } });
    const kernel = makeKernel(local, remote, [mutationCap]);

    const outcome = await kernel.execute({
      capabilityId: "calendar.create",
      arguments: { title: "Sync" },
      authority: { principal: "alice@example.com" },
      idempotencyKey: "req_001",
    });

    expect(outcome.status).toBe("UNKNOWN");
    expect(outcome.error).toMatch(/result schema validation failed/);
  });

  it("accepts a dispatched result that satisfies its contract", async () => {
    const local = new MockPort({ status: "SUCCEEDED" });
    const remote = new MockPort({ status: "SUCCEEDED", result: { eventId: "evt_1" } });
    const kernel = makeKernel(local, remote, [mutationCap]);

    const outcome = await kernel.execute({
      capabilityId: "calendar.create",
      arguments: { title: "Sync" },
      authority: { principal: "alice@example.com", authorityRef: "grant_123" },
      idempotencyKey: "req_002",
    });

    expect(outcome.status).toBe("SUCCEEDED");
  });
});
