import { describe, expect, it } from "vitest";

import type {
  ExecutionPort,
  KernelExecutionOutcome,
  KernelExecutionRequest,
} from "../contracts/index";
import {
  CapabilityCatalog,
  NemoKernel,
  SnapshotError,
  loadCatalogFromSnapshot,
  parseRegistrySnapshot,
} from "../kernel/index";

class MockPort implements ExecutionPort {
  readonly calls: KernelExecutionRequest[] = [];
  private readonly response: KernelExecutionOutcome;

  constructor(response: KernelExecutionOutcome) {
    this.response = response;
  }

  async execute(request: KernelExecutionRequest): Promise<KernelExecutionOutcome> {
    this.calls.push(request);
    return this.response;
  }
}

const DIGEST = "a".repeat(64);

function snapshot(descriptors: unknown[]): unknown {
  return { registry_sha256: DIGEST, descriptors };
}

const pureLocal = {
  id: "math.add",
  descriptor_version: 1,
  execution_class: "PURE",
  assurance_profile: "NONE",
  execution_route: "LOCAL",
  schema: { type: "object" },
  authority_policy: { id: "math.compute", grant_required: false },
  adapter_id: "local",
};

const pureDurable = {
  ...pureLocal,
  id: "math.add.durable",
  execution_route: "CRABEDENCE",
  adapter_id: "crabedence",
};

describe("registry snapshot loading", () => {
  it("rejects malformed snapshots", () => {
    expect(() => parseRegistrySnapshot(null)).toThrow(SnapshotError);
    expect(() => parseRegistrySnapshot({ descriptors: [] })).toThrow(/registry_sha256/);
    expect(() => parseRegistrySnapshot({ registry_sha256: "short", descriptors: [] })).toThrow(/registry_sha256/);
    expect(() => parseRegistrySnapshot({ registry_sha256: DIGEST, descriptors: {} })).toThrow(/must be an array/);
    expect(() => parseRegistrySnapshot(snapshot([null]))).toThrow(/must be an object/);
    expect(() => parseRegistrySnapshot(snapshot([{ ...pureLocal, id: "" }]))).toThrow(/has no id/);
    expect(() => parseRegistrySnapshot(snapshot([{ ...pureLocal, execution_class: "SIDEWAYS" }]))).toThrow(
      /invalid execution_class/,
    );
    expect(() => parseRegistrySnapshot(snapshot([{ ...pureLocal, execution_route: "FABRIC" }]))).toThrow(
      /invalid execution_route/,
    );
    expect(() => parseRegistrySnapshot(snapshot([{ ...pureLocal, adapter_id: "" }]))).toThrow(/adapter_id is required/);
  });

  it("loads descriptors with their registry routes", () => {
    const { catalog, registrySha256 } = loadCatalogFromSnapshot(snapshot([pureLocal, pureDurable]));
    expect(registrySha256).toBe(DIGEST);
    expect(catalog.has("math.add")).toBe(true);
    expect(catalog.routeOf("math.add")).toBe("LOCAL");
    expect(catalog.routeOf("math.add.durable")).toBe("CRABEDENCE");
    expect(catalog.lookup("math.add").executionClass).toBe("PURE");
  });

  it("routes on the resolved route, not the execution class", async () => {
    const local = new MockPort({ status: "SUCCEEDED", result: 1 });
    const remote = new MockPort({ status: "SUCCEEDED", result: 2 });
    const { catalog } = loadCatalogFromSnapshot(snapshot([pureLocal, pureDurable]));
    const kernel = new NemoKernel(catalog, { local, remote });

    const localOutcome = await kernel.execute({
      capabilityId: "math.add",
      arguments: {},
      authority: { principal: "alice@example.com" },
    });
    expect(localOutcome.status).toBe("SUCCEEDED");
    expect(local.calls).toHaveLength(1);
    expect(remote.calls).toHaveLength(0);

    // Same class (PURE), different registry route: this one must go to
    // the service, proving the route — not the class — decides.
    const remoteOutcome = await kernel.execute({
      capabilityId: "math.add.durable",
      arguments: {},
      authority: { principal: "alice@example.com" },
    });
    expect(remoteOutcome.status).toBe("SUCCEEDED");
    expect(remote.calls).toHaveLength(1);
    expect(local.calls).toHaveLength(1);
  });

  it("fails closed on a route/class pairing the registry could not produce", () => {
    const catalog = new CapabilityCatalog();
    expect(() =>
      catalog.register({
        id: "bad.capability",
        schema: { type: "object" },
        executionClass: "READ",
        executionRoute: "LOCAL",
        adapter: "local",
        authorityPolicy: "bad",
      }),
    ).toThrow(/route LOCAL requires PURE/);
    expect(catalog.has("bad.capability")).toBe(false);

    expect(() =>
      catalog.register({
        id: "bad.mutation",
        schema: { type: "object" },
        executionClass: "MUTATION",
        executionRoute: "DIRECT",
        adapter: "direct",
        authorityPolicy: "bad",
      }),
    ).toThrow(/route DIRECT requires READ/);
  });

  it("resolves the documented default route for descriptors without one", () => {
    const catalog = new CapabilityCatalog();
    catalog.register({
      id: "default.pure",
      schema: { type: "object" },
      executionClass: "PURE",
      adapter: "local",
      authorityPolicy: "default",
    });
    catalog.register({
      id: "default.read",
      schema: { type: "object" },
      executionClass: "READ",
      adapter: "crabedence",
      authorityPolicy: "default",
    });
    catalog.register({
      id: "default.mutation",
      schema: { type: "object" },
      executionClass: "MUTATION",
      adapter: "crabedence",
      authorityPolicy: "default",
    });
    expect(catalog.routeOf("default.pure")).toBe("LOCAL");
    expect(catalog.routeOf("default.read")).toBe("DIRECT");
    expect(catalog.routeOf("default.mutation")).toBe("CRABEDENCE");
  });
});
