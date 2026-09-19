import { createHash } from "node:crypto";
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
  parseRegistryEnvelope,
} from "../kernel/index";
import { createTestKernel } from "../kernel/testing";

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

/** envelopeOf builds the verifiable envelope the registry exports. */
function envelopeOf(descriptors: unknown[]): { registry_sha256: string; canonical_payload: string } {
  const payload = Buffer.from(JSON.stringify(descriptors), "utf-8");
  return {
    registry_sha256: createHash("sha256").update(payload).digest("hex"),
    canonical_payload: payload.toString("base64"),
  };
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

describe("registry envelope verification", () => {
  it("rejects malformed envelopes", () => {
    expect(() => parseRegistryEnvelope(null)).toThrow(SnapshotError);
    expect(() => parseRegistryEnvelope({ canonical_payload: "e30=" })).toThrow(/registry_sha256/);
    expect(() => parseRegistryEnvelope({ registry_sha256: "short", canonical_payload: "e30=" })).toThrow(
      /registry_sha256/,
    );
    expect(() => parseRegistryEnvelope({ registry_sha256: "a".repeat(64) })).toThrow(/canonical_payload/);
    expect(() => parseRegistryEnvelope({ registry_sha256: "a".repeat(64), canonical_payload: "" })).toThrow(
      /canonical_payload/,
    );
    expect(() =>
      parseRegistryEnvelope({ registry_sha256: "a".repeat(64), canonical_payload: "not base64!!" }),
    ).not.toThrow(); // shape is fine; the payload check happens on load
    expect(() =>
      loadCatalogFromSnapshot({ registry_sha256: "a".repeat(64), canonical_payload: "not base64!!" }),
    ).toThrow(/not valid base64/);
  });

  it("rejects a payload its digest does not cover (the tampering case)", () => {
    // A legitimate export for a MUTATION capability.
    const trusted = envelopeOf([
      { ...pureDurable, id: "account.delete", execution_class: "MUTATION", execution_route: "CRABEDENCE" },
    ]);
    // The attack: rewrite the payload to a harmless-looking PURE/LOCAL
    // capability and keep the original digest.
    const tamperedPayload = Buffer.from(
      JSON.stringify([
        {
          ...pureLocal,
          id: "account.delete",
          execution_class: "PURE",
          execution_route: "LOCAL",
        },
      ]),
      "utf-8",
    );
    const tampered = {
      registry_sha256: trusted.registry_sha256,
      canonical_payload: tamperedPayload.toString("base64"),
    };
    expect(() => loadCatalogFromSnapshot(tampered)).toThrow(/does not cover its payload/);
  });

  it("rejects a digest that does not match its payload", () => {
    const envelope = envelopeOf([pureLocal]);
    const wrongDigest = { ...envelope, registry_sha256: "b".repeat(64) };
    expect(() => loadCatalogFromSnapshot(wrongDigest)).toThrow(/does not cover its payload/);
  });

  it("rejects invalid descriptors inside a valid envelope", () => {
    expect(() => loadCatalogFromSnapshot(envelopeOf([null]))).toThrow(/must be an object/);
    expect(() => loadCatalogFromSnapshot(envelopeOf([{ ...pureLocal, id: "" }]))).toThrow(/has no id/);
    expect(() => loadCatalogFromSnapshot(envelopeOf([{ ...pureLocal, execution_class: "SIDEWAYS" }]))).toThrow(
      /invalid execution_class/,
    );
    expect(() => loadCatalogFromSnapshot(envelopeOf([{ ...pureLocal, execution_route: "FABRIC" }]))).toThrow(
      /invalid execution_route/,
    );
    expect(() => loadCatalogFromSnapshot(envelopeOf([{ ...pureLocal, adapter_id: "" }]))).toThrow(
      /adapter_id is required/,
    );
    expect(() => loadCatalogFromSnapshot(envelopeOf([{ not: "an array element" }]))).toThrow(/has no id/);
    // A payload that is valid JSON but not an array.
    const payload = Buffer.from(JSON.stringify({ descriptors: [] }), "utf-8");
    expect(() =>
      loadCatalogFromSnapshot({
        registry_sha256: createHash("sha256").update(payload).digest("hex"),
        canonical_payload: payload.toString("base64"),
      }),
    ).toThrow(/must be a descriptor array/);
  });

  it("rejects LOCAL with a required grant — LOCAL never reaches the authority resolver", () => {
    expect(() =>
      loadCatalogFromSnapshot(
        envelopeOf([{ ...pureLocal, authority_policy: { id: "sensitive.local", grant_required: true } }]),
      ),
    ).toThrow(/LOCAL route cannot require a grant/);
  });

  it("loads descriptors with their registry routes", () => {
    const { catalog, registrySha256 } = loadCatalogFromSnapshot(envelopeOf([pureLocal, pureDurable]));
    expect(registrySha256).toHaveLength(64);
    expect(catalog.has("math.add")).toBe(true);
    expect(catalog.routeOf("math.add")).toBe("LOCAL");
    expect(catalog.routeOf("math.add.durable")).toBe("CRABEDENCE");
    expect(catalog.lookup("math.add").executionClass).toBe("PURE");
  });

  it("routes on the resolved route, not the execution class", async () => {
    const local = new MockPort({ status: "SUCCEEDED", result: 1 });
    const remote = new MockPort({ status: "SUCCEEDED", result: 2 });
    const { catalog } = loadCatalogFromSnapshot(envelopeOf([pureLocal, pureDurable]));
    const kernel = createTestKernel(catalog, { local, remote });

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
