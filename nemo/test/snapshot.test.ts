import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  SnapshotError,
  loadRegistrySnapshot,
  parseRegistryEnvelope,
} from "../registry-snapshot/index";

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
      loadRegistrySnapshot({ registry_sha256: "a".repeat(64), canonical_payload: "not base64!!" }),
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
    expect(() => loadRegistrySnapshot(tampered)).toThrow(/does not cover its payload/);
  });

  it("rejects a digest that does not match its payload", () => {
    const envelope = envelopeOf([pureLocal]);
    const wrongDigest = { ...envelope, registry_sha256: "b".repeat(64) };
    expect(() => loadRegistrySnapshot(wrongDigest)).toThrow(/does not cover its payload/);
  });

  it("rejects invalid descriptors inside a valid envelope", () => {
    expect(() => loadRegistrySnapshot(envelopeOf([null]))).toThrow(/must be an object/);
    expect(() => loadRegistrySnapshot(envelopeOf([{ ...pureLocal, id: "" }]))).toThrow(/has no id/);
    expect(() => loadRegistrySnapshot(envelopeOf([{ ...pureLocal, execution_class: "SIDEWAYS" }]))).toThrow(
      /invalid execution_class/,
    );
    expect(() => loadRegistrySnapshot(envelopeOf([{ ...pureLocal, execution_route: "FABRIC" }]))).toThrow(
      /invalid execution_route/,
    );
    expect(() => loadRegistrySnapshot(envelopeOf([{ ...pureLocal, adapter_id: "" }]))).toThrow(
      /adapter_id is required/,
    );
    expect(() => loadRegistrySnapshot(envelopeOf([{ not: "an array element" }]))).toThrow(/has no id/);
    // A payload that is valid JSON but not an array.
    const payload = Buffer.from(JSON.stringify({ descriptors: [] }), "utf-8");
    expect(() =>
      loadRegistrySnapshot({
        registry_sha256: createHash("sha256").update(payload).digest("hex"),
        canonical_payload: payload.toString("base64"),
      }),
    ).toThrow(/must be a descriptor array/);
  });

  it("rejects LOCAL with a required grant — LOCAL never reaches the authority resolver", () => {
    expect(() =>
      loadRegistrySnapshot(
        envelopeOf([{ ...pureLocal, authority_policy: { id: "sensitive.local", grant_required: true } }]),
      ),
    ).toThrow(/LOCAL route cannot require a grant/);
  });

  it("loads descriptors with their registry routes", () => {
    const { descriptors, registrySha256 } = loadRegistrySnapshot(
      envelopeOf([pureLocal, pureDurable]),
    );
    expect(registrySha256).toHaveLength(64);
    expect(descriptors).toHaveLength(2);

    const byId = new Map(descriptors.map((descriptor) => [descriptor.id, descriptor]));
    expect(byId.get("math.add")?.execution_route).toBe("LOCAL");
    expect(byId.get("math.add.durable")?.execution_route).toBe("CRABEDENCE");
    // Same class, different route: the route is the registry's, not a
    // function of the class.
    expect(byId.get("math.add")?.execution_class).toBe("PURE");
    expect(byId.get("math.add.durable")?.execution_class).toBe("PURE");
    expect(byId.get("math.add")?.adapter_id).toBe("local");
  });

  it("refuses a descriptor that declares no execution route", () => {
    // The route is registry policy and is never derived locally (finding 8).
    // A descriptor that omits it is not a registry export, so the loader
    // refuses it rather than inferring one from the execution class.
    const { execution_route: _omitted, ...withoutRoute } = pureLocal;
    expect(() => loadRegistrySnapshot(envelopeOf([withoutRoute]))).toThrow(
      /invalid execution_route/,
    );
  });
});
