/**
 * Registry envelope verification.
 *
 * NEMO does not maintain a capability catalog: it loads the
 * authoritative registry's verifiable export (written by
 * `crabbox serve-execution` next to the socket) and routes on the
 * trusted descriptors.
 *
 * The export is an envelope that carries the registry digest AND the
 * exact canonical bytes it covers:
 *
 *   { "registry_sha256": "...", "canonical_payload": "<base64>" }
 *
 * Verification is: base64-decode → SHA-256 → compare → only then
 * parse. The descriptors NEMO routes on are therefore provably the
 * bytes the authoritative registry digested, and a payload that does
 * not match its digest fails closed.
 *
 * Cross-language canonicalization never enters this boundary: the
 * canonical bytes are produced once, by the authoritative Go
 * implementation, and verified here as bytes. There is no second
 * serializer whose number representation or key order could differ.
 */
import { createHash, timingSafeEqual } from "node:crypto";

import type { CapabilityDescriptor, ExecutionClass, ExecutionRoute } from "../contracts/index";
import { VerifiedCapabilityCatalog } from "./kernel";

/** RegistryDescriptor is the canonical envelope descriptor shape. */
export interface RegistryDescriptor {
  readonly id: string;
  readonly descriptor_version: number;
  readonly policy_revision?: string;
  readonly execution_class: ExecutionClass;
  readonly assurance_profile: string;
  readonly execution_route: ExecutionRoute;
  readonly schema?: unknown;
  readonly authority_policy?: {
    readonly id?: string;
    readonly grant_required?: boolean;
  };
  readonly adapter_id: string;
}

/** RegistryEnvelope is the verifiable registry export. */
export interface RegistryEnvelope {
  readonly registry_sha256: string;
  readonly canonical_payload: string;
}

/** SnapshotError is thrown when an export is not a valid, verified registry envelope. */
export class SnapshotError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SnapshotError";
  }
}

const EXECUTION_CLASSES = new Set(["PURE", "READ", "MUTATION", "CRITICAL"]);
const EXECUTION_ROUTES = new Set(["LOCAL", "DIRECT", "CRABEDENCE"]);
const HEX_DIGEST = /^[0-9a-f]{64}$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

/** parseRegistryEnvelope validates the envelope shape, failing closed. */
export function parseRegistryEnvelope(raw: unknown): RegistryEnvelope {
  if (typeof raw !== "object" || raw === null) {
    throw new SnapshotError("registry snapshot must be a JSON object");
  }
  const envelope = raw as Record<string, unknown>;
  if (typeof envelope.registry_sha256 !== "string" || !HEX_DIGEST.test(envelope.registry_sha256)) {
    throw new SnapshotError("registry snapshot registry_sha256 must be a 64-character hex digest");
  }
  if (typeof envelope.canonical_payload !== "string" || envelope.canonical_payload === "") {
    throw new SnapshotError("registry snapshot canonical_payload must be a base64 string");
  }
  return {
    registry_sha256: envelope.registry_sha256,
    canonical_payload: envelope.canonical_payload,
  };
}

function decodeCanonicalPayload(envelope: RegistryEnvelope): Buffer {
  if (!BASE64.test(envelope.canonical_payload) || envelope.canonical_payload.length % 4 !== 0) {
    throw new SnapshotError("registry snapshot canonical_payload is not valid base64");
  }
  return Buffer.from(envelope.canonical_payload, "base64");
}

function constantTimeEqualHex(left: string, right: string): boolean {
  if (left.length !== right.length) {
    return false;
  }
  return timingSafeEqual(Buffer.from(left, "utf-8"), Buffer.from(right, "utf-8"));
}

function parseDescriptors(value: unknown): RegistryDescriptor[] {
  if (!Array.isArray(value)) {
    throw new SnapshotError("registry snapshot payload must be a descriptor array");
  }
  return value.map((entry, index) => {
    if (typeof entry !== "object" || entry === null) {
      throw new SnapshotError(`registry snapshot descriptor ${index} must be an object`);
    }
    const descriptor = entry as Record<string, unknown>;
    if (typeof descriptor.id !== "string" || descriptor.id === "") {
      throw new SnapshotError(`registry snapshot descriptor ${index} has no id`);
    }
    if (typeof descriptor.execution_class !== "string" || !EXECUTION_CLASSES.has(descriptor.execution_class)) {
      throw new SnapshotError(`capability ${descriptor.id}: invalid execution_class ${JSON.stringify(descriptor.execution_class)}`);
    }
    if (typeof descriptor.execution_route !== "string" || !EXECUTION_ROUTES.has(descriptor.execution_route)) {
      throw new SnapshotError(`capability ${descriptor.id}: invalid execution_route ${JSON.stringify(descriptor.execution_route)}`);
    }
    if (typeof descriptor.adapter_id !== "string" || descriptor.adapter_id === "") {
      throw new SnapshotError(`capability ${descriptor.id}: adapter_id is required`);
    }
    // The registry refuses LOCAL + grant-required at registration; a
    // snapshot that carries it anyway is not a registry export and must
    // not become a catalog — LOCAL execution never reaches the
    // authority resolver.
    const grantRequired = (descriptor.authority_policy as { grant_required?: unknown } | undefined)?.grant_required;
    if (descriptor.execution_route === "LOCAL" && grantRequired === true) {
      throw new SnapshotError(
        `capability ${descriptor.id}: LOCAL route cannot require a grant — LOCAL execution never reaches the authority resolver`,
      );
    }
    return descriptor as unknown as RegistryDescriptor;
  });
}

/**
 * loadCatalogFromSnapshot verifies the registry envelope and builds a
 * capability catalog from the verified bytes.
 */
export function loadCatalogFromSnapshot(raw: unknown): {
  catalog: VerifiedCapabilityCatalog;
  registrySha256: string;
} {
  const envelope = parseRegistryEnvelope(raw);
  const payload = decodeCanonicalPayload(envelope);
  const computed = createHash("sha256").update(payload).digest("hex");
  if (!constantTimeEqualHex(computed, envelope.registry_sha256)) {
    throw new SnapshotError(
      "registry snapshot digest does not cover its payload — refusing to load an unverified or tampered snapshot",
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(payload.toString("utf-8"));
  } catch (error) {
    throw new SnapshotError(`registry snapshot payload is not valid JSON: ${(error as Error).message}`);
  }

  const descriptors = parseDescriptors(parsed);
  // Verification happens inside the catalog factory: no code path
  // produces a verified catalog without a passing digest comparison.
  const catalog = VerifiedCapabilityCatalog.fromVerifiedPayload(payload, envelope.registry_sha256);
  for (const descriptor of descriptors) {
    const kernelDescriptor: CapabilityDescriptor = {
      id: descriptor.id,
      schema: descriptor.schema ?? { type: "object" },
      executionClass: descriptor.execution_class,
      executionRoute: descriptor.execution_route,
      descriptorVersion: descriptor.descriptor_version,
      adapter: descriptor.adapter_id,
      authorityPolicy: descriptor.authority_policy?.id ?? descriptor.id,
    };
    catalog.register(kernelDescriptor);
  }
  return { catalog, registrySha256: envelope.registry_sha256 };
}
