/**
 * Registry snapshot loading.
 *
 * NEMO does not maintain a capability catalog: it loads the
 * authoritative registry's canonical export (written by
 * `crabbox serve-execution` next to the socket) and routes on the
 * trusted descriptors. A snapshot descriptor carries the resolved
 * route, class, assurance, version, and canonical digest — the same
 * bytes the registry digest covers.
 */
import type { CapabilityDescriptor, ExecutionClass, ExecutionRoute } from "../contracts/index";
import { CapabilityCatalog } from "./kernel";

/** RegistryDescriptor is the canonical snapshot descriptor shape. */
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

/** RegistrySnapshot is the canonical registry export. */
export interface RegistrySnapshot {
  readonly registry_sha256: string;
  readonly descriptors: readonly RegistryDescriptor[];
}

/** SnapshotError is thrown when a snapshot is not a valid registry export. */
export class SnapshotError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SnapshotError";
  }
}

const EXECUTION_CLASSES = new Set(["PURE", "READ", "MUTATION", "CRITICAL"]);
const EXECUTION_ROUTES = new Set(["LOCAL", "DIRECT", "CRABEDENCE"]);

/** parseRegistrySnapshot validates the snapshot shape, failing closed. */
export function parseRegistrySnapshot(raw: unknown): RegistrySnapshot {
  if (typeof raw !== "object" || raw === null) {
    throw new SnapshotError("registry snapshot must be a JSON object");
  }
  const snapshot = raw as Record<string, unknown>;
  if (typeof snapshot.registry_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(snapshot.registry_sha256)) {
    throw new SnapshotError("registry snapshot registry_sha256 must be a 64-character hex digest");
  }
  if (!Array.isArray(snapshot.descriptors)) {
    throw new SnapshotError("registry snapshot descriptors must be an array");
  }

  const descriptors = snapshot.descriptors.map((entry, index) => {
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
    return descriptor as unknown as RegistryDescriptor;
  });

  return { registry_sha256: snapshot.registry_sha256, descriptors };
}

/**
 * loadCatalogFromSnapshot builds a capability catalog from a validated
 * registry snapshot. Every descriptor carries an explicit route, so
 * the catalog never falls back to a derived one.
 */
export function loadCatalogFromSnapshot(raw: unknown): {
  catalog: CapabilityCatalog;
  registrySha256: string;
} {
  const snapshot = parseRegistrySnapshot(raw);
  const catalog = new CapabilityCatalog();
  for (const descriptor of snapshot.descriptors) {
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
  return { catalog, registrySha256: snapshot.registry_sha256 };
}
