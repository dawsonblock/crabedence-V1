/**
 * Test-only kernel construction.
 *
 * Production code builds its catalog from the authoritative registry's
 * verified envelope (`loadCatalogFromSnapshot`), and the production
 * `NemoKernel` accepts only a `VerifiedCapabilityCatalog`. Tests
 * legitimately need hand-built catalogs, so this module makes that path
 * explicit: importing `createTestKernel` is a deliberate, greppable
 * statement that the catalog did not come from the registry.
 */
import type { CapabilityDescriptor } from "../contracts/index";
import {
  CapabilityCatalog,
  NemoKernel,
  VerifiedCapabilityCatalog,
  type KernelPorts,
} from "./kernel";

/** createTestCatalog builds a hand-populated catalog for tests. */
export function createTestCatalog(descriptors: CapabilityDescriptor[] = []): CapabilityCatalog {
  const catalog = new CapabilityCatalog();
  for (const descriptor of descriptors) {
    catalog.register(descriptor);
  }
  return catalog;
}

/**
 * createTestKernel wraps a hand-built catalog in a verified-catalog
 * shell so tests can construct a kernel. Every descriptor is
 * re-registered (and therefore re-validated: route/class pairing,
 * schema compilation) on the way in.
 */
export function createTestKernel(catalog: CapabilityCatalog, ports: KernelPorts): NemoKernel {
  // forTestOnly is the deliberately-named, greppable escape hatch: the
  // production path (loadCatalogFromSnapshot) can only produce a
  // verified catalog by passing a real digest comparison.
  const verified = VerifiedCapabilityCatalog.forTestOnly();
  for (const descriptor of catalog.list()) {
    verified.register(descriptor);
  }
  return new NemoKernel(verified, ports);
}
