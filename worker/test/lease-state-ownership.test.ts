import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

// Lease state ownership, enforced at the source level rather than by
// import shape alone. Every lease transition is owned by
// ./lease-lifecycle and persisted through ./lease-repository; the router
// may select a named transition, but a direct state assignment is how a
// second owner of lease state appears. This test is the tripwire for
// that regression: if it fails, move the transition into the lifecycle
// module instead of adding an allowance.
const fleetSource = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), "../src/fleet.ts"),
  "utf-8",
);

const LEASE_STATES = ["provisioning", "active", "released", "expired", "failed"] as const;

const stateAssignment = new RegExp(`\\.state\\s*=\\s*"(${LEASE_STATES.join("|")})"`, "g");

// The initial state of a newly created managed lease is owned by the
// lifecycle module too: the router may not write the literal.
const initialLiteral = /state:\s*"provisioning"/g;

describe("lease state ownership", () => {
  it("fleet.ts never assigns a lease state directly", () => {
    const matches = [...fleetSource.matchAll(stateAssignment)].map((match) => match[0]);
    expect(matches, `lease state assignments in fleet.ts: ${matches.join(", ")}`).toEqual([]);
  });

  it("fleet.ts never writes the initial lease state literal", () => {
    const matches = [...fleetSource.matchAll(initialLiteral)].map((match) => match[0]);
    expect(matches, `initial lease state literals in fleet.ts: ${matches.join(", ")}`).toEqual([]);
  });
});
