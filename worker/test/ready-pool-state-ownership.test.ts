import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

// Ready-pool state ownership, enforced at the source level: every pool
// transition is owned by ./ready-pool-lifecycle, so the router may select
// a named transition but must never assign a pool state directly. This is
// the tripwire for a second owner of pool state appearing.
const fleetSource = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), "../src/fleet.ts"),
  "utf-8",
);

const READY_POOL_STATES = ["ready", "busy", "draining", "quarantined", "stale"] as const;

const stateAssignment = new RegExp(
  `\\\\.state\\\\s*=(?!=)\\\\s*[^;\\\\n]*(?:"(?:${READY_POOL_STATES.join("|")})")`,
  "g",
);

const initialLiteral = /state:\s*"ready"/g;

describe("ready pool state ownership", () => {
  it("fleet.ts never assigns a pool state directly", () => {
    const matches = [...fleetSource.matchAll(stateAssignment)].map((match) => match[0]);
    expect(matches, `pool state assignments in fleet.ts: ${matches.join(", ")}`).toEqual([]);
  });

  it("fleet.ts never writes the initial pool state literal", () => {
    const matches = [...fleetSource.matchAll(initialLiteral)].map((match) => match[0]);
    expect(matches, `initial pool state literals in fleet.ts: ${matches.join(", ")}`).toEqual([]);
  });
});
