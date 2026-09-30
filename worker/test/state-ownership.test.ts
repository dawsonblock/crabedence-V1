import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

// State ownership for the coordinator's lifecycle records, enforced at
// the source level across ALL of worker/src — not just the router.
//
// Why this file self-tests its patterns: an earlier version of this guard
// was double-escaped, so it matched nothing and silently protected
// nothing. A guard that cannot fail is worse than no guard, so the
// patterns are proven against known-bad samples before they are trusted.
//
// Limitation, stated precisely: this is a lexical guard, not symbol
// resolution. The native TypeScript 7 toolchain used by this repository
// (the tsgo surface) does not expose the legacy JavaScript Compiler API
// and its type checker, which is what symbol-level enforcement would
// need — so an assignment through an alias whose record type is not
// visible in the same file can still slip past. The stronger form, an
// AST/lint rule that resolves the LeaseRecord/ReadyPoolEntry symbol and
// forbids writes outside the approved modules, is the tracked follow-up;
// until then this guard plus the allowlist below is what stands between
// the codebase and a second owner of lifecycle state.

const LEASE_STATES = ["provisioning", "active", "released", "expired", "failed"] as const;
const POOL_STATES = ["ready", "busy", "draining", "quarantined", "stale"] as const;

const assignmentPattern = new RegExp(
  `\\.state\\s*=(?!=)\\s*[^;\\n]*(?:"(?:${[...LEASE_STATES, ...POOL_STATES].join("|")})"|leaseIsLive|isIrreversiblyEnded|isRecoverableLeaseFailure)`,
  "g",
);

const leaseLiteralPattern = new RegExp(`state:\\s*"(?:${LEASE_STATES.join("|")})"`, "g");

const poolLiteralPattern = new RegExp(`state:\\s*"(?:${POOL_STATES.join("|")})"`, "g");

// Files that legitimately own lifecycle state, or that hold a different
// record type whose state vocabulary overlaps these literals. Every entry
// is a deliberate decision, not a convenience.
const approvedOwners = new Set([
  "lease-lifecycle.ts",
  "lease-repository.ts",
  "ready-pool-lifecycle.ts",
]);
const otherRecordTypes = new Set([
  "run-lifecycle.ts", // run records (owner of run state)
  "run-repository.ts",
  "cloudflare-container-runner.ts", // container records
  "cloudflare-dynamic-worker-runner.ts", // dynamic runner records
  "checkpoints.ts", // checkpoint records
  "portal.ts", // DOM dataset.state
  "types.ts", // the record type declarations themselves
]);

// The router may hold exactly these two non-lease shapes. Anything else is
// a second owner of lease or pool state.
const fleetAllowances = [
  // The cancel-create HTTP response shape, not a persisted lease.
  'state: "released"',
];

const sourceFiles: Array<{ name: string; text: string }> = [];
const walk = (dir: string) => {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full);
    } else if (entry.name.endsWith(".ts")) {
      sourceFiles.push({ name: entry.name, text: readFileSync(full, "utf-8") });
    }
  }
};
walk(join(dirname(fileURLToPath(import.meta.url)), "../src"));

describe("state ownership guard self-test", () => {
  it("matches every known-bad shape", () => {
    const samples = [
      'current.state = "active";',
      'entry.state = "ready";',
      'latest.state = canceled ? "released" : "failed";',
      'current.state = leaseIsLive(current) ? "expired" : current.state;',
    ];
    const missed = samples.filter((sample) => [...sample.matchAll(assignmentPattern)].length === 0);
    // The array names exactly which known-bad shapes the pattern missed.
    expect(missed).toEqual([]);
    expect([...`state: "provisioning",`.matchAll(leaseLiteralPattern)].length).toBe(1);
    expect([...`state: "quarantined",`.matchAll(poolLiteralPattern)].length).toBe(1);
  });

  it("does not match comparisons, other record vocabularies, or the DOM", () => {
    const nonMatches = [
      'if (reservation.state === "released") unbound.state = "canceled";',
      'record.state = "stopped";',
      'pasteBtn.dataset.state = "ok";',
      "operation.step.state = journal.state;",
    ];
    const falsePositives = nonMatches.filter(
      (sample) => [...sample.matchAll(assignmentPattern)].length > 0,
    );
    expect(falsePositives).toEqual([]);
  });
});

describe("lifecycle state ownership", () => {
  it("no file outside the approved owners assigns a lease or pool state", () => {
    const violations: string[] = [];
    for (const file of sourceFiles) {
      if (approvedOwners.has(file.name) || otherRecordTypes.has(file.name)) continue;
      for (const match of file.text.matchAll(assignmentPattern)) {
        violations.push(`${file.name}: ${match[0]}`);
      }
    }
    expect(violations).toEqual([]);
  });

  it("no file outside the approved owners writes a lease or pool state literal", () => {
    const violations: string[] = [];
    for (const file of sourceFiles) {
      if (approvedOwners.has(file.name) || otherRecordTypes.has(file.name)) continue;
      const matches = [
        ...file.text.matchAll(leaseLiteralPattern),
        ...file.text.matchAll(poolLiteralPattern),
      ].map((match) => match[0]);
      for (const match of matches) {
        if (file.name === "fleet.ts" && fleetAllowances.includes(match)) continue;
        violations.push(`${file.name}: ${match}`);
      }
    }
    expect(violations).toEqual([]);
  });

  it("keeps the fleet allowance list honest", () => {
    const fleet = sourceFiles.find((file) => file.name === "fleet.ts");
    expect(fleet).toBeDefined();
    for (const allowance of fleetAllowances) {
      expect(fleet!.text.includes(allowance), `allowance no longer present: ${allowance}`).toBe(
        true,
      );
    }
  });
});
