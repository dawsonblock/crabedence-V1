import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

// The run lifecycle is a domain module: it decides how a run changes
// state and delegates persistence to the RunRepository contract. It must
// not reach into the fleet router, the storage adapter, Cloudflare
// runtime globals, HTTP routing code, or environment parsing — a new
// import here is a deliberate layering decision, not an accident.
const source = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), "../src/run-lifecycle.ts"),
  "utf-8",
);

const specifiers = [...source.matchAll(/from "([^"]+)"/g)].map((match) => match[1]);

const allowedSpecifiers = new Set(["./authorization", "./run-receipt", "./types"]);

describe("run lifecycle module layering", () => {
  it("imports only authorization, receipt contracts, and domain types", () => {
    expect(specifiers.length).toBeGreaterThan(0);
    for (const specifier of specifiers) {
      expect(
        allowedSpecifiers.has(specifier),
        `run-lifecycle.ts must not import ${specifier}`,
      ).toBe(true);
    }
  });

  it("never reaches into the router, the storage adapter, or runtime globals", () => {
    for (const forbidden of ["./fleet", "./run-repository", "./coordinator-runtime", "./http"]) {
      expect(specifiers).not.toContain(forbidden);
    }
    for (const specifier of specifiers) {
      expect(specifier.startsWith("node:")).toBe(false);
      expect(specifier.startsWith("cloudflare:")).toBe(false);
    }
  });
});
