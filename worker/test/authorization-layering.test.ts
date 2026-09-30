import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

// The authorization module is a leaf of the coordinator: it may depend
// on identity and authentication primitives, never on the fleet router,
// the storage layer, or any higher-level service. This is the
// architectural dependency check for the extraction — a new import here
// is a deliberate layering decision, not an accident.
const allowedSpecifiers = new Set(["./auth", "./http", "./org-identity", "./types"]);

const source = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), "../src/authorization.ts"),
  "utf-8",
);

const specifiers = [...source.matchAll(/from "(\.[^"]+)"/g)].map((match) => match[1]);

describe("authorization module layering", () => {
  it("imports only identity and authentication primitives", () => {
    expect(specifiers.length).toBeGreaterThan(0);
    for (const specifier of specifiers) {
      expect(
        allowedSpecifiers.has(specifier),
        `authorization.ts must not import ${specifier}`,
      ).toBe(true);
    }
  });
});
