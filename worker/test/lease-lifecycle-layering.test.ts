import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

// The lease lifecycle is a domain module: it owns how a lease changes
// state and must not reach into the fleet router, the storage layer,
// Cloudflare runtime globals, HTTP routing code, or environment
// parsing. A new import here is a deliberate layering decision.
const source = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), "../src/lease-lifecycle.ts"),
  "utf-8",
);

// The repository adapter may depend on storage primitives, but never on
// the router: the dependency direction is router → lifecycle → repository.
const repositorySource = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), "../src/lease-repository.ts"),
  "utf-8",
);

const specifiers = [...source.matchAll(/from "([^"]+)"/g)].map((match) => match[1]);

const allowedSpecifiers = new Set(["./config", "./provider-key", "./types"]);

describe("lease lifecycle module layering", () => {
  it("imports only domain types and the provider key helper", () => {
    expect(specifiers.length).toBeGreaterThan(0);
    for (const specifier of specifiers) {
      expect(
        allowedSpecifiers.has(specifier),
        `lease-lifecycle.ts must not import ${specifier}`,
      ).toBe(true);
    }
  });

  it("never reaches into the router, storage, or runtime globals", () => {
    for (const forbidden of ["./fleet", "./lease-repository", "./coordinator-runtime", "./http"]) {
      expect(specifiers).not.toContain(forbidden);
    }
    for (const specifier of specifiers) {
      expect(specifier.startsWith("node:")).toBe(false);
      expect(specifier.startsWith("cloudflare:")).toBe(false);
    }
  });
});

describe("lease repository module layering", () => {
  it("never imports the fleet router", () => {
    const repositorySpecifiers = [...repositorySource.matchAll(/from "([^"]+)"/g)].map(
      (match) => match[1],
    );
    expect(repositorySpecifiers.length).toBeGreaterThan(0);
    for (const specifier of repositorySpecifiers) {
      expect(
        specifier !== "./fleet" && !specifier.startsWith("cloudflare:"),
        `lease-repository.ts must not import ${specifier}`,
      ).toBe(true);
    }
  });
});
