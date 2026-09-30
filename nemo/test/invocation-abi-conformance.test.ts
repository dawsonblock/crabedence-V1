import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { validateInvocationRequest } from "../contracts/invocation-abi";

const corpusPath = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../internal/execution/testdata/invocation-abi-conformance/vectors.json",
);

interface ConformanceVector {
  name: string;
  wire?: string;
  wire_b64?: string;
  expected: "accept" | "reject";
  error_contains?: string;
}

const corpus = JSON.parse(readFileSync(corpusPath, "utf-8")) as {
  description: string;
  vectors: ConformanceVector[];
};

// The same corpus runs against the Go parser in
// internal/execution/invocation_abi_conformance_test.go: both runtimes
// must accept or reject each raw wire request identically.
describe("capability invocation ABI conformance (Go↔NEMO)", () => {
  it("corpus is non-empty", () => {
    expect(corpus.vectors.length).toBeGreaterThan(0);
  });

  for (const vector of corpus.vectors) {
    it(`${vector.expected}s ${vector.name}`, () => {
      const bytes = vector.wire_b64
        ? new Uint8Array(Buffer.from(vector.wire_b64, "base64"))
        : new Uint8Array(Buffer.from(vector.wire ?? "", "utf-8"));
      const result = validateInvocationRequest(bytes);
      if (vector.expected === "accept") {
        expect(result.ok, result.ok ? "" : result.error).toBe(true);
        return;
      }
      expect(result.ok).toBe(false);
      if (!result.ok && vector.error_contains) {
        expect(result.error).toContain(vector.error_contains);
      }
    });
  }
});
