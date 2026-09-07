import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { validateRunEvidence } from "../src/run-receipt.ts";

const fixturesPath = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../internal/cli/testdata/run-evidence-conformance/fixtures.json",
);

interface ConformanceFixture {
  name: string;
  evidence: unknown;
  expected: "accept" | "reject";
  error_contains?: string;
}

interface ConformanceFile {
  description: string;
  fixtures: ConformanceFixture[];
}

const file = JSON.parse(readFileSync(fixturesPath, "utf-8")) as ConformanceFile;

// Minimal binding for validation. The conformance corpus tests structural
// validation, not run binding, so we use permissive binding values.
const binding = {
  runID: "",
  leaseID: "",
  provider: "test-provider",
  exitCode: 0,
  receipt: undefined as
    | {
        schema_version: number;
        evidence_sha256?: string;
      }
    | undefined,
};

describe("run-evidence conformance corpus", () => {
  it("should have fixtures", () => {
    expect(file.fixtures.length).toBeGreaterThan(0);
  });

  for (const fx of file.fixtures) {
    it(`fixture: ${fx.name}`, async () => {
      // Adjust binding to match the evidence's exit_code and provider so
      // binding checks don't interfere with structural validation tests.
      const ev = fx.evidence as Record<string, unknown>;
      const localBinding = {
        ...binding,
        provider: typeof ev["provider"] === "string" ? ev["provider"] : "test-provider",
        exitCode: typeof ev["exit_code"] === "number" ? ev["exit_code"] : 0,
        runID: typeof ev["run_id"] === "string" ? ev["run_id"] : "",
        leaseID: typeof ev["lease_id"] === "string" ? ev["lease_id"] : "",
      };

      // For accept fixtures, provide a mock v3 receipt that binds the
      // evidence digest. This allows testing structural validation
      // without needing a real Ed25519-signed receipt.
      if (fx.expected === "accept" && typeof ev["digest"] === "string") {
        localBinding.receipt = {
          schema_version: 3,
          evidence_sha256: ev["digest"],
        };
      }

      const err = await validateRunEvidence(fx.evidence, localBinding);

      if (fx.expected === "reject") {
        expect(err, `expected rejection but evidence was accepted`).toBeInstanceOf(Error);
        if (fx.error_contains && err instanceof Error) {
          expect(
            err.message.toLowerCase(),
            `expected error containing "${fx.error_contains}"`,
          ).toContain(fx.error_contains.toLowerCase());
        }
      } else {
        expect(
          err,
          `expected acceptance but got error: ${err instanceof Error ? err.message : String(err)}`,
        ).toBeUndefined();
      }
    });
  }
});
