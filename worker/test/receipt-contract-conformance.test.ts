import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { verifyTerminalReceipt } from "../src/run-receipt";
import type { RunRecord, TerminalRunReceipt } from "../src/types";

const fixturesPath = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../internal/cli/testdata/receipt-contract/fixtures.json",
);

interface ContractFixture {
  name: string;
  description: string;
  schema_version: number;
  evidence_sha256: string | null;
  expected: "accept" | "reject";
  error_contains?: string;
}

interface ContractFile {
  description: string;
  fixtures: ContractFixture[];
}

const file = JSON.parse(readFileSync(fixturesPath, "utf-8")) as ContractFile;

const validDigest = "0".repeat(64);

function stubReceipt(overrides: Partial<TerminalRunReceipt>): TerminalRunReceipt {
  return {
    schema_version: 3,
    receipt_type: "terminal",
    started_at: "2026-08-23T10:00:00Z",
    ended_at: "2026-08-23T10:00:01Z",
    provider: "aws",
    lease_id: "cbx_abc123",
    slug: "blue-lobster",
    run_id: "run_123",
    command: "true",
    command_sha256: "sha256:5bcb64bd81339235f6b76ab37c6f4e5febc1b787fcaf4e27783410b477c8ed5c",
    exit_code: 0,
    sync_ms: 0,
    command_ms: 1000,
    duration_ms: 1000,
    log_sha256: "sha256:6da5b18878e110928643ebcc38dbb7552cf3a296eea56493e23edc2b93eecff8",
    retained_log_sha256: "sha256:6da5b18878e110928643ebcc38dbb7552cf3a296eea56493e23edc2b93eecff8",
    log_truncated: false,
    evidence_sha256: validDigest,
    public_key: "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=",
    signer: "sha256:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c",
    signature:
      "3N80Q2zyXRS0g3V3phmRmegGwIkO6n9eiXXO+d36LKbfbAl7FDTAupodcy76YKk7WD5voQk9R5a9prqjNmxKDg==",
    ...overrides,
  } as TerminalRunReceipt;
}

const stubRun: RunRecord = {
  id: "run_123",
  leaseID: "cbx_abc123",
  slug: "blue-lobster",
  owner: "alice@example.com",
  org: "example-org",
  provider: "aws",
  class: "standard",
  serverType: "small",
  command: ["true"],
  state: "running",
  logBytes: 0,
  logTruncated: false,
  startedAt: "2026-08-23T10:00:00Z",
};

describe("receipt contract conformance corpus", () => {
  it("should have fixtures", () => {
    expect(file.fixtures.length).toBeGreaterThan(0);
  });

  for (const fx of file.fixtures) {
    it(`fixture: ${fx.name}`, async () => {
      const overrides: Partial<TerminalRunReceipt> = {
        schema_version: fx.schema_version,
      };
      if (fx.evidence_sha256 === null) {
        (overrides as Record<string, unknown>).evidence_sha256 = undefined;
      } else {
        (overrides as Record<string, unknown>).evidence_sha256 = fx.evidence_sha256;
      }
      const receipt = stubReceipt(overrides);
      const promise = verifyTerminalReceipt(receipt, {
        run: stubRun,
        exitCode: 0,
        syncMs: 0,
        commandMs: 1000,
        log: "",
        logTruncated: false,
        observedAt: new Date("2026-08-23T10:00:01Z"),
      });
      if (fx.expected === "reject") {
        // eslint-disable-next-line vitest/no-conditional-expect
        await expect(promise).rejects.toThrow(fx.error_contains ?? "error");
      } else {
        // Accept means the V2/V3 contract rule passed. Signature may
        // still fail, but not on the contract rule.
        // eslint-disable-next-line vitest/no-conditional-expect
        await expect(promise).rejects.not.toThrow(
          fx.schema_version === 2 ? "evidence_sha256" : "must bind",
        );
      }
    });
  }
});
