import { describe, expect, it } from "vitest";

import { verifyTerminalReceipt } from "../src/run-receipt";
import type { RunRecord, TerminalRunReceipt } from "../src/types";

const validDigest = "0".repeat(64);
const malformedDigest = "not-a-hex-digest";

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

describe("terminal run receipt", () => {
  it("verifies the Go signing golden", async () => {
    const receipt: TerminalRunReceipt = {
      schema_version: 2,
      receipt_type: "terminal",
      started_at: "2026-08-23T10:00:00Z",
      ended_at: "2026-08-23T10:00:01Z",
      provider: "aws",
      lease_id: "cbx_abc123",
      slug: "blue-lobster",
      run_id: "run_123",
      command: "sh -c \"printf '<ok>\\n'; exit 17\"",
      command_sha256: "sha256:5bcb64bd81339235f6b76ab37c6f4e5febc1b787fcaf4e27783410b477c8ed5c",
      exit_code: 17,
      sync_ms: 100,
      command_ms: 900,
      duration_ms: 1000,
      log_sha256: "sha256:6da5b18878e110928643ebcc38dbb7552cf3a296eea56493e23edc2b93eecff8",
      retained_log_sha256:
        "sha256:6da5b18878e110928643ebcc38dbb7552cf3a296eea56493e23edc2b93eecff8",
      log_truncated: false,
      public_key: "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=",
      signer: "sha256:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c",
      signature:
        "3N80Q2zyXRS0g3V3phmRmegGwIkO6n9eiXXO+d36LKbfbAl7FDTAupodcy76YKk7WD5voQk9R5a9prqjNmxKDg==",
    };
    const run: RunRecord = {
      id: "run_123",
      leaseID: "cbx_abc123",
      slug: "blue-lobster",
      owner: "alice@example.com",
      org: "example-org",
      provider: "aws",
      class: "standard",
      serverType: "small",
      command: ["sh", "-c", "printf '<ok>\\n'; exit 17"],
      state: "running",
      logBytes: 0,
      logTruncated: false,
      startedAt: "2026-08-23T10:00:00Z",
    };
    await expect(
      verifyTerminalReceipt(receipt, {
        run,
        exitCode: 17,
        syncMs: 100,
        commandMs: 900,
        log: "failed\n",
        logTruncated: false,
        observedAt: new Date("2026-08-23T10:00:01Z"),
      }),
    ).resolves.toEqual(receipt);
  });

  it("V2/V3 evidence_sha256 contract matrix", async () => {
    // Both Go and TypeScript must produce identical acceptance outcomes.
    // V2 + no evidence      → valid (legacy)
    // V2 + evidence present  → INVALID
    // V2 + malformed evidence → INVALID
    // V3 + no evidence       → INVALID
    // V3 + malformed evidence → INVALID
    // V3 + valid evidence    → valid (signature may still fail, but parse passes)
    const cases: Array<{
      name: string;
      schema: 2 | 3;
      evidence?: string;
      expectParseError: string | null;
    }> = [
      { name: "v2_no_evidence_pass", schema: 2, expectParseError: null },
      {
        name: "v2_evidence_present_fail",
        schema: 2,
        evidence: validDigest,
        expectParseError: "v2 terminal receipt must not contain evidence_sha256",
      },
      {
        name: "v2_malformed_evidence_fail",
        schema: 2,
        evidence: malformedDigest,
        expectParseError: "v2 terminal receipt must not contain evidence_sha256",
      },
      {
        name: "v3_no_evidence_fail",
        schema: 3,
        expectParseError: "v3 terminal receipt must bind evidence_sha256",
      },
      {
        name: "v3_malformed_evidence_fail",
        schema: 3,
        evidence: malformedDigest,
        expectParseError: "invalid terminal receipt evidence_sha256",
      },
      { name: "v3_valid_evidence_pass", schema: 3, evidence: validDigest, expectParseError: null },
    ];

    for (const tc of cases) {
      const overrides: Partial<TerminalRunReceipt> = { schema_version: tc.schema };
      if (tc.evidence === undefined) {
        (overrides as Record<string, unknown>).evidence_sha256 = undefined;
      } else {
        (overrides as Record<string, unknown>).evidence_sha256 = tc.evidence;
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
      if (tc.expectParseError !== null) {
        // eslint-disable-next-line vitest/no-conditional-expect, no-await-in-loop
        await expect(promise).rejects.toThrow(tc.expectParseError);
      } else {
        // Valid parse may still fail on signature, but not on the
        // V2/V3 contract rule.
        // eslint-disable-next-line vitest/no-conditional-expect, no-await-in-loop
        await expect(promise).rejects.not.toThrow(
          tc.name.includes("v2") ? "evidence_sha256" : "must bind",
        );
      }
    }
  });

  it("V2 receipt with injected unsigned evidence_sha256 is rejected", async () => {
    const receipt = stubReceipt({
      schema_version: 2,
      evidence_sha256: validDigest,
    } as Partial<TerminalRunReceipt>);
    await expect(
      verifyTerminalReceipt(receipt, {
        run: stubRun,
        exitCode: 0,
        syncMs: 0,
        commandMs: 1000,
        log: "",
        logTruncated: false,
        observedAt: new Date("2026-08-23T10:00:01Z"),
      }),
    ).rejects.toThrow("v2 terminal receipt must not contain evidence_sha256");
  });
});
