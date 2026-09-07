import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import { validateRunEvidence } from "../src/run-receipt";
import type { RunEvidenceV1, TerminalRunReceipt } from "../src/types";

interface GoldenCase {
  name: string;
  evidence: RunEvidenceV1;
  canonical_json: string;
  sha256: string;
  expected_validation: "pass" | "fail";
  expected_failure?: string;
}

async function loadGoldenCases(): Promise<GoldenCase[]> {
  const raw = await readFile(
    new URL("../../internal/cli/testdata/evidence-golden.json", import.meta.url),
    "utf8",
  );
  return JSON.parse(raw) as GoldenCase[];
}

// Independent implementation of the canonicalization rules from
// docs/spec/run-evidence.md, deliberately NOT imported from the worker
// source: if the worker's canonicalizer diverges from the spec, this
// reproduction is what catches it.
function specCanonicalize(value: unknown): string {
  const stable = specStable(value);
  return JSON.stringify(stable);
}

function specStable(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(specStable);
  if (!value || typeof value !== "object") return value ?? null;
  return Object.fromEntries(
    Object.entries(value)
      .toSorted(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, entry]) => [key, specStable(entry)]),
  );
}

async function specDigest(evidence: Record<string, unknown>): Promise<string> {
  const bytes = new TextEncoder().encode(specCanonicalize({ ...evidence, digest: "" }));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function stubV3Receipt(evidence: RunEvidenceV1, digest: string): TerminalRunReceipt {
  return {
    schema_version: 3,
    receipt_type: "terminal",
    started_at: evidence.started_at ?? "2026-01-15T12:30:00Z",
    ended_at: evidence.ended_at ?? "2026-01-15T12:30:05Z",
    provider: evidence.provider,
    lease_id: evidence.lease_id,
    run_id: evidence.run_id,
    command: evidence.command_text ?? "cmd",
    command_sha256: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    exit_code: evidence.exit_code,
    sync_ms: 0,
    command_ms: evidence.command_ms,
    duration_ms: evidence.total_ms,
    log_sha256: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    retained_log_sha256: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    log_truncated: false,
    evidence_sha256: digest,
    public_key: "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=",
    signer: "sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070",
    signature: "A".repeat(86) + "==",
  };
}

describe("RunEvidenceV1", () => {
  it("accepts a valid evidence record with required fields", () => {
    const evidence: RunEvidenceV1 = {
      schema_version: 1,
      evidence_type: "run",
      provider: "hetzner",
      exit_code: 0,
      run_status: "succeeded",
      total_ms: 5000,
      command_ms: 3000,
      sync_ms: 2000,
      digest: "a".repeat(64),
    };
    expect(evidence.schema_version).toBe(1);
    expect(evidence.evidence_type).toBe("run");
    expect(evidence.run_status).toBe("succeeded");
  });

  it("accepts a failed run with failure classification", () => {
    const evidence: RunEvidenceV1 = {
      schema_version: 1,
      evidence_type: "run",
      provider: "aws",
      lease_id: "cbx_test001",
      exit_code: 1,
      run_status: "failed",
      error_kind: "command-exit",
      total_ms: 8000,
      command_ms: 6000,
      sync_ms: 2000,
      blocked_stage: "user-command",
      retry_likely: "false",
      digest: "b".repeat(64),
    };
    expect(evidence.error_kind).toBe("command-exit");
    expect(evidence.blocked_stage).toBe("user-command");
  });

  it("accepts a delegated run with phases and artifacts", () => {
    const evidence: RunEvidenceV1 = {
      schema_version: 1,
      evidence_type: "run",
      provider: "daytona",
      run_id: "run_001",
      exit_code: 0,
      run_status: "succeeded",
      total_ms: 12000,
      command_ms: 8000,
      sync_ms: 4000,
      sync_delegated: true,
      runner_phases: [{ name: "command", ms: 8000 }],
      sync_phases: [
        { name: "rsync", ms: 3000 },
        { name: "git_hydrate", ms: 1000 },
      ],
      artifacts: [{ kind: "junit", path: "test-results.xml", bytes: 2048 }],
      started_at: "2026-01-01T12:00:00Z",
      ended_at: "2026-01-01T12:00:12Z",
      digest: "c".repeat(64),
    };
    expect(evidence.runner_phases?.length).toBe(1);
    expect(evidence.sync_phases?.length).toBe(2);
    expect(evidence.artifacts?.[0]?.kind).toBe("junit");
  });

  it("accepts a timed-out run", () => {
    const evidence: RunEvidenceV1 = {
      schema_version: 1,
      evidence_type: "run",
      provider: "gcp",
      exit_code: 124,
      run_status: "timed-out",
      error_kind: "timeout",
      total_ms: 30000,
      command_ms: 30000,
      sync_ms: 0,
      digest: "d".repeat(64),
    };
    expect(evidence.run_status).toBe("timed-out");
    expect(evidence.error_kind).toBe("timeout");
  });

  // Cross-language golden fixture: this evidence was generated by the Go
  // CLI (REGEN_GOLDEN=1 go test -run TestRegenerateEvidenceGoldenFixture)
  // and must validate through the TypeScript coordinator's
  // validateRunEvidence. This is the interoperability contract test for
  // the RunEvidenceV1 wire format. The cases deliberately cover the
  // canonicalization edge cases: HTML-significant characters, non-ASCII
  // Unicode, nested phase arrays, artifacts, integers at the IEEE-754
  // safe boundary, a minimal record with omitted fields, and a tampered
  // record whose stale digest must be rejected.
  it("reproduces every fixture's canonical bytes and digest from the spec", async () => {
    const cases = await loadGoldenCases();
    expect(cases.length).toBeGreaterThanOrEqual(7);
    const digests = await Promise.all(
      cases.map(({ evidence }) => specDigest(evidence as unknown as Record<string, unknown>)),
    );
    cases.forEach(({ name, evidence, canonical_json: canonicalJSON, sha256 }, index) => {
      // The digest must be a raw 64-char hex string (no sha256: prefix).
      expect(evidence.digest, `${name}: digest format`).toMatch(/^[0-9a-f]{64}$/u);
      // Byte-identical canonicalization: the spec implementation must
      // reproduce the Go-generated canonical bytes exactly.
      const reproduced = specCanonicalize({ ...evidence, digest: "" });
      expect(reproduced, `${name}: canonical bytes differ from fixture`).toBe(canonicalJSON);
      // The spec-recomputed digest must match the fixture's sha256 —
      // for tampered cases this is the digest the tamperer failed to
      // update to, proving the tamper is detectable.
      expect(digests[index], `${name}: spec digest differs from fixture sha256`).toBe(sha256);
    });
  });

  it("accepts every pass fixture through the worker validator", async () => {
    const cases = (await loadGoldenCases()).filter((entry) => entry.expected_validation === "pass");
    expect(cases.length).toBeGreaterThanOrEqual(6);
    const results = await Promise.all(
      cases.map(async ({ name, evidence }) => {
        const error = await validateRunEvidence(evidence, {
          runID: evidence.run_id ?? "",
          leaseID: evidence.lease_id ?? "",
          provider: evidence.provider,
          exitCode: evidence.exit_code,
          receipt: stubV3Receipt(evidence, evidence.digest),
        });
        return { name, error };
      }),
    );
    for (const { name, error } of results) {
      expect(error, `${name}: expected validation to pass`).toBeUndefined();
    }
  });

  it("rejects every fail fixture with the recorded failure reason", async () => {
    const cases = (await loadGoldenCases()).filter((entry) => entry.expected_validation === "fail");
    expect(cases.length).toBeGreaterThanOrEqual(1);
    const results = await Promise.all(
      cases.map(async ({ name, evidence, expected_failure: expectedFailure }) => {
        expect(expectedFailure, `${name}: fail case needs expected_failure`).toBeTruthy();
        const error = await validateRunEvidence(evidence, {
          runID: evidence.run_id ?? "",
          leaseID: evidence.lease_id ?? "",
          provider: evidence.provider,
          exitCode: evidence.exit_code,
          receipt: stubV3Receipt(evidence, evidence.digest),
        });
        return { name, error, expectedFailure };
      }),
    );
    for (const { name, error, expectedFailure } of results) {
      expect(error, `${name}: expected validation to fail`).toBeDefined();
      expect(error?.message, `${name}: unexpected failure reason`).toContain(expectedFailure!);
    }
  });

  it("rejects tampered golden evidence (digest mismatch)", async () => {
    const [first] = await loadGoldenCases();
    const tampered = { ...first.evidence, total_ms: first.evidence.total_ms + 1 };
    const error = await validateRunEvidence(tampered, {
      runID: first.evidence.run_id ?? "",
      leaseID: first.evidence.lease_id ?? "",
      provider: first.evidence.provider,
      exitCode: first.evidence.exit_code,
      receipt: stubV3Receipt(first.evidence, first.evidence.digest),
    });
    expect(error).toBeDefined();
    expect(error?.message).toContain("evidence digest mismatch");
  });

  it("rejects evidence with an unknown field (digest covers the whole object)", async () => {
    const [first] = await loadGoldenCases();
    const extended = {
      ...first.evidence,
      injected_field: "attacker-controlled",
    } as unknown as RunEvidenceV1;
    const error = await validateRunEvidence(extended, {
      runID: first.evidence.run_id ?? "",
      leaseID: first.evidence.lease_id ?? "",
      provider: first.evidence.provider,
      exitCode: first.evidence.exit_code,
      receipt: stubV3Receipt(first.evidence, first.evidence.digest),
    });
    expect(error).toBeDefined();
    expect(error?.message).toContain("evidence digest mismatch");
  });

  it("rejects a receipt whose evidence_sha256 does not match the evidence digest", async () => {
    const [first] = await loadGoldenCases();
    const wrongDigest = "f".repeat(64);
    const error = await validateRunEvidence(first.evidence, {
      runID: first.evidence.run_id ?? "",
      leaseID: first.evidence.lease_id ?? "",
      provider: first.evidence.provider,
      exitCode: first.evidence.exit_code,
      receipt: stubV3Receipt(first.evidence, wrongDigest),
    });
    expect(error).toBeDefined();
    expect(error?.message).toContain("does not match receipt evidence_sha256");
  });

  it("rejects evidence without a receipt binding", async () => {
    const [first] = await loadGoldenCases();
    const error = await validateRunEvidence(first.evidence, {
      runID: first.evidence.run_id ?? "",
      leaseID: first.evidence.lease_id ?? "",
      provider: first.evidence.provider,
      exitCode: first.evidence.exit_code,
    });
    expect(error).toBeDefined();
    expect(error?.message).toContain("requires a signed terminal receipt binding");
  });

  it("rejects evidence with a v2 receipt (cannot bind evidence)", async () => {
    const [first] = await loadGoldenCases();
    const v2 = stubV3Receipt(first.evidence, first.evidence.digest);
    delete (v2 as Partial<TerminalRunReceipt>).evidence_sha256;
    const receipt: TerminalRunReceipt = { ...v2, schema_version: 2 };
    const error = await validateRunEvidence(first.evidence, {
      runID: first.evidence.run_id ?? "",
      leaseID: first.evidence.lease_id ?? "",
      provider: first.evidence.provider,
      exitCode: first.evidence.exit_code,
      receipt,
    });
    expect(error).toBeDefined();
    expect(error?.message).toContain("v3 terminal receipt");
  });

  it("rejects a v3 receipt that omits evidence_sha256", async () => {
    const [first] = await loadGoldenCases();
    const noBinding = stubV3Receipt(first.evidence, first.evidence.digest);
    delete (noBinding as Partial<TerminalRunReceipt>).evidence_sha256;
    const error = await validateRunEvidence(first.evidence, {
      runID: first.evidence.run_id ?? "",
      leaseID: first.evidence.lease_id ?? "",
      provider: first.evidence.provider,
      exitCode: first.evidence.exit_code,
      receipt: noBinding,
    });
    expect(error).toBeDefined();
    expect(error?.message).toContain("requires receipt.evidence_sha256 binding");
  });

  it("rejects a sha256-prefixed digest (wire contract is raw hex)", async () => {
    const [first] = await loadGoldenCases();
    const prefixed = {
      ...first.evidence,
      digest: `sha256:${first.evidence.digest}`,
    };
    const error = await validateRunEvidence(prefixed, {
      runID: first.evidence.run_id ?? "",
      leaseID: first.evidence.lease_id ?? "",
      provider: first.evidence.provider,
      exitCode: first.evidence.exit_code,
      receipt: stubV3Receipt(first.evidence, prefixed.digest),
    });
    expect(error).toBeDefined();
    expect(error?.message).toContain("64-character hex string");
  });

  it("rejects uppercase hex digests", async () => {
    const [first] = await loadGoldenCases();
    const upper = { ...first.evidence, digest: first.evidence.digest.toUpperCase() };
    const error = await validateRunEvidence(upper, {
      runID: first.evidence.run_id ?? "",
      leaseID: first.evidence.lease_id ?? "",
      provider: first.evidence.provider,
      exitCode: first.evidence.exit_code,
      receipt: stubV3Receipt(first.evidence, upper.digest),
    });
    expect(error).toBeDefined();
    expect(error?.message).toContain("64-character hex string");
  });

  it("rejects non-object evidence", async () => {
    const error = await validateRunEvidence(["not", "an", "object"], {
      runID: "run_x",
      leaseID: "cbx_x",
      provider: "tart",
      exitCode: 0,
      receipt: stubV3Receipt({ provider: "tart", exit_code: 0 } as RunEvidenceV1, "0".repeat(64)),
    });
    expect(error).toBeDefined();
    expect(error?.message).toContain("evidence must be an object");
  });

  it("rejects an unsupported schema_version", async () => {
    const [first] = await loadGoldenCases();
    const bad = { ...first.evidence, schema_version: 2 };
    const error = await validateRunEvidence(bad, {
      runID: first.evidence.run_id ?? "",
      leaseID: first.evidence.lease_id ?? "",
      provider: first.evidence.provider,
      exitCode: first.evidence.exit_code,
      receipt: stubV3Receipt(first.evidence, first.evidence.digest),
    });
    expect(error).toBeDefined();
    expect(error?.message).toContain("schema_version must be 1");
  });

  it("rejects evidence whose provider does not match the run", async () => {
    const [first] = await loadGoldenCases();
    const error = await validateRunEvidence(first.evidence, {
      runID: first.evidence.run_id ?? "",
      leaseID: first.evidence.lease_id ?? "",
      provider: "someone-else",
      exitCode: first.evidence.exit_code,
      receipt: stubV3Receipt(first.evidence, first.evidence.digest),
    });
    expect(error).toBeDefined();
    expect(error?.message).toContain("does not match run provider");
  });

  it("rejects evidence whose exit_code does not match the finish exit code", async () => {
    const [first] = await loadGoldenCases();
    const error = await validateRunEvidence(first.evidence, {
      runID: first.evidence.run_id ?? "",
      leaseID: first.evidence.lease_id ?? "",
      provider: first.evidence.provider,
      exitCode: first.evidence.exit_code + 1,
      receipt: stubV3Receipt(first.evidence, first.evidence.digest),
    });
    expect(error).toBeDefined();
    expect(error?.message).toContain("does not match finish exitCode");
  });

  it("rejects evidence that is too large", async () => {
    const [first] = await loadGoldenCases();
    const oversized = {
      ...first.evidence,
      failure_hint: "x".repeat(80 * 1024),
      digest: first.evidence.digest,
    };
    const error = await validateRunEvidence(oversized, {
      runID: first.evidence.run_id ?? "",
      leaseID: first.evidence.lease_id ?? "",
      provider: first.evidence.provider,
      exitCode: first.evidence.exit_code,
      receipt: stubV3Receipt(first.evidence, first.evidence.digest),
    });
    expect(error).toBeDefined();
    expect(error?.message).toContain("too large");
  });

  it("rejects a single string field exceeding the byte limit", async () => {
    const [first] = await loadGoldenCases();
    const longField = {
      ...first.evidence,
      failure_hint: "x".repeat(5 * 1024), // under the 64 KiB total, over the 4 KiB field limit
      digest: first.evidence.digest,
    } as unknown as RunEvidenceV1;
    const error = await validateRunEvidence(longField, {
      runID: first.evidence.run_id ?? "",
      leaseID: first.evidence.lease_id ?? "",
      provider: first.evidence.provider,
      exitCode: first.evidence.exit_code,
      receipt: stubV3Receipt(first.evidence, first.evidence.digest),
    });
    expect(error).toBeDefined();
    expect(error?.message).toContain("string field exceeds byte limit");
  });

  it("rejects phase arrays exceeding the entry limit", async () => {
    const [first] = await loadGoldenCases();
    const tooManyPhases = {
      ...first.evidence,
      runner_phases: Array.from({ length: 65 }, (_, i) => ({ name: `p${i}`, ms: 1 })),
      digest: first.evidence.digest,
    } as unknown as RunEvidenceV1;
    const error = await validateRunEvidence(tooManyPhases, {
      runID: first.evidence.run_id ?? "",
      leaseID: first.evidence.lease_id ?? "",
      provider: first.evidence.provider,
      exitCode: first.evidence.exit_code,
      receipt: stubV3Receipt(first.evidence, first.evidence.digest),
    });
    expect(error).toBeDefined();
    expect(error?.message).toContain("runner_phases exceeds");
  });

  it("rejects deeply nested evidence", async () => {
    const [first] = await loadGoldenCases();
    // Build a chain of nested objects well past the depth limit but tiny
    // in total bytes, so only the depth check can catch it.
    let deep: Record<string, unknown> = { leaf: "x" };
    for (let i = 0; i < 20; i++) {
      deep = { nested: deep };
    }
    const deepEvidence = {
      ...first.evidence,
      failure_hint: deep,
      digest: first.evidence.digest,
    } as unknown as RunEvidenceV1;
    const error = await validateRunEvidence(deepEvidence, {
      runID: first.evidence.run_id ?? "",
      leaseID: first.evidence.lease_id ?? "",
      provider: first.evidence.provider,
      exitCode: first.evidence.exit_code,
      receipt: stubV3Receipt(first.evidence, first.evidence.digest),
    });
    expect(error).toBeDefined();
    expect(error?.message).toContain("nesting depth");
  });
});
