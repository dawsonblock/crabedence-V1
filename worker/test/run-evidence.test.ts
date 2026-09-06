import { describe, expect, it } from "vitest";

import type { RunEvidenceV1 } from "../src/types";

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
});
