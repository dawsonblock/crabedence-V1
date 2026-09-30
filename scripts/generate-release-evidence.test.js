import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const scripts = import.meta.dirname;
const GENERATOR = path.join(scripts, "generate-release-evidence.sh");
const LIB = path.join(scripts, "lib", "live-gate.sh");

// Runs run_required_live_go_gate in isolation with stubbed generator
// collaborators, so the guard's behaviour is exercised without invoking
// the full qualification pipeline.
function runGuard({ databaseUrl, args = ["go", "test", "./internal/execution/"] } = {}) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-live-gate-")));
  try {
    const harness = `
set -euo pipefail
EVIDENCE_DIR="$1"
mkdir -p "$EVIDENCE_DIR/gate-results"
GATE_START_MS=""
now_ms() { echo 0; }
record_gate() { printf 'RECORD\\t%s\\t%s\\t%s\\n' "$1" "$3" "$4"; }
run_gate() { printf 'RUN_GATE\\t%s\\t%s\\t%s\\t%s\\n' "$1" "$2" "$3" "$4"; }
source "$2"
shift 2
run_required_live_go_gate "$@"
`;
    const env = { ...process.env };
    if (databaseUrl === undefined) {
      delete env.CRABBOX_TEST_DATABASE_URL;
    } else {
      env.CRABBOX_TEST_DATABASE_URL = databaseUrl;
    }
    const result = spawnSync(
      "bash",
      ["-c", harness, "_", root, LIB, "critical-external", "INTEGRATION", ...args],
      { encoding: "utf8", env },
    );
    return { status: result.status, output: `${result.stdout}${result.stderr}`, root };
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

test("an unset database records the gate as FAIL instead of aborting", () => {
  const { status, output } = runGuard({ databaseUrl: undefined });
  assert.equal(status, 0, output);
  assert.doesNotMatch(output, /unbound variable/);
  assert.match(output, /RECORD\tcritical-external\tFAIL\t1/);
  assert.doesNotMatch(output, /RUN_GATE/);
});

test("an empty database records the gate as FAIL", () => {
  const { status, output } = runGuard({ databaseUrl: "" });
  assert.equal(status, 0, output);
  assert.match(output, /RECORD\tcritical-external\tFAIL\t1/);
});

test("a configured database delegates to run_gate with the URL bound", () => {
  const { status, output } = runGuard({ databaseUrl: "postgres://q:q@127.0.0.1:5432/q" });
  assert.equal(status, 0, output);
  assert.match(output, /RUN_GATE\tcritical-external\tINTEGRATION\tenv\tCRABBOX_TEST_DATABASE_URL=postgres:\/\/q:q@127\.0\.0\.1:5432\/q/);
  assert.doesNotMatch(output, /RECORD\tcritical-external\tFAIL/);
});

test("the live gates route through the fail-closed helper", () => {
  const source = fs.readFileSync(GENERATOR, "utf8");
  // The exact regression: passing the URL straight into a gate with a bare
  // expansion aborts under set -u before the gate runs. Guarded uses inside
  // an `if [ -n "${VAR:-}" ]` block are fine and remain.
  assert.doesNotMatch(source, /CRABBOX_TEST_DATABASE_URL="\$CRABBOX_TEST_DATABASE_URL"/);
  assert.doesNotMatch(source, /run_gate critical-external/);
  assert.doesNotMatch(source, /run_gate critical-faults/);
  assert.match(source, /run_required_live_go_gate critical-external INTEGRATION/);
  assert.match(source, /run_required_live_go_gate critical-faults FAULT_INJECTION/);
  assert.match(source, /source "\$REPO_ROOT\/scripts\/lib\/live-gate\.sh"/);
});

test("the generator and the live-gate helper parse", () => {
  for (const file of [GENERATOR, LIB]) {
    execFileSync("bash", ["-n", file]);
  }
});
