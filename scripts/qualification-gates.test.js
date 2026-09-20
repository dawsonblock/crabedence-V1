import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const scripts = import.meta.dirname;
const ADMISSION = path.join(scripts, "check-release-admission.sh");
const LIB = path.join(scripts, "lib", "qualification-gates.sh");
const sha256 = (buffer) => crypto.createHash("sha256").update(buffer).digest("hex");

function gateLog(root, id, content = "gate ran\n") {
  fs.mkdirSync(path.join(root, "gate-results"), { recursive: true });
  const relative = `gate-results/${id}.log`;
  fs.writeFileSync(path.join(root, relative), content);
  return { file: relative, sha256: sha256(fs.readFileSync(path.join(root, relative))) };
}

function gate(root, overrides = {}) {
  const id = overrides.gate_id ?? "gate";
  return {
    gate_id: id,
    gate_type: "TEST",
    mandatory: true,
    status: "PASS",
    exit_code: 0,
    tests_executed: 10,
    tests_failed: 0,
    duration_ms: 5,
    evidence: gateLog(root, id),
    ...overrides,
  };
}

// Builds a qualification record + evidence directory. `mutate` can edit
// the record before it is written.
function record(t, mutate = () => {}) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-gates-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const gates = [
    gate(root, { gate_id: "go-tests", gate_type: "TEST", tests_executed: 42 }),
    gate(root, { gate_id: "go-vet", gate_type: "STATIC_ANALYSIS", tests_executed: 0 }),
    gate(root, { gate_id: "postgres-fencing", gate_type: "INTEGRATION", tests_executed: 7 }),
    gate(root, { gate_id: "registry-digest", gate_type: "PROVENANCE", tests_executed: 0 }),
  ];
  const qualification = {
    schema_version: 2,
    release_status: "PASS",
    artifact_promotable: true,
    gate_summary: { total: gates.length, passed: gates.length, failed: 0, skipped: 0 },
    gates,
    invariants: [{ id: "CRAB-V1-012", description: "every mandatory qualification gate was executed and passed" }],
  };
  mutate(qualification, root);

  const passed = qualification.gates.filter((g) => g.status === "PASS").length;
  qualification.gate_summary = {
    total: qualification.gates.length,
    passed,
    failed: qualification.gates.length - passed,
    skipped: 0,
  };
  const consistent = passed === qualification.gates.length;
  qualification.release_status = consistent ? "PASS" : "FAIL";
  qualification.artifact_promotable = consistent;

  fs.writeFileSync(path.join(root, "qualification.json"), JSON.stringify(qualification, null, 2));
  return root;
}

function validate(root) {
  const result = spawnSync(
    "bash",
    ["-c", `source "${LIB}" && validate_qualification_gates "$1"`, "_", path.join(root, "qualification.json")],
    { encoding: "utf8" },
  );
  return { status: result.status, findings: result.stdout.trim() };
}

function admit(root) {
  const result = spawnSync("bash", [ADMISSION, path.join(root, "qualification.json")], { encoding: "utf8" });
  return { status: result.status, output: `${result.stdout}\n${result.stderr}` };
}

test("a canonical record satisfies the validator and admits", (t) => {
  const root = record(t);
  assert.equal(validate(root).status, 0, validate(root).findings);
  const { status, output } = admit(root);
  assert.equal(status, 0, output);
  assert.match(output, /RELEASE ADMISSION: PASS \(4\/4 gates\)/);
});

test("a mandatory gate that is not PASS is rejected", (t) => {
  const root = record(t, (q) => {
    q.gates[0].status = "SKIP";
    q.gates[0].exit_code = 1;
  });
  assert.match(validate(root).findings, /mandatory gate status=SKIP/);
  assert.equal(admit(root).status, 1);
});

test("a TEST gate with zero executed tests is rejected", (t) => {
  const root = record(t, (q) => {
    q.gates[0].tests_executed = 0;
  });
  assert.match(validate(root).findings, /TEST gate PASSed with tests_executed=0/);
  assert.equal(admit(root).status, 1);
});

test("a TEST gate reporting failures is rejected", (t) => {
  const root = record(t, (q) => {
    q.gates[0].tests_failed = 2;
  });
  assert.match(validate(root).findings, /tests_failed=2/);
});

test("a non-test gate claiming test counts is rejected", (t) => {
  const root = record(t, (q) => {
    q.gates[1].tests_executed = 5;
  });
  assert.match(validate(root).findings, /non-test gate \(STATIC_ANALYSIS\) reports test counts/);
});

test("an unknown gate type fails closed", (t) => {
  const root = record(t, (q) => {
    q.gates[0].gate_type = "VIBES";
  });
  assert.match(validate(root).findings, /unknown gate_type 'VIBES'/);
  assert.equal(admit(root).status, 1);
});

test("a duplicate gate id is rejected", (t) => {
  const root = record(t, (q, fixtureRoot) => {
    q.gates[1].gate_id = q.gates[0].gate_id;
    q.gates[1].evidence = gateLog(fixtureRoot, "duplicate");
  });
  assert.match(validate(root).findings, /duplicate gate_id/);
});

test("a PASS gate with a nonzero exit code is rejected", (t) => {
  const root = record(t, (q) => {
    q.gates[0].exit_code = 3;
  });
  assert.match(validate(root).findings, /PASS with exit_code=3/);
});

test("a malformed evidence digest is rejected", (t) => {
  const root = record(t, (q) => {
    q.gates[0].evidence.sha256 = "not-a-digest";
  });
  assert.match(validate(root).findings, /evidence sha256 is missing or malformed/);
});

test("an unknown schema version is rejected", (t) => {
  const root = record(t, (q) => {
    q.schema_version = 1;
  });
  assert.match(validate(root).findings, /schema_version=1 \(want 2\)/);
});

test("tampered gate evidence is rejected by admission", (t) => {
  const root = record(t);
  fs.appendFileSync(path.join(root, "gate-results", "go-tests.log"), "tampered\n");
  const { status, output } = admit(root);
  assert.equal(status, 1);
  assert.match(output, /evidence digest .* does not match the recorded/);
});

test("a missing gate evidence file is rejected by admission", (t) => {
  const root = record(t);
  fs.rmSync(path.join(root, "gate-results", "go-vet.log"));
  const { status, output } = admit(root);
  assert.equal(status, 1);
  assert.match(output, /references missing evidence/);
});

test("declared summary drift is rejected", (t) => {
  const root = record(t);
  const qualificationPath = path.join(root, "qualification.json");
  const qualification = JSON.parse(fs.readFileSync(qualificationPath, "utf8"));
  qualification.gate_summary.passed = 3;
  fs.writeFileSync(qualificationPath, JSON.stringify(qualification));
  const { status, output } = admit(root);
  assert.equal(status, 1);
  assert.match(output, /declared passed \(3\) != derived passed \(4\)/);
});

test("the admission script and the verifier share one validator", () => {
  const admission = fs.readFileSync(ADMISSION, "utf8");
  const verifier = fs.readFileSync(path.join(scripts, "verify-release-artifact.sh"), "utf8");
  for (const [name, source] of [["admission", admission], ["verifier", verifier]]) {
    assert.match(source, /source ".*lib\/qualification-gates\.sh"/, `${name} must source the shared validator`);
    assert.match(source, /validate_qualification_gates/, `${name} must consume the shared validator`);
  }
  // No name-based gate classification may survive in either consumer.
  for (const [name, source] of [["admission", admission], ["verifier", verifier]]) {
    assert.doesNotMatch(source, /startswith\("postgres-/, `${name} must not classify gates by name`);
    assert.doesNotMatch(source, /test\("tests"\)/, `${name} must not classify gates by name`);
    assert.doesNotMatch(source, /knownTestGateIDs/, `${name} must not use hardcoded gate lists`);
  }
  execFileSync("bash", ["-n", LIB]);
});

// A raw record writer for defects that remove or retype the gates array
// itself, which record() cannot express because it recomputes the
// summary from gates.
function rawRecord(t, qualification) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-gates-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(path.join(root, "qualification.json"), JSON.stringify(qualification, null, 2));
  return root;
}

const summaryOf = (gates) => ({
  total: gates.length,
  passed: gates.filter((g) => g.status === "PASS").length,
  failed: gates.filter((g) => g.status !== "PASS").length,
  skipped: 0,
});

test("a gate with a missing gate_id fails closed", (t) => {
  const root = record(t, (q) => { delete q.gates[0].gate_id; });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /gates\[0\]\.gate_id is missing/);
});

test("a gate with an empty gate_id fails closed", (t) => {
  const root = record(t, (q) => { q.gates[0].gate_id = ""; });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /gates\[0\]\.gate_id is empty/);
});

test("a gate with a missing mandatory flag fails closed", (t) => {
  const root = record(t, (q) => { delete q.gates[0].mandatory; });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /mandatory is missing/);
});

test("a gate with a missing status fails closed", (t) => {
  const root = record(t, (q) => { delete q.gates[0].status; });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /status is missing/);
});

test("a gate with a missing exit_code fails closed", (t) => {
  const root = record(t, (q) => { delete q.gates[0].exit_code; });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /exit_code is missing/);
});

test("a gate with a missing evidence.file fails closed", (t) => {
  const root = record(t, (q) => { delete q.gates[0].evidence.file; });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /evidence\.file is missing/);
});

test("a gate that is not an object fails closed", (t) => {
  const root = record(t, (q) => { q.gates[0] = "not-a-gate"; });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /gates\[0\] is not an object/);
});

test("a test-bearing gate that omits its test counts fails closed", (t) => {
  const root = record(t, (q) => { delete q.gates[0].tests_executed; });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /must report tests_executed and tests_failed/);
});

test("a truncated evidence digest fails closed", (t) => {
  const root = record(t, (q) => { q.gates[0].evidence.sha256 = "a".repeat(63); });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /evidence sha256 is missing or malformed/);
});

test("an uppercase evidence digest fails closed", (t) => {
  const root = record(t, (q) => { q.gates[0].evidence.sha256 = "A".repeat(64); });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /evidence sha256 is missing or malformed/);
});

test("a missing gates array fails closed", (t) => {
  const root = rawRecord(t, {
    schema_version: 2,
    release_status: "PASS",
    artifact_promotable: true,
    gate_summary: summaryOf([]),
    invariants: [],
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /gates is missing/);
});

test("an empty gates array fails closed in the validator", (t) => {
  const root = rawRecord(t, {
    schema_version: 2,
    release_status: "PASS",
    artifact_promotable: true,
    gate_summary: summaryOf([]),
    gates: [],
    invariants: [],
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /gates is empty/);
});

test("an empty gates array is rejected by admission", (t) => {
  const root = rawRecord(t, {
    schema_version: 2,
    release_status: "PASS",
    artifact_promotable: true,
    gate_summary: summaryOf([]),
    gates: [],
    invariants: [],
  });
  const { status, output } = admit(root);
  assert.equal(status, 1);
  assert.match(output, /no gates found/);
});

test("a gates value that is not an array fails closed", (t) => {
  const root = rawRecord(t, {
    schema_version: 2,
    release_status: "PASS",
    artifact_promotable: true,
    gate_summary: summaryOf([]),
    gates: {},
    invariants: [],
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /gates is not an array/);
});
