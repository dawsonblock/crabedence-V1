import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

// Adversarial coverage for the per-test lane qualification binding
// (Phase 01): a lane gate may only PASS when every required case in the
// authoritative inventory executed exactly once and passed — on the
// right lane, for this commit, under this toolchain. Aggregate counts
// alone can never qualify a lane.

const scripts = import.meta.dirname;
const ADMISSION = path.join(scripts, "check-release-admission.sh");
const LIB = path.join(scripts, "lib", "qualification-gates.sh");
const NORMALIZER = path.join(scripts, "go-test-case-evidence.py");
const sha256 = (buffer) => crypto.createHash("sha256").update(buffer).digest("hex");

const LANE = "apple-hypervisor-framework";
const GATE_ID = "live-microvm-apple";
const COMMIT = "a".repeat(40);
const GO = "go version go1.26.5 darwin/arm64";
// go test -json events name the full import path; the suite package is
// the inventory's `package` under this module root.
const PKG = "github.com/example/module/internal/sandboxexecutor";

const INVENTORY = {
  schema_version: 1,
  suite: "live-microvm",
  package: "internal/sandboxexecutor",
  run_pattern: "TestMSBLive",
  lanes: {
    // Matches qualification/required-tests.json: the apple lane pins
    // goarch, the linux lane accepts either KVM-capable arch.
    "apple-hypervisor-framework": { goos: "darwin", goarch: "arm64", gate_id: GATE_ID },
    "linux-kvm": { goos: "linux", gate_id: "live-microvm-linux-kvm" },
  },
  common_required_tests: ["TestMSBLiveA", "TestMSBLiveB", "TestMSBLiveC"],
  platform_specific_tests: {
    "apple-hypervisor-framework": [],
    "linux-kvm": ["TestMSBLiveLinuxKVM"],
  },
};

// The output bytes the stream attributes to a test; the case's claimed
// digest is the sha256 of exactly these bytes — the verifier re-derives
// the digest from the stream, so the two must agree byte-for-byte.
const caseOutput = (name) => `${name} log\n`;

// A "case" in the normalized results file: the terminal outcome the raw
// go test -json stream is claimed to show.
function caseEntry(name, status = "pass", extra = {}) {
  return {
    name,
    status,
    elapsed_seconds: 0.01,
    terminal_events: 1,
    output_sha256: sha256(caseOutput(name)),
    ...extra,
  };
}

// The raw go test -json stream matching a set of cases: per-test
// run/output/terminal events followed by the package's own terminal
// event — the canonical verifier requires both halves of a real run.
function rawStream(cases) {
  const events = [];
  for (const c of cases) {
    events.push({ Time: "2026-01-01T00:00:00Z", Action: "run", Package: PKG, Test: c.name });
    events.push({ Time: "2026-01-01T00:00:01Z", Action: "output", Package: PKG, Test: c.name, Output: caseOutput(c.name) });
    events.push({ Time: "2026-01-01T00:00:02Z", Action: c.status, Package: PKG, Test: c.name, Elapsed: 0.01 });
  }
  const failed = cases.some((c) => c.status === "fail" || c.status === "incomplete");
  events.push({ Time: "2026-01-01T00:00:03Z", Action: "output", Package: PKG, Output: `${failed ? "FAIL" : "ok"}  \t${PKG}\t0.03s\n` });
  events.push({ Time: "2026-01-01T00:00:03Z", Action: failed ? "fail" : "pass", Package: PKG, Elapsed: 0.03 });
  return events.map((e) => JSON.stringify(e)).join("\n") + "\n";
}

function resultsRecord(cases, overrides = {}) {
  return {
    schema_version: 1,
    suite: "live-microvm",
    lane: LANE,
    source_commit: COMMIT,
    toolchain_go: GO,
    runner: { os: "darwin", arch: "arm64" },
    packages: [PKG],
    tests: cases,
    counts: {
      passed: cases.filter((c) => c.status === "pass").length,
      failed: cases.filter((c) => c.status === "fail").length,
      skipped: cases.filter((c) => c.status === "skip").length,
      incomplete: cases.filter((c) => c.status === "incomplete").length,
    },
    ...overrides,
  };
}

function gateLog(root, id, content = "gate ran\n") {
  fs.mkdirSync(path.join(root, "gate-results"), { recursive: true });
  const relative = `gate-results/${id}.log`;
  fs.writeFileSync(path.join(root, relative), content);
  return { file: relative, sha256: sha256(fs.readFileSync(path.join(root, relative))) };
}

// Builds a qualification bundle: qualification.json, the required-test
// inventory, and a lane gate whose test_suite binds digest-pinned
// results + raw stream. `cases` is the normalized case list; `mutate`
// can edit the record before digests and summaries are (re)derived.
function laneBundle(t, { cases, mutate = () => {}, claimLane = true, rebind = true }) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-lane-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  fs.writeFileSync(path.join(root, "required-tests.json"), JSON.stringify(INVENTORY, null, 2));
  fs.mkdirSync(path.join(root, "gate-results"), { recursive: true });
  const results = resultsRecord(cases);
  fs.writeFileSync(path.join(root, `gate-results/${GATE_ID}.cases.json`), JSON.stringify(results, null, 2));
  fs.writeFileSync(path.join(root, `gate-results/${GATE_ID}.test.json`), rawStream(cases));

  const bound = (rel) => ({ file: rel, sha256: sha256(fs.readFileSync(path.join(root, rel))) });
  const laneGate = {
    gate_id: GATE_ID,
    gate_type: "TEST",
    mandatory: true,
    status: "PASS",
    exit_code: 0,
    tests_executed: cases.filter((c) => c.status === "pass" || c.status === "fail").length,
    tests_failed: cases.filter((c) => c.status === "fail").length,
    duration_ms: 5,
    evidence: gateLog(root, GATE_ID),
    test_suite: {
      suite: "live-microvm",
      lane: LANE,
      inventory: bound("required-tests.json"),
      results: bound(`gate-results/${GATE_ID}.cases.json`),
      raw: bound(`gate-results/${GATE_ID}.test.json`),
    },
  };
  const gates = [
    laneGate,
    {
      gate_id: "go-tests",
      gate_type: "TEST",
      mandatory: true,
      status: "PASS",
      exit_code: 0,
      tests_executed: 42,
      tests_failed: 0,
      duration_ms: 5,
      evidence: gateLog(root, "go-tests"),
    },
  ];
  const qualification = {
    schema_version: 2,
    release: "0.54.0-rc.7.3",
    release_status: "PASS",
    artifact_promotable: true,
    claimed_lanes: claimLane ? [LANE] : [],
    gate_summary: {},
    gates,
    invariants: [],
    provenance: { commit: COMMIT, tree: "b".repeat(40), branch: "test" },
    toolchains: { go: GO },
    environment: { os: "Darwin", os_version: "25.0.0", arch: "arm64", date: "2026-01-01T00:00:00Z" },
  };
  mutate(qualification, root, results);

  if (rebind && qualification.gates[0].test_suite) {
    // Mutations of the bound files get re-bound so tests exercise the
    // semantic check rather than tripping the digest check by accident.
    const ts = qualification.gates[0].test_suite;
    for (const key of ["inventory", "results", "raw"]) {
      const rel = ts[key]?.file;
      if (rel && fs.existsSync(path.join(root, rel))) {
        ts[key].sha256 = sha256(fs.readFileSync(path.join(root, rel)));
      }
    }
  }

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

const ALL_PASS = () => [
  caseEntry("TestMSBLiveA"),
  caseEntry("TestMSBLiveB"),
  caseEntry("TestMSBLiveC"),
  caseEntry("TestMSBLiveLinuxKVM", "skip"), // foreign-lane case: skipped is honest
];

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

const rewrite = (root, rel, fn) => {
  const p = path.join(root, rel);
  fs.writeFileSync(p, fn(fs.readFileSync(p, "utf8")));
};

// ─── The honest record ────────────────────────────────────────────────

test("a lane gate with complete per-test evidence validates and admits", (t) => {
  const root = laneBundle(t, { cases: ALL_PASS() });
  const { status, findings } = validate(root);
  assert.equal(status, 0, findings);
  const { status: astatus, output } = admit(root);
  assert.equal(astatus, 0, output);
});

test("a lane gate PASSes without a lane claim too — claims restrict, evidence does not require them", (t) => {
  const root = laneBundle(t, { cases: ALL_PASS(), claimLane: false });
  assert.equal(validate(root).status, 0, validate(root).findings);
});

// ─── Required-case coverage ───────────────────────────────────────────

test("a gate with one passing case and missing mandatory cases is rejected", (t) => {
  const root = laneBundle(t, { cases: [caseEntry("TestMSBLiveA")] });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /required test TestMSBLiveB absent/);
  assert.match(findings, /required test TestMSBLiveC absent/);
});

test("a gate with zero executed cases is rejected", (t) => {
  const root = laneBundle(t, { cases: [] });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /required test TestMSBLiveA absent/);
});

test("a skipped required case is rejected", (t) => {
  const root = laneBundle(t, {
    cases: [caseEntry("TestMSBLiveA"), caseEntry("TestMSBLiveB", "skip"), caseEntry("TestMSBLiveC")],
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /required test TestMSBLiveB status=skip/);
});

test("a failed required case is rejected", (t) => {
  const root = laneBundle(t, {
    cases: [caseEntry("TestMSBLiveA"), caseEntry("TestMSBLiveB", "fail"), caseEntry("TestMSBLiveC")],
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /required test TestMSBLiveB status=fail/);
});

test("a duplicated required case is rejected", (t) => {
  const root = laneBundle(t, {
    cases: [
      caseEntry("TestMSBLiveA"),
      caseEntry("TestMSBLiveA"),
      caseEntry("TestMSBLiveB"),
      caseEntry("TestMSBLiveC"),
    ],
    mutate: (q, root, results) => {
      // Raw stream keeps single events; duplicate exists only in results.
      fs.writeFileSync(
        path.join(root, `gate-results/${GATE_ID}.test.json`),
        rawStream([caseEntry("TestMSBLiveA"), caseEntry("TestMSBLiveA"), caseEntry("TestMSBLiveB"), caseEntry("TestMSBLiveC")]),
      );
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /TestMSBLiveA recorded more than once|TestMSBLiveA recorded 2 times/);
});

test("a required case with multiple terminal events is rejected", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS().map((c) => (c.name === "TestMSBLiveB" ? { ...c, terminal_events: 2 } : c)),
    mutate: (q, root) => {
      fs.writeFileSync(
        path.join(root, `gate-results/${GATE_ID}.test.json`),
        rawStream([caseEntry("TestMSBLiveA"), caseEntry("TestMSBLiveB"), caseEntry("TestMSBLiveB"), caseEntry("TestMSBLiveC"), caseEntry("TestMSBLiveLinuxKVM", "skip")]),
      );
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /TestMSBLiveB recorded 2 terminal events/);
});

// ─── Lane separation ──────────────────────────────────────────────────

test("a case platform-specific to another lane executing here is rejected", (t) => {
  const root = laneBundle(t, {
    cases: [...ALL_PASS().filter((c) => c.name !== "TestMSBLiveLinuxKVM"), caseEntry("TestMSBLiveLinuxKVM", "pass")],
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /TestMSBLiveLinuxKVM is platform-specific to another lane/);
});

test("results recorded for the wrong lane are rejected", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q, root, results) => {
      results.lane = "linux-kvm";
      rewrite(root, `gate-results/${GATE_ID}.cases.json`, () => JSON.stringify(results, null, 2));
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /results lane linux-kvm != apple-hypervisor-framework/);
});

test("results from a non-lane runner OS are rejected", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q, root, results) => {
      results.runner.os = "linux";
      rewrite(root, `gate-results/${GATE_ID}.cases.json`, () => JSON.stringify(results, null, 2));
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /runner os linux is not the apple-hypervisor-framework lane os darwin/);
});

// ─── Identity binding ─────────────────────────────────────────────────

test("results from another source commit are rejected", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q, root, results) => {
      results.source_commit = "f".repeat(40);
      rewrite(root, `gate-results/${GATE_ID}.cases.json`, () => JSON.stringify(results, null, 2));
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /results commit f+ does not match the qualified commit/);
});

test("results from another toolchain version are rejected", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q, root, results) => {
      results.toolchain_go = "go version go1.24.0 darwin/arm64";
      rewrite(root, `gate-results/${GATE_ID}.cases.json`, () => JSON.stringify(results, null, 2));
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /results toolchain .* does not run the qualified toolchain version/);
});

// A lane legitimately runs on a different platform than the evidence
// host — the toolchain's os/arch tail is the LANE's identity, not the
// record host's. Only the version must match the qualified toolchain.
test("results with the same toolchain version on the lane platform are accepted", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q, root, results) => {
      results.toolchain_go = "go version go1.26.5 darwin/arm64";
      rewrite(root, `gate-results/${GATE_ID}.cases.json`, () => JSON.stringify(results, null, 2));
    },
  });
  assert.equal(validate(root).status, 0, validate(root).findings);
});

// ─── Forged and inconsistent evidence ─────────────────────────────────

test("a forged inventory digest is rejected", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    rebind: false,
    mutate: (q) => {
      q.gates[0].test_suite.inventory.sha256 = "0".repeat(64);
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /inventory digest .* does not match/);
});

test("a swapped inventory is rejected", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q, root) => {
      const forged = { ...INVENTORY, common_required_tests: ["TestMSBLiveA"] };
      rewrite(root, "required-tests.json", () => JSON.stringify(forged, null, 2));
    },
  });
  // The forged inventory dropped required cases but the results still
  // show them executed — an executed case that is not required by the
  // bound inventory is evidence the inventory does not describe.
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /test TestMSBLiveB executed but is not in the required inventory/);
});

test("an inventory for a different suite is rejected", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q, root) => {
      const forged = { ...INVENTORY, suite: "other-suite" };
      rewrite(root, "required-tests.json", () => JSON.stringify(forged, null, 2));
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /inventory suite other-suite != live-microvm/);
});

test("case results disagreeing with the raw stream are rejected", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q, root) => {
      // Raw stream claims B failed; the results file claims it passed.
      const raw = [
        caseEntry("TestMSBLiveA"),
        caseEntry("TestMSBLiveB", "fail"),
        caseEntry("TestMSBLiveC"),
        caseEntry("TestMSBLiveLinuxKVM", "skip"),
      ];
      rewrite(root, `gate-results/${GATE_ID}.test.json`, () => rawStream(raw));
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /TestMSBLiveB status='pass' does not match the stream-derived 'fail'/);
});

test("aggregate counts inconsistent with the case results are rejected", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q) => {
      q.gates[0].tests_executed = 99;
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /tests_executed=99 inconsistent with case results/);
});

test("a bound evidence path escaping the bundle is rejected", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q) => {
      q.gates[0].test_suite.results.file = "../outside.cases.json";
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /evidence path escapes the bundle/);
});

test("a missing bound evidence file is rejected", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q) => {
      q.gates[0].test_suite.raw.file = "gate-results/no-such-file.json";
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /evidence file missing/);
});

test("a malformed test_suite binding fails structurally", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q) => {
      delete q.gates[0].test_suite.raw;
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /test_suite\.raw is missing/);
});

// ─── Reproduced validator escapes (permanent regression) ──────────────
// These are the three evidence shapes an earlier validator accepted:
// the raw stream is rewritten while the digest-bound results record
// stays consistent — only canonical re-derivation catches each one.

test("a duplicate terminal event in the raw stream is rejected", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q, root) => {
      // The record still claims terminal_events:1 — the extra pass in
      // the stream must be caught by re-derivation, not by comparing
      // final outcomes. It lands before the package terminal, exactly
      // where a real event stream would place a second outcome for B.
      rewrite(root, `gate-results/${GATE_ID}.test.json`, (raw) => {
        const lines = raw.trimEnd().split("\n");
        const extra = JSON.stringify({ Time: "2026-01-01T00:00:02Z", Action: "pass", Package: PKG, Test: "TestMSBLiveB", Elapsed: 0.02 });
        lines.splice(lines.length - 2, 0, extra);
        return lines.join("\n") + "\n";
      });
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /TestMSBLiveB.*(after its terminal outcome|2 terminal events|terminal_events=1 .* '2')/);
});

test("an output-digest mismatch between stream and results is rejected", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q, root) => {
      // Change the bytes the stream attributes to B without updating
      // the claimed output digest — the binding stays honest.
      rewrite(root, `gate-results/${GATE_ID}.test.json`, (raw) =>
        raw.replace("TestMSBLiveB log\\n", "TestMSBLiveB tampered\\n"),
      );
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /TestMSBLiveB output_sha256=.*does not match the stream-derived/);
});

test("a runner CPU architecture other than the lane's is rejected", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q, root, results) => {
      results.runner.arch = "x86_64";
      rewrite(root, `gate-results/${GATE_ID}.cases.json`, () => JSON.stringify(results, null, 2));
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /runner arch x86_64 is not the apple-hypervisor-framework lane arch arm64/);
});

test("a raw stream the run never completed is rejected", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q, root) => {
      // Drop the package terminal: the stream shows tests passing but
      // the package itself never reported an outcome — an interrupted
      // or truncated run must not qualify.
      rewrite(root, `gate-results/${GATE_ID}.test.json`, (raw) =>
        raw.split("\n").filter((l) => !l.includes(`"Package":"${PKG}","Output"`) && !l.includes(`"Package":"${PKG}","Elapsed"`)).join("\n"),
      );
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /has no terminal outcome|records .* cases; the raw stream derives|do not match the stream-derived/);
});

test("a stream containing a foreign package is rejected", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q, root) => {
      rewrite(root, `gate-results/${GATE_ID}.test.json`, (raw) =>
        raw + JSON.stringify({ Time: "2026-01-01T00:00:04Z", Action: "pass", Package: "github.com/example/other", Elapsed: 0.01 }) + "\n",
      );
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /package github\.com\/example\/other is not the declared suite package|packages .* do not match the stream-derived/);
});

test("a malformed event line in the raw stream is rejected", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q, root) => {
      rewrite(root, `gate-results/${GATE_ID}.test.json`, (raw) => "this is decorated output\n" + raw);
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /not a go test -json event line/);
});

test("results whose packages identity is foreign are rejected", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q, root, results) => {
      results.packages = ["github.com/example/other/package"];
      rewrite(root, `gate-results/${GATE_ID}.cases.json`, () => JSON.stringify(results, null, 2));
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /packages.*(not the suite package|do not match the stream-derived)/);
});

test("a toolchain naming a foreign platform is rejected", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q, root, results) => {
      // Same Go version but the wrong lane platform — version equality
      // alone must not launder a platform substitution.
      results.toolchain_go = "go version go1.26.5 linux/amd64";
      rewrite(root, `gate-results/${GATE_ID}.cases.json`, () => JSON.stringify(results, null, 2));
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /toolchain os linux is not the apple-hypervisor-framework lane os darwin/);
});

// ─── Lane claims ──────────────────────────────────────────────────────

test("a claimed lane with no lane gate is rejected", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q) => {
      // Remove the lane binding: the gate passes but proves no lane.
      delete q.gates[0].test_suite;
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /claimed lane apple-hypervisor-framework has no passing mandatory lane gate/);
});

test("a claimed lane whose lane gate failed is rejected", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q) => {
      q.gates[0].status = "FAIL";
      q.gates[0].exit_code = 1;
      q.gates[0].tests_failed = 1;
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /claimed lane apple-hypervisor-framework has no passing mandatory lane gate/);
});

test("a claimed lane satisfied only by another lane's gate is rejected", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q, root, results) => {
      // The binding claims linux-kvm evidence for the apple claim. The
      // toolchain and runner identities stay internally consistent so
      // only the lane substitution is exercised.
      q.gates[0].test_suite.lane = "linux-kvm";
      results.lane = "linux-kvm";
      results.runner.os = "linux";
      results.runner.arch = "x86_64";
      results.toolchain_go = "go version go1.26.5 linux/amd64";
      results.tests = results.tests.filter((c) => c.name !== "TestMSBLiveLinuxKVM");
      results.tests.push(caseEntry("TestMSBLiveLinuxKVM"));
      rewrite(root, `gate-results/${GATE_ID}.cases.json`, () => JSON.stringify(results, null, 2));
      rewrite(root, `gate-results/${GATE_ID}.test.json`, () => rawStream(results.tests));
      results.counts = {
        passed: results.tests.length,
        failed: 0,
        skipped: 0,
        incomplete: 0,
      };
      rewrite(root, `gate-results/${GATE_ID}.cases.json`, () => JSON.stringify(results, null, 2));
      q.gates[0].tests_executed = results.tests.length;
      q.claimed_lanes = [LANE, "linux-kvm"];
    },
  });
  // linux-kvm is satisfied by its own lane gate; the apple claim still
  // has no passing apple-lane gate.
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /claimed lane apple-hypervisor-framework has no passing mandatory lane gate/);
});

test("a malformed claimed_lanes declaration fails structurally", (t) => {
  const root = laneBundle(t, {
    cases: ALL_PASS(),
    mutate: (q) => {
      q.claimed_lanes = "apple-hypervisor-framework";
    },
  });
  const { status, findings } = validate(root);
  assert.notEqual(status, 0);
  assert.match(findings, /claimed_lanes is not an array/);
});

// ─── The normalizer ───────────────────────────────────────────────────

function runNormalizer(args, opts = {}) {
  return spawnSync("python3", [NORMALIZER, ...args], { encoding: "utf8", ...opts });
}

test("the normalizer renders per-test evidence from a go test -json stream", (t) => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-norm-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const raw = path.join(root, "raw.json");
  const out = path.join(root, "cases.json");
  fs.writeFileSync(raw, rawStream(ALL_PASS()));
  const res = runNormalizer([
    "--stream", raw, "--out", out,
    "--suite", "live-microvm", "--lane", LANE,
    "--commit", COMMIT, "--toolchain-go", GO,
  ]);
  assert.equal(res.status, 0, res.stderr);
  const cases = JSON.parse(fs.readFileSync(out, "utf8"));
  assert.equal(cases.suite, "live-microvm");
  assert.equal(cases.lane, LANE);
  assert.equal(cases.source_commit, COMMIT);
  assert.equal(cases.toolchain_go, GO);
  assert.deepEqual(cases.counts, { passed: 3, failed: 0, skipped: 1, incomplete: 0 });
  assert.deepEqual(
    cases.tests.map((c) => [c.name, c.status]),
    ALL_PASS().map((c) => [c.name, c.status]),
  );
});

test("the normalizer rejects a stream containing non-JSON lines", (t) => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-norm-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const raw = path.join(root, "raw.json");
  fs.writeFileSync(raw, `{"Action":"run","Test":"TestX"}\nthis is decorated output\n`);
  const res = runNormalizer([
    "--stream", raw, "--out", path.join(root, "cases.json"),
    "--suite", "live-microvm", "--lane", LANE,
    "--commit", COMMIT, "--toolchain-go", GO,
  ]);
  assert.notEqual(res.status, 0);
  assert.match(res.stderr, /not a go test -json event line/);
});

test("the normalizer fails when a suite test is missing from the inventory", (t) => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-norm-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  // A fake source tree whose package has a test the inventory forgot.
  const pkgDir = path.join(root, "internal/sandboxexecutor");
  fs.mkdirSync(pkgDir, { recursive: true });
  fs.writeFileSync(
    path.join(pkgDir, "msb_live_test.go"),
    "package sandboxexecutor\nfunc TestMSBLiveA(t *testing.T) {}\nfunc TestMSBLiveB(t *testing.T) {}\nfunc TestMSBLiveC(t *testing.T) {}\nfunc TestMSBLiveUninventoried(t *testing.T) {}\n",
  );
  const raw = path.join(root, "raw.json");
  fs.writeFileSync(raw, rawStream(ALL_PASS()));
  fs.writeFileSync(path.join(root, "inv.json"), JSON.stringify(INVENTORY));
  const res2 = runNormalizer([
    "--stream", raw, "--out", path.join(root, "cases.json"),
    "--suite", "live-microvm", "--lane", LANE,
    "--commit", COMMIT, "--toolchain-go", GO,
    "--inventory", path.join(root, "inv.json"), "--source-root", root,
  ]);
  assert.notEqual(res2.status, 0);
  assert.match(res2.stderr, /missing from the required-test inventory: TestMSBLiveUninventoried/);
});
