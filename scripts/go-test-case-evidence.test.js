import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

// Adversarial corpus for the go test -json case-evidence tool. The
// mandatory invariant under test: for any identical input stream,
// evidence GENERATION rejects everything evidence VERIFICATION rejects
// for lifecycle incompleteness — the two modes share one authoritative
// lifecycle implementation (the scan plus the lifecycle findings), so a
// truncated or contradictory stream can never be normalized into
// plausible evidence.

const scripts = import.meta.dirname;
const TOOL = path.join(scripts, "go-test-case-evidence.py");
const PKG = "example.com/mod/pkg";

const prereq = spawnSync("python3", ["--version"], { stdio: "ignore" }).status === 0;
const skip = prereq ? false : "requires python3";

function tmpdir(t) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-cases-")));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function writeStream(t, events) {
  const dir = tmpdir(t);
  const file = path.join(dir, "stream.json");
  fs.writeFileSync(file, events.map((e) => JSON.stringify(e)).join("\n") + "\n");
  return { dir, file };
}

function runGenerate(streamPath, dir) {
  const out = path.join(dir, "cases.json");
  const res = spawnSync(
    "python3",
    [
      TOOL, "--stream", streamPath, "--out", out,
      "--suite", "s", "--lane", "l", "--commit", "deadbeef",
      "--toolchain-go", "go version go1.26.5 darwin/arm64",
    ],
    { encoding: "utf8" },
  );
  return { status: res.status, output: `${res.stdout}\n${res.stderr}`, out };
}

function runVerify(streamPath, resultsPath) {
  const res = spawnSync(
    "python3",
    [TOOL, "--verify", "--stream", streamPath, "--results", resultsPath],
    { encoding: "utf8" },
  );
  return { status: res.status, output: `${res.stdout}\n${res.stderr}` };
}

// A complete, well-formed two-test run: generation must accept it and
// verification must derive the same record it wrote.
const GOOD = [
  { Action: "start", Package: PKG },
  { Action: "run", Package: PKG, Test: "TestA" },
  { Action: "output", Package: PKG, Test: "TestA", Output: "=== RUN TestA\n" },
  { Action: "pass", Package: PKG, Test: "TestA", Elapsed: 0.01 },
  { Action: "run", Package: PKG, Test: "TestB" },
  { Action: "output", Package: PKG, Test: "TestB", Output: "=== RUN TestB\n" },
  { Action: "skip", Package: PKG, Test: "TestB", Elapsed: 0.0 },
  { Action: "pass", Package: PKG, Elapsed: 0.05 },
];

// A claimed record for verify mode: generated once from a clean stream.
// The verify findings for a malformed stream name the lifecycle defect
// itself, independent of how far the claimed record diverges.
function claimedResults(t) {
  const { file, dir } = writeStream(t, GOOD);
  const gen = runGenerate(file, dir);
  assert.equal(gen.status, 0, gen.output);
  return gen.out;
}

test("a complete passing stream generates and verifies", { skip }, (t) => {
  const { file, dir } = writeStream(t, GOOD);
  const gen = runGenerate(file, dir);
  assert.equal(gen.status, 0, gen.output);
  const check = runVerify(file, gen.out);
  assert.equal(check.status, 0, check.output);
});

// The adversarial catalogue: every stream below must be refused by
// generation AND rejected by verification. The regression this guards:
// generation used to accept streams whose package never terminated.
const CASES = [
  {
    name: "test passes but the package never terminates (truncated stream)",
    events: [
      { Action: "start", Package: PKG },
      { Action: "run", Package: PKG, Test: "TestA" },
      { Action: "pass", Package: PKG, Test: "TestA", Elapsed: 0.01 },
      // no package-level terminal event
    ],
    want: /no terminal outcome/,
  },
  {
    name: "package fails while its tests claim pass (outcome laundering)",
    events: [
      { Action: "start", Package: PKG },
      { Action: "run", Package: PKG, Test: "TestA" },
      { Action: "pass", Package: PKG, Test: "TestA", Elapsed: 0.01 },
      { Action: "fail", Package: PKG, Elapsed: 0.05 },
    ],
    want: /outcome fail|not passing evidence/,
  },
  {
    name: "package passes while a test failed",
    events: [
      { Action: "start", Package: PKG },
      { Action: "run", Package: PKG, Test: "TestA" },
      { Action: "fail", Package: PKG, Test: "TestA", Elapsed: 0.01 },
      { Action: "pass", Package: PKG, Elapsed: 0.05 },
    ],
    want: /reports pass while|failed or incomplete/,
  },
  {
    name: "package passes while a test never terminated",
    events: [
      { Action: "start", Package: PKG },
      { Action: "run", Package: PKG, Test: "TestA" },
      { Action: "output", Package: PKG, Test: "TestA", Output: "half a line\n" },
      { Action: "pass", Package: PKG, Elapsed: 0.05 },
    ],
    want: /0 terminal events|incomplete/,
  },
  {
    name: "a test records two terminal outcomes",
    events: [
      { Action: "start", Package: PKG },
      { Action: "run", Package: PKG, Test: "TestA" },
      { Action: "fail", Package: PKG, Test: "TestA", Elapsed: 0.01 },
      { Action: "run", Package: PKG, Test: "TestA" },
      { Action: "pass", Package: PKG, Test: "TestA", Elapsed: 0.02 },
      { Action: "pass", Package: PKG, Elapsed: 0.05 },
    ],
    want: /duplicate run|2 terminal events/,
  },
  {
    name: "a package records two terminal outcomes",
    events: [
      { Action: "start", Package: PKG },
      { Action: "pass", Package: PKG, Elapsed: 0.05 },
      { Action: "pass", Package: PKG, Elapsed: 0.06 },
    ],
    want: /2 terminal outcomes|after its terminal/,
  },
  {
    name: "a terminal test outcome with no run event",
    events: [
      { Action: "start", Package: PKG },
      { Action: "pass", Package: PKG, Test: "TestA", Elapsed: 0.01 },
      { Action: "pass", Package: PKG, Elapsed: 0.05 },
    ],
    want: /without a preceding run/,
  },
  {
    name: "an event lands after the package's terminal outcome",
    events: [
      { Action: "start", Package: PKG },
      { Action: "run", Package: PKG, Test: "TestA" },
      { Action: "pass", Package: PKG, Test: "TestA", Elapsed: 0.01 },
      { Action: "pass", Package: PKG, Elapsed: 0.05 },
      { Action: "output", Package: PKG, Output: "late\n" },
    ],
    want: /after its terminal outcome/,
  },
  {
    name: "the package reports skip while tests claim pass",
    events: [
      { Action: "start", Package: PKG },
      { Action: "run", Package: PKG, Test: "TestA" },
      { Action: "pass", Package: PKG, Test: "TestA", Elapsed: 0.01 },
      { Action: "skip", Package: PKG, Elapsed: 0.0 },
    ],
    want: /outcome skip|not passing evidence/,
  },
  {
    name: "a test pauses while it was never running",
    events: [
      { Action: "start", Package: PKG },
      { Action: "pause", Package: PKG, Test: "TestA" },
      { Action: "run", Package: PKG, Test: "TestA" },
      { Action: "pass", Package: PKG, Test: "TestA", Elapsed: 0.01 },
      { Action: "pass", Package: PKG, Elapsed: 0.05 },
    ],
    want: /pause|not running|without a preceding run/,
  },
  {
    name: "a test continues while it was never paused",
    events: [
      { Action: "start", Package: PKG },
      { Action: "run", Package: PKG, Test: "TestA" },
      { Action: "cont", Package: PKG, Test: "TestA" },
      { Action: "pass", Package: PKG, Test: "TestA", Elapsed: 0.01 },
      { Action: "pass", Package: PKG, Elapsed: 0.05 },
    ],
    want: /continues while not paused/,
  },
  {
    name: "an event arrives after the test's terminal outcome",
    events: [
      { Action: "start", Package: PKG },
      { Action: "run", Package: PKG, Test: "TestA" },
      { Action: "pass", Package: PKG, Test: "TestA", Elapsed: 0.01 },
      { Action: "output", Package: PKG, Test: "TestA", Output: "posthumous\n" },
      { Action: "pass", Package: PKG, Elapsed: 0.05 },
    ],
    want: /after its terminal outcome/,
  },
  {
    name: "the same test appears under two package identities",
    events: [
      { Action: "start", Package: PKG },
      { Action: "run", Package: PKG, Test: "TestA" },
      { Action: "output", Package: "example.com/other", Test: "TestA", Output: "x\n" },
      { Action: "pass", Package: PKG, Test: "TestA", Elapsed: 0.01 },
      { Action: "pass", Package: PKG, Elapsed: 0.05 },
      { Action: "pass", Package: "example.com/other", Elapsed: 0.05 },
    ],
    want: /conflicting package identity/,
  },
];

for (const tc of CASES) {
  test(`generation refuses: ${tc.name}`, { skip }, (t) => {
    const { file, dir } = writeStream(t, tc.events);
    const gen = runGenerate(file, dir);
    assert.notEqual(gen.status, 0, `generation accepted a stream verification rejects:\n${gen.output}`);
    assert.match(gen.output, tc.want);
  });
  test(`verification rejects: ${tc.name}`, { skip }, (t) => {
    const { file } = writeStream(t, tc.events);
    const ver = runVerify(file, claimedResults(t));
    assert.notEqual(ver.status, 0, "verification accepted a malformed stream");
    assert.match(ver.output, tc.want);
  });
}

test("a package with no test cases still requires its own terminal outcome", { skip }, (t) => {
  const { file, dir } = writeStream(t, [
    { Action: "start", Package: PKG },
    { Action: "output", Package: PKG, Output: "testing: warning: no tests to run\n" },
    { Action: "pass", Package: PKG, Elapsed: 0.02 },
  ]);
  const gen = runGenerate(file, dir);
  assert.equal(gen.status, 0, gen.output);
  const rec = JSON.parse(fs.readFileSync(gen.out, "utf8"));
  assert.equal(rec.counts.passed, 0);
  assert.deepEqual(rec.packages, [PKG]);
});

test("a package with no test cases and no terminal outcome is refused", { skip }, (t) => {
  const { file, dir } = writeStream(t, [
    { Action: "start", Package: PKG },
    { Action: "output", Package: PKG, Output: "build failed mid-way\n" },
  ]);
  assert.notEqual(runGenerate(file, dir).status, 0);
  assert.notEqual(runVerify(file, claimedResults(t)).status, 0);
});

test("a stream of non-JSON lines is refused by both modes", { skip }, (t) => {
  const dir = tmpdir(t);
  const file = path.join(dir, "stream.json");
  fs.writeFileSync(file, "this is not json\n{also: no}\n");
  assert.notEqual(runGenerate(file, dir).status, 0);
  assert.notEqual(runVerify(file, claimedResults(t)).status, 0);
});
