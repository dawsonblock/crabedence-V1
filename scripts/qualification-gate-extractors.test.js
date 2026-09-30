import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

// The release evidence generator records each gate's test accounting by
// dispatching on the gate's LOG FORMAT (go test -v, vitest, -json,
// postgres json). A test-bearing gate whose name matches no extractor
// falls through to the default branch, records tests_executed=0, and is
// rejected downstream by the gate validator — after the whole
// qualification has run. This test makes that failure mode impossible
// to introduce silently: every test-bearing gate must be matched by an
// extractor pattern in all three extractors.

const GENERATOR = path.join(import.meta.dirname, "generate-release-evidence.sh");
const TEST_BEARING_TYPES = new Set(["TEST", "INTEGRATION", "SECURITY", "FAULT_INJECTION"]);
const EXTRACTORS = ["extract_tests_executed", "extract_tests_skipped", "extract_tests_failed"];

const source = fs.readFileSync(GENERATOR, "utf-8");

/** Every gate the generator declares with a test-bearing type. */
function testBearingGates() {
  const gates = new Map();
  const pattern =
    /^\s*(?:run_gate|run_required_live_go_gate)\s+([a-z0-9][a-z0-9-]*)\s+([A-Z_]+)/gm;
  for (const match of source.matchAll(pattern)) {
    const [, name, type] = match;
    if (TEST_BEARING_TYPES.has(type)) {
      gates.set(name, type);
    }
  }
  return gates;
}

/** The case labels one extractor dispatches on (the default `*` excluded). */
function extractorPatterns(name) {
  const start = source.indexOf(`${name}() {`);
  assert.notEqual(start, -1, `${name} is missing from the generator`);
  const body = source.slice(start, source.indexOf("\n}\n", start));
  const caseStart = body.indexOf('case "$gate_name" in');
  assert.notEqual(caseStart, -1, `${name} has no gate-name dispatch`);
  const caseBody = body.slice(caseStart, body.indexOf("esac", caseStart));
  const patterns = new Set();
  for (const match of caseBody.matchAll(/^\s+([a-z0-9*][a-z0-9*|-]*)\)\s*$/gm)) {
    for (const alternative of match[1].split("|")) {
      if (alternative !== "*") {
        patterns.add(alternative);
      }
    }
  }
  assert.ok(patterns.size > 0, `${name} exposes no case patterns`);
  return patterns;
}

/** Match a gate name against an extractor's patterns, `*` as a wildcard. */
function matchesAny(patterns, gateName) {
  return [...patterns].some((pattern) =>
    new RegExp(`^${pattern.split("*").map(escapeRegExp).join(".*")}$`).test(gateName),
  );
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

test("every test-bearing gate is matched by all three extractors", () => {
  const gates = testBearingGates();
  assert.ok(gates.size >= 15, `expected the generator's gates, found ${gates.size}`);
  const patternsByExtractor = new Map(
    EXTRACTORS.map((name) => [name, extractorPatterns(name)]),
  );

  for (const [gateName, type] of gates) {
    for (const [extractor, patterns] of patternsByExtractor) {
      assert.ok(
        matchesAny(patterns, gateName),
        `${gateName} (${type}) is not matched by ${extractor}; it would record ` +
          "tests_executed=0 and fail the gate validator after the run",
      );
    }
  }
});

test("the post-dispatch timeout gate reports through the Go extractors", () => {
  // The regression this pins: the gate was added without an extractor
  // pattern, so a successful run produced a self-rejecting record.
  const patterns = extractorPatterns("extract_tests_executed");
  assert.ok(matchesAny(patterns, "effect-fabric-post-dispatch-timeout"));
  assert.ok(
    !matchesAny(patterns, "some-unregistered-gate"),
    "the check must not accept a gate no extractor knows",
  );
});
