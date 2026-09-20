import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const scripts = import.meta.dirname;
const LIB = path.join(scripts, "lib", "redact.sh");
const GENERATOR = path.join(scripts, "generate-release-evidence.sh");
const SENTINEL = "DO_NOT_LEAK_123";

function redact(...args) {
  const quoted = args.map((arg) => JSON.stringify(arg)).join(" ");
  const result = spawnSync("bash", ["-c", `source "$1"; redact_command ${quoted}`, "_", LIB], {
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout;
}

test("a database URL in argv is redacted", () => {
  const output = redact("env", `CRABBOX_TEST_DATABASE_URL=postgres://u:${SENTINEL}@h/db`, "go", "test");
  assert.doesNotMatch(output, new RegExp(SENTINEL));
  assert.match(output, /CRABBOX_TEST_DATABASE_URL=<redacted>/);
});

test("a token in argv is redacted", () => {
  const output = redact("env", `GITHUB_TOKEN=${SENTINEL}`, "go", "test");
  assert.doesNotMatch(output, new RegExp(SENTINEL));
  assert.match(output, /GITHUB_TOKEN=<redacted>/);
});

test("non-secret arguments are preserved verbatim", () => {
  const output = redact("go", "test", "-count=1", "-run", "TestLive", "./internal/execution/");
  assert.equal(output, "go test -count=1 -run TestLive ./internal/execution/");
});

test("a bare value is never mistaken for a secret", () => {
  const output = redact("postgres://u:p@h/db", "verify");
  assert.equal(output, "postgres://u:p@h/db verify");
});

test("the gate runner redacts the command line it records", () => {
  const source = fs.readFileSync(GENERATOR, "utf8");
  assert.match(source, /command=\$\(redact_command "\$@"\)/);
  assert.doesNotMatch(source, /echo "command=\$\*"/);
  assert.match(source, /source "\$REPO_ROOT\/scripts\/lib\/redact\.sh"/);
});

test("the redaction library parses", () => {
  execFileSync("bash", ["-n", LIB]);
});
