import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const scripts = import.meta.dirname;
const SCANNER = path.join(scripts, "scan-evidence-secrets.sh");
const GENERATOR = path.join(scripts, "generate-release-evidence.sh");
const SENTINEL = "DO_NOT_LEAK_123";

const CREDENTIAL_VARS = [
  "CRABBOX_TEST_DATABASE_URL",
  "CRABBOX_GITHUB_TEST_TOKEN",
  "GITHUB_TOKEN",
  "CRABBOX_OPENCOMPUTER_API_KEY",
  "OPENCOMPUTER_API_KEY",
];

function evidence(t, files) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-scan-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const [rel, content] of Object.entries(files)) {
    const file = path.join(root, rel);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, content);
  }
  return root;
}

function scan(root, args = [], extraEnv = {}) {
  const env = { ...process.env, ...extraEnv };
  for (const name of CREDENTIAL_VARS) {
    if (!(name in extraEnv)) delete env[name];
  }
  const result = spawnSync("bash", [SCANNER, root, ...args], { encoding: "utf8", env });
  return { status: result.status, output: `${result.stdout}${result.stderr}` };
}

test("a clean evidence tree passes", (t) => {
  const root = evidence(t, { "qualification.json": "{}\n", "gate-results/go-vet.log": "PASS\n" });
  const { status, output } = scan(root, [SENTINEL]);
  assert.equal(status, 0, output);
  assert.match(output, /no known secret value present/);
});

test("a secret printed by a gate fails the scan", (t) => {
  // A fake gate that wrote its credential to stderr.
  const root = evidence(t, {
    "gate-results/fake-gate.log": `connecting with postgres://u:${SENTINEL}@h/db\n`,
  });
  const { status, output } = scan(root, [SENTINEL]);
  assert.equal(status, 1, output);
  assert.match(output, /LEAK: a known secret value appears in .*fake-gate\.log/);
  // The scanner names the offending file and never re-prints the secret.
  assert.doesNotMatch(output, new RegExp(SENTINEL));
});

test("a nested secret is found", (t) => {
  const root = evidence(t, { "attestation/attestation.json": `{"token":"${SENTINEL}"}\n` });
  assert.equal(scan(root, [SENTINEL]).status, 1);
});

test("an environment credential is scanned for without being passed as an argument", (t) => {
  const dsn = `postgres://u:${SENTINEL}@h/db`;
  const root = evidence(t, { "gate-results/x.log": `dsn=${dsn}\n` });
  const { status } = scan(root, [], { CRABBOX_TEST_DATABASE_URL: dsn });
  assert.equal(status, 1);
});

test("no known secrets means nothing to scan for", (t) => {
  const root = evidence(t, { "qualification.json": "{}\n" });
  const { status, output } = scan(root);
  assert.equal(status, 0, output);
  assert.match(output, /no known secret values in the environment/);
});

test("the generator scans evidence for secrets before finalization", () => {
  const source = fs.readFileSync(GENERATOR, "utf8");
  assert.match(source, /run_gate evidence-secret-scan PROVENANCE/);
  assert.match(source, /scan-evidence-secrets\.sh/);
  const scanAt = source.indexOf("evidence-secret-scan");
  const qualifyAt = source.indexOf("=== Generating qualification.json ===");
  assert.ok(scanAt >= 0 && scanAt < qualifyAt, "the scan runs before qualification.json is generated");
});

test("the scanner parses", () => {
  execFileSync("bash", ["-n", SCANNER]);
});
