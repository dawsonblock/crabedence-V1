import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const scripts = import.meta.dirname;
const PACKAGER = path.join(scripts, "package-release-evidence.sh");
const sha256 = (buffer) => crypto.createHash("sha256").update(buffer).digest("hex");

// Builds a finalized-shaped evidence directory: a checksum manifest that
// references every file, plus the bundle identity.
function evidenceFixture(t, { omitOne = false } = {}) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-evidence-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dir = path.join(root, "release-evidence");
  fs.mkdirSync(path.join(dir, "gate-results"), { recursive: true });

  const files = {
    "qualification.json": '{"schema_version":2}\n',
    "artifact.json": '{"schema_version":2}\n',
    "registry.sha256": `${"a".repeat(64)}\n`,
    "gate-results/go-vet.log": "PASS\n",
  };
  for (const [rel, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, rel), content);
  }

  const entries = Object.keys(files).map(
    (rel) => `${sha256(fs.readFileSync(path.join(dir, rel)))}  ./${rel}`,
  );
  fs.writeFileSync(path.join(dir, "SHA256SUMS"), `${entries.join("\n")}\n`);
  fs.writeFileSync(
    path.join(dir, "evidence-manifest.json"),
    JSON.stringify({
      name: "crabedence-test",
      sha256: sha256(fs.readFileSync(path.join(dir, "SHA256SUMS"))),
      digest_of: "SHA256SUMS",
      file_count: entries.length,
    }),
  );

  // The manifest still references artifact.json, but the file is gone.
  if (omitOne) fs.rmSync(path.join(dir, "artifact.json"));
  return { root, dir };
}

function packageIt(dir, out) {
  const result = spawnSync("bash", [PACKAGER, dir, out], { encoding: "utf8" });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

test("the bundle contains every path the checksum manifest references", (t) => {
  const { root, dir } = evidenceFixture(t);
  const out = path.join(root, "crabedence-test-release-evidence.tar.gz");
  const { status, stdout } = packageIt(dir, out);
  assert.equal(status, 0, stdout);
  assert.match(stdout, /^[0-9a-f]{64}$/m);

  const extract = path.join(root, "extracted");
  fs.mkdirSync(extract);
  execFileSync("tar", ["xzf", out, "-C", extract]);
  const unpacked = path.join(extract, "release-evidence");

  const manifest = fs.readFileSync(path.join(dir, "SHA256SUMS"), "utf8").trim().split("\n");
  for (const line of manifest) {
    const rel = line.split("  ./")[1];
    assert.ok(fs.existsSync(path.join(unpacked, rel)), `${rel} is present in the bundle`);
  }
  // Every checksum verifies from the unpacked tree alone — the published
  // set is sufficient for consumer verification.
  execFileSync("shasum", ["-a", "256", "-c", "SHA256SUMS"], { cwd: unpacked });
});

// A content-addressed snapshot of the whole tree, so any mutation —
// rewrite, addition, deletion — is visible.
function snapshot(dir) {
  const out = {};
  const walk = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) walk(full);
      else out[path.relative(dir, full)] = sha256(fs.readFileSync(full));
    }
  };
  walk(dir);
  return out;
}

test("packaging never mutates the finalized evidence directory", (t) => {
  const { root, dir } = evidenceFixture(t);
  const before = snapshot(dir);
  const { status } = packageIt(dir, path.join(root, "bundle.tar.gz"));
  assert.equal(status, 0);
  assert.deepEqual(snapshot(dir), before, "the finalized evidence tree is immutable after packaging");
});

test("packaging refuses an evidence tree missing a referenced file", (t) => {
  const { root, dir } = evidenceFixture(t, { omitOne: true });
  const out = path.join(root, "bundle.tar.gz");
  const { status, stderr } = packageIt(dir, out);
  assert.equal(status, 1);
  assert.match(stderr, /missing evidence file: artifact\.json/);
  assert.equal(fs.existsSync(out), false);
});

test("packaging refuses a file added after finalization", (t) => {
  const { root, dir } = evidenceFixture(t);
  // A file that is not covered by SHA256SUMS must not ship inside the
  // bundle — the packaged set has to equal the finalized set exactly.
  fs.writeFileSync(path.join(dir, "late-added.txt"), "not checksummed\n");
  const out = path.join(root, "bundle.tar.gz");
  const { status, stderr } = packageIt(dir, out);
  assert.equal(status, 1);
  assert.match(stderr, /not covered by SHA256SUMS/);
  assert.equal(fs.existsSync(out), false);
});

test("packaging refuses a non-regular member that cannot be checksummed", (t) => {
  const { root, dir } = evidenceFixture(t);
  fs.symlinkSync("qualification.json", path.join(dir, "link.json"));
  const out = path.join(root, "bundle.tar.gz");
  const { status, stderr } = packageIt(dir, out);
  assert.equal(status, 1);
  assert.match(stderr, /non-regular file/);
  assert.equal(fs.existsSync(out), false);
});

test("packaging refuses an unfinalized evidence directory", (t) => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-unfinalized-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dir = path.join(root, "release-evidence");
  fs.mkdirSync(dir);
  fs.writeFileSync(path.join(dir, "qualification.json"), "{}\n");
  const { status, stderr } = packageIt(dir, path.join(root, "bundle.tar.gz"));
  assert.equal(status, 1);
  assert.match(stderr, /not finalized/);
});

test("the packager parses", () => {
  execFileSync("bash", ["-n", PACKAGER]);
});
