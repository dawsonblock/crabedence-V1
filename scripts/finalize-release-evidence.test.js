import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const scripts = import.meta.dirname;
const FINALIZER = path.join(scripts, "finalize-release-evidence.sh");

function sha256File(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

// Builds the state generate-release-evidence.sh leaves behind: a
// qualification bundle whose SHA256SUMS and evidence-manifest.json were
// produced BEFORE artifact.json existed (so they do not cover it).
function fixture(t, { artifact = true, manifest = true } = {}) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-finalize-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const identity = {
    name: "crabedence-v1.0.0-rc.7",
    commit: "a".repeat(40),
    tree: "b".repeat(40),
    branch: "release/crabedence-v1-rc6-qualified-execution",
  };
  fs.writeFileSync(
    path.join(root, "provenance.json"),
    JSON.stringify({ ...identity, dirty: false }, null, 2),
  );
  fs.writeFileSync(
    path.join(root, "qualification.json"),
    JSON.stringify(
      {
        release_status: "PASS",
        artifact_promotable: true,
        provenance: { ...identity, timestamp: "2026-09-18T00:00:00Z" },
        gate_summary: { total: 0, passed: 0, failed: 0, skipped: 0 },
        gates: [],
        invariants: [],
        toolchains: {},
        environment: {},
      },
      null,
      2,
    ),
  );
  fs.writeFileSync(
    path.join(root, "release-manifest.json"),
    JSON.stringify({ release_name: identity.name, status: "PASS" }, null, 2),
  );
  fs.mkdirSync(path.join(root, "gate-results"));
  fs.writeFileSync(path.join(root, "gate-results", "go-tests.log"), "ok\n");
  if (manifest) {
    fs.writeFileSync(
      path.join(root, "evidence-manifest.json"),
      JSON.stringify(
        {
          ...identity,
          manifest_type: "evidence-bundle",
          sha256: "0".repeat(64),
          digest_of: "SHA256SUMS",
          file_count: 0,
          generated_at: "2026-09-18T00:00:00Z",
        },
        null,
        2,
      ),
    );
  }
  fs.writeFileSync(path.join(root, "SHA256SUMS"), "");
  if (artifact) {
    fs.writeFileSync(
      path.join(root, "artifact.json"),
      JSON.stringify(
        {
          name: "crabedence-1.0.0-rc.7.tar.gz",
          sha256: "c".repeat(64),
          source_commit: identity.commit,
          source_tree: identity.tree,
          release_version: "1.0.0-rc.7",
          registry_sha256: "d".repeat(64),
        },
        null,
        2,
      ),
    );
  }
  return root;
}

function finalize(root, args = []) {
  return spawnSync("bash", [FINALIZER, ...args, root], { encoding: "utf8" });
}

function finalizeEnv(root, env) {
  return spawnSync("bash", [FINALIZER, root], { encoding: "utf8", env: { ...process.env, ...env } });
}

// Every byte of the four canonical finalization artifacts.
function canonicalBytes(root) {
  return Object.fromEntries(
    ["evidence-root.json", "FINAL_QUALIFICATION_REPORT.md", "SHA256SUMS", "evidence-manifest.json"].map(
      (name) => [name, fs.readFileSync(path.join(root, name), "utf8")],
    ),
  );
}

test("artifact.json is covered by the final checksum manifest", (t) => {
  const root = fixture(t);
  const result = finalize(root);
  assert.equal(result.status, 0, result.stderr);

  const sums = fs.readFileSync(path.join(root, "SHA256SUMS"), "utf8");
  assert.match(sums, /[ \t]\.\/artifact\.json\n/);

  // The regenerated manifest verifies as a whole.
  execFileSync("shasum", ["-a", "256", "-c", "SHA256SUMS"], { cwd: root, stdio: "pipe" });
});

test("final manifest digest and file count match the checksum manifest", (t) => {
  const root = fixture(t);
  assert.equal(finalize(root).status, 0);

  const manifest = JSON.parse(fs.readFileSync(path.join(root, "evidence-manifest.json"), "utf8"));
  assert.equal(manifest.sha256, sha256File(path.join(root, "SHA256SUMS")));
  assert.equal(manifest.digest_of, "SHA256SUMS");
  assert.equal(manifest.file_count, fs.readFileSync(path.join(root, "SHA256SUMS"), "utf8").trimEnd().split("\n").length);
});

test("source identity is preserved, never re-derived", (t) => {
  const root = fixture(t);
  assert.equal(finalize(root).status, 0);

  const manifest = JSON.parse(fs.readFileSync(path.join(root, "evidence-manifest.json"), "utf8"));
  assert.equal(manifest.name, "crabedence-v1.0.0-rc.7");
  assert.equal(manifest.commit, "a".repeat(40));
  assert.equal(manifest.tree, "b".repeat(40));
  assert.equal(manifest.branch, "release/crabedence-v1-rc6-qualified-execution");
});

test("a relative evidence path is resolved before any cd", (t) => {
  const root = fixture(t);
  // The release workflow passes a relative path; the script cd's into the
  // evidence directory, so a relative argument must be anchored first.
  const parent = path.dirname(root);
  const relative = path.relative(parent, root);
  const result = spawnSync("bash", [FINALIZER, relative], { cwd: parent, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);

  const manifest = JSON.parse(fs.readFileSync(path.join(root, "evidence-manifest.json"), "utf8"));
  assert.equal(manifest.sha256, sha256File(path.join(root, "SHA256SUMS")));
  assert.equal(fs.existsSync(path.join(root, "evidence-manifest.json")), true);
});

test("fails closed without artifact.json (qualification-only bundle)", (t) => {
  const root = fixture(t, { artifact: false });
  const result = finalize(root);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /artifact\.json is required/);
});

test("falls back to provenance.json when no prior manifest exists", (t) => {
  const root = fixture(t, { manifest: false });
  assert.equal(finalize(root).status, 0);

  const manifest = JSON.parse(fs.readFileSync(path.join(root, "evidence-manifest.json"), "utf8"));
  assert.equal(manifest.commit, "a".repeat(40));
  assert.equal(manifest.tree, "b".repeat(40));
});

test("a sealed bundle refuses finalization — attestations are never silently removed", (t) => {
  const root = fixture(t);
  fs.mkdirSync(path.join(root, "attestation"));
  fs.writeFileSync(
    path.join(root, "attestation", "attestation.json"),
    JSON.stringify({ attestation_url: "https://example.invalid/stale" }),
  );
  const result = finalize(root);
  assert.notEqual(result.status, 0, "finalization over an attested bundle must refuse");
  assert.match(result.stderr, /refusing to rewrite sealed evidence/);
  // And the attestation is still there — removal is an operator's
  // deliberate act, never a side effect of this script.
  assert.equal(fs.existsSync(path.join(root, "attestation", "attestation.json")), true);
});

test("re-finalization is byte-identical: same digest, same coverage", (t) => {
  const root = fixture(t);
  assert.equal(finalize(root).status, 0);
  const first = canonicalBytes(root);

  assert.equal(finalize(root).status, 0);
  assert.deepEqual(canonicalBytes(root), first);
});

test("hidden and temporary working entries never enter the checksum manifest", (t) => {
  const root = fixture(t);
  // Scratch state left inside the bundle directory — a temporary
  // extraction dir, an editor file, a nested hidden directory.
  fs.mkdirSync(path.join(root, ".run1"));
  fs.writeFileSync(path.join(root, ".run1", "scratch.log"), "scratch\n");
  fs.writeFileSync(path.join(root, ".DS_Store"), "junk");
  fs.mkdirSync(path.join(root, "gate-results", ".tmp-work"));
  fs.writeFileSync(path.join(root, "gate-results", ".tmp-work", "partial"), "x\n");

  assert.equal(finalize(root).status, 0);
  const sums = fs.readFileSync(path.join(root, "SHA256SUMS"), "utf8");
  assert.doesNotMatch(sums, /\.run1|\.DS_Store|\.tmp-work/);
  // And they still don't enter on re-finalization.
  assert.equal(finalize(root).status, 0);
  assert.doesNotMatch(fs.readFileSync(path.join(root, "SHA256SUMS"), "utf8"), /\.run1|\.DS_Store|\.tmp-work/);
});

test("finalization is deterministic across locale and timezone", (t) => {
  const root = fixture(t);
  assert.equal(finalizeEnv(root, { TZ: "UTC", LC_ALL: "C" }).status, 0);
  const first = canonicalBytes(root);
  assert.equal(finalizeEnv(root, { TZ: "Pacific/Kiritimati", LC_ALL: "en_US.UTF-8" }).status, 0);
  assert.deepEqual(canonicalBytes(root), first);
  assert.equal(finalizeEnv(root, { TZ: "America/St_Johns", LC_ALL: "C.UTF-8" }).status, 0);
  assert.deepEqual(canonicalBytes(root), first);
});

test("a relocated bundle finalizes and verifies identically — no path leaks", (t) => {
  const root = fixture(t);
  assert.equal(finalize(root).status, 0);
  const first = canonicalBytes(root);

  const copy = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-finalize-copy-")));
  t.after(() => fs.rmSync(copy, { recursive: true, force: true }));
  for (const name of fs.readdirSync(root)) {
    fs.cpSync(path.join(root, name), path.join(copy, name), { recursive: true });
  }
  assert.equal(finalize(copy, ["--verify"]).status, 0);
  assert.equal(finalize(copy).status, 0);
  assert.deepEqual(canonicalBytes(copy), first);
});

test("--verify confirms a finalized bundle and writes nothing", (t) => {
  const root = fixture(t);
  assert.equal(finalize(root).status, 0);
  const before = canonicalBytes(root);
  const result = finalize(root, ["--verify"]);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(canonicalBytes(root), before);
});

test("--verify fails on a mutated evidence file", (t) => {
  const root = fixture(t);
  assert.equal(finalize(root).status, 0);
  fs.writeFileSync(path.join(root, "gate-results", "go-tests.log"), "tampered\n");
  const result = finalize(root, ["--verify"]);
  assert.notEqual(result.status, 0);
});

test("--verify fails on a bundle that was never finalized", (t) => {
  const root = fixture(t);
  const result = finalize(root, ["--verify"]);
  assert.notEqual(result.status, 0);
});

test("--verify does not reject a sealed bundle", (t) => {
  const root = fixture(t);
  assert.equal(finalize(root).status, 0);
  fs.mkdirSync(path.join(root, "attestation"));
  fs.writeFileSync(
    path.join(root, "attestation", "attestation.json"),
    JSON.stringify({ attestation_url: "https://example.invalid/att" }),
  );
  // Verification of an attested bundle is a read operation — the seal
  // blocks rewriting, not reading.
  const result = finalize(root, ["--verify"]);
  assert.equal(result.status, 0, result.stderr);
});
