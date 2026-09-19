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
    JSON.stringify({ release_status: "PASS", gates: [] }, null, 2),
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

function finalize(root) {
  return spawnSync("bash", [FINALIZER, root], { encoding: "utf8" });
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

test("a stale attestation reference is removed from the final bundle", (t) => {
  const root = fixture(t);
  fs.mkdirSync(path.join(root, "attestation"));
  fs.writeFileSync(
    path.join(root, "attestation", "attestation.json"),
    JSON.stringify({ attestation_url: "https://example.invalid/stale" }),
  );
  assert.equal(finalize(root).status, 0);
  assert.equal(fs.existsSync(path.join(root, "attestation")), false);
});

test("re-finalization is stable: same digest, same coverage", (t) => {
  const root = fixture(t);
  assert.equal(finalize(root).status, 0);
  const first = JSON.parse(fs.readFileSync(path.join(root, "evidence-manifest.json"), "utf8"));
  const firstSums = fs.readFileSync(path.join(root, "SHA256SUMS"), "utf8");

  assert.equal(finalize(root).status, 0);
  const second = JSON.parse(fs.readFileSync(path.join(root, "evidence-manifest.json"), "utf8"));
  assert.equal(second.sha256, first.sha256);
  assert.equal(second.file_count, first.file_count);
  assert.equal(fs.readFileSync(path.join(root, "SHA256SUMS"), "utf8"), firstSums);
});
