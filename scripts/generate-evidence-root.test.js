import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const scripts = import.meta.dirname;
const ROOT_GEN = path.join(scripts, "generate-evidence-root.py");

// A minimal but complete evidence directory: provenance, the source
// manifests, registry envelopes, the qualification record with gates,
// the runtime record, the SBOM, and the release manifest — enough for
// every binding the root claims to be exercised.
function makeEvidence(t) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-eroot-")));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const sha = (s) => createHash("sha256").update(s).digest("hex");
  const logShaA = sha("log A\n");
  const logShaB = sha("log B\n");
  fs.writeFileSync(path.join(dir, "provenance.json"),
    JSON.stringify({ commit: "c".repeat(40), tree: "t".repeat(40), branch: "main" }));
  fs.writeFileSync(path.join(dir, "source-tree-sha256.txt"), "manifest bytes\n");
  fs.writeFileSync(path.join(dir, "source-tree-git-blobs.txt"), "blob rows\n");
  fs.writeFileSync(path.join(dir, "registry.json"), "{}");
  fs.writeFileSync(path.join(dir, "qualification-registry.json"), "{}");
  fs.writeFileSync(path.join(dir, "nemo-runtime.json"),
    JSON.stringify({ nemo_runtime_sha256: "r".repeat(64) }));
  fs.writeFileSync(path.join(dir, "sbom.spdx.json"), "{}");
  fs.writeFileSync(path.join(dir, "release-manifest.json"),
    JSON.stringify({ release_name: "crabedence-test" }));
  fs.writeFileSync(path.join(dir, "nemo-transfer-manifest.json"),
    JSON.stringify({
      shipped_tree_sha256: "r".repeat(64),
      source: { sha256: "b".repeat(64) },
    }));
  fs.writeFileSync(path.join(dir, "qualification.json"), JSON.stringify({
    schema_version: 2,
    release_status: "PASS",
    gates: [
      { gate_id: "gate-b", status: "PASS", evidence: { file: "gate-results/b.log", sha256: logShaB } },
      { gate_id: "gate-a", status: "PASS", evidence: { file: "gate-results/a.log", sha256: logShaA } },
    ],
  }));
  fs.mkdirSync(path.join(dir, "gate-results"));
  fs.writeFileSync(path.join(dir, "gate-results", "a.log"), "log A\n");
  fs.writeFileSync(path.join(dir, "gate-results", "b.log"), "log B\n");
  return dir;
}

function generate(dir, extra = []) {
  return spawnSync("python3", [ROOT_GEN, dir, ...extra], { encoding: "utf8" });
}
function verify(dir, extra = []) {
  return spawnSync("python3", [ROOT_GEN, "--verify", dir, ...extra], { encoding: "utf8" });
}
const prereq = spawnSync("python3", ["--version"], { stdio: "ignore" }).status === 0;
const skip = "requires python3";

test("a generated root verifies, and binds every evidence identity", { skip: !prereq && skip }, (t) => {
  const dir = makeEvidence(t);
  assert.equal(generate(dir).status, 0);
  const doc = JSON.parse(fs.readFileSync(path.join(dir, "evidence-root.json"), "utf8"));
  assert.equal(doc.document, "evidence-root");
  assert.equal(doc.source.commit, "c".repeat(40));
  assert.equal(doc.qualification.gate_count, 2);
  // Gates are sorted for a canonical document.
  assert.deepEqual(doc.qualification.gates.map((g) => g.gate_id), ["gate-a", "gate-b"]);
  assert.equal(doc.components.nemo_transfer_manifest.baseline_source_sha256, "b".repeat(64));
  assert.equal(doc.artifacts.status, "pending", "no artifact.json means pending artifacts");
  assert.match(doc.root_sha256, /^[0-9a-f]{64}$/);

  const v = verify(dir);
  assert.equal(v.status, 0, `${v.stdout}\n${v.stderr}`);
});

test("a stored root that does not match the files fails verification", { skip: !prereq && skip }, (t) => {
  const dir = makeEvidence(t);
  assert.equal(generate(dir).status, 0);
  // Lie about a gate outcome inside the stored document.
  const p = path.join(dir, "evidence-root.json");
  const doc = JSON.parse(fs.readFileSync(p, "utf8"));
  doc.qualification.gates[0].status = "FAIL";
  fs.writeFileSync(p, JSON.stringify(doc, null, 1));
  const v = verify(dir);
  assert.notEqual(v.status, 0);
  assert.match(v.stderr, /does not match|root_sha256 does not cover/);
});

test("an honest-looking root with a forged root_sha256 fails", { skip: !prereq && skip }, (t) => {
  const dir = makeEvidence(t);
  assert.equal(generate(dir).status, 0);
  const p = path.join(dir, "evidence-root.json");
  const doc = JSON.parse(fs.readFileSync(p, "utf8"));
  doc.root_sha256 = "0".repeat(64);
  fs.writeFileSync(p, JSON.stringify(doc, null, 1));
  const v = verify(dir);
  assert.notEqual(v.status, 0);
  assert.match(v.stderr, /root_sha256 does not cover/);
});

test("mutating an evidence file after generation fails the binding", { skip: !prereq && skip }, (t) => {
  const dir = makeEvidence(t);
  assert.equal(generate(dir).status, 0);
  fs.appendFileSync(path.join(dir, "source-tree-sha256.txt"), "extra\n");
  const v = verify(dir);
  assert.notEqual(v.status, 0);
  assert.match(v.stderr, /source_manifest|does not match/);
});

test("artifact.json lands: the root rebinds as bound with artifact digests", { skip: !prereq && skip }, (t) => {
  const dir = makeEvidence(t);
  assert.equal(generate(dir).status, 0);
  fs.writeFileSync(path.join(dir, "artifact.json"), JSON.stringify({
    schema_version: 2,
    artifact: {
      filename: "rel.tar.gz", sha256: "a".repeat(64), size: 10,
      zip_filename: "rel.zip", zip_sha256: "z".repeat(64), zip_size: 20,
    },
  }));
  assert.equal(generate(dir).status, 0);
  const doc = JSON.parse(fs.readFileSync(path.join(dir, "evidence-root.json"), "utf8"));
  assert.equal(doc.artifacts.status, "bound");
  assert.equal(doc.artifacts.entries.length, 2);
  assert.equal(doc.artifacts.entries[0].sha256, "a".repeat(64));
  const v = verify(dir);
  assert.equal(v.status, 0, `${v.stdout}\n${v.stderr}`);
});

test("a missing evidence-root.json fails verification closed", { skip: !prereq && skip }, (t) => {
  const dir = makeEvidence(t);
  const v = verify(dir);
  assert.notEqual(v.status, 0);
  assert.match(v.stderr, /missing/);
});
