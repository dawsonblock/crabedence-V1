import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const scripts = import.meta.dirname;
const RECEIPT = path.join(scripts, "generate-rc-receipt.sh");
const sha256 = (buffer) => crypto.createHash("sha256").update(buffer).digest("hex");

function fixture(t) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-receipt-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const evidence = path.join(root, "release-evidence");
  const dist = path.join(root, "dist");
  fs.mkdirSync(evidence, { recursive: true });
  fs.mkdirSync(dist, { recursive: true });

  fs.writeFileSync(
    path.join(evidence, "qualification.json"),
    JSON.stringify({
      schema_version: 2,
      release_status: "PASS",
      artifact_promotable: true,
      gate_summary: { total: 2, passed: 2, failed: 0, skipped: 0 },
      gates: [
        { gate_id: "a", gate_type: "TEST", mandatory: true, status: "PASS", exit_code: 0, tests_executed: 10, tests_failed: 0 },
        { gate_id: "b", gate_type: "PROVENANCE", mandatory: true, status: "PASS", exit_code: 0 },
      ],
    }),
  );
  fs.writeFileSync(path.join(evidence, "qualification-registry.sha256"), `${"b".repeat(64)}\n`);

  fs.writeFileSync(
    path.join(evidence, "artifact.json"),
    JSON.stringify({
      schema_version: 2,
      release: "9.9.9-rc.1",
      source: { commit: "a".repeat(40), tree: "c".repeat(40), manifest_sha256: "d".repeat(64) },
      artifact: {
        filename: "x.tar.gz", sha256: "e".repeat(64), size: 1,
        zip_filename: "x.zip", zip_sha256: "f".repeat(64),
      },
      policy: { registry_sha256: "1".repeat(64) },
      qualification: {
        sha256: sha256(fs.readFileSync(path.join(evidence, "qualification.json"))),
        schema_version: 2,
      },
      sbom: { sha256: "2".repeat(64) },
      provenance: { sha256: "3".repeat(64) },
    }),
  );
  fs.writeFileSync(
    path.join(dist, "crabedence-9.9.9-rc.1-release-evidence.tar.gz.sha256"),
    // Published sidecars use the GNU "<digest>  <filename>" format.
    `${"4".repeat(64)}  crabedence-9.9.9-rc.1-release-evidence.tar.gz\n`,
  );
  return { evidence, dist };
}

function run(evidence, dist, extra = []) {
  const result = spawnSync("bash", [RECEIPT, "--evidence", evidence, "--dist", dist, ...extra], {
    encoding: "utf8",
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

test("the receipt binds every identity from the evidence", (t) => {
  const { evidence, dist } = fixture(t);
  const { status, stdout } = run(evidence, dist, ["--clean-room", "PASS"]);
  assert.equal(status, 0, stdout);
  const receipt = JSON.parse(stdout);
  assert.equal(receipt.release, "9.9.9-rc.1");
  assert.equal(receipt.commit, "a".repeat(40));
  assert.equal(receipt.tree, "c".repeat(40));
  assert.equal(receipt.tar_sha256, "e".repeat(64));
  assert.equal(receipt.zip_sha256, "f".repeat(64));
  assert.equal(receipt.evidence_bundle_sha256, "4".repeat(64));
  assert.equal(receipt.qualification_registry_sha256, "b".repeat(64));
  assert.equal(receipt.release_registry_sha256, "1".repeat(64));
  assert.equal(receipt.qualification_status, "PASS");
  assert.equal(receipt.artifact_promotable, true);
  assert.deepEqual(receipt.gates, { total: 2, passed: 2, failed: 0, mandatory: 2 });
  assert.deepEqual(receipt.tests, { executed: 10, failed: 0 });
  assert.equal(receipt.clean_room, "PASS");
});

test("stages that have not run are reported PENDING", (t) => {
  const { evidence, dist } = fixture(t);
  const { stdout } = run(evidence, dist);
  const receipt = JSON.parse(stdout);
  assert.equal(receipt.clean_room, "PENDING");
  assert.equal(receipt.attestation, "PENDING");
  assert.equal(receipt.public_reverify, "PENDING");
});

test("an invalid stage outcome is rejected", (t) => {
  const { evidence, dist } = fixture(t);
  const { status, stderr } = run(evidence, dist, ["--clean-room", "MAYBE"]);
  assert.equal(status, 2);
  assert.match(stderr, /must be PASS, FAIL, or PENDING/);
});

test("a missing artifact.json is rejected", (t) => {
  const { evidence, dist } = fixture(t);
  fs.rmSync(path.join(evidence, "artifact.json"));
  const { status, stderr } = run(evidence, dist);
  assert.equal(status, 1);
  assert.match(stderr, /artifact\.json not found/);
});

test("the receipt generator parses", () => {
  execFileSync("bash", ["-n", RECEIPT]);
});
