import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const scripts = import.meta.dirname;
const VERIFIER = path.join(scripts, "verify-release-artifact.sh");

const sha256 = (buffer) => crypto.createHash("sha256").update(buffer).digest("hex");

// Builds a minimal evidence bundle. It is intentionally NOT a fully valid
// qualification bundle — the tests assert the specific closure checks
// (artifact coverage, manifest count, attestation binding), which run
// independently of the qualification gates.
function bundle(t, { artifactCovered = true, fileCount = null, attestation = {} } = {}) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-verify-artifact-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const identity = { commit: "a".repeat(40), tree: "b".repeat(40), branch: "main" };
  fs.writeFileSync(path.join(root, "provenance.json"), JSON.stringify({ ...identity, dirty: false }));

  const artifact = Buffer.from(
    JSON.stringify({
      name: "crabedence-1.0.0-rc.7.tar.gz",
      sha256: "c".repeat(64),
      source_commit: identity.commit,
      source_tree: identity.tree,
      release_version: "1.0.0-rc.7",
      registry_sha256: "d".repeat(64),
    }),
  );
  fs.writeFileSync(path.join(root, "artifact.json"), artifact);
  fs.writeFileSync(path.join(root, "qualification-summary.txt"), "gates: none\n");

  const entries = [
    `${sha256(fs.readFileSync(path.join(root, "provenance.json")))}  ./provenance.json`,
    `${sha256(fs.readFileSync(path.join(root, "qualification-summary.txt")))}  ./qualification-summary.txt`,
  ];
  if (artifactCovered) {
    entries.push(`${sha256(artifact)}  ./artifact.json`);
  }
  fs.writeFileSync(path.join(root, "SHA256SUMS"), entries.join("\n") + "\n");

  const manifest = {
    name: "crabedence-v1.0.0-rc.7",
    manifest_type: "evidence-bundle",
    sha256: sha256(fs.readFileSync(path.join(root, "SHA256SUMS"))),
    digest_of: "SHA256SUMS",
    file_count: fileCount ?? entries.length,
    ...identity,
    generated_at: "2026-09-19T00:00:00Z",
  };
  fs.writeFileSync(path.join(root, "evidence-manifest.json"), JSON.stringify(manifest));

  if (attestation !== null) {
    fs.mkdirSync(path.join(root, "attestation"));
    fs.writeFileSync(
      path.join(root, "attestation", "attestation.json"),
      JSON.stringify({
        tool: "github-actions-attest",
        attestation_url: "https://github.com/example/attestations/1",
        subject: "dist/release-evidence/evidence-manifest.json",
        evidence_sha256: manifest.sha256,
        ...attestation,
      }),
    );
  }
  return { root, manifest };
}

function verify(root, extra = []) {
  const result = spawnSync("bash", [VERIFIER, root, root, ...extra], { encoding: "utf8" });
  return `${result.stdout}\n${result.stderr}`;
}

test("a covered artifact.json passes the closure checks", (t) => {
  const { root } = bundle(t);
  const output = verify(root);
  assert.match(output, /artifact\.json covered by checksums\s+PASS/);
  assert.match(output, /Evidence manifest file count\s+PASS/);
  assert.match(output, /Attestation binds the final evidence manifest\s+PASS/);
});

test("an artifact.json outside the checksum manifest fails closed", (t) => {
  const { root } = bundle(t, { artifactCovered: false });
  const output = verify(root);
  assert.match(output, /artifact\.json covered by checksums\s+FAIL/);
  assert.match(output, /does not bind the release artifact/);
});

test("a stale manifest file count fails closed", (t) => {
  const { root } = bundle(t, { fileCount: 99 });
  const output = verify(root);
  assert.match(output, /Evidence manifest file count\s+FAIL/);
});

test("an attestation of a superseded manifest fails closed", (t) => {
  const { root } = bundle(t, { attestation: { evidence_sha256: "e".repeat(64) } });
  const output = verify(root);
  assert.match(output, /Attestation binds the final evidence manifest\s+FAIL/);
});

test("an attestation of a different subject fails closed", (t) => {
  const { root } = bundle(t, { attestation: { subject: "dist/release-evidence/qualification.json" } });
  const output = verify(root);
  assert.match(output, /Attestation binds the final evidence manifest\s+FAIL/);
});

test("release mode recomputes the archive against artifact.json", (t) => {
  const { root } = bundle(t);
  const archive = path.join(root, "crabedence-1.0.0-rc.7.tar.gz");
  fs.writeFileSync(archive, "fixture archive bytes\n");
  // The bundle's artifact.json claims a digest that does not match the
  // archive: release mode must recompute and refuse.
  const output = verify(root, [archive]);
  assert.match(output, /Archive matches artifact\.json \(recomputed\)\s+FAIL/);
  assert.match(output, /does not equal artifact\.json/);
});
