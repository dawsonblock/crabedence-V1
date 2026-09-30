import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

// Adversarial coverage for the release trust boundary: every case here is
// a deliberate defect that must fail CLOSED — REJECTED, FAIL, exit≠0 —
// never a warning. Gate-semantics cases live in qualification-gates.test.js;
// this suite covers the bindings between objects: toolchain identity,
// qualification digest, source manifest digest, and archive equivalence.

const scripts = import.meta.dirname;
const ADMISSION = path.join(scripts, "check-release-admission.sh");
const VERIFIER = path.join(scripts, "verify-release-artifact.sh");
const COMPARE = path.join(scripts, "compare-source-trees.sh");
const sha256 = (buffer) => crypto.createHash("sha256").update(buffer).digest("hex");

function tmpdir(t, prefix) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

// ─── Admission fixture ──────────────────────────────────────────────────
// qualification.json plus the release object admission independently
// cross-checks. `mutate` edits both before they are written.
function admissionFixture(t, mutate = () => {}) {
  const root = tmpdir(t, "cbx-adv-admit-");
  fs.mkdirSync(path.join(root, "gate-results"), { recursive: true });
  fs.writeFileSync(path.join(root, "gate-results", "go-tests.log"), "PASS\n");
  const logSha = sha256(fs.readFileSync(path.join(root, "gate-results", "go-tests.log")));

  const qualification = {
    schema_version: 2,
    release_status: "PASS",
    artifact_promotable: true,
    gate_summary: { total: 1, passed: 1, failed: 0, skipped: 0 },
    gates: [
      {
        gate_id: "exact-toolchain",
        gate_type: "BUILD",
        mandatory: true,
        status: "PASS",
        exit_code: 0,
        tests_executed: 0,
        tests_failed: 0,
        duration_ms: 5,
        evidence: { file: "gate-results/go-tests.log", sha256: logSha },
      },
    ],
    toolchains: { go: "go1.26.5" },
  };
  const artifact = {
    schema_version: 2,
    toolchain: { go: "go1.26.5" },
  };
  mutate(qualification, artifact, root);
  fs.writeFileSync(path.join(root, "qualification.json"), JSON.stringify(qualification));
  fs.writeFileSync(path.join(root, "artifact.json"), JSON.stringify(artifact));
  return root;
}

function admit(root) {
  const result = spawnSync("bash", [ADMISSION, path.join(root, "qualification.json")], { encoding: "utf8" });
  return { status: result.status, output: `${result.stdout}\n${result.stderr}` };
}

test("admission accepts declared = qualified toolchain", (t) => {
  const root = admissionFixture(t);
  const { status, output } = admit(root);
  assert.equal(status, 0, output);
  assert.match(output, /Toolchain binding: go1\.26\.5 \(declared = qualified\)/);
});

test("admission rejects a toolchain qualified on a different patch", (t) => {
  const root = admissionFixture(t, (q) => {
    q.toolchains.go = "go1.26.6";
  });
  const { status, output } = admit(root);
  assert.equal(status, 1, output);
  assert.match(output, /declares toolchain go1\.26\.5 but qualification ran on go1\.26\.6/);
  assert.match(output, /RELEASE ADMISSION: REJECTED/);
});

test("admission rejects a missing qualified toolchain record", (t) => {
  const root = admissionFixture(t, (q) => {
    delete q.toolchains;
  });
  const { status, output } = admit(root);
  assert.equal(status, 1, output);
  assert.match(output, /records no actual Go toolchain version/);
});

test("admission rejects a malformed toolchain declaration", (t) => {
  const root = admissionFixture(t, (_q, a) => {
    a.toolchain.go = "go1.26";
  });
  const { status, output } = admit(root);
  assert.equal(status, 1, output);
  assert.match(output, /toolchain\.go is missing or malformed/);
});

// ─── Verifier fixture ───────────────────────────────────────────────────
// A minimal release-mode bundle: artifact.json bound to real bytes, a
// qualification record carrying the toolchain it ran on, and a source dir
// whose go.mod pins the same toolchain.
function verifierFixture(t, mutate = () => {}) {
  const root = tmpdir(t, "cbx-adv-verify-");
  const source = path.join(root, "src");
  fs.mkdirSync(source, { recursive: true });
  fs.writeFileSync(path.join(source, "go.mod"), "module example.com/x\n\ngo 1.26\n\ntoolchain go1.26.5\n");

  const identity = { commit: "a".repeat(40), tree: "b".repeat(40), branch: "main" };
  fs.writeFileSync(path.join(root, "provenance.json"), JSON.stringify({ ...identity, dirty: false }));
  fs.writeFileSync(path.join(root, "source-commit.txt"), `${identity.commit}\n`);
  // A real manifest record for the one file the source tree carries, so
  // the source-identity leg of the verifier actually exercises.
  fs.writeFileSync(
    path.join(root, "source-tree-sha256.txt"),
    `100644 file ${sha256(fs.readFileSync(path.join(source, "go.mod")))}  go.mod\n`,
  );

  const canonicalPayload = Buffer.from(JSON.stringify([{ id: "system.echo", execution_class: "PURE" }]));
  const registrySha = sha256(canonicalPayload);
  fs.writeFileSync(path.join(root, "registry.sha256"), `${registrySha}\n`);
  fs.writeFileSync(
    path.join(root, "registry.json"),
    JSON.stringify({ registry_sha256: registrySha, canonical_payload: canonicalPayload.toString("base64") }),
  );
  const extDescriptor = { id: "qualification.critical.commit", execution_class: "CRITICAL" };
  const qualPayload = Buffer.from(JSON.stringify([...JSON.parse(canonicalPayload.toString()), extDescriptor]));
  const qualRegSha = sha256(qualPayload);
  fs.writeFileSync(path.join(root, "qualification-registry.sha256"), `${qualRegSha}\n`);
  fs.writeFileSync(
    path.join(root, "qualification-registry.json"),
    JSON.stringify({ registry_sha256: qualRegSha, canonical_payload: qualPayload.toString("base64") }),
  );
  fs.writeFileSync(
    path.join(root, "qualification-registry-extensions.json"),
    JSON.stringify({
      base_registry_sha256: registrySha,
      qualification_registry_sha256: qualRegSha,
      qualification_extensions: [
        { capability_id: "qualification.critical.commit", descriptor_sha256: sha256(Buffer.from(JSON.stringify(extDescriptor))) },
      ],
    }),
  );

  const tarBytes = Buffer.from("fixture tar bytes\n");
  const zipBytes = Buffer.from("fixture zip bytes\n");
  const sbomBytes = Buffer.from(JSON.stringify({ bomFormat: "CycloneDX", components: [] }));
  fs.writeFileSync(path.join(root, "crabedence-1.0.0-rc.7.tar.gz"), tarBytes);
  fs.writeFileSync(path.join(root, "crabedence-1.0.0-rc.7.zip"), zipBytes);
  fs.writeFileSync(path.join(root, "crabedence-1.0.0-rc.7.bom.json"), sbomBytes);

  fs.mkdirSync(path.join(root, "gate-results"), { recursive: true });
  fs.writeFileSync(path.join(root, "gate-results", "exact-toolchain.log"), "toolchain=go1.26.5 verified\n");
  const gateLogSha = sha256(fs.readFileSync(path.join(root, "gate-results", "exact-toolchain.log")));
  const qualification = {
    schema_version: 2,
    release_status: "PASS",
    artifact_promotable: true,
    gate_summary: { total: 1, passed: 1, failed: 0, skipped: 0 },
    gates: [
      {
        gate_id: "exact-toolchain",
        gate_type: "BUILD",
        mandatory: true,
        status: "PASS",
        exit_code: 0,
        tests_executed: 0,
        tests_failed: 0,
        duration_ms: 5,
        evidence: { file: "gate-results/exact-toolchain.log", sha256: gateLogSha },
      },
    ],
    invariants: [
      ...Array.from({ length: 11 }, (_, i) => ({
        id: `CRAB-V1-${String(i + 1).padStart(3, "0")}`,
        description: `qualification invariant ${i + 1}`,
      })),
      { id: "CRAB-V1-022", description: "declared toolchain = installed toolchain = runtime GOVERSION" },
    ],
    provenance: { ...identity, timestamp: "2026-09-19T00:00:00Z" },
    toolchains: { go: "go1.26.5", node: "v24.16.0", npm: "11.0.0", git: "2.50.0" },
    environment: { os: "linux", os_version: "ubuntu-24.04", arch: "x86_64", date: "2026-09-19" },
  };
  const artifact = {
    schema_version: 2,
    release: "1.0.0-rc.7",
    source: {
      commit: identity.commit,
      tree: identity.tree,
      manifest_sha256: sha256(fs.readFileSync(path.join(root, "source-tree-sha256.txt"))),
    },
    artifact: {
      filename: "crabedence-1.0.0-rc.7.tar.gz",
      sha256: sha256(tarBytes),
      size: tarBytes.length,
      zip_filename: "crabedence-1.0.0-rc.7.zip",
      zip_sha256: sha256(zipBytes),
      zip_size: zipBytes.length,
    },
    policy: { registry_sha256: registrySha },
    qualification: { sha256: "0".repeat(64), schema_version: 2 },
    sbom: { sha256: sha256(sbomBytes) },
    provenance: { sha256: sha256(fs.readFileSync(path.join(root, "provenance.json"))) },
    toolchain: { go: "go1.26.5" },
  };
  // The verifier also insists on the release manifest and an in-evidence
  // SPDX SBOM, both covered by the checksum manifest.
  fs.writeFileSync(
    path.join(root, "release-manifest.json"),
    JSON.stringify({ status: "PASS", release_name: "crabedence-v1.0.0-rc.7", provenance: identity }),
  );
  fs.writeFileSync(
    path.join(root, "sbom.spdx.json"),
    JSON.stringify({
      spdxVersion: "SPDX-2.3",
      packages: [{ name: "fixture", SPDXID: "SPDXRef-Package-fixture" }],
    }),
  );

  mutate(qualification, artifact, root, source);

  fs.writeFileSync(path.join(root, "qualification.json"), JSON.stringify(qualification));
  artifact.qualification.sha256 = sha256(fs.readFileSync(path.join(root, "qualification.json")));
  const artifactBytes = Buffer.from(JSON.stringify(artifact));
  fs.writeFileSync(path.join(root, "artifact.json"), artifactBytes);

  const covered = [
    "provenance.json",
    "source-commit.txt",
    "source-tree-sha256.txt",
    "registry.sha256",
    "registry.json",
    "qualification-registry.sha256",
    "qualification-registry.json",
    "qualification-registry-extensions.json",
    "qualification.json",
    "artifact.json",
    "release-manifest.json",
    "sbom.spdx.json",
    "gate-results/exact-toolchain.log",
  ];
  fs.writeFileSync(
    path.join(root, "SHA256SUMS"),
    covered.map((rel) => `${sha256(fs.readFileSync(path.join(root, rel)))}  ./${rel}`).join("\n") + "\n",
  );
  fs.writeFileSync(
    path.join(root, "evidence-manifest.json"),
    JSON.stringify({
      name: "crabedence-v1.0.0-rc.7",
      manifest_type: "evidence-bundle",
      sha256: sha256(fs.readFileSync(path.join(root, "SHA256SUMS"))),
      digest_of: "SHA256SUMS",
      file_count: covered.length,
      ...identity,
      generated_at: "2026-09-19T00:00:00Z",
    }),
  );
  return { root, source };
}

function verifyRelease(root, source) {
  const result = spawnSync(
    "bash",
    [
      VERIFIER,
      "--mode", "release",
      "--evidence", root,
      "--source", source,
      "--archive", path.join(root, "crabedence-1.0.0-rc.7.tar.gz"),
      "--zip", path.join(root, "crabedence-1.0.0-rc.7.zip"),
      "--sbom", path.join(root, "crabedence-1.0.0-rc.7.bom.json"),
    ],
    { encoding: "utf8" },
  );
  return { status: result.status, output: `${result.stdout}\n${result.stderr}` };
}

test("a consistent toolchain binding verifies", (t) => {
  const { root, source } = verifierFixture(t);
  const { status, output } = verifyRelease(root, source);
  assert.equal(status, 0, output);
  assert.match(output, /artifact\.json toolchain declaration\s+PASS/);
  assert.match(output, /Declared toolchain = qualified toolchain\s+PASS/);
  assert.match(output, /Declared toolchain = go\.mod toolchain\s+PASS/);
});

test("a toolchain declared for a different patch than qualification ran fails closed", (t) => {
  const { root, source } = verifierFixture(t, (q) => {
    q.toolchains.go = "go1.26.8";
  });
  const { status, output } = verifyRelease(root, source);
  assert.equal(status, 1);
  assert.match(output, /Declared toolchain = qualified toolchain\s+FAIL/);
});

test("a toolchain the source tree never declared fails closed", (t) => {
  const { root, source } = verifierFixture(t, (q, a, _r, src) => {
    a.toolchain.go = "go1.26.8";
    q.toolchains.go = "go1.26.8";
    fs.writeFileSync(path.join(src, "go.mod"), "module example.com/x\n\ngo 1.26\n\ntoolchain go1.26.5\n");
  });
  const { status, output } = verifyRelease(root, source);
  assert.equal(status, 1);
  assert.match(output, /Declared toolchain = go\.mod toolchain\s+FAIL/);
});

test("a missing toolchain declaration fails closed", (t) => {
  const { root, source } = verifierFixture(t, (_q, a) => {
    delete a.toolchain;
  });
  const { status, output } = verifyRelease(root, source);
  assert.equal(status, 1);
  assert.match(output, /artifact\.json toolchain declaration\s+FAIL/);
});

test("an artifact bound to a different qualification record fails closed", (t) => {
  const { root, source } = verifierFixture(t);
  // The fixture derives the binding from the real record; force the
  // divergence by rewriting the file after the checksum manifest is honest.
  const artifactPath = path.join(root, "artifact.json");
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  artifact.qualification.sha256 = "f".repeat(64);
  fs.writeFileSync(artifactPath, JSON.stringify(artifact));
  const sums = fs
    .readFileSync(path.join(root, "SHA256SUMS"), "utf8")
    .replace(/^[0-9a-f]{64} {2}\.\/artifact\.json$/m, `${sha256(fs.readFileSync(artifactPath))}  ./artifact.json`);
  fs.writeFileSync(path.join(root, "SHA256SUMS"), sums);

  const { output } = verifyRelease(root, source);
  assert.match(output, /artifact\.json binds the qualification record\s+FAIL/);
});

test("an artifact bound to a different source manifest fails closed", (t) => {
  const { root, source } = verifierFixture(t);
  const artifactPath = path.join(root, "artifact.json");
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  artifact.source.manifest_sha256 = "0".repeat(64);
  fs.writeFileSync(artifactPath, JSON.stringify(artifact));
  const sums = fs
    .readFileSync(path.join(root, "SHA256SUMS"), "utf8")
    .replace(/^[0-9a-f]{64} {2}\.\/artifact\.json$/m, `${sha256(fs.readFileSync(artifactPath))}  ./artifact.json`);
  fs.writeFileSync(path.join(root, "SHA256SUMS"), sums);

  const { status, output } = verifyRelease(root, source);
  assert.equal(status, 1);
  assert.match(output, /artifact\.json binds the source manifest\s+FAIL/);
});

// ─── Tar/ZIP semantic equivalence ───────────────────────────────────────
function sourceTree(t, mutate = () => {}) {
  const dir = tmpdir(t, "cbx-adv-tree-");
  fs.writeFileSync(path.join(dir, "tracked.txt"), "hello\n");
  fs.writeFileSync(path.join(dir, "run.sh"), "#!/bin/sh\necho hi\n");
  fs.chmodSync(path.join(dir, "run.sh"), 0o755);
  fs.symlinkSync("tracked.txt", path.join(dir, "link.txt"));
  mutate(dir);
  return dir;
}

function compareTrees(a, b) {
  const result = spawnSync("bash", [COMPARE, a, b], { encoding: "utf8" });
  return { status: result.status, output: `${result.stdout}\n${result.stderr}` };
}

test("identical source trees compare equal", (t) => {
  const a = sourceTree(t);
  const b = sourceTree(t);
  const { status, output } = compareTrees(a, b);
  assert.equal(status, 0, output);
  assert.match(output, /identical inventories/);
});

test("a content change fails the tree comparison", (t) => {
  const a = sourceTree(t);
  const b = sourceTree(t, (dir) => fs.writeFileSync(path.join(dir, "tracked.txt"), "tampered\n"));
  assert.equal(compareTrees(a, b).status, 1);
});

test("an executable-bit change fails the tree comparison", (t) => {
  const a = sourceTree(t);
  const b = sourceTree(t, (dir) => fs.chmodSync(path.join(dir, "run.sh"), 0o644));
  assert.equal(compareTrees(a, b).status, 1);
});

test("a repointed symlink fails the tree comparison", (t) => {
  const a = sourceTree(t);
  const b = sourceTree(t, (dir) => {
    fs.rmSync(path.join(dir, "link.txt"));
    fs.symlinkSync("run.sh", path.join(dir, "link.txt"));
  });
  assert.equal(compareTrees(a, b).status, 1);
});

test("a file/symlink type swap fails the tree comparison", (t) => {
  const a = sourceTree(t);
  const b = sourceTree(t, (dir) => {
    fs.rmSync(path.join(dir, "link.txt"));
    fs.writeFileSync(path.join(dir, "link.txt"), "tracked.txt");
  });
  assert.equal(compareTrees(a, b).status, 1);
});

test("an extra file fails the tree comparison", (t) => {
  const a = sourceTree(t);
  const b = sourceTree(t, (dir) => fs.writeFileSync(path.join(dir, "extra.txt"), "extra\n"));
  assert.equal(compareTrees(a, b).status, 1);
});

test("a missing file fails the tree comparison", (t) => {
  const a = sourceTree(t);
  const b = sourceTree(t, (dir) => fs.rmSync(path.join(dir, "tracked.txt")));
  assert.equal(compareTrees(a, b).status, 1);
});

test("a missing tree root fails the comparison", (t) => {
  const a = sourceTree(t);
  const missing = path.join(a, "..", "does-not-exist");
  const { status, output } = compareTrees(a, missing);
  assert.equal(status, 1);
  assert.match(output, /does not exist/);
});

test("the tree comparator parses", () => {
  execFileSync("bash", ["-n", COMPARE]);
});
