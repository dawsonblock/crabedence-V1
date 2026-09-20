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
// qualification bundle (qualification.json is absent, so the schema gate
// is skipped) — the tests assert the closure checks (artifact coverage,
// registry binding, release-object binding, manifest count, attestation
// binding) and the mode contracts.
function bundle(
  t,
  {
    artifactCovered = true,
    artifact = true,
    registryBound = true,
    registryEnvelope = null,
    fileCount = null,
    attestation = {},
    artifactSchema = 2,
    sbomBound = true,
    qualificationReplacedRelease = false,
    extraQualificationDescriptor = false,
    extensionRecords = null,
    extensionBaseSha = null,
    extensionQualSha = null,
  } = {},
) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-verify-artifact-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const identity = { commit: "a".repeat(40), tree: "b".repeat(40), branch: "main" };
  fs.writeFileSync(path.join(root, "provenance.json"), JSON.stringify({ ...identity, dirty: false }));
  fs.writeFileSync(path.join(root, "source-tree-sha256.txt"), "fixture manifest\n");

  // Registry policy identity: envelope (digest + canonical payload) and
  // the bare digest file the artifact binding is compared against.
  const canonicalPayload = Buffer.from(JSON.stringify([{ id: "system.echo", execution_class: "PURE" }]));
  const registrySha = sha256(canonicalPayload);
  fs.writeFileSync(path.join(root, "registry.sha256"), registrySha + "\n");
  fs.writeFileSync(
    path.join(root, "registry.json"),
    JSON.stringify(
      registryEnvelope ?? {
        registry_sha256: registrySha,
        canonical_payload: canonicalPayload.toString("base64"),
      },
    ),
  );

  // Qualification registry: the release registry plus one explicit
  // extension descriptor, bound by the extension record.
  const releaseDescriptors = JSON.parse(canonicalPayload.toString());
  const extensionDescriptor = { id: "qualification.critical.commit", execution_class: "CRITICAL" };
  // The descriptor digest is SHA-256 of the descriptor's exact canonical
  // bytes. Because the payload is a JSON array, those bytes are exactly
  // the element's serialization — the same span the verifier hashes.
  const extensionDigest = sha256(Buffer.from(JSON.stringify(extensionDescriptor)));
  let qualificationDescriptors = qualificationReplacedRelease
    ? [{ ...releaseDescriptors[0], execution_class: "MUTATION" }, extensionDescriptor]
    : [...releaseDescriptors, extensionDescriptor];
  if (extraQualificationDescriptor) {
    qualificationDescriptors = [...qualificationDescriptors, { id: "qualification.undeclared", execution_class: "MUTATION" }];
  }
  const qualificationPayload = Buffer.from(JSON.stringify(qualificationDescriptors));
  const qualificationSha = sha256(qualificationPayload);
  fs.writeFileSync(path.join(root, "qualification-registry.sha256"), qualificationSha + "\n");
  fs.writeFileSync(
    path.join(root, "qualification-registry.json"),
    JSON.stringify({ registry_sha256: qualificationSha, canonical_payload: qualificationPayload.toString("base64") }),
  );
  fs.writeFileSync(
    path.join(root, "qualification-registry-extensions.json"),
    JSON.stringify({
      base_registry_sha256: extensionBaseSha ?? registrySha,
      qualification_registry_sha256: extensionQualSha ?? qualificationSha,
      qualification_extensions: extensionRecords ?? [
        { capability_id: "qualification.critical.commit", descriptor_sha256: extensionDigest },
      ],
    }),
  );

  const sbomPath = path.join(root, "crabedence-1.0.0-rc.7.bom.json");
  const sbomBytes = Buffer.from(JSON.stringify({ bomFormat: "CycloneDX", components: [] }));
  fs.writeFileSync(sbomPath, sbomBytes);

  // The zip is an official artifact with its own identity, so the fixture
  // carries a real one whose digest matches artifact.json.
  const zipBytes = Buffer.from("fixture zip bytes\n");
  const zipPath = path.join(root, "crabedence-1.0.0-rc.7.zip");
  fs.writeFileSync(zipPath, zipBytes);

  const artifactBytes = Buffer.from(
    JSON.stringify({
      schema_version: artifactSchema,
      release: "1.0.0-rc.7",
      source: {
        commit: identity.commit,
        tree: identity.tree,
        manifest_sha256: sha256(fs.readFileSync(path.join(root, "source-tree-sha256.txt"))),
      },
      artifact: {
        filename: "crabedence-1.0.0-rc.7.tar.gz",
        sha256: "c".repeat(64),
        size: 21,
        zip_filename: "crabedence-1.0.0-rc.7.zip",
        zip_sha256: sha256(zipBytes),
      },
      policy: { registry_sha256: registryBound ? registrySha : "f".repeat(64) },
      qualification: { sha256: "e".repeat(64), schema_version: 2 },
      sbom: { sha256: sbomBound ? sha256(sbomBytes) : "9".repeat(64) },
      provenance: { sha256: sha256(fs.readFileSync(path.join(root, "provenance.json"))) },
      toolchain: { go: "go1.26.5", node: "v24.16.0", npm: "11.0.0" },
    }),
  );
  if (artifact) {
    fs.writeFileSync(path.join(root, "artifact.json"), artifactBytes);
  }
  fs.writeFileSync(path.join(root, "qualification-summary.txt"), "gates: none\n");

  const entries = [
    `${sha256(fs.readFileSync(path.join(root, "provenance.json")))}  ./provenance.json`,
    `${sha256(fs.readFileSync(path.join(root, "qualification-summary.txt")))}  ./qualification-summary.txt`,
    `${sha256(fs.readFileSync(path.join(root, "registry.sha256")))}  ./registry.sha256`,
    `${sha256(fs.readFileSync(path.join(root, "registry.json")))}  ./registry.json`,
  ];
  if (artifact) {
    entries.push(`${sha256(artifactBytes)}  ./artifact.json`);
  }
  if (!artifactCovered) {
    entries.pop();
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
  return { root, manifest, registrySha, artifactBytes, sbomPath, zipPath, zipBytes };
}

function verify(root, args = []) {
  const result = spawnSync("bash", [VERIFIER, ...args], { encoding: "utf8" });
  return { status: result.status, output: `${result.stdout}\n${result.stderr}` };
}

const qualificationArgs = (root) => ["--mode", "qualification", "--evidence", root, "--source", root];

test("a covered artifact.json passes the closure checks", (t) => {
  const { root } = bundle(t);
  const { output } = verify(root, qualificationArgs(root));
  assert.match(output, /artifact\.json covered by checksums\s+PASS/);
  assert.match(output, /Evidence manifest file count\s+PASS/);
  assert.match(output, /Attestation binds the final evidence manifest\s+PASS/);
  assert.match(output, /Registry digest recomputed \(envelope\)\s+PASS/);
  assert.match(output, /artifact\.json binds the qualified registry\s+PASS/);
  assert.match(output, /artifact\.json binds the source manifest\s+PASS/);
  assert.match(output, /artifact\.json binds provenance\s+PASS/);
});

test("an artifact.json outside the checksum manifest fails closed", (t) => {
  const { root } = bundle(t, { artifactCovered: false });
  const { output } = verify(root, qualificationArgs(root));
  assert.match(output, /artifact\.json covered by checksums\s+FAIL/);
  assert.match(output, /does not bind the release artifact/);
});

test("a stale manifest file count fails closed", (t) => {
  const { root } = bundle(t, { fileCount: 99 });
  const { output } = verify(root, qualificationArgs(root));
  assert.match(output, /Evidence manifest file count\s+FAIL/);
});

test("an attestation of a superseded manifest fails closed", (t) => {
  const { root } = bundle(t, { attestation: { evidence_sha256: "e".repeat(64) } });
  const { output } = verify(root, qualificationArgs(root));
  assert.match(output, /Attestation binds the final evidence manifest\s+FAIL/);
});

test("an attestation of a different subject fails closed", (t) => {
  const { root } = bundle(t, { attestation: { subject: "dist/release-evidence/qualification.json" } });
  const { output } = verify(root, qualificationArgs(root));
  assert.match(output, /Attestation binds the final evidence manifest\s+FAIL/);
});

test("a tampered registry envelope fails closed", (t) => {
  const { root } = bundle(t, {
    registryEnvelope: {
      registry_sha256: "0".repeat(64),
      canonical_payload: Buffer.from("[]").toString("base64"),
    },
  });
  const { output } = verify(root, qualificationArgs(root));
  assert.match(output, /Registry digest recomputed \(envelope\)\s+FAIL/);
});

test("an artifact.json bound to a different policy fails closed", (t) => {
  const { root } = bundle(t, { registryBound: false });
  const { output } = verify(root, qualificationArgs(root));
  assert.match(output, /artifact\.json binds the qualified registry\s+FAIL/);
});

test("an unknown artifact schema version fails closed", (t) => {
  const { root } = bundle(t, { artifactSchema: 3 });
  const { status, output } = verify(root, qualificationArgs(root));
  assert.equal(status, 1);
  assert.match(output, /artifact\.json schema version\s+FAIL/);
  assert.match(output, /refusing to interpret an unknown release object/);
});

test("release mode requires an archive (contract violation)", (t) => {
  const { root, sbomPath } = bundle(t);
  const { status, output } = verify(root, [
    "--mode", "release", "--evidence", root, "--source", root, "--sbom", sbomPath,
  ]);
  assert.equal(status, 1);
  assert.match(output, /MODE CONTRACT VIOLATED/);
  assert.match(output, /requires the release tar\.gz/);
});

test("release mode requires artifact.json (contract violation)", (t) => {
  const { root, sbomPath } = bundle(t, { artifact: false });
  const archive = path.join(root, "crabedence-1.0.0-rc.7.tar.gz");
  fs.writeFileSync(archive, "fixture archive bytes\n");
  const { status, output } = verify(root, [
    "--mode", "release", "--evidence", root, "--source", root, "--archive", archive, "--sbom", sbomPath,
  ]);
  assert.equal(status, 1);
  assert.match(output, /MODE CONTRACT VIOLATED/);
  assert.match(output, /requires artifact\.json/);
});

test("release mode requires the SBOM (contract violation)", (t) => {
  const { root } = bundle(t);
  const archive = path.join(root, "crabedence-1.0.0-rc.7.tar.gz");
  fs.writeFileSync(archive, "fixture archive bytes\n");
  const { status, output } = verify(root, [
    "--mode", "release", "--evidence", root, "--source", root, "--archive", archive,
  ]);
  assert.equal(status, 1);
  assert.match(output, /MODE CONTRACT VIOLATED/);
  assert.match(output, /requires the SBOM/);
});

test("qualification mode accepts a bundle without archive or artifact", (t) => {
  const { root } = bundle(t, { artifact: false, artifactCovered: false });
  const { output } = verify(root, qualificationArgs(root));
  assert.match(output, /mode:     qualification/);
  assert.doesNotMatch(output, /MODE CONTRACT VIOLATED/);
  assert.match(output, /Registry digest recomputed \(envelope\)\s+PASS/);
});

test("release mode recomputes the archive against artifact.json", (t) => {
  const { root, sbomPath, zipPath } = bundle(t);
  const archive = path.join(root, "crabedence-1.0.0-rc.7.tar.gz");
  fs.writeFileSync(archive, "fixture archive bytes\n");
  // artifact.json claims a digest and size that do not match the archive.
  const { output } = verify(root, [
    "--mode", "release", "--evidence", root, "--source", root, "--archive", archive,
    "--zip", zipPath, "--sbom", sbomPath,
  ]);
  assert.match(output, /Archive matches artifact\.json \(recomputed\)\s+FAIL/);
  assert.match(output, /Archive size matches artifact\.json\s+FAIL/);
});

test("release mode accepts an archive whose bytes match the binding", (t) => {
  const { root, sbomPath, zipPath } = bundle(t);
  const archive = path.join(root, "crabedence-1.0.0-rc.7.tar.gz");
  fs.writeFileSync(archive, "fixture archive bytes\n");
  // Rewrite artifact.json to bind the actual archive bytes and size.
  const artifactPath = path.join(root, "artifact.json");
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  artifact.artifact.sha256 = sha256(fs.readFileSync(archive));
  artifact.artifact.size = fs.statSync(archive).size;
  fs.writeFileSync(artifactPath, JSON.stringify(artifact));
  // Regenerate the checksum manifest so the coverage check stays honest.
  const sums = fs
    .readFileSync(path.join(root, "SHA256SUMS"), "utf8")
    .trimEnd()
    .split("\n")
    .map((line) =>
      line.replace(/^[0-9a-f]{64} {2}\.\/artifact\.json$/, `${sha256(fs.readFileSync(artifactPath))}  ./artifact.json`),
    )
    .join("\n");
  fs.writeFileSync(path.join(root, "SHA256SUMS"), sums + "\n");

  const { output } = verify(root, [
    "--mode", "release", "--evidence", root, "--source", root, "--archive", archive,
    "--zip", zipPath, "--sbom", sbomPath,
  ]);
  assert.match(output, /Archive matches artifact\.json \(recomputed\)\s+PASS/);
  assert.match(output, /Archive size matches artifact\.json\s+PASS/);
  assert.match(output, /Zip matches artifact\.json \(recomputed\)\s+PASS/);
  assert.match(output, /Zip filename matches artifact\.json\s+PASS/);
  assert.match(output, /artifact\.json binds the SBOM\s+PASS/);
});

test("an SBOM that does not match the binding fails closed", (t) => {
  const { root, sbomPath, zipPath } = bundle(t, { sbomBound: false });
  const archive = path.join(root, "crabedence-1.0.0-rc.7.tar.gz");
  fs.writeFileSync(archive, "fixture archive bytes\n");
  const { output } = verify(root, [
    "--mode", "release", "--evidence", root, "--source", root, "--archive", archive,
    "--zip", zipPath, "--sbom", sbomPath,
  ]);
  assert.match(output, /artifact\.json binds the SBOM\s+FAIL/);
});

test("an unknown mode is a usage error", (t) => {
  const { root } = bundle(t);
  const { status, output } = verify(root, ["--mode", "whatever", "--evidence", root, "--source", root]);
  assert.equal(status, 2);
  assert.match(output, /--mode must be qualification or release/);
});

test("legacy positional form still works and announces the inferred mode", (t) => {
  const { root } = bundle(t);
  const { output } = verify(root, [root, root]);
  assert.match(output, /mode was inferred from the supplied arguments/);
  assert.match(output, /Registry digest recomputed \(envelope\)\s+PASS/);
});

test("the qualification registry extension is bound to the release registry", (t) => {
  const { root } = bundle(t);
  const { output } = verify(root, qualificationArgs(root));
  assert.match(output, /Qualification registry digest recomputed\s+PASS/);
  assert.match(output, /Extension record binds the release registry\s+PASS/);
  assert.match(output, /Extension record binds the qualification registry\s+PASS/);
  assert.match(output, /Extension records unique\s+PASS/);
  assert.match(output, /Extension descriptor digests recomputed\s+PASS/);
  assert.match(output, /Extensions are qualification-only\s+PASS/);
  assert.match(output, /Extensions add without replacing release policy\s+PASS/);
});

test("a qualification registry that replaces release policy fails closed", (t) => {
  const { root } = bundle(t, { qualificationReplacedRelease: true });
  const { output } = verify(root, qualificationArgs(root));
  assert.match(output, /Extensions add without replacing release policy\s+FAIL/);
  assert.match(output, /not the release registry plus the declared extensions/);
});

test("a mislabelled extension descriptor digest fails closed", (t) => {
  const { root } = bundle(t, {
    extensionRecords: [{ capability_id: "qualification.critical.commit", descriptor_sha256: "b".repeat(64) }],
  });
  const { output } = verify(root, qualificationArgs(root));
  assert.match(output, /Extension descriptor digests recomputed\s+FAIL/);
  assert.match(output, /its canonical bytes hash to/);
});

test("an extension digest borrowed from another capability fails closed", (t) => {
  const echoDigest = sha256(Buffer.from(JSON.stringify({ id: "system.echo", execution_class: "PURE" })));
  const { root } = bundle(t, {
    extensionRecords: [{ capability_id: "qualification.critical.commit", descriptor_sha256: echoDigest }],
  });
  const { output } = verify(root, qualificationArgs(root));
  assert.match(output, /Extension descriptor digests recomputed\s+FAIL/);
});

test("an extension that claims a production capability fails closed", (t) => {
  const echoDigest = sha256(Buffer.from(JSON.stringify({ id: "system.echo", execution_class: "PURE" })));
  const { root } = bundle(t, {
    extensionRecords: [{ capability_id: "system.echo", descriptor_sha256: echoDigest }],
  });
  const { output } = verify(root, qualificationArgs(root));
  assert.match(output, /Extensions are qualification-only\s+FAIL/);
  assert.match(output, /may not redeclare production policy/);
});

test("a duplicate extension record fails closed", (t) => {
  const extensionDigest = sha256(
    Buffer.from(JSON.stringify({ id: "qualification.critical.commit", execution_class: "CRITICAL" })),
  );
  const { root } = bundle(t, {
    extensionRecords: [
      { capability_id: "qualification.critical.commit", descriptor_sha256: extensionDigest },
      { capability_id: "qualification.critical.commit", descriptor_sha256: extensionDigest },
    ],
  });
  const { output } = verify(root, qualificationArgs(root));
  assert.match(output, /Extension records unique\s+FAIL/);
});

test("a declared extension missing from the registry fails closed", (t) => {
  const { root } = bundle(t, {
    extensionRecords: [{ capability_id: "qualification.absent", descriptor_sha256: "c".repeat(64) }],
  });
  const { output } = verify(root, qualificationArgs(root));
  assert.match(output, /Extension descriptor digests recomputed\s+FAIL/);
  assert.match(output, /want exactly 1/);
});

test("an undeclared extra descriptor fails closed", (t) => {
  const { root } = bundle(t, { extraQualificationDescriptor: true });
  const { output } = verify(root, qualificationArgs(root));
  assert.match(output, /Extensions add without replacing release policy\s+FAIL/);
});

test("an extension record bound to the wrong base registry fails closed", (t) => {
  const { root } = bundle(t, { extensionBaseSha: "0".repeat(64) });
  const { output } = verify(root, qualificationArgs(root));
  assert.match(output, /Extension record binds the release registry\s+FAIL/);
});

test("an extension record bound to the wrong qualification registry fails closed", (t) => {
  const { root } = bundle(t, { extensionQualSha: "0".repeat(64) });
  const { output } = verify(root, qualificationArgs(root));
  assert.match(output, /Extension record binds the qualification registry\s+FAIL/);
});

test("release mode requires the zip (contract violation)", (t) => {
  const { root, sbomPath } = bundle(t);
  const archive = path.join(root, "crabedence-1.0.0-rc.7.tar.gz");
  fs.writeFileSync(archive, "fixture archive bytes\n");
  const { status, output } = verify(root, [
    "--mode", "release", "--evidence", root, "--source", root, "--archive", archive, "--sbom", sbomPath,
  ]);
  assert.equal(status, 1);
  assert.match(output, /requires the release zip/);
});

test("a zip whose bytes do not match the binding fails closed", (t) => {
  const { root, sbomPath, zipPath } = bundle(t);
  const archive = path.join(root, "crabedence-1.0.0-rc.7.tar.gz");
  fs.writeFileSync(archive, "fixture archive bytes\n");
  // One byte of the zip changes; the recorded digest no longer covers it.
  const bytes = fs.readFileSync(zipPath);
  bytes[0] ^= 0x01;
  fs.writeFileSync(zipPath, bytes);
  const { output } = verify(root, [
    "--mode", "release", "--evidence", root, "--source", root, "--archive", archive,
    "--zip", zipPath, "--sbom", sbomPath,
  ]);
  assert.match(output, /Zip matches artifact\.json \(recomputed\)\s+FAIL/);
});

test("a zip under the wrong filename fails closed", (t) => {
  const { root, sbomPath, zipBytes } = bundle(t);
  const archive = path.join(root, "crabedence-1.0.0-rc.7.tar.gz");
  fs.writeFileSync(archive, "fixture archive bytes\n");
  const renamed = path.join(root, "renamed.zip");
  fs.writeFileSync(renamed, zipBytes);
  const { output } = verify(root, [
    "--mode", "release", "--evidence", root, "--source", root, "--archive", archive,
    "--zip", renamed, "--sbom", sbomPath,
  ]);
  assert.match(output, /Zip filename matches artifact\.json\s+FAIL/);
});

test("a missing zip file fails closed", (t) => {
  const { root, sbomPath } = bundle(t);
  const archive = path.join(root, "crabedence-1.0.0-rc.7.tar.gz");
  fs.writeFileSync(archive, "fixture archive bytes\n");
  const { status, output } = verify(root, [
    "--mode", "release", "--evidence", root, "--source", root, "--archive", archive,
    "--zip", path.join(root, "absent.zip"), "--sbom", sbomPath,
  ]);
  assert.equal(status, 1);
  assert.match(output, /MODE CONTRACT VIOLATED/);
  assert.match(output, /requires the release zip/);
});
