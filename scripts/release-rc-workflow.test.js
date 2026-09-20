import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const repoRoot = path.resolve(import.meta.dirname, "..");
const workflow = fs.readFileSync(path.join(repoRoot, ".github/workflows/release-rc.yml"), "utf8");

// Extracts a job body. Job entries are the only two-space-indented keys.
function job(name) {
  const start = workflow.indexOf(`\n  ${name}:\n`);
  assert.ok(start >= 0, `job ${name} exists`);
  const rest = workflow.slice(start + 1);
  const next = rest.search(/\n  [a-z][a-z0-9-]*:\n/);
  return next < 0 ? rest : rest.slice(0, next);
}

test("clean-room verification gates publication", () => {
  const cleanRoom = job("clean-room-verify");
  assert.match(cleanRoom, /needs: build\n/);
  // The clean room verifies the staged bytes; it must not depend on a
  // published release existing.
  assert.doesNotMatch(cleanRoom, /gh release download/);
  assert.match(cleanRoom, /name: release-source-archive/);

  const publish = job("publish");
  assert.match(publish, /needs: \[provenance, build, clean-room-verify, attest\]/);

  // Publication actions (tag push, release creation) exist only in the
  // publish job, so a failed clean-room verification cannot publish.
  assert.doesNotMatch(job("build"), /git push origin|softprops\/action-gh-release/);
  assert.doesNotMatch(cleanRoom, /git push origin|softprops\/action-gh-release/);
  assert.match(publish, /git push origin "\$RELEASE_VERSION"/);
  assert.match(publish, /softprops\/action-gh-release@/);
});

test("artifact attestations are created only after clean-room verification", () => {
  const attest = job("attest");
  assert.match(attest, /needs: \[build, clean-room-verify\]/);
  assert.match(attest, /- name: Attest source archive/);
  assert.match(attest, /- name: Attest zip archive/);
  assert.match(attest, /- name: Attest SBOM/);
  // The build job must not attest the archives before they are verified.
  assert.doesNotMatch(job("build"), /- name: Attest source archive/);
  assert.doesNotMatch(job("build"), /- name: Attest zip archive/);
});

test("release evidence finalization precedes the final-manifest attestation", () => {
  const build = job("build");
  const order = [
    "Generate SBOM",
    "Generate artifact.json",
    "Finalize release evidence",
    "Create GitHub artifact attestation",
    "Save attestation reference",
    "Verify release artifact",
  ];
  let last = -1;
  for (const step of order) {
    const at = build.indexOf(`- name: ${step}`);
    assert.ok(at > last, `${step} is ordered after the previous step`);
    last = at;
  }
  assert.match(build, /subject-path: dist\/release-evidence\/evidence-manifest\.json/);
  assert.match(build, /"evidence_sha256": "\$\{\{ steps\.qual_summary\.outputs\.evidence_sha256 \}\}"/);
  assert.match(build, /finalize-release-evidence\.sh dist\/release-evidence/);
  // The SBOM is generated before artifact.json so the release object can
  // bind its digest.
  assert.match(build, /"schema_version": 2|schema_version: 2/);
});

test("release-mode verification binds the archive and the SBOM", () => {
  const build = job("build");
  assert.match(build, /--mode release/);
  assert.match(build, /--archive "dist\/crabedence-\$\{RELEASE_VERSION\}\.tar\.gz"/);
  assert.match(build, /--sbom "dist\/crabedence-\$\{RELEASE_VERSION\}\.bom\.json"/);
  const cleanRoom = job("clean-room-verify");
  assert.match(cleanRoom, /--sbom "archive\/crabedence-\$\{RELEASE_VERSION\}\.bom\.json"/);
  const reverify = job("public-reverify");
  assert.match(reverify, /--sbom "public\/crabedence-\$\{RELEASE_VERSION\}\.bom\.json"/);
  assert.match(reverify, /--pattern "crabedence-\$\{RELEASE_VERSION\}\.bom\.json"/);
});

test("publication re-verifies every staged artifact against the build digests", () => {
  const publish = job("publish");
  assert.match(publish, /needs\.build\.outputs\.tar_sha256/);
  assert.match(publish, /needs\.build\.outputs\.zip_sha256/);
  assert.match(publish, /needs\.build\.outputs\.evidence_archive_sha256/);
  assert.match(publish, /sha256sum "\$file"/);
  const verifyIndex = publish.indexOf("Verify staged artifacts before publication");
  const tagIndex = publish.indexOf("Tag release candidate");
  assert.ok(verifyIndex >= 0 && verifyIndex < tagIndex, "staged bytes are verified before tagging");
});

test("the build job stages the exact bytes the clean room and publish consume", () => {
  const build = job("build");
  assert.match(build, /name: release-source-archive/);
  assert.match(build, /name: release-evidence/);
  assert.match(build, /dist\/crabedence-\$\{\{ env\.RELEASE_VERSION \}\}\.tar\.gz\.sha256/);
  assert.equal((build.match(/retention-days: 30/g) ?? []).length, 2);
});

test("the complete evidence bundle is a published release asset", () => {
  const publish = job("publish");
  assert.match(publish, /dist\/crabedence-\$\{\{ env\.RELEASE_VERSION \}\}-release-evidence\.tar\.gz/);
  // The partial allow-list is gone. SHA256SUMS covers every evidence file,
  // so publishing a subset leaves the published set unable to verify
  // itself — a consumer would hold a manifest referencing files that were
  // never uploaded.
  assert.doesNotMatch(publish, /dist\/release-evidence\/SHA256SUMS/);
  assert.doesNotMatch(publish, /dist\/release-evidence\/artifact\.json/);
  assert.doesNotMatch(publish, /dist\/release-evidence\/registry\.json/);
});

test("published bytes are reverified after publication", () => {
  const reverify = job("public-reverify");
  assert.match(reverify, /needs: \[build, publish\]/);
  assert.match(reverify, /gh release download/);
  assert.match(reverify, /needs\.build\.outputs\.tar_sha256/);
  assert.match(reverify, /gh attestation verify/);
  assert.match(reverify, /--mode release/);
  // Distribution verification runs after publication; it never gates it.
  assert.doesNotMatch(job("publish"), /public-reverify/);
});

test("the published evidence bundle is packaged from the finalized tree", () => {
  const build = job("build");
  // Packaging runs after finalization, so the bundle is the finalized tree
  // and nothing mutates the evidence directory afterwards.
  const finalize = build.indexOf("Finalize release evidence");
  const packageStep = build.indexOf("Package release evidence bundle");
  assert.ok(finalize >= 0 && packageStep > finalize, "the bundle is packaged after finalization");
  assert.match(build, /package-release-evidence\.sh/);
  assert.match(build, /sha256=\$sha/);
  assert.match(build, /dist\/crabedence-\$\{\{ env\.RELEASE_VERSION \}\}-release-evidence\.tar\.gz/);
});

test("nothing mutates the finalized evidence after packaging", () => {
  const build = job("build");
  const packageAt = build.indexOf("Package release evidence bundle");
  assert.ok(packageAt >= 0, "the packaging step exists");
  // Everything after packaging may READ the evidence, but must not write
  // into it: the packaged bundle is the frozen public object, and a
  // reference written afterwards could never appear in it.
  const after = build.slice(packageAt);
  assert.doesNotMatch(after, /mkdir -p dist\/release-evidence/);
  assert.doesNotMatch(after, /cat > dist\/release-evidence/);
  assert.doesNotMatch(after, /> dist\/release-evidence\//);
  assert.doesNotMatch(after, /dist\/release-evidence\/attestation/);
  // The attestation reference lives outside the closure.
  assert.match(build, /> dist\/attestation\//);
});

test("the clean room verifies the published evidence bundle, not the raw directory", () => {
  const cleanRoom = job("clean-room-verify");
  assert.match(cleanRoom, /-release-evidence\.tar\.gz/);
  assert.match(cleanRoom, /-C clean-room\/qualification --strip-components=1/);
  assert.match(cleanRoom, /shasum -a 256 -c SHA256SUMS/);
  // The internal raw evidence artifact is not a verification input.
  assert.doesNotMatch(cleanRoom, /name: release-evidence/);
  assert.doesNotMatch(cleanRoom, /cp -r evidence/);
});

test("the release script suite gates the build", () => {
  const scriptsJob = job("release-scripts");
  assert.match(scriptsJob, /node --test scripts\/\*\.test\.js scripts\/\*\.test\.mjs/);
  assert.match(scriptsJob, /needs: provenance/);
  assert.match(
    job("build"),
    /needs: \[provenance, go-tests, go-race, worker, postgres, nemo, cross-language, release-scripts\]/,
  );
});

test("public reverify consumes public assets only", () => {
  const reverify = job("public-reverify");
  assert.match(reverify, /gh release download/);
  assert.match(reverify, /-release-evidence\.tar\.gz/);
  assert.match(reverify, /--pattern "crabedence-\$\{RELEASE_VERSION\}\.zip"/);
  // It must never substitute the internal Actions evidence artifact for
  // published evidence: if the release cannot be verified from the public
  // bytes alone, it is not self-verifying.
  assert.doesNotMatch(reverify, /actions\/download-artifact@/);
  assert.doesNotMatch(reverify, /name: release-evidence/);
  assert.doesNotMatch(reverify, /cp -r evidence clean-room\/qualification/);
  assert.match(reverify, /shasum -a 256 -c SHA256SUMS/);
});

test("both archives and the evidence bundle traverse the whole DAG", () => {
  for (const name of ["clean-room-verify", "attest", "publish", "public-reverify"]) {
    const body = job(name);
    assert.match(body, /\.tar\.gz/, `${name} handles the tar.gz`);
    assert.match(body, /\.zip/, `${name} handles the zip`);
    assert.match(body, /-release-evidence\.tar\.gz/, `${name} handles the evidence bundle`);
    assert.match(body, /outputs\.tar_sha256/, `${name} compares the tar digest`);
    assert.match(body, /outputs\.zip_sha256/, `${name} compares the zip digest`);
    assert.match(body, /outputs\.evidence_archive_sha256/, `${name} compares the evidence digest`);
  }
});

test("neither release workflow writes an attestation inside the evidence closure", () => {
  // An attestation is an external statement about the frozen evidence
  // object. A reference written into the closure would make the evidence
  // manifest cover an attestation of that same manifest, and — because the
  // public bundle is packaged before it exists — it could never appear in
  // the published bundle, so the bundle could not satisfy its own verifier.
  for (const file of [".github/workflows/release-rc.yml", ".github/workflows/release-qualification.yml"]) {
    const source = fs.readFileSync(path.join(repoRoot, file), "utf8");
    assert.doesNotMatch(source, /mkdir -p dist\/release-evidence\/attestation/, file);
    assert.doesNotMatch(source, /dist\/release-evidence\/attestation\//, file);
    assert.match(source, /mkdir -p dist\/attestation/, `${file} keeps the reference outside the closure`);
  }
});
