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
  assert.match(publish, /needs: \[provenance, build, clean-room-verify\]/);

  // Publication actions (tag push, release creation) exist only in the
  // publish job, so a failed clean-room verification cannot publish.
  assert.doesNotMatch(job("build"), /git push origin|softprops\/action-gh-release/);
  assert.doesNotMatch(cleanRoom, /git push origin|softprops\/action-gh-release/);
  assert.match(publish, /git push origin "\$RELEASE_VERSION"/);
  assert.match(publish, /softprops\/action-gh-release@/);
});

test("release evidence finalization precedes the final-manifest attestation", () => {
  const build = job("build");
  const order = [
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
});

test("publication re-verifies the staged archive against the build digest", () => {
  const publish = job("publish");
  assert.match(publish, /expected="\$\{\{ needs\.build\.outputs\.tar_sha256 \}\}"/);
  assert.match(publish, /sha256sum "dist\/crabedence-\$\{RELEASE_VERSION\}\.tar\.gz"/);
  const verifyIndex = publish.indexOf("Verify staged archive before publication");
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

test("the final evidence manifest is a published release asset", () => {
  const publish = job("publish");
  assert.match(publish, /dist\/release-evidence\/evidence-manifest\.json/);
  assert.match(publish, /dist\/release-evidence\/artifact\.json/);
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

test("the published evidence set is sufficient for consumer verification", () => {
  const publish = job("publish");
  for (const file of [
    "artifact.json",
    "evidence-manifest.json",
    "registry.sha256",
    "registry.json",
    "attestation/attestation.json",
    "SHA256SUMS",
  ]) {
    assert.ok(
      publish.includes(`dist/release-evidence/${file}`),
      `publish must include dist/release-evidence/${file}`,
    );
  }
});
