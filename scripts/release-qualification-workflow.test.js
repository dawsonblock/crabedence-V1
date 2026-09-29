import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const repoRoot = path.resolve(import.meta.dirname, "..");
const workflow = fs.readFileSync(
  path.join(repoRoot, ".github/workflows/release-qualification.yml"),
  "utf8",
);

// Extracts a job body. Job entries are the only two-space-indented keys.
function job(name) {
  const start = workflow.indexOf(`\n  ${name}:\n`);
  assert.ok(start >= 0, `job ${name} exists`);
  const rest = workflow.slice(start + 1);
  const next = rest.search(/\n  [a-z][a-z0-9-]*:\n/);
  return next < 0 ? rest : rest.slice(0, next);
}

test("every Go setup pins the exact release toolchain and asserts it", () => {
  // go-version-file: go.mod resolves a 1.26.x, not the pinned patch:
  // qualification must not delegate patch selection to the module
  // directive, and GOTOOLCHAIN=local stops a later silent substitution.
  assert.doesNotMatch(workflow, /go-version-file: go\.mod/);
  assert.match(workflow, /GOTOOLCHAIN: local/);
  const setups = workflow.match(/uses: actions\/setup-go@/g) ?? [];
  const pins = workflow.match(/go-version: \$\{\{ env\.GO_EXACT_VERSION \}\}/g) ?? [];
  const assertions = workflow.match(/- name: Assert the exact Go toolchain/g) ?? [];
  assert.ok(setups.length > 0, "the workflow sets up Go");
  assert.equal(pins.length, setups.length, "every setup-go uses the exact pin");
  assert.equal(assertions.length, setups.length, "every setup-go is followed by a GOVERSION assertion");
  assert.match(workflow, /GO_EXACT_VERSION: '1\.26\.5'/);
});

test("permissions are read-only except the attesting evidence job", () => {
  assert.match(workflow, /\npermissions:\n  contents: read\n/);
  const evidence = job("evidence");
  assert.match(
    evidence,
    /\n    permissions:\n      contents: read\n      attestations: write\n      id-token: write\n/,
  );
  // No other job carries a write scope: qualification produces evidence
  // and an attestation, nothing else.
  for (const name of [
    "provenance",
    "go-tests",
    "go-race",
    "worker",
    "postgres",
    "nemo",
    "cross-language",
  ]) {
    assert.doesNotMatch(job(name), /contents: write|id-token: write|attestations: write/, `${name} is read-only`);
  }
});

test("every checkout drops the persistent credential", () => {
  // No job in this workflow pushes or publishes; no checkout needs the
  // credential left in .git/config.
  const checkouts = workflow.match(/uses: actions\/checkout@/g) ?? [];
  const drops = workflow.match(/persist-credentials: false/g) ?? [];
  assert.ok(checkouts.length > 0, "the workflow checks out the source");
  assert.equal(drops.length, checkouts.length, "every checkout drops credentials");
});

test("evidence is verified before it is attested", () => {
  const evidence = job("evidence");
  const order = [
    "Generate release evidence",
    "Check release admission",
    "Verify release artifact",
    "Extract qualification summary for attestation",
    "Create GitHub artifact attestation",
    "Save attestation reference",
    "Upload release evidence",
  ];
  let last = -1;
  for (const step of order) {
    const at = evidence.indexOf(`- name: ${step}`);
    assert.ok(at > last, `${step} is ordered after the previous step`);
    last = at;
  }
  assert.match(evidence, /subject-path: dist\/release-evidence\/evidence-manifest\.json/);
  assert.match(evidence, /"evidence_sha256": "\$\{\{ steps\.qual_summary\.outputs\.evidence_sha256 \}\}"/);
  assert.match(evidence, /needs: \[provenance, go-tests, go-race, worker, postgres, nemo, cross-language\]/);
});

test("the evidence job runs the full release-script gate inputs", () => {
  const evidence = job("evidence");
  assert.match(evidence, /generate-release-evidence\.sh/);
  assert.match(evidence, /check-release-admission\.sh/);
  assert.match(evidence, /verify-release-artifact\.sh --mode qualification/);
});
