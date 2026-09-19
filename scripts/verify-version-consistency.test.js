import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { baseVersion, compareBaseVersions, verifyVersionConsistency } from "./verify-version-consistency.mjs";

const WORKER_NAME = "@openclaw/crabbox-worker";

function makeTree(overrides = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cbx-version-"));
  const files = {
    VERSION: "0.50.0\n",
    "worker/package.json": JSON.stringify({ name: WORKER_NAME, version: "0.50.0" }),
    "worker/package-lock.json": JSON.stringify({
      name: WORKER_NAME,
      version: "0.50.0",
      lockfileVersion: 3,
      packages: { "": { name: WORKER_NAME, version: "0.50.0" } },
    }),
    "nemo/package.json": JSON.stringify({ name: "@crabedence/nemo", version: "0.50.0" }),
    "nemo/package-lock.json": JSON.stringify({
      name: "@crabedence/nemo",
      version: "0.50.0",
      lockfileVersion: 3,
      packages: { "": { name: "@crabedence/nemo", version: "0.50.0" } },
    }),
    "go.mod": "module example.test/release\n\ngo 1.26\n\ntoolchain go1.26.4\n",
    "CHANGELOG.md": "# Changelog\n\n## Unreleased\n\n- next\n\n## 0.50.0 - 2026-09-05\n\n- shipped\n",
    "scripts/release-config.sh": "CRABBOX_RELEASE_GO_VERSION=go1.26.4\n",
    "scripts/release-provenance.mjs": 'const GO_VERSION = "go1.26.4";\n',
    ...overrides,
  };
  for (const [relative, content] of Object.entries(files)) {
    const file = path.join(root, relative);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, content);
  }
  return root;
}

function withTree(t, overrides) {
  const root = makeTree(overrides);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

test("consistent tree passes", async (t) => {
  assert.deepEqual(await verifyVersionConsistency({ root: withTree(t) }), []);
});

test("worker package version drift is rejected", async (t) => {
  const root = withTree(t, {
    "worker/package.json": JSON.stringify({ name: WORKER_NAME, version: "0.49.0" }),
  });
  const findings = await verifyVersionConsistency({ root });
  assert.equal(findings.length, 1);
  assert.match(findings[0], /worker\/package\.json version 0\.49\.0/);
});

test("lockfile root entry drift is rejected", async (t) => {
  const root = withTree(t, {
    "worker/package-lock.json": JSON.stringify({
      name: WORKER_NAME,
      version: "0.50.0",
      lockfileVersion: 3,
      packages: { "": { name: WORKER_NAME, version: "0.49.0" } },
    }),
  });
  const findings = await verifyVersionConsistency({ root });
  assert.equal(findings.length, 1);
  assert.match(findings[0], /packages\[""\]\.version 0\.49\.0/);
});

test("nemo package drift is rejected", async (t) => {
  const root = withTree(t, {
    "nemo/package.json": JSON.stringify({ name: "@crabedence/nemo", version: "0.1.0" }),
  });
  const findings = await verifyVersionConsistency({ root });
  assert.equal(findings.length, 1);
  assert.match(findings[0], /nemo\/package\.json version 0\.1\.0/);
});

test("changelog mismatch is rejected", async (t) => {
  const root = withTree(t, {
    "CHANGELOG.md": "# Changelog\n\n## Unreleased\n\n- next\n\n## 0.49.1 - 2026-09-04\n\n- older\n",
  });
  const findings = await verifyVersionConsistency({ root });
  assert.equal(findings.length, 1);
  assert.match(findings[0], /latest released section 0\.49\.1 does not equal VERSION 0\.50\.0/);
});

test("nemo lockfile drift is rejected", async (t) => {
  const root = withTree(t, {
    "nemo/package-lock.json": JSON.stringify({
      name: "@crabedence/nemo",
      version: "0.1.0",
      lockfileVersion: 3,
      packages: { "": { name: "@crabedence/nemo", version: "0.1.0" } },
    }),
  });
  const findings = await verifyVersionConsistency({ root });
  assert.equal(findings.length, 2);
  assert.ok(findings.some((finding) => /nemo\/package-lock\.json version 0\.1\.0/.test(finding)));
  assert.ok(findings.some((finding) => /packages\[""\]\.version 0\.1\.0/.test(finding)));
});

test("preparing a pre-release requires a newer base than the latest release", async (t) => {
  const nemoLock = (version) =>
    JSON.stringify({
      name: "@crabedence/nemo",
      version,
      lockfileVersion: 3,
      packages: { "": { name: "@crabedence/nemo", version } },
    });
  const files = {
    VERSION: "0.51.0-rc.1\n",
    "worker/package.json": JSON.stringify({ name: WORKER_NAME, version: "0.51.0-rc.1" }),
    "worker/package-lock.json": JSON.stringify({
      name: WORKER_NAME,
      version: "0.51.0-rc.1",
      lockfileVersion: 3,
      packages: { "": { name: WORKER_NAME, version: "0.51.0-rc.1" } },
    }),
    "nemo/package.json": JSON.stringify({ name: "@crabedence/nemo", version: "0.51.0-rc.1" }),
    "nemo/package-lock.json": nemoLock("0.51.0-rc.1"),
  };
  assert.deepEqual(await verifyVersionConsistency({ root: withTree(t, files) }), []);

  const stale = withTree(t, {
    ...files,
    VERSION: "0.50.0-rc.1\n",
    "worker/package.json": JSON.stringify({ name: WORKER_NAME, version: "0.50.0-rc.1" }),
    "worker/package-lock.json": JSON.stringify({
      name: WORKER_NAME,
      version: "0.50.0-rc.1",
      lockfileVersion: 3,
      packages: { "": { name: WORKER_NAME, version: "0.50.0-rc.1" } },
    }),
    "nemo/package.json": JSON.stringify({ name: "@crabedence/nemo", version: "0.50.0-rc.1" }),
    "nemo/package-lock.json": nemoLock("0.50.0-rc.1"),
  });
  const findings = await verifyVersionConsistency({ root: stale });
  assert.equal(findings.length, 1);
  assert.match(findings[0], /must be newer than the latest released section 0\.50\.0/);
});

test("release tag must equal vVERSION", async (t) => {
  const root = withTree(t);
  assert.deepEqual(await verifyVersionConsistency({ root, tag: "v0.50.0" }), []);
  const findings = await verifyVersionConsistency({ root, tag: "v0.51.0-rc.1" });
  assert.equal(findings.length, 1);
  assert.match(findings[0], /release tag v0\.51\.0-rc\.1 does not equal v0\.50\.0/);
});

test("release toolchain drift is rejected", async (t) => {
  const root = withTree(t, {
    "scripts/release-provenance.mjs": 'const GO_VERSION = "go1.26.5";\n',
  });
  const findings = await verifyVersionConsistency({ root });
  assert.ok(findings.some((finding) => /release Go toolchain drift/.test(finding)));
  assert.ok(findings.some((finding) => /does not equal the go\.mod toolchain/.test(finding)));
});

test("release toolchain must match the module toolchain", async (t) => {
  // Both release declarations agree with each other but disagree with
  // go.mod — exactly the drift a mutual-agreement check cannot see.
  const root = withTree(t, {
    "scripts/release-config.sh": "CRABBOX_RELEASE_GO_VERSION=go1.26.3\n",
    "scripts/release-provenance.mjs": 'const GO_VERSION = "go1.26.3";\n',
  });
  const findings = await verifyVersionConsistency({ root });
  assert.equal(findings.length, 2);
  assert.ok(findings.every((finding) => /does not equal the go\.mod toolchain go1\.26\.4/.test(finding)));
});

test("a missing module toolchain is rejected", async (t) => {
  const root = withTree(t, { "go.mod": "module example.test/release\n\ngo 1.26\n" });
  const findings = await verifyVersionConsistency({ root });
  assert.deepEqual(findings, ["go.mod does not declare a toolchain"]);
});

test("malformed VERSION is rejected", async (t) => {
  const root = withTree(t, { VERSION: "0.50\n" });
  const findings = await verifyVersionConsistency({ root });
  assert.equal(findings.length, 1);
  assert.match(findings[0], /VERSION must be X\.Y\.Z/);
});

test("version comparison helpers", () => {
  assert.equal(baseVersion("0.52.0-rc.1"), "0.52.0");
  assert.ok(compareBaseVersions("0.52.0-rc.1", "0.51.0") > 0);
  assert.ok(compareBaseVersions("0.50.0", "0.50.0") === 0);
  assert.ok(compareBaseVersions("0.49.1", "0.50.0") < 0);
});
