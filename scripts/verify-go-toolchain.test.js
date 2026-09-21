import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const scripts = import.meta.dirname;
const GATE = path.join(scripts, "verify-go-toolchain.sh");

// A fixture module plus a stub `go` whose reported version and GOTOOLCHAIN
// the test controls — the gate must never take the real toolchain's word
// for what a fixture claims.
function fixture(
  t,
  { directive = "toolchain go1.26.5", goversion = "go1.26.5", gotoolchain = "local" } = {},
) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-toolchain-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(path.join(root, "go.mod"), `module example.com/fixture\n\ngo 1.26\n\n${directive}\n`);

  const bin = path.join(root, "bin");
  fs.mkdirSync(bin);
  fs.writeFileSync(
    path.join(bin, "go"),
    `#!/bin/sh
case "$1" in
  version) echo "go version ${goversion} darwin/arm64" ;;
  env)
    case "$2" in
      GOVERSION) echo "${goversion}" ;;
      GOTOOLCHAIN) echo "${gotoolchain}" ;;
      *) echo "" ;;
    esac ;;
  *) exit 64 ;;
esac
`,
    { mode: 0o755 },
  );
  return { root, bin };
}

function run(root, bin) {
  const result = spawnSync("bash", [GATE, root], {
    encoding: "utf8",
    env: { PATH: `${bin}:/usr/bin:/bin` },
  });
  return { status: result.status, output: `${result.stdout}\n${result.stderr}` };
}

test("declared 1.26.5 with installed 1.26.5 passes", (t) => {
  const { root, bin } = fixture(t);
  const { status, output } = run(root, bin);
  assert.equal(status, 0, output);
  assert.match(output, /goversion=go1\.26\.5/);
  assert.match(output, /gotoolchain=local/);
  assert.match(output, /toolchain=go1\.26\.5 verified/);
});

test("declared 1.26.5 with installed 1.26.6 fails closed", (t) => {
  const { root, bin } = fixture(t, { goversion: "go1.26.6" });
  const { status, output } = run(root, bin);
  assert.equal(status, 1);
  assert.match(output, /GOVERSION=go1\.26\.6 != declared go1\.26\.5/);
});

test("declared 1.26.5 with installed 1.26.8 fails closed", (t) => {
  const { root, bin } = fixture(t, { goversion: "go1.26.8" });
  const { status, output } = run(root, bin);
  assert.equal(status, 1);
  assert.match(output, /!= declared go1\.26\.5/);
});

test("a missing actual version fails closed", (t) => {
  const { root, bin } = fixture(t, { goversion: "" });
  const { status, output } = run(root, bin);
  assert.equal(status, 1);
  assert.match(output, /produced no version/);
});

test("a malformed toolchain declaration fails closed", (t) => {
  const { root, bin } = fixture(t, { directive: "toolchain go1.26" });
  const { status, output } = run(root, bin);
  assert.equal(status, 1);
  assert.match(output, /does not declare an exact toolchain/);
});

test("a missing toolchain directive fails closed", (t) => {
  const { root, bin } = fixture(t, { directive: "" });
  const { status, output } = run(root, bin);
  assert.equal(status, 1);
  assert.match(output, /does not declare an exact toolchain/);
});

test("GOTOOLCHAIN=auto fails closed even when versions agree", (t) => {
  const { root, bin } = fixture(t, { gotoolchain: "auto" });
  const { status, output } = run(root, bin);
  assert.equal(status, 1);
  assert.match(output, /GOTOOLCHAIN=auto \(want local\)/);
});

test("a missing go.mod fails closed", (t) => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-toolchain-nogomod-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const { status, output } = run(root, "/nonexistent-bin");
  assert.equal(status, 1);
  assert.match(output, /go\.mod not found/);
});

test("the real repository pins and resolves go1.26.5", () => {
  // The release environment contract: go.mod declares the exact pin, and
  // the effective toolchain the go command selects inside the repo is that
  // pin (the pinned-version assertion about the INSTALLED toolchain runs in
  // the qualification workflow, which also forces GOTOOLCHAIN=local).
  const repoRoot = path.resolve(scripts, "..");
  const goMod = fs.readFileSync(path.join(repoRoot, "go.mod"), "utf8");
  assert.match(goMod, /^toolchain go1\.26\.5$/m);
  assert.equal(
    execFileSync("go", ["env", "GOVERSION"], { cwd: repoRoot, encoding: "utf8" }).trim(),
    "go1.26.5",
  );
});

test("the toolchain gate parses", () => {
  execFileSync("bash", ["-n", GATE]);
});
