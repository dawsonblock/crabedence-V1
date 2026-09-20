import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const scripts = import.meta.dirname;
const GENERATOR = path.join(scripts, "generate-source-manifest.sh");
const VERIFIER = path.join(scripts, "verify-source-manifest.sh");

// A small repository carrying one tracked file, one ignored directory, and
// one ignored file — the shape that made the manifest diverge from the
// released archive and from the verifier's walk.
function makeRepo(t) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-manifest-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const git = (...args) => execFileSync("git", ["-C", root, ...args], { encoding: "utf8" });
  git("init", "--quiet");
  git("config", "user.email", "test@example.com");
  git("config", "user.name", "Test");
  fs.writeFileSync(path.join(root, ".gitignore"), "ignored/\ncache.bin\n");
  fs.writeFileSync(path.join(root, "tracked.txt"), "hello\n");
  fs.mkdirSync(path.join(root, "ignored"));
  fs.writeFileSync(path.join(root, "ignored", "run.tar.gz"), "capture\n");
  fs.writeFileSync(path.join(root, "cache.bin"), "binary\n");
  git("add", ".gitignore", "tracked.txt");
  git("commit", "--quiet", "-m", "fixture");
  return root;
}

function generate(t, root) {
  const out = fs.realpathSync(
    fs.mkdtempSync(path.join(os.tmpdir(), "cbx-manifest-out-")),
  );
  t.after(() => fs.rmSync(out, { recursive: true, force: true }));
  const manifestPath = path.join(out, "source-tree-sha256.txt");
  const result = spawnSync("bash", [GENERATOR, manifestPath, root], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return { manifestPath, manifest: fs.readFileSync(manifestPath, "utf8") };
}

const listedPaths = (manifest) =>
  manifest
    .trim()
    .split("\n")
    .map((line) => line.replace(/^[0-9a-f]{64} {2}/, ""));

test("ignored files present in the tree are excluded from the manifest", (t) => {
  const { manifest } = generate(t, makeRepo(t));
  assert.match(manifest, /tracked\.txt$/m);
  assert.match(manifest, /\.gitignore$/m);
  assert.doesNotMatch(manifest, /ignored\/run\.tar\.gz/);
  assert.doesNotMatch(manifest, /cache\.bin/);
});

test("the manifest lists exactly what git archive packages", (t) => {
  const root = makeRepo(t);
  const { manifest } = generate(t, root);
  const archive = execFileSync("git", ["-C", root, "archive", "--format=tar", "HEAD"]);
  const entries = execFileSync("tar", ["-tf", "-"], { input: archive, encoding: "utf8" })
    .trim()
    .split("\n")
    .filter((entry) => entry !== "" && !entry.endsWith("/"));
  assert.deepEqual([...listedPaths(manifest)].sort(), [...entries].sort());
});

test("the verifier accepts a working tree carrying ignored files", (t) => {
  const root = makeRepo(t);
  const { manifestPath } = generate(t, root);
  const result = spawnSync("bash", [VERIFIER, manifestPath, root], { encoding: "utf8" });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  assert.match(result.stdout, /unexpected=0/);
  assert.match(result.stdout, /status=PASS/);
});

test("the verifier works on an extracted archive with no .git", (t) => {
  const root = makeRepo(t);
  const { manifestPath } = generate(t, root);
  const extracted = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-extract-")));
  t.after(() => fs.rmSync(extracted, { recursive: true, force: true }));
  const archive = execFileSync("git", ["-C", root, "archive", "--format=tar", "HEAD"]);
  execFileSync("tar", ["-xf", "-", "-C", extracted], { input: archive });
  const result = spawnSync("bash", [VERIFIER, manifestPath, extracted], { encoding: "utf8" });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  assert.match(result.stdout, /status=PASS/);
});

test("the generator and verifier parse", () => {
  for (const file of [GENERATOR, VERIFIER]) {
    execFileSync("bash", ["-n", file]);
  }
});
