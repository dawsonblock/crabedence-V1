import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const scripts = import.meta.dirname;
const GENERATOR = path.join(scripts, "generate-source-manifest.sh");

// A small repository carrying one tracked file, one ignored directory, and
// one ignored file — the shape that made the manifest diverge from the
// released archive.
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

function generate(root) {
  const out = path.join(os.tmpdir(), `${path.basename(root)}-manifest.txt`);
  const result = spawnSync("bash", [GENERATOR, out, root], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const manifest = fs.readFileSync(out, "utf8");
  fs.rmSync(out, { force: true });
  return manifest;
}

const listedPaths = (manifest) =>
  manifest
    .trim()
    .split("\n")
    .map((line) => line.replace(/^[0-9a-f]{64} {2}/, ""));

test("ignored files present in the tree are excluded from the manifest", (t) => {
  const manifest = generate(makeRepo(t));
  assert.match(manifest, /tracked\.txt$/m);
  assert.match(manifest, /\.gitignore$/m);
  assert.doesNotMatch(manifest, /ignored\/run\.tar\.gz/);
  assert.doesNotMatch(manifest, /cache\.bin/);
});

test("the manifest lists exactly what git archive packages", (t) => {
  const root = makeRepo(t);
  const manifest = generate(root);
  const archive = execFileSync("git", ["-C", root, "archive", "--format=tar", "HEAD"]);
  const entries = execFileSync("tar", ["-tf", "-"], { input: archive, encoding: "utf8" })
    .trim()
    .split("\n")
    .filter((entry) => entry !== "" && !entry.endsWith("/"));
  assert.deepEqual([...listedPaths(manifest)].sort(), [...entries].sort());
});

test("the generator parses", () => {
  execFileSync("bash", ["-n", GENERATOR]);
});
