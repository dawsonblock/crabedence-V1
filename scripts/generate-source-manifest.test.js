import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const scripts = import.meta.dirname;
const GENERATOR = path.join(scripts, "generate-source-manifest.sh");
const VERIFIER = path.join(scripts, "verify-source-manifest.sh");

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

// A small repository covering every Git object type the manifest must
// represent — regular file, executable, and symlink — plus ignored
// material that `git archive` does not package.
function makeRepo(t) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-manifest-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const git = (...args) => execFileSync("git", ["-C", root, ...args], { encoding: "utf8" });
  git("init", "--quiet");
  git("config", "user.email", "test@example.com");
  git("config", "user.name", "Test");
  fs.writeFileSync(path.join(root, ".gitignore"), "ignored/\ncache.bin\n");
  fs.writeFileSync(path.join(root, "tracked.txt"), "hello\n");
  fs.writeFileSync(path.join(root, "run.sh"), "#!/bin/sh\necho hi\n");
  fs.chmodSync(path.join(root, "run.sh"), 0o755);
  fs.symlinkSync("tracked.txt", path.join(root, "link.txt"));
  fs.mkdirSync(path.join(root, "ignored"));
  fs.writeFileSync(path.join(root, "ignored", "run.tar.gz"), "capture\n");
  fs.writeFileSync(path.join(root, "cache.bin"), "binary\n");
  git("add", ".gitignore", "tracked.txt", "run.sh", "link.txt");
  git("commit", "--quiet", "-m", "fixture");
  return root;
}

function generate(t, root) {
  const out = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-manifest-out-")));
  t.after(() => fs.rmSync(out, { recursive: true, force: true }));
  const manifestPath = path.join(out, "source-tree-sha256.txt");
  const result = spawnSync("bash", [GENERATOR, manifestPath, root], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return { manifestPath, manifest: fs.readFileSync(manifestPath, "utf8") };
}

function extract(t, root) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-extract-")));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const archive = execFileSync("git", ["-C", root, "archive", "--format=tar", "HEAD"]);
  execFileSync("tar", ["-xf", "-", "-C", dir], { input: archive });
  return dir;
}

function verify(manifestPath, root) {
  const result = spawnSync("bash", [VERIFIER, manifestPath, root], { encoding: "utf8" });
  return { status: result.status, output: `${result.stdout}${result.stderr}` };
}

const recordFor = (manifest, name) =>
  manifest
    .trim()
    .split("\n")
    .find((line) => line.endsWith(`  ${name}`));

const manifestPaths = (manifest) =>
  manifest
    .trim()
    .split("\n")
    .map((line) => line.replace(/^\d{6} \w+ [0-9a-f]{64} {2}/, ""));

test("the manifest records type and mode for every Git object kind", (t) => {
  const { manifest } = generate(t, makeRepo(t));
  assert.equal(recordFor(manifest, "tracked.txt"), `100644 file ${sha256("hello\n")}  tracked.txt`);
  assert.equal(recordFor(manifest, "run.sh"), `100755 file ${sha256("#!/bin/sh\necho hi\n")}  run.sh`);
  // A symlink digests its TARGET BYTES, never the linked file's contents.
  assert.equal(recordFor(manifest, "link.txt"), `120000 symlink ${sha256("tracked.txt")}  link.txt`);
});

test("ignored files present in the tree are excluded from the manifest", (t) => {
  const { manifest } = generate(t, makeRepo(t));
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
  assert.deepEqual([...manifestPaths(manifest)].sort(), [...entries].sort());
});

test("the verifier accepts the working tree and an extracted archive", (t) => {
  const root = makeRepo(t);
  const { manifestPath } = generate(t, root);
  for (const target of [root, extract(t, root)]) {
    const { status, output } = verify(manifestPath, target);
    assert.equal(status, 0, output);
    assert.match(output, /status=PASS/);
  }
});

test("a symlink replaced by a regular file fails closed", (t) => {
  const root = makeRepo(t);
  const { manifestPath } = generate(t, root);
  const dir = extract(t, root);
  fs.rmSync(path.join(dir, "link.txt"));
  fs.writeFileSync(path.join(dir, "link.txt"), "tracked.txt");
  const { status, output } = verify(manifestPath, dir);
  assert.equal(status, 1, output);
  assert.match(output, /TYPE MISMATCH: link\.txt/);
});

test("a repointed symlink fails closed", (t) => {
  const root = makeRepo(t);
  const { manifestPath } = generate(t, root);
  const dir = extract(t, root);
  fs.rmSync(path.join(dir, "link.txt"));
  fs.symlinkSync("other.txt", path.join(dir, "link.txt"));
  const { status, output } = verify(manifestPath, dir);
  assert.equal(status, 1, output);
  assert.match(output, /MISMATCH: link\.txt/);
});

test("a cleared executable bit fails closed", (t) => {
  const root = makeRepo(t);
  const { manifestPath } = generate(t, root);
  const dir = extract(t, root);
  fs.chmodSync(path.join(dir, "run.sh"), 0o644);
  const { status, output } = verify(manifestPath, dir);
  assert.equal(status, 1, output);
  assert.match(output, /MODE MISMATCH: run\.sh \(expected executable\)/);
});

test("an unexpected executable bit fails closed", (t) => {
  const root = makeRepo(t);
  const { manifestPath } = generate(t, root);
  const dir = extract(t, root);
  fs.chmodSync(path.join(dir, "tracked.txt"), 0o755);
  const { status, output } = verify(manifestPath, dir);
  assert.equal(status, 1, output);
  assert.match(output, /MODE MISMATCH: tracked\.txt \(unexpected executable bit\)/);
});

test("a deleted symlink fails closed", (t) => {
  const root = makeRepo(t);
  const { manifestPath } = generate(t, root);
  const dir = extract(t, root);
  fs.rmSync(path.join(dir, "link.txt"));
  const { status, output } = verify(manifestPath, dir);
  assert.equal(status, 1, output);
  assert.match(output, /MISSING: link\.txt/);
});

test("a regular file replaced by a symlink fails closed", (t) => {
  const root = makeRepo(t);
  const { manifestPath } = generate(t, root);
  const dir = extract(t, root);
  fs.rmSync(path.join(dir, "tracked.txt"));
  fs.symlinkSync("run.sh", path.join(dir, "tracked.txt"));
  const { status, output } = verify(manifestPath, dir);
  assert.equal(status, 1, output);
  assert.match(output, /TYPE MISMATCH: tracked\.txt/);
});

test("a changed file content fails closed", (t) => {
  const root = makeRepo(t);
  const { manifestPath } = generate(t, root);
  const dir = extract(t, root);
  fs.writeFileSync(path.join(dir, "tracked.txt"), "tampered\n");
  const { status, output } = verify(manifestPath, dir);
  assert.equal(status, 1, output);
  assert.match(output, /MISMATCH: tracked\.txt/);
});

test("a deleted regular file fails closed", (t) => {
  const root = makeRepo(t);
  const { manifestPath } = generate(t, root);
  const dir = extract(t, root);
  fs.rmSync(path.join(dir, "tracked.txt"));
  const { status, output } = verify(manifestPath, dir);
  assert.equal(status, 1, output);
  assert.match(output, /MISSING: tracked\.txt/);
});

test("a file added after manifest generation fails closed", (t) => {
  const root = makeRepo(t);
  const { manifestPath } = generate(t, root);
  const dir = extract(t, root);
  fs.writeFileSync(path.join(dir, "extra.txt"), "unmanifested\n");
  const { status, output } = verify(manifestPath, dir);
  assert.equal(status, 1, output);
  assert.match(output, /UNEXPECTED: extra\.txt/);
});

test("the generator and verifier parse", () => {
  for (const file of [GENERATOR, VERIFIER]) {
    execFileSync("bash", ["-n", file]);
  }
});

test("tracked .gitattributes introduces no archive-transforming attributes", () => {
  // The manifest derives from the Git HEAD tree, while `git archive` also
  // applies export-ignore and export-subst. If either appears, the tree
  // identity and the packaged archive can diverge silently, so
  // qualification must fail until the generator has explicit support for
  // those semantics.
  const repoRoot = path.resolve(scripts, "..");
  const tracked = execFileSync("git", ["-C", repoRoot, "ls-files", "-z"], { encoding: "utf8" })
    .split("\0")
    .filter((file) => file === ".gitattributes" || file.endsWith("/.gitattributes"));
  assert.ok(tracked.length > 0, "the repository tracks at least one .gitattributes");
  for (const file of tracked) {
    const content = fs.readFileSync(path.join(repoRoot, file), "utf8");
    for (const line of content.split("\n")) {
      assert.doesNotMatch(
        line,
        /(^|\s)(export-ignore|export-subst)(\s|$)/,
        `${file} must not use archive-transforming attributes: ${line}`,
      );
    }
  }
});
