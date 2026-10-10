import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const scripts = import.meta.dirname;

// Distribution qualification is the lane an extracted source archive
// runs on itself: only the archive is copied into a clean room, it is
// extracted, and the SUITE SHIPPED INSIDE THE ARCHIVE verifies the
// tree — embedded source manifest, path policy, symlinks, generated
// content, and build inputs. No parent repository, and the git-on-PATH
// shim proves nothing in the lane can reach a repository even if one
// is offered.
const have = (tool) => spawnSync("bash", ["-c", `command -v ${tool}`], { stdio: "ignore" }).status === 0;
const prerequisites = ["bash", "git", "tar", "shasum", "python3", "find"].every(have);
const zipTools = ["zip", "unzip"].every(have);
const skipReason = "requires git, tar, shasum, python3, find";

// A scratch repository carrying the distribution lane and every script
// it drives. The build-input stubs satisfy the declared-build-inputs
// gate; tracked.txt/link.txt/run.sh cover content, link, and mode.
function makeRepo(t) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-dist-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const name of [
    "package-source-archive.sh",
    "generate-source-manifest.sh",
    "verify-source-manifest.sh",
    "qualify-source-distribution.sh",
    "lib/release-paths.sh",
  ]) {
    const dest = path.join(root, "scripts", name);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(path.join(scripts, name), dest);
    fs.chmodSync(dest, 0o755);
  }
  const git = (...args) => execFileSync("git", ["-C", root, ...args], { encoding: "utf8" });
  git("init", "--quiet");
  git("config", "user.email", "test@example.com");
  git("config", "user.name", "Test");
  fs.writeFileSync(path.join(root, "VERSION"), "0.0.0-test\n");
  fs.writeFileSync(path.join(root, "go.mod"), "module fixture\n\ngo 1.26\n");
  fs.writeFileSync(path.join(root, "go.sum"), "");
  fs.writeFileSync(path.join(root, "tracked.txt"), "hello\n");
  fs.writeFileSync(path.join(root, "run.sh"), "#!/bin/sh\necho hi\n");
  fs.chmodSync(path.join(root, "run.sh"), 0o755);
  fs.symlinkSync("tracked.txt", path.join(root, "link.txt"));
  for (const [f, content] of [
    ["worker/package.json", '{"name":"fixture-worker","version":"0.0.0"}\n'],
    ["worker/package-lock.json", '{"name":"fixture-worker","version":"0.0.0","lockfileVersion":3}\n'],
    ["nemo/package.json", '{"name":"fixture-nemo","version":"0.0.0"}\n'],
  ]) {
    const abs = path.join(root, f);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  git("add", ".");
  git("commit", "--quiet", "-m", "fixture");
  return { root, git };
}

function outDir(t) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-dist-out-")));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function pack(root, archive, format = "tar.gz") {
  const r = spawnSync(
    "bash",
    [path.join(root, "scripts", "package-source-archive.sh"),
      "--format", format, "--prefix", "fixture", "-o", archive],
    { cwd: root, encoding: "utf8" },
  );
  assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
}

// Extract ONLY the archive into a clean directory — nothing else from
// the repository is visible to the suite.
function extract(archive, dst) {
  fs.mkdirSync(dst);
  if (archive.endsWith(".zip")) execFileSync("unzip", ["-q", archive, "-d", dst]);
  else execFileSync("tar", ["-xzf", archive, "-C", dst]);
  return path.join(dst, "fixture");
}

// A PATH shim making git unusable: if any distribution-lane step can
// reach a repository, this forces it to fail visibly instead.
function gitlessEnv(t) {
  const shim = fs.mkdtempSync(path.join(os.tmpdir(), "cbx-nogit-"));
  t.after(() => fs.rmSync(shim, { recursive: true, force: true }));
  fs.writeFileSync(path.join(shim, "git"), "#!/bin/sh\nexit 3\n");
  fs.chmodSync(path.join(shim, "git"), 0o755);
  return { ...process.env, PATH: `${shim}:${process.env.PATH}` };
}

function qualify(extracted, env = process.env) {
  // The suite under test is the copy SHIPPED IN THE ARCHIVE, run
  // against its own root — exactly the documented verifier command.
  return spawnSync(
    "bash",
    [path.join(extracted, "scripts", "qualify-source-distribution.sh"), extracted],
    { encoding: "utf8", env },
  );
}

test("the archive carries its own source manifest", { skip: !prerequisites && skipReason }, (t) => {
  const { root } = makeRepo(t);
  const out = outDir(t);
  const archive = path.join(out, "fixture.tar.gz");
  pack(root, archive);
  const members = execFileSync("tar", ["-tzf", archive], { encoding: "utf8" });
  assert.ok(
    members.includes("fixture/release-evidence/source-tree-sha256.txt"),
    "the embedded source manifest is part of the shipped artifact",
  );
});

for (const format of ["tar.gz", "zip"]) {
  const ok = prerequisites && (format === "tar.gz" || zipTools);
  const reason = format === "zip" ? "requires zip tools" : skipReason;
  test(
    `the extracted ${format} archive qualifies standalone in a clean room`,
    { skip: !ok && reason },
    (t) => {
      const { root } = makeRepo(t);
      const clean = outDir(t);
      const archive = path.join(clean, `fixture.${format}`);
      pack(root, archive, format);
      // Only the archive moves to the clean room.
      const extracted = extract(archive, path.join(clean, "room"));
      const r = qualify(extracted);
      assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
      assert.match(r.stdout, /qualify-source-distribution: PASS/);
    },
  );
}

test("the distribution lane never reaches for git", { skip: !prerequisites && skipReason }, (t) => {
  const { root } = makeRepo(t);
  const out = outDir(t);
  const archive = path.join(out, "fixture.tar.gz");
  pack(root, archive);
  const extracted = extract(archive, path.join(out, "room"));
  const r = qualify(extracted, gitlessEnv(t));
  assert.equal(
    r.status, 0,
    `the suite must pass with git unusable on PATH:\n${r.stdout}\n${r.stderr}`,
  );
});

// The release clean room verifies the extracted archive against the
// PUBLISHED manifest — a file that lives outside the tree. The embedded
// manifest copy is exempt from the inverse check only while it is
// byte-identical to the manifest under verification.
test("the extracted archive verifies against an external manifest", { skip: !prerequisites && skipReason }, (t) => {
  const { root } = makeRepo(t);
  const out = outDir(t);
  const archive = path.join(out, "fixture.tar.gz");
  pack(root, archive);
  const extracted = extract(archive, path.join(out, "room"));
  const embedded = path.join(extracted, "release-evidence", "source-tree-sha256.txt");
  const published = path.join(out, "published-source-tree-sha256.txt");
  fs.copyFileSync(embedded, published);
  const r = spawnSync(
    "bash",
    [path.join(extracted, "scripts", "verify-source-manifest.sh"), published, extracted],
    { encoding: "utf8" },
  );
  assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
  assert.match(r.stdout, /status=PASS/);
});

test("a divergent embedded manifest fails external verification", { skip: !prerequisites && skipReason }, (t) => {
  const { root } = makeRepo(t);
  const out = outDir(t);
  const archive = path.join(out, "fixture.tar.gz");
  pack(root, archive);
  const extracted = extract(archive, path.join(out, "room"));
  const embedded = path.join(extracted, "release-evidence", "source-tree-sha256.txt");
  const published = path.join(out, "published-source-tree-sha256.txt");
  fs.copyFileSync(embedded, published);
  fs.appendFileSync(embedded, "# tampered self-identity\n");
  const r = spawnSync(
    "bash",
    [path.join(extracted, "scripts", "verify-source-manifest.sh"), published, extracted],
    { encoding: "utf8" },
  );
  assert.notEqual(r.status, 0);
  assert.match(r.stdout + r.stderr, /UNEXPECTED: release-evidence\/source-tree-sha256\.txt/);
});

test("a mutated byte fails the embedded manifest", { skip: !prerequisites && skipReason }, (t) => {
  const { root } = makeRepo(t);
  const out = outDir(t);
  const archive = path.join(out, "fixture.tar.gz");
  pack(root, archive);
  const extracted = extract(archive, path.join(out, "room"));
  fs.appendFileSync(path.join(extracted, "tracked.txt"), "tampered\n");
  const r = qualify(extracted);
  assert.notEqual(r.status, 0);
  assert.match(r.stdout + r.stderr, /MISMATCH|FAIL: source-manifest/);
});

test("an extra file fails the manifest's inverse check", { skip: !prerequisites && skipReason }, (t) => {
  const { root } = makeRepo(t);
  const out = outDir(t);
  const archive = path.join(out, "fixture.tar.gz");
  pack(root, archive);
  const extracted = extract(archive, path.join(out, "room"));
  fs.writeFileSync(path.join(extracted, "stray.txt"), "not in the commit\n");
  const r = qualify(extracted);
  assert.notEqual(r.status, 0);
  assert.match(r.stdout + r.stderr, /UNEXPECTED: stray\.txt/);
});

test("a tree carrying .git is refused — it is not a distribution", { skip: !prerequisites && skipReason }, (t) => {
  const { root } = makeRepo(t);
  const out = outDir(t);
  const archive = path.join(out, "fixture.tar.gz");
  pack(root, archive);
  const extracted = extract(archive, path.join(out, "room"));
  fs.mkdirSync(path.join(extracted, ".git"));
  const r = qualify(extracted);
  assert.notEqual(r.status, 0);
  assert.match(r.stdout + r.stderr, /\.git entry in distribution tree|FAIL: no-git-in-extraction/);
});

test("a missing embedded manifest fails closed", { skip: !prerequisites && skipReason }, (t) => {
  const { root } = makeRepo(t);
  const out = outDir(t);
  const archive = path.join(out, "fixture.tar.gz");
  pack(root, archive);
  const extracted = extract(archive, path.join(out, "room"));
  fs.rmSync(path.join(extracted, "release-evidence", "source-tree-sha256.txt"));
  const r = qualify(extracted);
  assert.notEqual(r.status, 0);
  assert.match(r.stdout + r.stderr, /no manifest|FAIL: source-manifest/);
});

test("a dangling symlink in the extraction fails", { skip: !prerequisites && skipReason }, (t) => {
  const { root } = makeRepo(t);
  const out = outDir(t);
  const archive = path.join(out, "fixture.tar.gz");
  pack(root, archive);
  const extracted = extract(archive, path.join(out, "room"));
  fs.rmSync(path.join(extracted, "tracked.txt"));
  const r = qualify(extracted);
  assert.notEqual(r.status, 0);
});

test("generated content smuggled into the tree fails", { skip: !prerequisites && skipReason }, (t) => {
  const { root } = makeRepo(t);
  const out = outDir(t);
  const archive = path.join(out, "fixture.tar.gz");
  pack(root, archive);
  const extracted = extract(archive, path.join(out, "room"));
  fs.mkdirSync(path.join(extracted, "node_modules", "smuggled"), { recursive: true });
  const r = qualify(extracted);
  assert.notEqual(r.status, 0);
  assert.match(r.stdout + r.stderr, /generated directory|FAIL: no-generated-content/);
});

// --require-source <dir> is the caller's frozen baseline. The declared
// source path resolves against the extracted root's parent, so the
// suite links the baseline there (the arrangement the packager's
// clean-room check makes) and hands the verifier the boolean flag —
// the directory must never reach it as a positional argument. The
// manifest fixture lands post-extraction because a manifest without a
// tree cannot survive the packager's own clean-room verification.
function injectTransferFixture(extracted) {
  const py = path.join(extracted, "scripts", "verify-nemo-transfer.py");
  fs.copyFileSync(path.join(scripts, "verify-nemo-transfer.py"), py);
  fs.chmodSync(py, 0o755);
  fs.mkdirSync(path.join(extracted, "runtimes"), { recursive: true });
  fs.writeFileSync(
    path.join(extracted, "runtimes", "nemo-transfer-manifest.json"),
    JSON.stringify({ source: { path: "../frozen-src", required: true } }),
  );
}

function qualifyRequireSource(extracted, req) {
  return spawnSync(
    "bash",
    [path.join(extracted, "scripts", "qualify-source-distribution.sh"),
      extracted, "--require-source", req],
    { encoding: "utf8" },
  );
}

test("--require-source links the baseline at the declared source path", { skip: !prerequisites && skipReason }, (t) => {
  const { root } = makeRepo(t);
  const out = outDir(t);
  const archive = path.join(out, "fixture.tar.gz");
  pack(root, archive);
  const extracted = extract(archive, path.join(out, "room"));
  injectTransferFixture(extracted);
  const frozen = outDir(t);
  const r = qualifyRequireSource(extracted, frozen);
  // The manifest fixture has no tree, so the verifier refuses its
  // CONTENT — proof the directory never reached it as the manifest
  // operand (the old bug surfaced there as "Is a directory").
  assert.equal(r.status, 1, `${r.stdout}\n${r.stderr}`);
  assert.match(r.stdout + r.stderr, /FAIL: nemo-transfer-manifest/);
  assert.match(r.stdout + r.stderr, /declares no tree/);
  assert.doesNotMatch(r.stdout + r.stderr, /Is a directory/);
  const dest = path.join(path.dirname(extracted), "frozen-src");
  assert.ok(fs.lstatSync(dest).isSymbolicLink(), `expected ${dest} to be a symlink`);
  assert.equal(fs.realpathSync(dest), fs.realpathSync(frozen));
});

test("--require-source refuses a non-directory", { skip: !prerequisites && skipReason }, (t) => {
  const { root } = makeRepo(t);
  const out = outDir(t);
  const archive = path.join(out, "fixture.tar.gz");
  pack(root, archive);
  const extracted = extract(archive, path.join(out, "room"));
  injectTransferFixture(extracted);
  const r = qualifyRequireSource(extracted, path.join(out, "missing"));
  assert.equal(r.status, 2, `${r.stdout}\n${r.stderr}`);
  assert.match(r.stderr, /is not a directory/);
});

test("--require-source accepts the baseline already at the declared path", { skip: !prerequisites && skipReason }, (t) => {
  const { root } = makeRepo(t);
  const out = outDir(t);
  const archive = path.join(out, "fixture.tar.gz");
  pack(root, archive);
  const room = path.join(out, "room");
  const extracted = extract(archive, room);
  injectTransferFixture(extracted);
  // A real directory — not a symlink — already occupying the declared
  // path and IS the caller's baseline: used as-is, never clobbered.
  const frozen = path.join(room, "frozen-src");
  fs.mkdirSync(frozen);
  const r = qualifyRequireSource(extracted, frozen);
  assert.equal(r.status, 1, `${r.stdout}\n${r.stderr}`);
  assert.match(r.stdout + r.stderr, /declares no tree/);
});

test("--require-source with a malformed manifest fails the gate, not the suite", { skip: !prerequisites && skipReason }, (t) => {
  const { root } = makeRepo(t);
  const out = outDir(t);
  const archive = path.join(out, "fixture.tar.gz");
  pack(root, archive);
  const extracted = extract(archive, path.join(out, "room"));
  injectTransferFixture(extracted);
  fs.writeFileSync(
    path.join(extracted, "runtimes", "nemo-transfer-manifest.json"),
    "{not json",
  );
  const r = qualifyRequireSource(extracted, outDir(t));
  assert.equal(r.status, 1, `${r.stdout}\n${r.stderr}`);
  assert.match(r.stdout + r.stderr, /FAIL: nemo-transfer-manifest/);
  assert.match(r.stdout + r.stderr, /not a valid transfer manifest/);
});

test("--require-source refuses to clobber a real directory", { skip: !prerequisites && skipReason }, (t) => {
  const { root } = makeRepo(t);
  const out = outDir(t);
  const archive = path.join(out, "fixture.tar.gz");
  pack(root, archive);
  const room = path.join(out, "room");
  const extracted = extract(archive, room);
  injectTransferFixture(extracted);
  fs.mkdirSync(path.join(room, "frozen-src"));
  const frozen = outDir(t);
  const r = qualifyRequireSource(extracted, frozen);
  assert.equal(r.status, 2, `${r.stdout}\n${r.stderr}`);
  assert.match(r.stderr, /exists and is not --require-source/);
});
