import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const scripts = import.meta.dirname;

// The packager runs against its own repository root, so the fixture is a
// scratch repository carrying the three scripts it drives. Its tree covers
// every object kind the release bundle must preserve — a symlink, an
// executable, and a .gitattributes-eol file whose worktree bytes differ
// from its blob — plus a dirty-tree refusal case. Without the vendored
// runtime the provenance-union and transfer-manifest gates skip, leaving
// the packaging and clean-room manifest verification under test.
const have = (tool) => spawnSync("bash", ["-c", `command -v ${tool}`], { stdio: "ignore" }).status === 0;
const baseTools = ["bash", "git", "tar", "shasum"];
const prerequisites = baseTools.every(have);
const zipTools = ["zip", "unzip"].every(have);
const skipReason = "requires git, tar, and shasum";

function makeRepo(t) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-pack-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, "scripts"));
  for (const name of [
    "package-source-archive.sh",
    "generate-source-manifest.sh",
    "verify-source-manifest.sh",
  ]) {
    const dest = path.join(root, "scripts", name);
    fs.copyFileSync(path.join(scripts, name), dest);
    fs.chmodSync(dest, 0o755);
  }
  const git = (...args) => execFileSync("git", ["-C", root, ...args], { encoding: "utf8" });
  git("init", "--quiet");
  git("config", "user.email", "test@example.com");
  git("config", "user.name", "Test");
  // `*.cmd text eol=crlf` smudges the worktree to CRLF while the blob
  // stays LF — the byte divergence `git archive` cannot represent.
  fs.writeFileSync(path.join(root, ".gitattributes"), "*.cmd text eol=crlf\n");
  fs.writeFileSync(path.join(root, "tracked.txt"), "hello\n");
  fs.writeFileSync(path.join(root, "run.sh"), "#!/bin/sh\necho hi\n");
  fs.chmodSync(path.join(root, "run.sh"), 0o755);
  fs.symlinkSync("tracked.txt", path.join(root, "link.txt"));
  fs.writeFileSync(path.join(root, "mock.cmd"), "@echo off\r\necho hi\r\n");
  git("add", ".");
  git("commit", "--quiet", "-m", "fixture");
  return root;
}

function pack(root, args, env = process.env) {
  const packager = path.join(root, "scripts", "package-source-archive.sh");
  return spawnSync("bash", [packager, ...args], { cwd: root, encoding: "utf8", env });
}

function outDir(t) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-pack-out-")));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test("the packager preserves symlinks, exec bits, and smudged worktree bytes", { skip: !prerequisites && skipReason }, (t) => {
  const root = makeRepo(t);
  const out = outDir(t);
  const archive = path.join(out, "fixture.tar.gz");
  const r = pack(root, ["--format", "tar.gz", "--prefix", "fixture", "-o", archive]);
  assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);

  const dst = path.join(out, "extract");
  fs.mkdirSync(dst);
  execFileSync("tar", ["-xzf", archive, "-C", dst]);
  const extracted = path.join(dst, "fixture");

  const link = path.join(extracted, "link.txt");
  assert.ok(fs.lstatSync(link).isSymbolicLink(), "a packaged symlink extracts as a link, not its target's contents");
  assert.equal(fs.readlinkSync(link), "tracked.txt");
  assert.ok(fs.statSync(path.join(extracted, "run.sh")).mode & 0o111, "the executable bit survives packaging");
  const cmd = fs.readFileSync(path.join(extracted, "mock.cmd"));
  assert.ok(
    cmd.includes(Buffer.from("\r\n")) && !cmd.includes(Buffer.from("off\n")),
    "the packaged bytes are the CRLF worktree bytes, not the normalized blob",
  );
  assert.ok(fs.existsSync(`${archive}.sha256`), "the archive carries a sha256 sidecar");
});

test("tar packaging uses GNU format with the system tar implementation", { skip: !prerequisites && skipReason }, (t) => {
  const root = makeRepo(t);
  const out = outDir(t);
  const wrapperDir = path.join(out, "bin");
  const tarLog = path.join(out, "tar-args.log");
  fs.mkdirSync(wrapperDir);
  const systemTar = execFileSync("which", ["tar"], { encoding: "utf8" }).trim();
  const wrapper = path.join(wrapperDir, "tar");
  fs.writeFileSync(
    wrapper,
    `#!/bin/sh\nprintf '%s\\n' "$*" >> "$TAR_ARGS_LOG"\nexec ${JSON.stringify(systemTar)} "$@"\n`,
  );
  fs.chmodSync(wrapper, 0o755);

  const archive = path.join(out, "fixture.tar.gz");
  const r = pack(root, ["--format", "tar.gz", "--prefix", "fixture", "-o", archive], {
    ...process.env,
    PATH: `${wrapperDir}${path.delimiter}${process.env.PATH}`,
    TAR_ARGS_LOG: tarLog,
  });
  assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);

  const tarCalls = fs.readFileSync(tarLog, "utf8").trim().split("\n");
  assert.ok(tarCalls.some((args) => args.includes("--format=gnu") && args.includes("-czf")),
    "the real archive creation command explicitly selects GNU format");
  assert.ok(!tarCalls.some((args) => args.includes("--format=gnutar")),
    "GNU tar's invalid gnutar format name is never used");
  execFileSync(systemTar, ["-tzf", archive]);
});

test("a modified tracked file refuses packaging unless --allow-dirty", { skip: !prerequisites && skipReason }, (t) => {
  const root = makeRepo(t);
  const out = outDir(t);
  fs.appendFileSync(path.join(root, "tracked.txt"), "dirty\n");

  const dirty = pack(root, ["--prefix", "fixture", "-o", path.join(out, "refused.tar.gz")]);
  assert.equal(dirty.status, 1);
  assert.match(dirty.stderr, /differ from HEAD/);
  assert.ok(!fs.existsSync(path.join(out, "refused.tar.gz")), "a dirty worktree emits no archive");

  const allowed = pack(root, ["--allow-dirty", "--prefix", "fixture", "-o", path.join(out, "dirty.tar.gz")]);
  assert.equal(allowed.status, 0, `${allowed.stdout}\n${allowed.stderr}`);
  const dst = path.join(out, "extract-dirty");
  fs.mkdirSync(dst);
  execFileSync("tar", ["-xzf", path.join(out, "dirty.tar.gz"), "-C", dst]);
  assert.match(
    fs.readFileSync(path.join(dst, "fixture", "tracked.txt"), "utf8"),
    /dirty\n$/,
    "--allow-dirty packages the worktree bytes, including the uncommitted change",
  );
});

test("zip output keeps symlink entries instead of dereferencing them", { skip: !(prerequisites && zipTools) && "requires git, tar, shasum, zip, unzip" }, (t) => {
  const root = makeRepo(t);
  const out = outDir(t);
  const archive = path.join(out, "fixture.zip");
  const r = pack(root, ["--format", "zip", "--prefix", "fixture", "-o", archive]);
  assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);

  const dst = path.join(out, "extract-zip");
  fs.mkdirSync(dst);
  execFileSync("unzip", ["-q", archive, "-d", dst]);
  const link = path.join(dst, "fixture", "link.txt");
  assert.ok(fs.lstatSync(link).isSymbolicLink(), "zip -y keeps the link entry — the defect that shipped without it");
  assert.equal(fs.readlinkSync(link), "tracked.txt");
});

test("the archive prefix must be a single directory name", { skip: !prerequisites && skipReason }, (t) => {
  const root = makeRepo(t);
  const out = outDir(t);
  for (const bad of ["a/b", "..", ".", "a\\b"]) {
    const r = pack(root, ["--prefix", bad, "-o", path.join(out, "bad.tar.gz")]);
    assert.equal(r.status, 2, `prefix ${JSON.stringify(bad)} must be refused`);
    assert.match(r.stderr, /single directory name/);
  }
});
