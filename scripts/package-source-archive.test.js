import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const scripts = import.meta.dirname;
const projectRoot = path.resolve(scripts, "..");

// The packager runs against its own repository root, so the fixture is a
// scratch repository carrying the three scripts it drives. Its tree covers
// every object kind the release bundle must preserve — a symlink, an
// executable, and a .gitattributes-eol file whose worktree bytes differ
// from its blob — plus a dirty-tree refusal case. The runtime fixture
// additionally carries runtimes/nemo-relay plus the real provenance
// policy so the provenance-covered => tracked gate runs against the real
// digest enumerator (NEMO_RUNTIME_DIGEST_BIN points the packager at a
// prebuilt binary; without it the fixture's `go run` has no module).
const have = (tool) => spawnSync("bash", ["-c", `command -v ${tool}`], { stdio: "ignore" }).status === 0;
const baseTools = ["bash", "git", "tar", "shasum"];
const prerequisites = baseTools.every(have);
const zipTools = ["zip", "unzip"].every(have);
const skipReason = "requires git, tar, and shasum";

// Build the real provenance enumerator once per run; its -list output is
// what the packager's tracked-only invariant consumes.
let digestBinCache;
function digestTool() {
  if (digestBinCache !== undefined) return digestBinCache;
  if (!have("go")) return (digestBinCache = null);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cbx-digest-"));
  process.on("exit", () => fs.rmSync(dir, { recursive: true, force: true }));
  const bin = path.join(dir, "nemo-runtime-digest");
  const r = spawnSync("go", ["build", "-o", bin, "./cmd/nemo-runtime-digest"], {
    cwd: projectRoot,
    encoding: "utf8",
  });
  return (digestBinCache = r.status === 0 ? bin : null);
}

function makeRepo(t, { runtime = false } = {}) {
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
  if (runtime) {
    const relay = path.join(root, "runtimes", "nemo-relay");
    fs.mkdirSync(relay, { recursive: true });
    fs.copyFileSync(
      path.join(projectRoot, "runtimes", "nemo-provenance-policy.json"),
      path.join(root, "runtimes", "nemo-provenance-policy.json"),
    );
    fs.writeFileSync(path.join(relay, "keep.txt"), "kept\n");
    fs.symlinkSync("keep.txt", path.join(relay, "keep-link"));
  }
  git("add", ".");
  git("commit", "--quiet", "-m", "fixture");
  return { root, git };
}

function pack(root, args) {
  const packager = path.join(root, "scripts", "package-source-archive.sh");
  const env = { ...process.env };
  const bin = digestTool();
  if (bin) env.NEMO_RUNTIME_DIGEST_BIN = bin;
  return spawnSync("bash", [packager, ...args], { cwd: root, encoding: "utf8", env });
}

function outDir(t) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-pack-out-")));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test("the packager preserves symlinks, exec bits, and smudged worktree bytes", { skip: !prerequisites && skipReason }, (t) => {
  const { root } = makeRepo(t);
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

test("a modified tracked file refuses packaging unless --allow-dirty", { skip: !prerequisites && skipReason }, (t) => {
  const { root } = makeRepo(t);
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
  const { root } = makeRepo(t);
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

test("the archive prefix accepts only [A-Za-z0-9][A-Za-z0-9._+-]*", { skip: !prerequisites && skipReason }, (t) => {
  const { root } = makeRepo(t);
  const out = outDir(t);
  // Every input that could become an option, a traversal, a path
  // component, or a control payload must fail with exit 2 before any
  // archive command runs — and must leave no archive behind.
  for (const bad of [
    "",
    ".",
    "..",
    "-Itrue",
    "--checkpoint=1",
    "-",
    "../escape",
    "foo/bar",
    "foo\\bar",
    "foo bar",
    "foo\tbar",
    "foo\nbar",
    " leading",
    "trailing ",
    ".hidden",
    "+plus",
    "_under",
  ]) {
    const archive = path.join(out, `bad-${bad.length}.tar.gz`);
    const r = pack(root, ["--prefix", bad, "-o", archive]);
    assert.equal(r.status, 2, `prefix ${JSON.stringify(bad)} must be refused`);
    assert.ok(
      r.stderr.includes("must match [A-Za-z0-9][A-Za-z0-9._+-]*"),
      `prefix ${JSON.stringify(bad)} must name the grammar: ${r.stderr}`,
    );
    assert.ok(!fs.existsSync(archive), `prefix ${JSON.stringify(bad)} left an archive behind`);
  }
});

test("a normal release prefix such as NEMO-CONTROL-v0.54.0-rc.1 is accepted", { skip: !prerequisites && skipReason }, (t) => {
  const { root } = makeRepo(t);
  const out = outDir(t);
  const archive = path.join(out, "rc.tar.gz");
  const r = pack(root, ["--prefix", "NEMO-CONTROL-v0.54.0-rc.1", "-o", archive]);
  assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
  const dst = path.join(out, "extract");
  fs.mkdirSync(dst);
  execFileSync("tar", ["-xzf", archive, "-C", dst]);
  assert.ok(fs.existsSync(path.join(dst, "NEMO-CONTROL-v0.54.0-rc.1", "tracked.txt")));
});

// The regression this guards: the packager must never produce a
// supposedly valid source artifact from provenance content outside the
// release commit. An object the policy enumerates but Git does not
// track is exactly the .claude/skills failure class — the union fix
// had packaged such bytes silently. Each object kind (regular file and
// symlink) is exercised through both archive formats. Note the success
// case commits, not just `git add`: a staged-only object is not
// represented by the release commit and must still fail.
const provenancePrereq = prerequisites && digestTool();
const provenanceSkip = "requires git, tar, shasum, and go for the digest tool";

for (const kind of ["file", "symlink"]) {
  for (const format of ["tar.gz", "zip"]) {
    const name = `a provenance-covered but untracked ${kind} fails ${format} packaging until committed`;
    const ok = provenancePrereq && (format === "tar.gz" || zipTools);
    const reason = format === "zip" && !zipTools
      ? "requires git, tar, shasum, go, zip, unzip"
      : provenanceSkip;
    test(name, { skip: !ok && reason }, (t) => {
      const { root, git } = makeRepo(t, { runtime: true });
      const out = outDir(t);
      const relay = path.join(root, "runtimes", "nemo-relay");
      const entry = kind === "file" ? "provenance-only.txt" : "provenance-link";
      const abs = path.join(relay, entry);
      if (kind === "file") fs.writeFileSync(abs, "covered but untracked\n");
      else fs.symlinkSync("keep.txt", abs);
      const rel = `runtimes/nemo-relay/${entry}`;

      const archive = path.join(out, `prov-${kind}.${format}`);
      const refused = pack(root, ["--format", format, "--prefix", "fixture", "-o", archive]);
      assert.equal(refused.status, 1, `${refused.stdout}\n${refused.stderr}`);
      assert.match(
        refused.stderr,
        new RegExp(`provenance-covered path is not tracked by release commit: ${rel.replace(/[.]/g, "\\.")}`),
        "the packager names the untracked provenance-covered path instead of silently adding it",
      );
      assert.ok(!fs.existsSync(archive), "no archive may be emitted from outside-commit provenance content");

      // A staged-only object is still outside the release commit: the
      // dirty-tree gate refuses first, and even with --allow-dirty the
      // tracked-by-commit gate refuses it.
      git("add", rel);
      const staged = pack(root, ["--format", format, "--prefix", "fixture", "-o", archive]);
      assert.equal(staged.status, 1, `${staged.stdout}\n${staged.stderr}`);
      const stagedDirty = pack(root, ["--format", format, "--allow-dirty", "--prefix", "fixture", "-o", archive]);
      assert.equal(stagedDirty.status, 1, `${stagedDirty.stdout}\n${stagedDirty.stderr}`);
      assert.match(stagedDirty.stderr, /not tracked by release commit/);
      assert.ok(!fs.existsSync(archive));

      git("commit", "--quiet", "-m", "track the provenance-covered object");
      const packed = pack(root, ["--format", format, "--prefix", "fixture", "-o", archive]);
      assert.equal(packed.status, 0, `${packed.stdout}\n${packed.stderr}`);
      assert.ok(fs.existsSync(archive), "tracked provenance content packages cleanly");

      const dst = path.join(out, `extract-${kind}-${format}`);
      fs.mkdirSync(dst);
      if (format === "zip") execFileSync("unzip", ["-q", archive, "-d", dst]);
      else execFileSync("tar", ["-xzf", archive, "-C", dst]);
      const extracted = path.join(dst, "fixture", rel);
      if (kind === "file") {
        assert.equal(fs.readFileSync(extracted, "utf8"), "covered but untracked\n");
      } else {
        assert.ok(fs.lstatSync(extracted).isSymbolicLink(), "the tracked link extracts as a link");
        assert.equal(fs.readlinkSync(extracted), "keep.txt");
      }
    });
  }
}
