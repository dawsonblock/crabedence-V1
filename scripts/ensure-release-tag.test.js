import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const scripts = import.meta.dirname;
const ENSURE = path.join(scripts, "ensure-release-tag.sh");

// Tag admission for a release candidate: the qualified commit is the
// only commit a tag may ever name — an existing tag on it is reused,
// an existing tag on anything else refuses (a published tag is never
// moved), and an absent tag is created annotated and pushed.
const prereq = ["bash", "git"].every(
  (t) => spawnSync("bash", ["-c", `command -v ${t}`], { stdio: "ignore" }).status === 0,
);

function makeRemote(t) {
  // A real remote: a bare repository the script queries and pushes to.
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-tag-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const remote = path.join(root, "remote.git");
  const work = path.join(root, "work");
  execFileSync("git", ["init", "--bare", "--quiet", remote]);
  execFileSync("git", ["init", "--quiet", "-b", "main", work]);
  const git = (...args) => execFileSync("git", ["-C", work, ...args], { encoding: "utf8" });
  git("config", "user.email", "test@example.com");
  git("config", "user.name", "Test");
  fs.writeFileSync(path.join(work, "f.txt"), "one\n");
  git("add", ".");
  git("commit", "--quiet", "-m", "one");
  const commitA = git("rev-parse", "HEAD").trim();
  fs.writeFileSync(path.join(work, "f.txt"), "two\n");
  git("add", ".");
  git("commit", "--quiet", "-m", "two");
  const commitB = git("rev-parse", "HEAD").trim();
  return { root, remote, work, git, commitA, commitB };
}

function ensure(remote, tag, commit, cwd, { dry = false, home = cwd } = {}) {
  return spawnSync("bash", [ENSURE, tag, commit], {
    cwd,
    encoding: "utf8",
    // Isolate git config: a user-level user.signingkey would flip the
    // script into the signed-tag lane.
    env: {
      ...process.env,
      HOME: home,
      XDG_CONFIG_HOME: home,
      GIT_CONFIG_NOSYSTEM: "1",
      RELEASE_REMOTE: remote,
      ENSURE_DRY_RUN: dry ? "1" : "0",
    },
  });
}

test("an absent tag is created annotated at the qualified commit and pushed", { skip: !prereq && "requires git" }, (t) => {
  const r = makeRemote(t);
  const res = ensure(r.remote, "v0.54.0-rc.1", r.commitA, r.work);
  assert.equal(res.status, 0, `${res.stdout}\n${res.stderr}`);
  // The remote now carries an annotated tag peeled to the qualified commit.
  const peeled = execFileSync(
    "git", ["--git-dir", r.remote, "rev-parse", "refs/tags/v0.54.0-rc.1^{}"],
    { encoding: "utf8" },
  ).trim();
  assert.equal(peeled, r.commitA);
  const objType = execFileSync(
    "git", ["--git-dir", r.remote, "cat-file", "-t", "refs/tags/v0.54.0-rc.1"],
    { encoding: "utf8" },
  ).trim();
  assert.equal(objType, "tag", "the pushed tag must be an annotated tag object");
  // The release verifier requires the annotation subject to be the bare
  // tag name — never a descriptive message.
  const subject = execFileSync(
    "git", ["--git-dir", r.remote, "for-each-ref", "--format=%(contents:subject)", "refs/tags/v0.54.0-rc.1"],
    { encoding: "utf8" },
  ).trim();
  assert.equal(subject, "v0.54.0-rc.1");
});

test("a configured signing key produces a signed tag", { skip: !prereq && "requires git" }, (t) => {
  const r = makeRemote(t);
  const key = path.join(r.root, "signing-key");
  execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", key]);
  r.git("config", "gpg.format", "ssh");
  r.git("config", "user.signingkey", key);
  const res = ensure(r.remote, "v0.54.0-rc.1", r.commitA, r.work, { home: r.root });
  assert.equal(res.status, 0, `${res.stdout}\n${res.stderr}`);
  const allowed = path.join(r.root, "allowed");
  fs.writeFileSync(allowed, `release@example.test ${fs.readFileSync(`${key}.pub`, "utf8").trim()}\n`);
  const verified = spawnSync(
    "git",
    ["--git-dir", r.remote, "-c", "gpg.format=ssh", "-c", `gpg.ssh.allowedSignersFile=${allowed}`, "tag", "-v", "v0.54.0-rc.1"],
    { encoding: "utf8" },
  );
  assert.equal(verified.status, 0, "expected a verifiable signed tag");
});

test("an existing tag on the qualified commit is reused", { skip: !prereq && "requires git" }, (t) => {
  const r = makeRemote(t);
  assert.equal(ensure(r.remote, "v0.54.0-rc.1", r.commitA, r.work).status, 0);
  const again = ensure(r.remote, "v0.54.0-rc.1", r.commitA, r.work);
  assert.equal(again.status, 0, `${again.stdout}\n${again.stderr}`);
  assert.match(again.stdout, /reusing it/);
});

test("an existing tag on any other commit refuses — the tag is never moved", { skip: !prereq && "requires git" }, (t) => {
  const r = makeRemote(t);
  assert.equal(ensure(r.remote, "v0.54.0-rc.1", r.commitA, r.work).status, 0);
  const res = ensure(r.remote, "v0.54.0-rc.1", r.commitB, r.work);
  assert.equal(res.status, 1, `${res.stdout}\n${res.stderr}`);
  assert.match(res.stderr, /already exists.*not the qualified commit|never moved/);
  // The remote tag is untouched — still peeled to the first commit.
  const peeled = execFileSync(
    "git", ["--git-dir", r.remote, "rev-parse", "refs/tags/v0.54.0-rc.1^{}"],
    { encoding: "utf8" },
  ).trim();
  assert.equal(peeled, r.commitA);
});

test("a pre-existing foreign tag on the same name refuses", { skip: !prereq && "requires git" }, (t) => {
  const r = makeRemote(t);
  // Someone else tagged a different commit under the rc name first.
  r.git("tag", "-a", "v0.54.0-rc.1", "-m", "foreign", r.commitB);
  r.git("push", r.remote, "v0.54.0-rc.1");
  const res = ensure(r.remote, "v0.54.0-rc.1", r.commitA, r.work);
  assert.equal(res.status, 1);
  assert.match(res.stderr, /already exists/);
});

test("dry-run reports without creating", { skip: !prereq && "requires git" }, (t) => {
  const r = makeRemote(t);
  const res = ensure(r.remote, "v0.54.0-rc.9", r.commitA, r.work, { dry: true });
  assert.equal(res.status, 0);
  const tags = execFileSync("git", ["--git-dir", r.remote, "tag"], { encoding: "utf8" }).trim();
  assert.equal(tags, "", "dry run created a tag");
});
