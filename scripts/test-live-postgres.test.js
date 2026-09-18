import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const repoRoot = path.resolve(import.meta.dirname, "..");
const script = path.join(repoRoot, "scripts", "test-live-postgres.sh");

// Stub layout: $dir/bin holds fake docker/initdb/pg_ctl/pg_isready/psql
// that append their argv to $STUB_LOG so the test can assert which
// lifecycle the script drove. $dir/out captures the URL the child
// command observed.
function fixture(t, { docker = "down" } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "crabbox-live-pg-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const bin = path.join(dir, "bin");
  fs.mkdirSync(bin);

  const log = path.join(dir, "stub.log");
  const writeStub = (name, body) => {
    const file = path.join(bin, name);
    fs.writeFileSync(file, `#!/usr/bin/env bash\n${body}\n`, "utf8");
    fs.chmodSync(file, 0o755);
  };
  const recorder = `echo "$(basename "$0") $*" >> "$STUB_LOG"`;

  if (docker === "down") {
    // Daemon absent or hung: info fails fast.
    writeStub("docker", `${recorder}\nexit 1`);
  } else {
    // Working daemon: run prints a container id, everything else ok.
    writeStub(
      "docker",
      `${recorder}\ncase "$1" in run) echo fakecid ;; esac\nexit 0`,
    );
  }
  for (const tool of ["initdb", "pg_ctl", "pg_isready", "psql", "go"]) {
    writeStub(tool, `${recorder}\nexit 0`);
  }

  const env = {
    ...process.env,
    PATH: `${bin}:${process.env.PATH}`,
    STUB_LOG: log,
    TMPDIR: dir,
    CRABBOX_TEST_DATABASE_URL: "",
  };
  delete env.CRABBOX_TEST_DATABASE_URL;
  return { dir, bin, log, env };
}

function urlCaptureCommand(dir) {
  const out = path.join(dir, "url.txt");
  return {
    out,
    argv: ["--", "sh", "-c", `printf %s "$CRABBOX_TEST_DATABASE_URL" > "${out}"`],
  };
}

test("falls back to initdb when Docker is unreachable", (t) => {
  const { dir, log, env } = fixture(t, { docker: "down" });
  const { out, argv } = urlCaptureCommand(dir);
  const res = spawnSync(script, argv, { env, encoding: "utf8" });
  assert.equal(res.status, 0, res.stderr);

  const calls = fs.readFileSync(log, "utf8");
  assert.match(calls, /initdb /);
  assert.match(calls, /pg_ctl .* start/);
  assert.match(calls, /pg_ctl .* stop/);
  assert.doesNotMatch(calls, /docker run/);

  const url = fs.readFileSync(out, "utf8");
  assert.match(url, /^postgres:\/\/postgres@127\.0\.0\.1:\d+\/crabbox_test\?sslmode=disable$/);
});

test("prefers Docker postgres image when the daemon answers", (t) => {
  const { dir, log, env } = fixture(t, { docker: "up" });
  const { out, argv } = urlCaptureCommand(dir);
  const res = spawnSync(script, argv, { env, encoding: "utf8" });
  assert.equal(res.status, 0, res.stderr);

  const calls = fs.readFileSync(log, "utf8");
  assert.match(calls, /docker run .*postgres:16/);
  assert.match(calls, /docker rm -f/);
  assert.doesNotMatch(calls, /initdb/);

  const url = fs.readFileSync(out, "utf8");
  assert.match(url, /^postgres:\/\/postgres:postgres@127\.0\.0\.1:\d+\/crabbox_test$/);
});

test("uses an existing CRABBOX_TEST_DATABASE_URL without managing a server", (t) => {
  const { dir, log, env } = fixture(t, { docker: "down" });
  env.CRABBOX_TEST_DATABASE_URL = "postgres://existing.example/db";
  const { out, argv } = urlCaptureCommand(dir);
  const res = spawnSync(script, argv, { env, encoding: "utf8" });
  assert.equal(res.status, 0, res.stderr);

  assert.equal(fs.readFileSync(out, "utf8"), "postgres://existing.example/db");
  assert.ok(!fs.existsSync(log), "no postgres tooling should run");
});

test("default command runs the live Go suites", (t) => {
  const { dir, log, env } = fixture(t, { docker: "down" });
  const res = spawnSync(script, [], { env, encoding: "utf8" });
  assert.equal(res.status, 0, res.stderr);

  const calls = fs.readFileSync(log, "utf8");
  assert.match(calls, /go test .*internal\/idempotency/);
  assert.match(calls, /go test .*internal\/authority/);
});
