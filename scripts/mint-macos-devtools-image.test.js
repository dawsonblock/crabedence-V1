import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const wrapperScript = path.join(scriptDir, "mint-macos-devtools-image.sh");

async function setupFakeLifecycle() {
  const dir = await mkdtemp(path.join(os.tmpdir(), "crabbox-macos-mint-test-"));
  const envPath = path.join(dir, "env.json");
  const prepPath = path.join(dir, "prep.sh");
  const lifecyclePath = path.join(dir, "lifecycle.sh");
  await writeFile(prepPath, "#!/usr/bin/env bash\nexit 0\n");
  await chmod(prepPath, 0o755);
  await writeFile(
    lifecyclePath,
    `#!/usr/bin/env bash
set -euo pipefail
node -e '
const fs = require("node:fs");
const keys = [
  "CRABBOX_MACOS_SOURCE_PREP_SCRIPT",
  "CRABBOX_MACOS_IMAGE_NAME",
  "CRABBOX_MACOS_REGION",
  "CRABBOX_MACOS_TYPE",
  "CRABBOX_MACOS_RUN",
  "CRABBOX_MACOS_ALLOCATE",
  "CRABBOX_MACOS_CREATE_IMAGE",
  "CRABBOX_MACOS_PROMOTE",
  "CRABBOX_MACOS_CHECKPOINT",
  "CRABBOX_MACOS_OPEN_WEBVNC",
  "CRABBOX_MACOS_KEEP_LEASE",
  "CRABBOX_MACOS_RELEASE_HOST",
  "CRABBOX_MACOS_REQUIRED_MAJOR",
  "CRABBOX_MACOS_REQUIRED_SWIFT_TOOLS",
  "CRABBOX_MACOS_REQUIRE_XCODE",
];
const out = {};
for (const key of keys) out[key] = process.env[key] || "";
fs.writeFileSync(process.env.CRABBOX_FAKE_ENV_PATH, JSON.stringify(out, null, 2));
'
`,
  );
  await chmod(lifecyclePath, 0o755);
  return { dir, envPath, prepPath, lifecyclePath };
}

function runWrapper(args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn("bash", [wrapperScript, ...args], {
      cwd: path.resolve(scriptDir, ".."),
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

test("mint wrapper defaults to no-spend promoted developer-tools proof", async () => {
  const fake = await setupFakeLifecycle();
  const result = await runWrapper([], {
    CRABBOX_FAKE_ENV_PATH: fake.envPath,
    CRABBOX_MACOS_LIFECYCLE_SCRIPT: fake.lifecyclePath,
    CRABBOX_MACOS_SOURCE_PREP_SCRIPT: fake.prepPath,
  });
  assert.equal(result.code, 0, result.stderr);
  const env = JSON.parse(await readFile(fake.envPath, "utf8"));
  assert.equal(env.CRABBOX_MACOS_SOURCE_PREP_SCRIPT, fake.prepPath);
  assert.match(env.CRABBOX_MACOS_IMAGE_NAME, /^crabbox-macos-devtools-/);
  assert.equal(env.CRABBOX_MACOS_TYPE, "mac-m4.metal");
  assert.equal(env.CRABBOX_MACOS_RUN, "0");
  assert.equal(env.CRABBOX_MACOS_ALLOCATE, "0");
  assert.equal(env.CRABBOX_MACOS_CREATE_IMAGE, "1");
  assert.equal(env.CRABBOX_MACOS_PROMOTE, "1");
  assert.equal(env.CRABBOX_MACOS_CHECKPOINT, "1");
  assert.equal(env.CRABBOX_MACOS_OPEN_WEBVNC, "0");
  assert.equal(env.CRABBOX_MACOS_RELEASE_HOST, "0");
  assert.equal(env.CRABBOX_MACOS_REQUIRED_MAJOR, "15");
  assert.equal(env.CRABBOX_MACOS_REQUIRED_SWIFT_TOOLS, "6.2");
  assert.equal(env.CRABBOX_MACOS_REQUIRE_XCODE, "1");
  assert.match(result.stderr, /paid:\s+use_existing=0 allocate=0 release_host=0/);
  assert.match(result.stderr, /tools:\s+macos>=15 swift>=6\.2 require_xcode=1/);
});

test("mint wrapper maps explicit paid-work flags to lifecycle env", async () => {
  const fake = await setupFakeLifecycle();
  const result = await runWrapper(
    [
      "--region",
      "us-west-2",
      "--type",
      "mac2.metal",
      "--name",
      "crabbox-macos-devtools-test",
      "--use-existing",
      "--allocate",
      "--release-host",
      "--keep-lease",
      "--open",
      "--no-promote",
      "--no-checkpoint",
    ],
    {
      CRABBOX_FAKE_ENV_PATH: fake.envPath,
      CRABBOX_MACOS_LIFECYCLE_SCRIPT: fake.lifecyclePath,
      CRABBOX_MACOS_SOURCE_PREP_SCRIPT: fake.prepPath,
    },
  );
  assert.equal(result.code, 0, result.stderr);
  const env = JSON.parse(await readFile(fake.envPath, "utf8"));
  assert.equal(env.CRABBOX_MACOS_IMAGE_NAME, "crabbox-macos-devtools-test");
  assert.equal(env.CRABBOX_MACOS_REGION, "us-west-2");
  assert.equal(env.CRABBOX_MACOS_TYPE, "mac2.metal");
  assert.equal(env.CRABBOX_MACOS_RUN, "1");
  assert.equal(env.CRABBOX_MACOS_ALLOCATE, "1");
  assert.equal(env.CRABBOX_MACOS_CREATE_IMAGE, "1");
  assert.equal(env.CRABBOX_MACOS_RELEASE_HOST, "1");
  assert.equal(env.CRABBOX_MACOS_KEEP_LEASE, "1");
  assert.equal(env.CRABBOX_MACOS_OPEN_WEBVNC, "1");
  assert.equal(env.CRABBOX_MACOS_PROMOTE, "0");
  assert.equal(env.CRABBOX_MACOS_CHECKPOINT, "0");
  assert.equal(env.CRABBOX_MACOS_REQUIRED_MAJOR, "15");
  assert.equal(env.CRABBOX_MACOS_REQUIRED_SWIFT_TOOLS, "6.2");
  assert.equal(env.CRABBOX_MACOS_REQUIRE_XCODE, "1");
});

test("mint wrapper preserves source-only checkpoint default", async () => {
  const fake = await setupFakeLifecycle();
  const result = await runWrapper([], {
    CRABBOX_FAKE_ENV_PATH: fake.envPath,
    CRABBOX_MACOS_LIFECYCLE_SCRIPT: fake.lifecyclePath,
    CRABBOX_MACOS_SOURCE_PREP_SCRIPT: fake.prepPath,
    CRABBOX_MACOS_CREATE_IMAGE: "0",
  });
  assert.equal(result.code, 0, result.stderr);
  const env = JSON.parse(await readFile(fake.envPath, "utf8"));
  assert.equal(env.CRABBOX_MACOS_CREATE_IMAGE, "0");
  assert.equal(env.CRABBOX_MACOS_CHECKPOINT, "0");
  assert.match(result.stderr, /proof:\s+create_image=0 checkpoint=0 promote=1/);
});

test("mint wrapper preserves explicit macOS toolchain overrides", async () => {
  const fake = await setupFakeLifecycle();
  const result = await runWrapper([], {
    CRABBOX_FAKE_ENV_PATH: fake.envPath,
    CRABBOX_MACOS_LIFECYCLE_SCRIPT: fake.lifecyclePath,
    CRABBOX_MACOS_SOURCE_PREP_SCRIPT: fake.prepPath,
    CRABBOX_MACOS_TYPE: "mac2.metal",
    CRABBOX_MACOS_REQUIRED_MAJOR: "14",
    CRABBOX_MACOS_REQUIRED_SWIFT_TOOLS: "6.0",
    CRABBOX_MACOS_REQUIRE_XCODE: "0",
  });
  assert.equal(result.code, 0, result.stderr);
  const env = JSON.parse(await readFile(fake.envPath, "utf8"));
  assert.equal(env.CRABBOX_MACOS_TYPE, "mac2.metal");
  assert.equal(env.CRABBOX_MACOS_REQUIRED_MAJOR, "14");
  assert.equal(env.CRABBOX_MACOS_REQUIRED_SWIFT_TOOLS, "6.0");
  assert.equal(env.CRABBOX_MACOS_REQUIRE_XCODE, "0");
  assert.match(result.stderr, /tools:\s+macos>=14 swift>=6\.0 require_xcode=0/);
});
