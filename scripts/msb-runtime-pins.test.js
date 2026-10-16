import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

// Adversarial coverage for the trusted runtime-pin closure (Phase 1.3):
// qualifying verification may only ever read the repository-bound
// manifest, and a substituted executable must fail even when it reports
// the pinned version and resolves a firmware path.

const scripts = import.meta.dirname;
const VERIFY = path.join(scripts, "verify-msb-runtime-pins.sh");
const PINS_TRUSTED = path.join(scripts, "..", "qualification", "msb-runtime-pins.json");
const PINS = JSON.parse(fs.readFileSync(PINS_TRUSTED, "utf8"));
const sha256 = (buffer) => crypto.createHash("sha256").update(buffer).digest("hex");

const hostOS = { darwin: "darwin", linux: "linux" }[process.platform];
const hostArchKey = { arm64: "aarch64", x64: "x86_64" }[process.arch];

// A stand-in msb: healthy doctor output resolving a caller-chosen
// firmware path, and the pinned version on --version. Whatever its
// bytes are, they are not the pinned asset's — that is the point.
function stubMsb(t, firmwarePath) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-msb-")));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const bin = path.join(dir, "msb");
  fs.writeFileSync(
    bin,
    `#!/usr/bin/env bash
case "$1" in
  doctor) echo "firmware: libkrunfw ${firmwarePath}" >&2; exit 0 ;;
  --version|-v|version) echo "msb ${PINS.version}"; exit 0 ;;
  *) exit 0 ;;
esac
`,
  );
  fs.chmodSync(bin, 0o755);
  return { dir, bin };
}

function verify(args, env = {}) {
  const res = spawnSync("bash", [VERIFY, ...args], {
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
  return { status: res.status, output: `${res.stdout}\n${res.stderr}` };
}

test("an MSB_PINS_FILE override is refused in qualifying mode", (t) => {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-pins-")));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const forged = path.join(dir, "forged-pins.json");
  fs.writeFileSync(forged, JSON.stringify({ version: PINS.version, assets: {} }));
  const { status, output } = verify([], { MSB_PINS_FILE: forged });
  assert.notEqual(status, 0);
  assert.match(output, /attempts to substitute the trusted pin manifest/);
});

test("a substituted executable is refused even when it reports the pinned version", (t) => {
  if (!hostOS || !hostArchKey) {
    t.skip("pins manifest has no asset key for this host");
    return;
  }
  const firmware = path.join(os.tmpdir(), `libkrunfw-fake-${process.pid}.dylib`);
  t.after(() => fs.rmSync(firmware, { force: true }));
  fs.writeFileSync(firmware, "attacker firmware\n");
  const { bin } = stubMsb(t, firmware);
  const { status, output } = verify([bin]);
  assert.notEqual(status, 0);
  assert.match(output, /msb executable digest .* does not match the trusted pin|trusted pins differ/);
});

test("a matching forged manifest still cannot qualify — it only runs non-qualifying", (t) => {
  if (!hostOS || !hostArchKey) {
    t.skip("pins manifest has no asset key for this host");
    return;
  }
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cbx-pins-")));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const firmware = path.join(dir, "libkrunfw.5.dylib");
  fs.writeFileSync(firmware, "attacker firmware\n");
  const { bin } = stubMsb(t, firmware);
  // Forge a manifest that matches the stub byte-for-byte: the attack a
  // qualifying override would enable.
  const forged = JSON.parse(JSON.stringify(PINS));
  forged.assets[`msb-${hostOS}-${hostArchKey}`] = sha256(fs.readFileSync(bin));
  forged.assets[`libkrunfw-${hostOS}-${hostArchKey}.dylib`] = sha256(fs.readFileSync(firmware));
  forged.assets[`libkrunfw-${hostOS}-${hostArchKey}.so`] = sha256(fs.readFileSync(firmware));
  const forgedPath = path.join(dir, "forged-pins.json");
  fs.writeFileSync(forgedPath, JSON.stringify(forged, null, 2));

  // Qualifying mode never touches it.
  const qualifying = verify([bin], { MSB_PINS_FILE: forgedPath });
  assert.notEqual(qualifying.status, 0);
  assert.match(qualifying.output, /attempts to substitute/);

  // Non-qualifying mode may consume it, but the result is labelled as
  // evidence of nothing — the label is the boundary.
  const dev = verify([bin], { MSB_PINS_FILE: forgedPath, MSB_PINS_NONQUALIFYING: "1" });
  assert.match(dev.output, /NON-QUALIFYING/);
});
