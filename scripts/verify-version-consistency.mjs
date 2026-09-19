#!/usr/bin/env node
// verify-version-consistency.mjs — one release version source.
//
// VERSION is the single source of the project version. Every file that
// carries the version must agree with it:
//
//   - worker/package.json
//   - worker/package-lock.json (root "version" and packages[""].version)
//   - nemo/package.json
//   - the latest versioned section in CHANGELOG.md
//   - the signed release tag (checked when --tag is passed)
//
// The release pipeline's toolchain declarations must also agree with
// each other (scripts/release-config.sh and scripts/release-provenance.mjs),
// so qualification tooling cannot silently drift apart.
//
// Usage:
//   node scripts/verify-version-consistency.mjs
//   node scripts/verify-version-consistency.mjs --tag v0.52.0-rc.1

import { readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const VERSION_PATTERN = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const CHANGELOG_SECTION = /^## (\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?) - \d{4}-\d{2}-\d{2}$/gm;

/** baseVersion strips a pre-release suffix: "0.52.0-rc.1" → "0.52.0". */
export function baseVersion(version) {
  return version.split("-")[0];
}

/** compareBaseVersions compares two X.Y.Z strings numerically. */
export function compareBaseVersions(a, b) {
  const left = baseVersion(a).split(".").map(Number);
  const right = baseVersion(b).split(".").map(Number);
  for (let index = 0; index < 3; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return 0;
}

/**
 * verifyVersionConsistency checks the repository's version and
 * toolchain declarations. Returns a list of findings — empty means
 * consistent.
 */
export async function verifyVersionConsistency({ root, tag } = {}) {
  const findings = [];
  const read = (relative) => readFile(path.join(root, relative), "utf8");
  const readJSON = async (relative) => JSON.parse(await read(relative));

  const version = (await read("VERSION")).trim();
  if (!VERSION_PATTERN.test(version)) {
    findings.push(`VERSION must be X.Y.Z or X.Y.Z-<prerelease>, got ${JSON.stringify(version)}`);
    return findings;
  }

  const worker = await readJSON("worker/package.json");
  if (worker.version !== version) {
    findings.push(`worker/package.json version ${worker.version} does not equal VERSION ${version}`);
  }

  const lock = await readJSON("worker/package-lock.json");
  if (lock.version !== version) {
    findings.push(`worker/package-lock.json version ${lock.version} does not equal VERSION ${version}`);
  }
  const lockRoot = lock.packages?.[""]?.version;
  if (lockRoot !== version) {
    findings.push(`worker/package-lock.json packages[""].version ${lockRoot} does not equal VERSION ${version}`);
  }

  const nemo = await readJSON("nemo/package.json");
  if (nemo.version !== version) {
    findings.push(`nemo/package.json version ${nemo.version} does not equal VERSION ${version}`);
  }

  const changelog = await read("CHANGELOG.md");
  const released = [...changelog.matchAll(CHANGELOG_SECTION)].map((match) => match[1]);
  if (released.length === 0) {
    findings.push("CHANGELOG.md has no versioned release section");
  } else if (version.includes("-")) {
    // Preparing a pre-release: the latest finalized release must be older.
    if (compareBaseVersions(version, released[0]) <= 0) {
      findings.push(
        `pre-release VERSION ${version} must be newer than the latest released section ${released[0]}`,
      );
    }
  } else if (released[0] !== version) {
    findings.push(`CHANGELOG.md latest released section ${released[0]} does not equal VERSION ${version}`);
  }

  const releaseConfig = await read("scripts/release-config.sh");
  const releaseGo = /CRABBOX_RELEASE_GO_VERSION=(go\d+\.\d+\.\d+)/.exec(releaseConfig)?.[1];
  const provenance = await read("scripts/release-provenance.mjs");
  const provenanceGo = /const GO_VERSION = "(go\d+\.\d+\.\d+)"/.exec(provenance)?.[1];
  if (!releaseGo) {
    findings.push("scripts/release-config.sh does not declare CRABBOX_RELEASE_GO_VERSION");
  }
  if (!provenanceGo) {
    findings.push("scripts/release-provenance.mjs does not declare GO_VERSION");
  }
  if (releaseGo && provenanceGo && releaseGo !== provenanceGo) {
    findings.push(
      `release Go toolchain drift: release-config.sh ${releaseGo} does not equal release-provenance.mjs ${provenanceGo}`,
    );
  }

  if (tag !== undefined) {
    const normalized = String(tag).replace(/^v/, "");
    if (normalized !== version) {
      findings.push(`release tag ${tag} does not equal v${version} (VERSION)`);
    }
  }

  return findings;
}

async function main() {
  const args = process.argv.slice(2);
  let tag;
  const tagIndex = args.indexOf("--tag");
  if (tagIndex >= 0) {
    tag = args[tagIndex + 1];
    if (!tag) {
      console.error("--tag requires a value");
      process.exitCode = 2;
      return;
    }
  }

  const root = path.resolve(import.meta.dirname, "..");
  const findings = await verifyVersionConsistency({ root, tag });
  if (findings.length > 0) {
    console.error(findings.join("\n"));
    process.exitCode = 1;
    return;
  }
  const version = (await readFile(path.join(root, "VERSION"), "utf8")).trim();
  console.log(`version consistency: OK (${version})`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
