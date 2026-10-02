import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const sourceRoot = path.resolve(import.meta.dirname, "..");
const familyTag = "nemo-v9.9.9";
const version = "9.9.9";
const runId = 9100;
const workflowId = 88;
const repository = "dawsonblock/crabedence-V1";
const releaseId = 4242;
const targets = ["darwin_amd64", "darwin_arm64", "linux_amd64", "linux_arm64"];
const signerIdentity = "dawsonblock@users.noreply.github.com";

// The fixture signs a real annotated nemo-v* tag and a real SHA256SUMS with a
// throwaway SSH key, so it needs a git whose gpg.format=ssh path works plus
// ssh-keygen -Y sign. Where either is unavailable the suite reports a missing
// prerequisite instead of a behavior regression.
const sshTaggingAvailable = (() => {
  const probe = fs.mkdtempSync(path.join(os.tmpdir(), "nemo-publish-probe-"));
  try {
    execFileSync("git", ["init", "--quiet", "-b", "main", "repo"], { cwd: probe });
    const repo = path.join(probe, "repo");
    execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", path.join(probe, "key")]);
    execFileSync("git", ["config", "user.name", "probe"], { cwd: repo });
    execFileSync("git", ["config", "user.email", "probe@example.test"], { cwd: repo });
    execFileSync("git", ["-c", "commit.gpgsign=false", "commit", "--quiet", "--allow-empty", "-m", "probe"], { cwd: repo });
    execFileSync("git", [
      "-c", "gpg.format=ssh",
      "-c", `user.signingkey=${path.join(probe, "key")}`,
      "tag", "-s", "nemo-v0.0.0", "-m", "nemo-v0.0.0",
    ], { cwd: repo });
    return true;
  } catch {
    return false;
  } finally {
    fs.rmSync(probe, { recursive: true, force: true });
  }
})();

function testWithSshTags(name, optionsOrFn, maybeFn) {
  const fn = typeof optionsOrFn === "function" ? optionsOrFn : maybeFn;
  const options = typeof optionsOrFn === "function" ? undefined : optionsOrFn;
  const wrapped = (t) => {
    if (!sshTaggingAvailable) {
      t.skip("ssh-signed git tags are not available in this environment");
      return;
    }
    return fn(t);
  };
  return options === undefined ? test(name, wrapped) : test(name, options, wrapped);
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function writeJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function copy(root, relative) {
  const destination = path.join(root, relative);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.copyFileSync(path.join(sourceRoot, relative), destination);
}

function git(root, ...args) {
  return execFileSync("git", args, {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

// A per-target artifact zip holding a tarball and its bound attestation.
// options can drift the tarball bytes, the attestation record, or add an
// unexpected member; the map records the bytes a correct SHA256SUMS binds.
function artifactZip(api, artifactId, target, sourceCommit, tarballBytes, options = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `nemo-artifact-${target}-`));
  const tarballName = `nemo-control_${version}_${target}.tar.gz`;
  fs.writeFileSync(path.join(dir, tarballName), tarballBytes);
  const attestation = {
    attestation_version: 1,
    subject: {
      name: "nemo-control",
      platform: target,
      version,
      component_manifest_sha256: "a".repeat(64),
      transfer_manifest_sha256: "b".repeat(64),
      archive_sha256: options.attestationSha ?? sha256(tarballBytes),
    },
    source: { commit: options.attestationCommit ?? sourceCommit },
    gates: options.gates ?? [
      { id: "installed-qualification", result: "pass" },
      { id: "restricted-linux", result: "pass" },
    ],
  };
  const attestationPath = path.join(dir, `${tarballName}.qualification.json`);
  if (options.attestationRaw != null) {
    fs.writeFileSync(attestationPath, options.attestationRaw);
  } else {
    writeJson(attestationPath, attestation);
  }
  // The signed checksum manifest binds the attestation bytes too — the
  // canonical target artifacts hand their exact bytes back for the sums.
  if (options.attestationBytes) {
    options.attestationBytes[`${tarballName}.qualification.json`] =
      fs.readFileSync(attestationPath);
  }
  if (options.extraFile) fs.writeFileSync(path.join(dir, options.extraFile), "surprise\n");
  const zip = path.join(api, `artifact-${artifactId}.zip`);
  execFileSync("zip", [
    "-q", "-j", zip,
    ...fs.readdirSync(dir).map((name) => path.join(dir, name)),
  ]);
  fs.rmSync(dir, { recursive: true, force: true });
  return zip;
}

function prepareFixture({ blockedRecord = false } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nemo-publish-test-"));
  const checkout = path.join(root, "repo");
  const api = path.join(root, "api");
  const bin = path.join(root, "bin");
  fs.mkdirSync(api);
  fs.mkdirSync(bin);
  fs.mkdirSync(checkout);
  execFileSync("git", ["init", "--quiet", "-b", "main", checkout]);
  // A fresh fixture repo stands in for the protected checkout: the publisher
  // only needs its own commit graph, tags, and working tree.

  const signingKey = path.join(root, "release-signing-key");
  execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", signingKey]);
  const publicKey = fs.readFileSync(`${signingKey}.pub`, "utf8").trim();

  for (const file of [
    ".github/workflows/nemo-distribution.yml",
    ".github/release-allowed-signers",
    "scripts/publish-nemo-release.sh",
    "scripts/release-config.sh",
    "scripts/verify-github-release-policy.mjs",
    "scripts/verify-release-source.sh",
  ]) {
    copy(checkout, file);
  }
  fs.writeFileSync(
    path.join(checkout, ".github/release-allowed-signers"),
    `${signerIdentity} ${publicKey}\n`,
  );
  fs.chmodSync(path.join(checkout, "scripts/publish-nemo-release.sh"), 0o755);
  fs.chmodSync(path.join(checkout, "scripts/verify-release-source.sh"), 0o755);
  git(checkout, "config", "user.name", "NEMO Publication Test");
  git(checkout, "config", "user.email", "nemo-publication@example.test");
  git(checkout, "add", ".github", "scripts");
  git(checkout, "-c", "commit.gpgsign=false", "commit", "-m", "test: protected family tooling");

  // The family tag is a real SSH-signed annotated tag over the tooling commit.
  const sourceCommit = git(checkout, "rev-parse", "HEAD");
  execFileSync("git", [
    "-c", "gpg.format=ssh",
    "-c", `user.signingkey=${signingKey}`,
    "tag", "-s", familyTag, "-m", familyTag, sourceCommit,
  ], { cwd: checkout });
  const tagObject = git(checkout, "rev-parse", `refs/tags/${familyTag}`);

  const record = {
    schemaVersion: 1,
    repository,
    tag: familyTag,
    tagObject,
    sourceCommit,
    publicationStatus: blockedRecord ? "blocked" : "ready",
    ...(blockedRecord ? { blocker: "test safety stop" } : {}),
  };
  const recordFile = path.join(checkout, "release", "records", `${familyTag}.json`);
  fs.mkdirSync(path.dirname(recordFile), { recursive: true });
  writeJson(recordFile, record);
  git(checkout, "add", "release");
  git(checkout, "-c", "commit.gpgsign=false", "commit", "-m", "test: family authorization record");
  const workflowCommit = git(checkout, "rev-parse", "HEAD");

  // Artifact zips: ids 601-604 per target, 605 the signed SHA256SUMS. Drift
  // variants for the linux_amd64 artifact cover the negative paths.
  const artifactRows = [];
  const tarballBytes = {};
  const attestationBytes = {};
  const targetArtifactId = (target) => 601 + targets.indexOf(target);
  const driftIds = {
    "sums-mismatch": 611,
    "attestation-sha-drift": 612,
    "attestation-commit-drift": 613,
    "gate-fail": 614,
    "extra-file": 615,
    "attestation-file-drift": 616,
  };
  for (const target of targets) {
    const bytes = Buffer.from(`exact fixture bytes for ${target}\n`);
    tarballBytes[`nemo-control_${version}_${target}.tar.gz`] = bytes;
    const zip = artifactZip(api, targetArtifactId(target), target, sourceCommit, bytes, { attestationBytes });
    artifactRows.push({
      id: targetArtifactId(target),
      name: `nemo-control_${version}_${target}`,
      size_in_bytes: fs.statSync(zip).size,
      digest: `sha256:${sha256(fs.readFileSync(zip))}`,
      expired: false,
    });
  }
  const driftTarget = "linux_amd64";
  const driftBytes = tarballBytes[`nemo-control_${version}_${driftTarget}.tar.gz`];
  // Content-drift modes keep the artifact attestation bytes: their signed
  // manifest binds the drifted bytes (a run that honestly signed a bad
  // attestation), so the publisher's *content* checks are what must refuse.
  const driftSinks = {
    "attestation-sha-drift": {},
    "attestation-commit-drift": {},
    "gate-fail": {},
  };
  const driftSumsIds = {
    "attestation-sha-drift": 617,
    "attestation-commit-drift": 618,
    "gate-fail": 619,
  };
  const driftZips = {
    "sums-mismatch": artifactZip(api, driftIds["sums-mismatch"], driftTarget, sourceCommit,
      Buffer.from("bytes the signed manifest does not bind\n")),
    "attestation-sha-drift": artifactZip(api, driftIds["attestation-sha-drift"], driftTarget, sourceCommit,
      driftBytes, { attestationSha: "c".repeat(64), attestationBytes: driftSinks["attestation-sha-drift"] }),
    "attestation-commit-drift": artifactZip(api, driftIds["attestation-commit-drift"], driftTarget, sourceCommit,
      driftBytes, { attestationCommit: "d".repeat(40), attestationBytes: driftSinks["attestation-commit-drift"] }),
    "gate-fail": artifactZip(api, driftIds["gate-fail"], driftTarget, sourceCommit,
      driftBytes, { gates: [{ id: "installed-qualification", result: "fail" }], attestationBytes: driftSinks["gate-fail"] }),
    "extra-file": artifactZip(api, driftIds["extra-file"], driftTarget, sourceCommit,
      driftBytes, { extraFile: "unexpected-member.txt" }),
    // Internally valid but byte-different from what the signed manifest
    // binds: without the attestation's own sums entry this substitution is
    // invisible — fabricated "pass" metadata beside an authentic archive.
    "attestation-file-drift": artifactZip(api, driftIds["attestation-file-drift"], driftTarget, sourceCommit,
      driftBytes, {
        attestationRaw: `${JSON.stringify({
          attestation_version: 1,
          subject: {
            name: "nemo-control",
            platform: driftTarget,
            version,
            component_manifest_sha256: "a".repeat(64),
            transfer_manifest_sha256: "b".repeat(64),
            archive_sha256: sha256(driftBytes),
          },
          source: { commit: sourceCommit },
          gates: [{ id: "installed-qualification", result: "pass" }],
        })}\n`,
      }),
  };

  // The signed checksum manifest artifact: SHA256SUMS plus its real
  // nemo-control-release signature; the unsigned variant drops the signature.
  const sumsName = `nemo-control_${version}_SHA256SUMS`;
  const sumsDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemo-sums-"));
  const sumsFile = path.join(sumsDir, sumsName);
  // The manifest binds every published byte stream — tarballs and the
  // attestation sidecars alike — matching the workflow's signed inventory.
  const boundBytes = { ...tarballBytes, ...attestationBytes };
  fs.writeFileSync(
    sumsFile,
    Object.keys(boundBytes)
      .sort()
      .map((name) => `${sha256(boundBytes[name])}  ${name}`)
      .join("\n") + "\n",
  );
  execFileSync("ssh-keygen", ["-Y", "sign", "-n", "nemo-control-release", "-f", signingKey, sumsFile]);
  const signedDir = fs.mkdtempSync(path.join(os.tmpdir(), "nemo-sums-signed-"));
  fs.copyFileSync(sumsFile, path.join(signedDir, sumsName));
  fs.copyFileSync(`${sumsFile}.sig`, path.join(signedDir, `${sumsName}.sig`));
  const signedZip = path.join(api, "artifact-605.zip");
  execFileSync("zip", ["-q", "-j", signedZip, path.join(signedDir, sumsName), path.join(signedDir, `${sumsName}.sig`)]);
  const unsignedZip = path.join(api, "artifact-6150.zip");
  execFileSync("zip", ["-q", "-j", unsignedZip, sumsFile]);

  // Content-drift modes sign their drifted attestation honestly: the
  // manifest authenticates, so refusal has to come from the publisher's
  // attestation content checks rather than its integrity check.
  const driftSumsZips = {};
  for (const [mode, sink] of Object.entries(driftSinks)) {
    const driftBound = { ...boundBytes, ...sink };
    const modeDir = fs.mkdtempSync(path.join(os.tmpdir(), `nemo-sums-${mode}-`));
    const modeSumsFile = path.join(modeDir, sumsName);
    fs.writeFileSync(
      modeSumsFile,
      Object.keys(driftBound)
        .sort()
        .map((name) => `${sha256(driftBound[name])}  ${name}`)
        .join("\n") + "\n",
    );
    execFileSync("ssh-keygen", ["-Y", "sign", "-n", "nemo-control-release", "-f", signingKey, modeSumsFile]);
    const modeZip = path.join(api, `artifact-${driftSumsIds[mode]}.zip`);
    execFileSync("zip", ["-q", "-j", modeZip, modeSumsFile, `${modeSumsFile}.sig`]);
    driftSumsZips[mode] = modeZip;
  }
  artifactRows.push({
    id: 605,
    name: "nemo-control_SHA256SUMS",
    size_in_bytes: fs.statSync(signedZip).size,
    digest: `sha256:${sha256(fs.readFileSync(signedZip))}`,
    expired: false,
  });
  fs.rmSync(sumsDir, { recursive: true, force: true });
  fs.rmSync(signedDir, { recursive: true, force: true });

  writeJson(path.join(api, "artifacts.json"), { total_count: artifactRows.length, artifacts: artifactRows });
  const missingRows = artifactRows.filter((row) => row.id !== targetArtifactId("linux_arm64"));
  writeJson(path.join(api, "artifacts-missing.json"), { total_count: missingRows.length, artifacts: missingRows });
  const unsignedRows = artifactRows.map((row) => row.id === 605
    ? { ...row, size_in_bytes: fs.statSync(unsignedZip).size, digest: `sha256:${sha256(fs.readFileSync(unsignedZip))}` }
    : row);
  writeJson(path.join(api, "artifacts-unsigned.json"), { total_count: unsignedRows.length, artifacts: unsignedRows });
  // Each drift mode models the run itself having produced bad bytes: the
  // inventory row for that artifact describes the drifted zip, and the zip
  // endpoint serves it — the failure must come from the family proof checks,
  // not the upstream artifact-integrity gate.
  for (const [mode, driftZip] of Object.entries(driftZips)) {
    const rows = artifactRows.map((row) => {
      if (row.id === targetArtifactId(driftTarget)) {
        return { ...row, size_in_bytes: fs.statSync(driftZip).size, digest: `sha256:${sha256(fs.readFileSync(driftZip))}` };
      }
      // The mode's own signed checksum manifest is a different zip — its
      // declared size and digest describe that artifact.
      if (row.id === 605 && driftSumsZips[mode]) {
        const sumsZip = driftSumsZips[mode];
        return { ...row, size_in_bytes: fs.statSync(sumsZip).size, digest: `sha256:${sha256(fs.readFileSync(sumsZip))}` };
      }
      return row;
    });
    writeJson(path.join(api, `artifacts-${mode}.json`), { total_count: rows.length, artifacts: rows });
  }

  writeJson(path.join(api, "repository.json"), { full_name: repository, default_branch: "main" });
  writeJson(path.join(api, "branch.json"), {
    name: "main",
    protected: true,
    commit: { sha: workflowCommit },
  });
  writeJson(path.join(api, "ruleset-list.json"), [{ id: 702 }, { id: 703 }, { id: 705 }]);
  writeJson(path.join(api, "ruleset-tag.json"), {
    id: 702,
    target: "tag",
    enforcement: "active",
    bypass_actors: [],
    conditions: { ref_name: { include: ["refs/tags/nemo-v*"], exclude: [] } },
    rules: [{ type: "deletion" }, { type: "non_fast_forward" }],
  });
  writeJson(path.join(api, "ruleset-tag-kernel-only.json"), {
    id: 702,
    target: "tag",
    enforcement: "active",
    bypass_actors: [],
    conditions: { ref_name: { include: ["refs/tags/v*"], exclude: [] } },
    rules: [{ type: "deletion" }, { type: "non_fast_forward" }],
  });
  writeJson(path.join(api, "ruleset-branch-history.json"), {
    id: 703,
    target: "branch",
    enforcement: "active",
    bypass_actors: [],
    conditions: { ref_name: { include: ["~DEFAULT_BRANCH"], exclude: [] } },
    rules: [{ type: "deletion" }, { type: "non_fast_forward" }],
  });
  writeJson(path.join(api, "ruleset-branch-check.json"), {
    id: 705,
    source_type: "Repository",
    source: repository,
    target: "branch",
    enforcement: "active",
    bypass_actors: [],
    conditions: { ref_name: { include: ["~DEFAULT_BRANCH"], exclude: [] } },
    rules: [
      {
        type: "required_status_checks",
        parameters: {
          strict_required_status_checks_policy: true,
          required_status_checks: [{ context: "Release Check", integration_id: 15368 }],
        },
      },
    ],
  });
  writeJson(path.join(api, "tag-ref.json"), {
    ref: `refs/tags/${familyTag}`,
    object: {
      type: "tag",
      sha: tagObject,
      url: `https://api.github.com/repos/${repository}/git/tags/${tagObject}`,
    },
  });
  writeJson(path.join(api, "tag-object.json"), {
    tag: familyTag,
    object: {
      type: "commit",
      sha: sourceCommit,
      url: `https://api.github.com/repos/${repository}/git/commits/${sourceCommit}`,
    },
    verification: { verified: true, reason: "valid" },
  });
  writeJson(path.join(api, "tag-object-unsigned.json"), {
    tag: familyTag,
    object: {
      type: "commit",
      sha: sourceCommit,
      url: `https://api.github.com/repos/${repository}/git/commits/${sourceCommit}`,
    },
    verification: { verified: false, reason: "unsigned" },
  });
  writeJson(path.join(api, "run.json"), {
    id: runId,
    conclusion: "success",
    event: "push",
    head_sha: sourceCommit,
    workflow_id: workflowId,
  });
  writeJson(path.join(api, "run-failed.json"), {
    id: runId,
    conclusion: "failure",
    event: "push",
    head_sha: sourceCommit,
    workflow_id: workflowId,
  });
  writeJson(path.join(api, "workflow.json"), {
    id: workflowId,
    name: "NEMO Distribution",
    path: ".github/workflows/nemo-distribution.yml",
    state: "active",
  });
  writeJson(path.join(api, "workflow-wrong.json"), {
    id: workflowId,
    name: "Verify Release Assets",
    path: ".github/workflows/release-assets.yml",
    state: "active",
  });
  writeJson(path.join(api, "release-pre-existing.json"), {
    id: 999,
    tag_name: familyTag,
    draft: false,
    immutable: true,
  });
  writeJson(path.join(api, "release-state.json"), { assets: [] });

  const gh = path.join(bin, "gh");
  fs.writeFileSync(
    gh,
    `#!/usr/bin/env node
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const args = process.argv.slice(2);
const api = process.env.MOCK_API;
const log = (line) => fs.appendFileSync(process.env.MOCK_LOG, line + "\\n");
const json = (name) => JSON.parse(fs.readFileSync(path.join(api, name), "utf8"));
const outputJson = (value) => process.stdout.write(JSON.stringify(value));
const outputFile = (name) => process.stdout.write(fs.readFileSync(path.join(api, name)));
const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");
const tag = ${JSON.stringify(familyTag)};
const releaseId = ${releaseId};

function readRelease(dir) {
  return JSON.parse(fs.readFileSync(path.join(dir, "release-state.json"), "utf8"));
}
function writeRelease(dir, release) {
  fs.writeFileSync(path.join(dir, "release-state.json"), JSON.stringify(release));
}

if (args[0] === "release") {
  const sub = args[1];
  const tagArg = args[2];
  if (sub === "create") {
    log("release\\tcreate");
    if (tagArg !== tag) process.exit(95);
    if (fs.existsSync(path.join(api, "release-created"))) process.exit(95);
    fs.writeFileSync(path.join(api, "release-created"), "yes\\n");
    const notesFile = args[args.indexOf("--notes-file") + 1];
    const release = {
      id: releaseId,
      tag_name: tagArg,
      name: args[args.indexOf("--title") + 1],
      body: fs.readFileSync(notesFile, "utf8"),
      draft: true,
      prerelease: false,
      immutable: false,
      target_commitish: "${sourceCommit}",
      assets: [],
    };
    writeRelease(api, release);
    process.stdout.write("https://example.test/releases/" + tagArg);
    process.exit(0);
  }
  if (sub === "upload") {
    log("release\\tupload");
    if (tagArg !== tag) process.exit(95);
    const release = readRelease(api);
    let nextId = 7000;
    for (let i = 3; i < args.length; i++) {
      if (args[i] === "--repo") { i++; continue; }
      const bytes = fs.readFileSync(args[i]);
      release.assets.push({
        id: nextId++,
        name: path.basename(args[i]),
        size: bytes.length,
        state: "uploaded",
        digest: "sha256:" + sha256(bytes),
      });
    }
    writeRelease(api, release);
    process.exit(0);
  }
  process.exit(96);
}

if (args.shift() !== "api") process.exit(90);
const methodIndex = args.indexOf("--method");
const method = methodIndex >= 0 ? args[methodIndex + 1] : "GET";
const endpoint = args.find((arg) => arg.startsWith("repos/"));
log(method + "\\t" + endpoint);

if (method === "PATCH") {
  if (endpoint !== "repos/${repository}/releases/" + releaseId) process.exit(91);
  const inputIndex = args.indexOf("--input");
  if (inputIndex < 0 || fs.readFileSync(args[inputIndex + 1], "utf8") !== '{"draft":false}\\n') process.exit(92);
  fs.writeFileSync(path.join(api, "published"), "yes\\n");
  const value = readRelease(api);
  value.draft = false;
  value.immutable = true;
  writeRelease(api, value);
  outputJson(value);
  process.exit(0);
}
if (method !== "GET") process.exit(93);
const published = fs.existsSync(path.join(api, "published"));
const created = fs.existsSync(path.join(api, "release-created"));

if (endpoint === "repos/${repository}") outputFile("repository.json");
else if (endpoint === "repos/${repository}/branches/main") outputFile("branch.json");
else if (endpoint === "repos/${repository}/rulesets?per_page=100") outputFile("ruleset-list.json");
else if (endpoint === "repos/${repository}/rulesets/702") {
  outputFile(process.env.MOCK_MODE === "tag-rules-missing" ? "ruleset-tag-kernel-only.json" : "ruleset-tag.json");
}
else if (endpoint === "repos/${repository}/rulesets/703") outputFile("ruleset-branch-history.json");
else if (endpoint === "repos/${repository}/rulesets/705") outputFile("ruleset-branch-check.json");
else if (endpoint === "repos/${repository}/git/ref/tags/" + tag) outputFile("tag-ref.json");
else if (endpoint.startsWith("repos/${repository}/git/tags/")) {
  outputFile(process.env.MOCK_MODE === "unsigned-tag" ? "tag-object-unsigned.json" : "tag-object.json");
}
else if (endpoint === "repos/${repository}/actions/runs/${runId}") {
  outputFile(process.env.MOCK_MODE === "failed-run" ? "run-failed.json" : "run.json");
}
else if (endpoint === "repos/${repository}/actions/workflows/${workflowId}") {
  outputFile(process.env.MOCK_MODE === "wrong-workflow" ? "workflow-wrong.json" : "workflow.json");
}
else if (endpoint === "repos/${repository}/actions/runs/${runId}/artifacts?per_page=100") {
  const driftModes = ["sums-mismatch", "attestation-sha-drift", "attestation-commit-drift", "gate-fail", "extra-file", "attestation-file-drift"];
  outputFile(
    process.env.MOCK_MODE === "missing-artifact"
      ? "artifacts-missing.json"
      : process.env.MOCK_MODE === "unsigned-sums"
        ? "artifacts-unsigned.json"
        : driftModes.includes(process.env.MOCK_MODE)
          ? "artifacts-" + process.env.MOCK_MODE + ".json"
          : "artifacts.json",
  );
}
else if (endpoint.startsWith("repos/${repository}/actions/artifacts/") && endpoint.endsWith("/zip")) {
  const id = endpoint.split("/")[5];
  const driftIds = { "sums-mismatch": "611", "attestation-sha-drift": "612", "attestation-commit-drift": "613", "gate-fail": "614", "extra-file": "615", "attestation-file-drift": "616" };
  const driftSumsIds = { "attestation-sha-drift": "617", "attestation-commit-drift": "618", "gate-fail": "619" };
  let requested = driftIds[process.env.MOCK_MODE] && id === "603" ? driftIds[process.env.MOCK_MODE] : id;
  if (id === "605" && driftSumsIds[process.env.MOCK_MODE]) requested = driftSumsIds[process.env.MOCK_MODE];
  const file = process.env.MOCK_MODE === "unsigned-sums" && id === "605" ? "artifact-6150.zip" : "artifact-" + requested + ".zip";
  if (!fs.existsSync(path.join(api, file))) process.exit(97);
  outputFile(file);
}
else if (endpoint === "repos/${repository}/immutable-releases") {
  outputJson({ enabled: process.env.MOCK_MODE !== "immutable-disabled" });
}
else if (endpoint === "repos/${repository}/releases/tags/" + tag) {
  if (process.env.MOCK_MODE === "existing-release") { outputFile("release-pre-existing.json"); process.exit(0); }
  if (!created) process.exit(1);
  outputJson(readRelease(api));
}
else if (endpoint === "repos/${repository}/releases/" + releaseId) {
  const value = readRelease(api);
  if (published) {
    if (process.env.MOCK_MODE === "public-readback-drift") value.assets[0].digest = "sha256:" + "e".repeat(64);
  } else if (process.env.MOCK_MODE === "prepatch-drift") {
    const countFile = path.join(api, "release-id-get-count");
    const count = fs.existsSync(countFile) ? Number(fs.readFileSync(countFile, "utf8")) + 1 : 1;
    fs.writeFileSync(countFile, String(count));
    if (count >= 1) value.assets[0].digest = "sha256:" + "f".repeat(64);
  }
  outputJson(value);
}
else process.exit(94);
`,
  );
  fs.chmodSync(gh, 0o755);

  const log = path.join(root, "gh.log");
  const run = (mode) => {
    const childEnv = {
      ...process.env,
      PATH: `${bin}:${process.env.PATH}`,
      MOCK_API: api,
      MOCK_LOG: log,
      MOCK_MODE: mode,
    };
    return spawnSync(
      "bash",
      [
        path.join(checkout, "scripts", "publish-nemo-release.sh"),
        familyTag,
        tagObject,
        sourceCommit,
        workflowCommit,
        String(runId),
        familyTag,
      ],
      { cwd: checkout, env: childEnv, encoding: "utf8" },
    );
  };
  const mutations = () => {
    if (!fs.existsSync(log)) return [];
    return fs
      .readFileSync(log, "utf8")
      .trim()
      .split("\n")
      .filter(Boolean)
      .filter((line) => !line.startsWith("GET\t"));
  };
  const releaseState = () => JSON.parse(fs.readFileSync(path.join(api, "release-state.json"), "utf8"));
  return { api, checkout, mutations, releaseState, root, run };
}

function withFixture(options, callback) {
  const fixture = prepareFixture(options);
  try {
    callback(fixture);
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
}

testWithSshTags("publishes the verified family on the signed nemo-v tag", () => {
  withFixture({}, ({ mutations, releaseState, run }) => {
    const result = run("ok");
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Published exact verified nemo-control release nemo-v9\.9\.9/);
    const release = releaseState();
    assert.equal(release.draft, false);
    assert.equal(release.tag_name, familyTag);
    assert.equal(release.assets.length, 10);
    assert.deepEqual(
      mutations().filter((line) => line.startsWith("PATCH")),
      [`PATCH\trepos/${repository}/releases/${releaseId}`],
    );
    assert.ok(mutations().includes("release\tcreate"));
    assert.ok(mutations().includes("release\tupload"));
  });
});

// Every pre-mutation failure must refuse before the first remote write —
// no draft, no upload, no PATCH.
for (const [mode, reason] of [
  ["tag-rules-missing", "release tags lack"],
  ["unsigned-tag", "signature or peeled commit"],
  ["failed-run", "successful push run"],
  ["wrong-workflow", "NEMO distribution workflow"],
  ["missing-artifact", "artifact inventory"],
  ["unsigned-sums", "manifest and its signature"],
  ["sums-mismatch", "signed SHA256SUMS"],
  ["attestation-sha-drift", "does not bind"],
  ["attestation-commit-drift", "does not bind"],
  ["attestation-file-drift", "does not match the signed SHA256SUMS"],
  ["gate-fail", "does not bind"],
  ["extra-file", "exactly the tarball and its attestation"],
  ["immutable-disabled", "release immutability"],
  ["existing-release", "already exists"],
]) {
  testWithSshTags(`refuses before mutation when ${mode}`, () => {
    withFixture({}, ({ mutations, run }) => {
      const result = run(mode);
      assert.notEqual(result.status, 0, `expected refusal, got: ${result.stdout}`);
      assert.match(result.stderr, new RegExp(reason, "i"));
      assert.deepEqual(mutations(), []);
    });
  });
}

testWithSshTags("refuses a blocked authorization record", () => {
  withFixture({ blockedRecord: true }, ({ mutations, run }) => {
    const result = run("ok");
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /blocked/i);
    assert.deepEqual(mutations(), []);
  });
});

testWithSshTags("refuses to publish a draft whose remote inventory drifted", () => {
  withFixture({}, ({ mutations, run }) => {
    const result = run("prepatch-drift");
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /remote asset inventory/);
    // The draft and uploads already happened; the sole PATCH must not.
    assert.equal(mutations().filter((line) => line.startsWith("PATCH")).length, 0);
    assert.ok(mutations().includes("release\tcreate"));
  });
});

testWithSshTags("reports a post-publication readback mismatch as an incident", () => {
  withFixture({}, ({ mutations, run }) => {
    const result = run("public-readback-drift");
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /remote asset inventory/);
    // Publication raced the final read — the PATCH ran; that is the
    // incident the contract documents, not a silent retry.
    assert.ok(mutations().some((line) => line.startsWith("PATCH")));
  });
});
