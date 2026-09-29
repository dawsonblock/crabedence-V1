import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const repoRoot = path.resolve(import.meta.dirname, "..");
const workflow = fs.readFileSync(
  path.join(repoRoot, ".github", "workflows", "daytona-snapshot-bootstrap.yml"),
  "utf8",
);

test("Daytona snapshot bootstrap is protected, manual, and serialized", () => {
  assert.match(workflow, /^  workflow_dispatch:$/m);
  assert.doesNotMatch(workflow, /^  (?:push|pull_request|schedule):/m);
  assert.match(workflow, /environment: image-publisher/);
  assert.match(workflow, /group: daytona-snapshot-bootstrap/);
  assert.match(workflow, /cancel-in-progress: false/);
  assert.match(
    workflow,
    /expected_workflow_ref="\$GITHUB_REPOSITORY\/\.github\/workflows\/daytona-snapshot-bootstrap\.yml@\$expected_ref"/,
  );
  assert.match(workflow, /\[\[ "\$GITHUB_REF" == "\$expected_ref" \]\]/);
  assert.match(workflow, /\[\[ "\$REF_PROTECTED" == true \]\]/);
  assert.match(workflow, /\[\[ "\$WORKFLOW_SHA" == "\$RUN_SHA" \]\]/);
  assert.match(workflow, /ref: \$\{\{ github\.workflow_sha \}\}/);
  assert.match(workflow, /persist-credentials: false/);
});

test("workflow accepts bounded inputs and requires explicit confirmation", () => {
  for (const input of ["name", "cpu", "memoryGiB", "diskGiB", "baseImage", "confirm"]) {
    assert.match(workflow, new RegExp(`^      ${input}:$`, "m"));
  }
  assert.match(workflow, /\[\[ "\$CONFIRM" == create \]\]/);
  assert.match(workflow, /\[\[ "\$CPU" =~ \^\[1-4\]\$ \]\]/);
  assert.match(workflow, /\[\[ "\$MEMORY_GIB" =~ \^\[1-8\]\$ \]\]/);
  assert.match(workflow, /\[\[ "\$DISK_GIB" =~ \^\(\[3-9\]\|10\)\$ \]\]/);
  assert.match(workflow, /@sha256:\[a-f0-9\]\{64\}\$/);
});

test("workflow uses broker admin auth without exposing provider credentials", () => {
  assert.match(workflow, /CRABBOX_COORDINATOR: \$\{\{ vars\.CRABBOX_COORDINATOR \}\}/);
  assert.match(
    workflow,
    /CRABBOX_COORDINATOR_ADMIN_TOKEN: \$\{\{ secrets\.CRABBOX_COORDINATOR_ADMIN_TOKEN \}\}/,
  );
  assert.match(workflow, /printf 'Authorization: Bearer '/);
  assert.match(workflow, /-H @-/);
  assert.match(workflow, /--data-binary @"\$payload"/);
  assert.match(workflow, /\/v1\/admin\/providers\/daytona\/snapshot-bootstrap/);
  assert.doesNotMatch(
    workflow,
    /DAYTONA_API_KEY|DAYTONA_CRABBOX_KEY|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY/,
  );
});

test("workflow verifies exact resources and uploads only sanitized proof", () => {
  assert.match(workflow, /\.snapshot\.sourceSnapshot == \$baseImage/);
  assert.match(workflow, /\.snapshot\.sourceCPU == \$cpu/);
  assert.match(workflow, /\.snapshot\.sourceMemoryGiB == \$memoryGiB/);
  assert.match(workflow, /\.snapshot\.sourceDiskGiB == \$diskGiB/);
  assert.match(workflow, /\.snapshot\.cleanup == "deleted"/);
  assert.match(workflow, /Upload sanitized snapshot proof/);
  assert.match(workflow, /path: \$\{\{ runner\.temp \}\}\/daytona-snapshot-proof/);
  assert.doesNotMatch(workflow, /path: \$\{\{ runner\.temp \}\}\/daytona-snapshot-response\.json/);
  assert.doesNotMatch(workflow, /sandboxID/);
});
