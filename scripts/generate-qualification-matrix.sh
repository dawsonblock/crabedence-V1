#!/usr/bin/env bash
# Generate qualification-matrix.md from qualification.json.
# The JSON is the source of truth; Markdown is presentation.
# Usage: ./scripts/generate-qualification-matrix.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
QUAL_FILE="$REPO_ROOT/release-evidence/qualification.json"
OUTPUT="$REPO_ROOT/release-evidence/qualification-matrix.md"

if [ ! -f "$QUAL_FILE" ]; then
  echo "ERROR: qualification.json not found at $QUAL_FILE" >&2
  echo "Run scripts/generate-release-evidence.sh first." >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required" >&2
  exit 1
fi

COMMIT="$(jq -r '.source.commit' "$QUAL_FILE")"
TREE="$(jq -r '.source.tree' "$QUAL_FILE")"
BRANCH="$(jq -r '.source.branch' "$QUAL_FILE")"
DATE="$(jq -r '.environment.date' "$QUAL_FILE")"
GO_VER="$(jq -r '.toolchains.go' "$QUAL_FILE")"
NODE_VER="$(jq -r '.toolchains.node' "$QUAL_FILE")"
RELEASE_STATUS="$(jq -r '.release_status' "$QUAL_FILE")"
PASSED="$(jq -r '.gate_summary.passed' "$QUAL_FILE")"
TOTAL="$(jq -r '.gate_summary.total' "$QUAL_FILE")"
FAILED="$(jq -r '.gate_summary.failed' "$QUAL_FILE")"

{
  echo "# Crabedence V1 Hardening — Qualification Matrix"
  echo ""
  echo "**Branch:** \`$BRANCH\`"
  echo "**Source commit:** \`$COMMIT\`"
  echo "**Git tree:** \`$TREE\`"
  echo "**Date:** $DATE"
  echo "**Release status:** $RELEASE_STATUS ($PASSED/$TOTAL gates passed)"
  echo ""
  echo "## Toolchains"
  echo ""
  echo "| Tool | Version |"
  echo "|------|---------|"
  echo "| Go | $GO_VER |"
  echo "| Node | $NODE_VER |"
  echo ""
  echo "## Gate Results"
  echo ""
  echo "| Gate | Status | Log |"
  echo "|------|--------|-----|"

  GATE_COUNT="$(jq '.gates | length' "$QUAL_FILE")"
  for i in $(seq 0 $((GATE_COUNT - 1))); do
    name="$(jq -r ".gates[$i].name" "$QUAL_FILE")"
    status="$(jq -r ".gates[$i].status" "$QUAL_FILE")"
    log="$(jq -r ".gates[$i].log" "$QUAL_FILE")"
    echo "| \`$name\` | $status | \`$log\` |"
  done

  echo ""
  echo "## Release Invariants"
  echo ""

  INV_COUNT="$(jq '.invariants | length' "$QUAL_FILE")"
  for i in $(seq 0 $((INV_COUNT - 1))); do
    inv_id="$(jq -r ".invariants[$i].id" "$QUAL_FILE")"
    inv_desc="$(jq -r ".invariants[$i].description" "$QUAL_FILE")"
    echo "- **$inv_id:** $inv_desc"
  done

  echo ""
  echo "## Provenance"
  echo ""
  echo "- Commit: \`$COMMIT\`"
  echo "- Tree: \`$TREE\`"
  echo "- Branch: \`$BRANCH\`"
  echo "- Dirty: false (clean working tree required)"
  echo ""
  echo "## Verification"
  echo ""
  echo "To verify this release artifact:"
  echo ""
  echo '```bash'
  echo "./scripts/verify-release-artifact.sh"
  echo '```'
  echo ""
  echo "To check release admission:"
  echo ""
  echo '```bash'
  echo "./scripts/check-release-admission.sh"
  echo '```'
} > "$OUTPUT"

echo "Generated $OUTPUT from $QUAL_FILE"
