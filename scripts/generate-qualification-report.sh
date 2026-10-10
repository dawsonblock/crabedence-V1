#!/usr/bin/env bash
# Render FINAL_QUALIFICATION_REPORT.md from the machine-readable
# qualification records. The Markdown is a VIEW over
# qualification.json / release-manifest.json / evidence-root.json —
# never the source of truth. A report that says PASS is only as good as
# the signed evidence root behind it.
#
# Usage: generate-qualification-report.sh [evidence-dir] [output.md]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVIDENCE_DIR="$(cd "${1:-$REPO_ROOT/dist/release-evidence}" && pwd)"
OUT="${2:-$EVIDENCE_DIR/FINAL_QUALIFICATION_REPORT.md}"

QUAL="$EVIDENCE_DIR/qualification.json"
RELMAN="$EVIDENCE_DIR/release-manifest.json"
ROOT_DOC="$EVIDENCE_DIR/evidence-root.json"
[ -f "$QUAL" ] || { echo "generate-qualification-report: no qualification.json in $EVIDENCE_DIR" >&2; exit 1; }

RELEASE_NAME="$(jq -r '.release_name // "crabedence-release"' "$RELMAN" 2>/dev/null || echo crabedence-release)"
RELEASE_VERSION="$(jq -r '.release_version // "unknown"' "$RELMAN" 2>/dev/null || echo unknown)"
STATUS="$(jq -r '.release_status' "$QUAL")"
PROMOTABLE="$(jq -r '.artifact_promotable' "$QUAL")"
COMMIT="$(jq -r '.provenance.commit' "$QUAL")"
TREE="$(jq -r '.provenance.tree' "$QUAL")"
BRANCH="$(jq -r '.provenance.branch' "$QUAL")"
# The report carries the qualification run's timestamp, not the wall
# clock — regenerating unchanged records must produce identical bytes.
STAMP="$(jq -r '.provenance.timestamp // "unknown"' "$QUAL")"
ROOT_SHA="not generated"
[ -f "$ROOT_DOC" ] && ROOT_SHA="$(jq -r '.root_sha256' "$ROOT_DOC")"

{
  cat <<EOF
# Final Qualification Report — ${RELEASE_NAME}

**Generated from machine-readable records — do not edit by hand.**
Source of truth: \`qualification.json\`, \`release-manifest.json\`,
\`gates/*.json\`, \`gate-results/*.log\`, \`SHA256SUMS\`, and
\`evidence-root.json\` in this evidence directory.

| Field | Value |
|---|---|
| Release | ${RELEASE_NAME} (${RELEASE_VERSION}) |
| Status | **${STATUS}** |
| Artifact promotable | ${PROMOTABLE} |
| Source commit | \`${COMMIT}\` |
| Source tree | \`${TREE}\` |
| Branch | \`${BRANCH}\` |
| Qualified at | ${STAMP} |
| Evidence root SHA-256 | \`${ROOT_SHA}\` |

## Gate summary

| Total | Passed | Failed | Skipped |
|---|---|---|---|
| $(jq -r '.gate_summary.total' "$QUAL") | $(jq -r '.gate_summary.passed' "$QUAL") | $(jq -r '.gate_summary.failed' "$QUAL") | $(jq -r '.gate_summary.skipped' "$QUAL") |

## Gates

Every gate's result is bound to the SHA-256 of its captured log; each
log is in turn covered by SHA256SUMS and the signed evidence root.

| Gate | Type | Mandatory | Status | Exit | Tests | Duration (ms) | Log SHA-256 |
|---|---|---|---|---|---|---|---|
EOF

  jq -r '.gates[] | "| \(.gate_id) | \(.gate_type) | \(.mandatory) | \(.status) | \(.exit_code) | \(.tests_executed // 0) | \(.duration_ms) | `\(.evidence.sha256[0:16])…` |"' "$QUAL"

  cat <<'EOF'

## Verification

From a checkout containing this evidence directory:

```sh
# 1. Every evidence file matches its recorded checksum.
(cd dist/release-evidence && shasum -a 256 -c SHA256SUMS)

# 2. The semantic evidence root honestly covers the bundle's identity
#    bindings and its root_sha256 covers the stored document.
python3 scripts/generate-evidence-root.py --verify dist/release-evidence

# 3. The extracted source archive qualifies standalone (the archive
#    carries its own embedded source manifest):
tar xzf <source-archive>.tar.gz -C <clean-room>
bash <clean-room>/<prefix>/scripts/qualify-source-distribution.sh <clean-room>/<prefix>
```

## Invariants asserted by this qualification

EOF

  jq -r '.invariants[] | "- **\(.id)** — \(.description)"' "$QUAL"

  cat <<EOF

## Toolchains

EOF
  jq -r '.toolchains | to_entries[] | "- \(.key): \(.value)"' "$QUAL"
  cat <<EOF

## Environment

EOF
  jq -r '.environment | to_entries[] | "- \(.key): \(.value)"' "$QUAL"
  cat <<EOF

---

_Generated from records qualified at ${STAMP}. If any
figure here disagrees with the JSON records, the JSON records win._
EOF
} > "$OUT"

echo "generate-qualification-report: wrote $OUT"
