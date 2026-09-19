#!/usr/bin/env bash
# Finalize the release evidence bundle after artifact.json exists.
#
# generate-release-evidence.sh produces the qualification bundle together
# with its SHA256SUMS and evidence-manifest.json BEFORE the release archive
# is built — artifact.json (which binds the archive digest to the qualified
# source and the capability registry digest) cannot exist yet, so the
# generator excludes it. The release workflow writes artifact.json after
# the archive, which leaves the bundle's checksum manifest and identity
# digest NOT covering the artifact binding.
#
# This script closes that gap: artifact.json -> final evidence manifest
# -> attestation.
#
#   1. Requires artifact.json (fail closed — this is the release path;
#      qualification-only bundles keep the generator's SHA256SUMS).
#   2. Regenerates SHA256SUMS over every evidence file except SHA256SUMS
#      and evidence-manifest.json, INCLUDING artifact.json.
#   3. Requires artifact.json to be listed in SHA256SUMS.
#   4. Regenerates evidence-manifest.json from the new SHA256SUMS,
#      preserving the source identity fields.
#   5. Verifies the final state: checksums verify, the manifest digest
#      matches SHA256(SHA256SUMS), and the file count matches.
#
# A stale attestation reference (attestation/) is removed: it attested a
# superseded manifest and must not ship with the final bundle. The
# attestation of the FINAL manifest is created downstream, after this
# script returns.
#
# Usage: ./scripts/finalize-release-evidence.sh [evidence-dir]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVIDENCE_DIR="${1:-$REPO_ROOT/dist/release-evidence}"

if [ ! -d "$EVIDENCE_DIR" ]; then
  echo "ERROR: evidence directory not found: $EVIDENCE_DIR" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required to finalize release evidence" >&2
  exit 1
fi

ARTIFACT_JSON="$EVIDENCE_DIR/artifact.json"
if [ ! -f "$ARTIFACT_JSON" ]; then
  echo "ERROR: artifact.json is required to finalize release evidence" >&2
  echo "       (qualification-only bundles do not finalize; the release path must bind the artifact)" >&2
  exit 1
fi

# ─── Source identity: preserve the qualified identity, never re-derive it ──
MANIFEST="$EVIDENCE_DIR/evidence-manifest.json"
PROVENANCE="$EVIDENCE_DIR/provenance.json"
read_identity() {
  local field="$1" value=""
  if [ -f "$MANIFEST" ]; then
    value="$(jq -r --arg f "$field" '.[$f] // empty' "$MANIFEST" 2>/dev/null || true)"
  fi
  if [ -z "$value" ] && [ -f "$PROVENANCE" ]; then
    value="$(jq -r --arg f "$field" '.[$f] // empty' "$PROVENANCE" 2>/dev/null || true)"
  fi
  printf '%s' "$value"
}

RELEASE_NAME="$(read_identity name)"
if [ -z "$RELEASE_NAME" ]; then
  RELEASE_NAME="crabedence-release"
fi
COMMIT="$(read_identity commit)"
TREE="$(read_identity tree)"
BRANCH="$(read_identity branch)"
if [ -z "$COMMIT" ] || [ -z "$TREE" ]; then
  echo "ERROR: cannot finalize evidence without a source identity (commit/tree)" >&2
  echo "       expected in evidence-manifest.json or provenance.json" >&2
  exit 1
fi

# ─── A superseded attestation reference must not ship ─────────────────────
if [ -d "$EVIDENCE_DIR/attestation" ]; then
  echo "  note: removing stale attestation reference (it attested a superseded manifest)"
  rm -rf "$EVIDENCE_DIR/attestation"
fi

# ─── Regenerate SHA256SUMS over the final bundle ──────────────────────────
# Same traversal as generate-release-evidence.sh, with artifact.json now
# INCLUDED. SHA256SUMS and evidence-manifest.json stay excluded: the
# manifest's digest is computed FROM SHA256SUMS, so including either
# would create a self-invalidating cycle.
cd "$EVIDENCE_DIR"
find . -type f ! -name SHA256SUMS ! -name evidence-manifest.json -print0 \
  | sort -z | xargs -0 shasum -a 256 > SHA256SUMS

# The release artifact binding must be inside the manifest — not merely
# present in the directory.
if ! grep -qE '[[:space:]]\./artifact\.json$' SHA256SUMS; then
  echo "ERROR: artifact.json is not listed in the regenerated SHA256SUMS" >&2
  exit 1
fi

if ! shasum -a 256 -c SHA256SUMS >/dev/null 2>&1; then
  echo "ERROR: regenerated SHA256SUMS does not verify" >&2
  exit 1
fi

# ─── Regenerate the evidence identity digest ──────────────────────────────
EVIDENCE_SHA="$(shasum -a 256 SHA256SUMS | awk '{print $1}')"
MANIFEST_FILE_COUNT="$(wc -l < SHA256SUMS | tr -d ' ')"
GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

jq -n \
  --arg name "$RELEASE_NAME" \
  --arg sha "$EVIDENCE_SHA" \
  --argjson count "$MANIFEST_FILE_COUNT" \
  --arg commit "$COMMIT" \
  --arg tree "$TREE" \
  --arg branch "$BRANCH" \
  --arg generated "$GENERATED_AT" \
  '{
    name: $name,
    manifest_type: "evidence-bundle",
    sha256: $sha,
    digest_of: "SHA256SUMS",
    file_count: $count,
    commit: $commit,
    tree: $tree,
    branch: $branch,
    generated_at: $generated
  }' > "$MANIFEST"

# ─── Verify the final state ───────────────────────────────────────────────
FINAL_SHA="$(jq -r '.sha256' "$MANIFEST")"
ACTUAL_SHA="$(shasum -a 256 SHA256SUMS | awk '{print $1}')"
if [ "$FINAL_SHA" != "$ACTUAL_SHA" ]; then
  echo "ERROR: evidence-manifest.json digest does not match SHA256SUMS" >&2
  exit 1
fi
FINAL_COUNT="$(jq -r '.file_count' "$MANIFEST")"
if [ "$FINAL_COUNT" != "$MANIFEST_FILE_COUNT" ]; then
  echo "ERROR: evidence-manifest.json file_count ($FINAL_COUNT) does not match SHA256SUMS ($MANIFEST_FILE_COUNT)" >&2
  exit 1
fi

echo ""
echo "=== Release Evidence Finalized ==="
echo "  artifact.json covered by SHA256SUMS"
echo "  evidence-manifest.json sha256: $FINAL_SHA"
echo "  evidence files: $FINAL_COUNT"
echo ""
