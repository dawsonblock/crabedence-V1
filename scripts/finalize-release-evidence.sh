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
# Determinism contract: unchanged evidence inputs produce byte-identical
# evidence-root.json, FINAL_QUALIFICATION_REPORT.md, SHA256SUMS and
# evidence-manifest.json on any host, at any wall-clock time, in any
# locale or timezone, at any directory path. Every generated timestamp is
# bound to the qualification record's own timestamp, never to the clock;
# the canonical traversal excludes hidden and temporary working entries and
# sorts with LC_ALL=C. A hidden or non-regular member is refused rather than
# silently pruned — the one inventory rule in
# scripts/lib/evidence-inventory.sh is what generation, verification and
# packaging all agree on.
#
# A bundle that already carries an attestation is SEALED: finalization
# refuses to rewrite or silently remove it — the attestation attested the
# manifest it was issued over, and rewriting underneath it is history
# revision. Re-running on an unsealed finalized bundle is byte-identical
# by the determinism contract.
#
# Usage:
#   ./scripts/finalize-release-evidence.sh [evidence-dir]
#   ./scripts/finalize-release-evidence.sh --verify [evidence-dir]
#       Verify a finalized bundle read-only: nothing is written or
#       removed; every final artifact is recomputed and byte-compared
#       against what is on disk.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$REPO_ROOT/scripts/lib/evidence-inventory.sh"

VERIFY_ONLY=0
EVIDENCE_DIR=""
for arg in "$@"; do
  case "$arg" in
    --verify) VERIFY_ONLY=1 ;;
    -*) echo "ERROR: unknown option: $arg" >&2; exit 2 ;;
    *) EVIDENCE_DIR="$arg" ;;
  esac
done
EVIDENCE_DIR="${EVIDENCE_DIR:-$REPO_ROOT/dist/release-evidence}"

if [ ! -d "$EVIDENCE_DIR" ]; then
  echo "ERROR: evidence directory not found: $EVIDENCE_DIR" >&2
  exit 1
fi

# Resolve to an absolute path before anything else: later stages cd into
# the evidence directory, so a relative argument would silently re-anchor
# every path derived from it.
EVIDENCE_DIR="$(cd "$EVIDENCE_DIR" && pwd)"

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
QUAL_JSON="$EVIDENCE_DIR/qualification.json"
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

# The bundle's timestamp is the qualification run's own — the wall clock
# at finalization is not an input and would make re-finalization produce
# different bytes for identical evidence.
GENERATED_AT=""
if [ -f "$QUAL_JSON" ]; then
  GENERATED_AT="$(jq -r '.provenance.timestamp // empty' "$QUAL_JSON" 2>/dev/null || true)"
fi
if [ -z "$GENERATED_AT" ] && [ -f "$MANIFEST" ]; then
  GENERATED_AT="$(jq -r '.generated_at // empty' "$MANIFEST" 2>/dev/null || true)"
fi

# ─── A sealed bundle is never rewritten, and attestations are never
#     silently removed ────────────────────────────────────────────────────
# An attestation attests the manifest it was issued over. Re-finalizing
# the same unsealed bundle is safe (byte-identical), but an existing
# attestation means the bundle's meaning was already published — removing
# or rewriting it here would revise signed history. An operator removes a
# stale attestation deliberately, never as a side effect of this script.
if [ -d "$EVIDENCE_DIR/attestation" ] && [ "$VERIFY_ONLY" -eq 0 ]; then
  echo "ERROR: $EVIDENCE_DIR/attestation already seals this bundle — refusing to rewrite sealed evidence" >&2
  echo "       (the attestation attested a superseded manifest; remove it deliberately if regeneration is intended)" >&2
  exit 1
fi

# ─── The canonical checksum traversal ───────────────────────────────────
# One inventory, shared by generation, finalization, verification and
# packaging so they can never disagree about what the bundle contains.
# Sorting is byte-wise so the manifest does not depend on the host locale.
checksums() {
  ( cd "$EVIDENCE_DIR" && evidence_checksum_members . | xargs -0 shasum -a 256 )
}

# Every stage agrees on what may exist in the tree: a hidden scratch entry
# or a non-regular member is never evidence and never ships, so finding one
# here is a refusal — silent pruning is exactly what let a finalized bundle
# reach packaging in a state the packager had to reject.
if ! evidence_refuse_strays "$EVIDENCE_DIR" "finalization"; then
  exit 1
fi

write_manifest() {
  local out="$1" sha count
  sha="$(cd "$EVIDENCE_DIR" && shasum -a 256 SHA256SUMS | awk '{print $1}')"
  count="$(wc -l < "$EVIDENCE_DIR/SHA256SUMS" | tr -d ' ')"
  jq -n \
    --arg name "$RELEASE_NAME" \
    --arg sha "$sha" \
    --argjson count "$count" \
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
      branch: $branch
    } + (if $generated == "" then {} else {generated_at: $generated} end)' > "$out"
}

if [ "$VERIFY_ONLY" -eq 1 ]; then
  # ─── Read-only verification: recompute every final artifact and byte-
  #     compare against the stored bundle. Nothing is written. ──────────
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  ok=1

  checksums > "$TMP/SHA256SUMS"
  if [ ! -f "$EVIDENCE_DIR/SHA256SUMS" ]; then
    echo "ERROR: SHA256SUMS is missing — the bundle is not finalized" >&2
    ok=0
  elif ! cmp -s "$TMP/SHA256SUMS" "$EVIDENCE_DIR/SHA256SUMS"; then
    echo "ERROR: SHA256SUMS does not match a fresh canonical traversal (stale or non-deterministic contents)" >&2
    diff "$TMP/SHA256SUMS" "$EVIDENCE_DIR/SHA256SUMS" >&2 || true
    ok=0
  fi
  if ! grep -qE '[[:space:]]\./artifact\.json$' "$EVIDENCE_DIR/SHA256SUMS" 2>/dev/null; then
    echo "ERROR: artifact.json is not listed in SHA256SUMS" >&2
    ok=0
  fi
  if ! (cd "$EVIDENCE_DIR" && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1); then
    echo "ERROR: SHA256SUMS does not verify against the bundle's files" >&2
    ok=0
  fi

  if [ "$ok" -eq 1 ]; then
    write_manifest "$TMP/evidence-manifest.json"
    if ! cmp -s "$TMP/evidence-manifest.json" "$MANIFEST"; then
      echo "ERROR: evidence-manifest.json differs from a fresh regeneration" >&2
      diff "$TMP/evidence-manifest.json" "$MANIFEST" >&2 || true
      ok=0
    fi
  fi

  if ! python3 "$REPO_ROOT/scripts/generate-evidence-root.py" --verify "$EVIDENCE_DIR" --repo-root "$REPO_ROOT"; then
    ok=0
  fi

  if [ -f "$EVIDENCE_DIR/FINAL_QUALIFICATION_REPORT.md" ]; then
    "$REPO_ROOT/scripts/generate-qualification-report.sh" "$EVIDENCE_DIR" "$TMP/FINAL_QUALIFICATION_REPORT.md" >/dev/null
    if ! cmp -s "$TMP/FINAL_QUALIFICATION_REPORT.md" "$EVIDENCE_DIR/FINAL_QUALIFICATION_REPORT.md"; then
      echo "ERROR: FINAL_QUALIFICATION_REPORT.md differs from a fresh regeneration" >&2
      diff "$TMP/FINAL_QUALIFICATION_REPORT.md" "$EVIDENCE_DIR/FINAL_QUALIFICATION_REPORT.md" >&2 || true
      ok=0
    fi
  fi

  if [ "$ok" -eq 0 ]; then
    echo "ERROR: evidence bundle verification failed" >&2
    exit 1
  fi
  echo "=== Release Evidence Verified ==="
  echo "  SHA256SUMS, evidence-manifest.json, evidence-root.json and the report"
  echo "  all match a fresh canonical regeneration — the bundle is deterministic"
  echo "  and unmutated."
  [ -d "$EVIDENCE_DIR/attestation" ] && \
    echo "  note: attestation/ present — the bundle is sealed; verify it with 'gh attestation verify'"
  exit 0
fi

# ─── Rebind the evidence root: artifacts pending -> bound ────────────────
# The qualification-time root recorded artifacts.status "pending"; with
# artifact.json present the root must bind the release artifact digests
# before SHA256SUMS seals it. The generated report displays the root
# digest, so it is regenerated with it.
python3 "$REPO_ROOT/scripts/generate-evidence-root.py" "$EVIDENCE_DIR" --repo-root "$REPO_ROOT"
"$REPO_ROOT/scripts/generate-qualification-report.sh" "$EVIDENCE_DIR"

# ─── Regenerate SHA256SUMS over the final bundle ──────────────────────────
# Same traversal as generate-release-evidence.sh, with artifact.json now
# INCLUDED. SHA256SUMS and evidence-manifest.json stay excluded: the
# manifest's digest is computed FROM SHA256SUMS, so including either
# would create a self-invalidating cycle.
checksums > "$EVIDENCE_DIR/SHA256SUMS"

# The release artifact binding must be inside the manifest — not merely
# present in the directory.
if ! grep -qE '[[:space:]]\./artifact\.json$' "$EVIDENCE_DIR/SHA256SUMS"; then
  echo "ERROR: artifact.json is not listed in the regenerated SHA256SUMS" >&2
  exit 1
fi

if ! (cd "$EVIDENCE_DIR" && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1); then
  echo "ERROR: regenerated SHA256SUMS does not verify" >&2
  exit 1
fi

# ─── Regenerate the evidence identity digest ──────────────────────────────
write_manifest "$MANIFEST"

# ─── Verify the final state ───────────────────────────────────────────────
FINAL_SHA="$(jq -r '.sha256' "$MANIFEST")"
ACTUAL_SHA="$(cd "$EVIDENCE_DIR" && shasum -a 256 SHA256SUMS | awk '{print $1}')"
if [ "$FINAL_SHA" != "$ACTUAL_SHA" ]; then
  echo "ERROR: evidence-manifest.json digest does not match SHA256SUMS" >&2
  exit 1
fi
FINAL_COUNT="$(jq -r '.file_count' "$MANIFEST")"
MANIFEST_FILE_COUNT="$(wc -l < "$EVIDENCE_DIR/SHA256SUMS" | tr -d ' ')"
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
