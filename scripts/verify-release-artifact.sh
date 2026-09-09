#!/usr/bin/env bash
# Verify a release artifact's evidence bundle.
# Checks:
#   - SHA256SUMS verifies
#   - Source manifest consistency
#   - Commit/tree metadata consistency
#   - qualification.json exists and all gates PASS
#   - Required evidence logs present
#   - Release invariants documented
# Usage: ./scripts/verify-release-artifact.sh [evidence-dir]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVIDENCE_DIR="${1:-$REPO_ROOT/release-evidence}"

if [ ! -d "$EVIDENCE_DIR" ]; then
  echo "ERROR: evidence directory not found: $EVIDENCE_DIR" >&2
  exit 1
fi

PASS_COUNT=0
FAIL_COUNT=0

check() {
  local label="$1" result="$2"
  if [ "$result" = "PASS" ]; then
    printf "  %-35s PASS\n" "$label"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    printf "  %-35s FAIL\n" "$label"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

echo ""
echo "=== Release Artifact Verification ==="
echo ""

# 1. SHA256SUMS verification.
if [ -f "$EVIDENCE_DIR/SHA256SUMS" ]; then
  if (cd "$EVIDENCE_DIR" && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1); then
    check "Artifact checksums" "PASS"
  else
    check "Artifact checksums" "FAIL"
  fi
else
  check "Artifact checksums (missing)" "FAIL"
fi

# 2. Source manifest verification.
if [ -f "$EVIDENCE_DIR/source-tree-sha256.txt" ]; then
  check "Source SHA-256 manifest present" "PASS"
else
  check "Source SHA-256 manifest present" "FAIL"
fi

if [ -f "$EVIDENCE_DIR/source-tree-git-manifest.txt" ]; then
  check "Source Git blob manifest present" "PASS"
else
  check "Source Git blob manifest present" "FAIL"
fi

# 2b. Detect extra files in packaged source tree not in manifest.
# The manifest records qualified source files. The actual Git-tracked
# source tree (excluding release-evidence/) must match exactly.
# Extra files mean the release includes unqualified code.
if [ -f "$EVIDENCE_DIR/source-tree-sha256.txt" ]; then
  MANIFEST_FILES="$(mktemp)"
  ACTUAL_FILES="$(mktemp)"
  # Extract file paths from manifest (column 3+, space-separated)
  awk '{$1=""; $2=""; sub(/^  /,""); print}' "$EVIDENCE_DIR/source-tree-sha256.txt" | sort > "$MANIFEST_FILES"
  # Get actual tracked source files (excluding release-evidence/)
  git -C "$REPO_ROOT" ls-files -- . ':(exclude)release-evidence/' | sort > "$ACTUAL_FILES"
  EXTRA="$(comm -13 "$MANIFEST_FILES" "$ACTUAL_FILES")"
  MISSING_FROM_TREE="$(comm -23 "$MANIFEST_FILES" "$ACTUAL_FILES")"
  rm -f "$MANIFEST_FILES" "$ACTUAL_FILES"
  if [ -n "$EXTRA" ]; then
    echo "  Extra files in source tree not in manifest:" >&2
    echo "$EXTRA" | head -20 | sed 's/^/    /' >&2
    check "Source manifest equality" "FAIL"
  elif [ -n "$MISSING_FROM_TREE" ]; then
    echo "  Files in manifest but not in source tree:" >&2
    echo "$MISSING_FROM_TREE" | head -20 | sed 's/^/    /' >&2
    check "Source manifest equality" "FAIL"
  else
    check "Source manifest equality" "PASS"
  fi
else
  check "Source manifest equality (missing)" "FAIL"
fi

# 3. Commit/tree metadata consistency.
if [ -f "$EVIDENCE_DIR/provenance.json" ] && [ -f "$EVIDENCE_DIR/source-commit.txt" ]; then
  PROV_COMMIT="$(jq -r '.commit' "$EVIDENCE_DIR/provenance.json" 2>/dev/null || echo "")"
  FILE_COMMIT="$(cat "$EVIDENCE_DIR/source-commit.txt" 2>/dev/null || echo "")"
  if [ -n "$PROV_COMMIT" ] && [ "$PROV_COMMIT" = "$FILE_COMMIT" ]; then
    check "Commit/tree consistency" "PASS"
  else
    check "Commit/tree consistency" "FAIL"
  fi
else
  check "Commit/tree consistency (missing)" "FAIL"
fi

# 4. qualification.json exists and all gates PASS.
if [ -f "$EVIDENCE_DIR/qualification.json" ]; then
  RELEASE_STATUS="$(jq -r '.release_status' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo "")"
  if [ "$RELEASE_STATUS" = "PASS" ]; then
    check "Qualification gates" "PASS"
  else
    check "Qualification gates ($RELEASE_STATUS)" "FAIL"
  fi

  # 4b. Validate each gate individually PASS (not just aggregate).
  GATE_COUNT="$(jq '.gates | length' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo 0)"
  FAILED_GATES="$(jq -r '.gates[] | select(.status != "PASS") | .name' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo "")"
  if [ "$GATE_COUNT" -gt 0 ] && [ -z "$FAILED_GATES" ]; then
    check "All gates individually PASS ($GATE_COUNT)" "PASS"
  else
    echo "  Failed gates:" >&2
    echo "$FAILED_GATES" | head -10 | sed 's/^/    /' >&2
    check "All gates individually PASS" "FAIL"
  fi

  # 4c. Verify artifact_promotable matches release_status.
  PROMOTABLE="$(jq -r '.artifact_promotable' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo "false")"
  if [ "$RELEASE_STATUS" = "PASS" ] && [ "$PROMOTABLE" = "true" ]; then
    check "Artifact promotable" "PASS"
  elif [ "$RELEASE_STATUS" != "PASS" ] && [ "$PROMOTABLE" = "false" ]; then
    check "Artifact promotable (correctly blocked)" "PASS"
  else
    check "Artifact promotable (mismatch)" "FAIL"
  fi

  # 4d. Validate qualification.json against schema if present.
  if [ -f "$REPO_ROOT/release/qualification-schema.json" ]; then
    if jq -e --slurp '.[0] as $schema | .[1] | $schema' \
      "$REPO_ROOT/release/qualification-schema.json" \
      "$EVIDENCE_DIR/qualification.json" >/dev/null 2>&1; then
      check "Qualification schema valid" "PASS"
    else
      check "Qualification schema valid" "FAIL"
    fi
  fi
else
  check "Qualification gates (missing)" "FAIL"
  check "All gates individually PASS (missing)" "FAIL"
  check "Artifact promotable (missing)" "FAIL"
fi

# 5. Required evidence logs present.
REQUIRED_LOGS=(
  "go-vet.log"
  "go-evidence-tests.log"
  "go-race-evidence.log"
  "go-race-providers.log"
  "go-tart-tests.log"
  "go-lume-tests.log"
  "go-shared-tests.log"
  "worker-typecheck.log"
  "worker-tests.log"
  "worker-format.log"
  "worker-lint.log"
  "worker-build.log"
  "postgres-fencing.log"
  "postgres-parity.log"
  "cross-language-conformance.log"
  "source-manifest-verify.log"
  "nemo-typecheck.log"
  "nemo-tests.log"
)
ALL_LOGS_PRESENT=true
for log in "${REQUIRED_LOGS[@]}"; do
  if [ ! -f "$EVIDENCE_DIR/$log" ]; then
    ALL_LOGS_PRESENT=false
    break
  fi
done
if [ "$ALL_LOGS_PRESENT" = true ]; then
  check "Required evidence logs" "PASS"
else
  check "Required evidence logs (missing)" "FAIL"
fi

# 6. Toolchain identity present.
if [ -f "$EVIDENCE_DIR/toolchains.json" ] && [ -f "$EVIDENCE_DIR/environment.json" ]; then
  check "Toolchain identity" "PASS"
else
  check "Toolchain identity (missing)" "FAIL"
fi

# 7. Release invariants documented.
if [ -f "$EVIDENCE_DIR/qualification.json" ]; then
  INV_COUNT="$(jq '.invariants | length' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo 0)"
  if [ "$INV_COUNT" -ge 12 ]; then
    check "Release invariants ($INV_COUNT)" "PASS"
  else
    check "Release invariants ($INV_COUNT)" "FAIL"
  fi
else
  check "Release invariants (missing)" "FAIL"
fi

echo ""
echo "  $PASS_COUNT passed, $FAIL_COUNT failed"
echo ""

if [ "$FAIL_COUNT" -eq 0 ]; then
  echo "ARTIFACT VERIFIED"
  exit 0
else
  echo "ARTIFACT VERIFICATION FAILED" >&2
  exit 1
fi
