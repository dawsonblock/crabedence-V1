#!/usr/bin/env bash
# Verify a release artifact's evidence bundle.
#
# Works standalone on an extracted archive — does NOT require .git.
# Checks:
#   - SHA256SUMS verifies
#   - Source manifest: every listed file exists with matching SHA-256
#   - Source manifest: no extra files in source tree
#   - Commit/tree metadata consistency
#   - qualification.json: every gate individually PASS
#   - artifact_promotable matches release_status
#   - Required evidence logs present
#   - Release invariants documented
#
# Usage: ./scripts/verify-release-artifact.sh [evidence-dir] [source-dir]
#   evidence-dir: directory containing release evidence (default: release-evidence/)
#   source-dir:    directory containing the source tree to verify (default: repo root)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
EVIDENCE_DIR="${1:-$REPO_ROOT/release-evidence}"
SOURCE_DIR="${2:-$REPO_ROOT}"

if [ ! -d "$EVIDENCE_DIR" ]; then
  echo "ERROR: evidence directory not found: $EVIDENCE_DIR" >&2
  exit 1
fi
if [ ! -d "$SOURCE_DIR" ]; then
  echo "ERROR: source directory not found: $SOURCE_DIR" >&2
  exit 1
fi

PASS_COUNT=0
FAIL_COUNT=0

check() {
  local label="$1" result="$2"
  if [ "$result" = "PASS" ]; then
    printf "  %-40s PASS\n" "$label"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    printf "  %-40s FAIL\n" "$label"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

echo ""
echo "=== Release Artifact Verification ==="
echo "  evidence: $EVIDENCE_DIR"
echo "  source:   $SOURCE_DIR"
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

# 2. Source manifest present.
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

# 2b. Verify manifest against actual source tree (standalone, no .git required).
# Checks: every manifest file exists with matching hash, and no extra files.
if [ -f "$EVIDENCE_DIR/source-tree-sha256.txt" ]; then
  MANIFEST_FILES="$(mktemp)"
  ACTUAL_FILES="$(mktemp)"
  MISMATCH_LOG="$(mktemp)"

  # Extract file paths from manifest.
  # Format: <64-char-sha256>  <path>
  # The SHA is 64 chars, followed by 2 spaces, then the path.
  # Use substr to extract everything after position 66.
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    # Extract path: everything after "hash  " (64 chars + 2 spaces = 66)
    path="${line:66}"
    echo "$path" >> "$MANIFEST_FILES"
  done < "$EVIDENCE_DIR/source-tree-sha256.txt"
  sort -o "$MANIFEST_FILES" "$MANIFEST_FILES"

  # Enumerate actual source files (excluding release-evidence/ and common generated dirs).
  # Use find so this works without .git.
  find "$SOURCE_DIR" -type f \
    ! -path "$SOURCE_DIR/release-evidence/*" \
    ! -path "$SOURCE_DIR/node_modules/*" \
    ! -path "$SOURCE_DIR/worker/node_modules/*" \
    ! -path "$SOURCE_DIR/nemo/node_modules/*" \
    ! -path "$SOURCE_DIR/.git/*" \
    ! -path "$SOURCE_DIR/bin/*" \
    ! -path "$SOURCE_DIR/dist/*" \
    ! -path "$SOURCE_DIR/worker/dist/*" \
    -print0 | while IFS= read -r -d '' f; do
    # Strip the SOURCE_DIR prefix to get relative path
    rel="${f#$SOURCE_DIR/}"
    printf '%s\n' "$rel"
  done | sort > "$ACTUAL_FILES"

  # Check for missing files (in manifest but not in source tree)
  MISSING="$(comm -23 "$MANIFEST_FILES" "$ACTUAL_FILES")"

  # Check for extra files (in source tree but not in manifest)
  EXTRA="$(comm -13 "$MANIFEST_FILES" "$ACTUAL_FILES")"

  # Check for hash mismatches
  MISMATCH_COUNT=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    expected_sha="${line:0:64}"
    file_path="${line:66}"
    if [ -f "$SOURCE_DIR/$file_path" ]; then
      actual_sha="$(shasum -a 256 "$SOURCE_DIR/$file_path" | cut -d ' ' -f 1)"
      if [ "$actual_sha" != "$expected_sha" ]; then
        echo "MISMATCH: $file_path (expected=$expected_sha actual=$actual_sha)" >> "$MISMATCH_LOG"
        MISMATCH_COUNT=$((MISMATCH_COUNT + 1))
      fi
    fi
  done < "$EVIDENCE_DIR/source-tree-sha256.txt"

  MANIFEST_COUNT="$(wc -l < "$MANIFEST_FILES" | tr -d ' ')"
  ACTUAL_COUNT="$(wc -l < "$ACTUAL_FILES" | tr -d ' ')"
  MISSING_COUNT="$(echo "$MISSING" | grep -c . 2>/dev/null || echo 0)"
  EXTRA_COUNT="$(echo "$EXTRA" | grep -c . 2>/dev/null || echo 0)"

  echo "  Manifest files: $MANIFEST_COUNT" >&2
  echo "  Actual files:   $ACTUAL_COUNT" >&2
  echo "  Missing:         $MISSING_COUNT" >&2
  echo "  Extra:           $EXTRA_COUNT" >&2
  echo "  Mismatched:      $MISMATCH_COUNT" >&2

  if [ "$MISSING_COUNT" -gt 0 ]; then
    echo "  Files in manifest but not in source tree:" >&2
    echo "$MISSING" | head -20 | sed 's/^/    /' >&2
  fi
  if [ "$EXTRA_COUNT" -gt 0 ]; then
    echo "  Files in source tree but not in manifest:" >&2
    echo "$EXTRA" | head -20 | sed 's/^/    /' >&2
  fi
  if [ "$MISMATCH_COUNT" -gt 0 ]; then
    echo "  Hash mismatches:" >&2
    cat "$MISMATCH_LOG" | head -20 | sed 's/^/    /' >&2
  fi

  rm -f "$MANIFEST_FILES" "$ACTUAL_FILES" "$MISMATCH_LOG"

  if [ "$MISSING_COUNT" -eq 0 ] && [ "$EXTRA_COUNT" -eq 0 ] && [ "$MISMATCH_COUNT" -eq 0 ]; then
    check "Source manifest equality" "PASS"
  else
    check "Source manifest equality" "FAIL"
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
    check "Qualification release_status" "PASS"
  else
    check "Qualification release_status ($RELEASE_STATUS)" "FAIL"
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

  # 4d. Cross-check: if any gate is FAIL, release_status must not be PASS.
  if [ -n "$FAILED_GATES" ] && [ "$RELEASE_STATUS" = "PASS" ]; then
    check "Gate-status consistency" "FAIL"
  else
    check "Gate-status consistency" "PASS"
  fi

  # 4e. Cross-check: every gate must have a matching log file.
  GATE_LOG_MISSING=false
  for log in $(jq -r '.gates[].log' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo ""); do
    if [ ! -f "$EVIDENCE_DIR/$log" ]; then
      GATE_LOG_MISSING=true
      echo "  Missing log for gate: $log" >&2
    fi
  done
  if [ "$GATE_LOG_MISSING" = false ]; then
    check "Gate log files present" "PASS"
  else
    check "Gate log files present" "FAIL"
  fi
else
  check "Qualification release_status (missing)" "FAIL"
  check "All gates individually PASS (missing)" "FAIL"
  check "Artifact promotable (missing)" "FAIL"
  check "Gate-status consistency (missing)" "FAIL"
  check "Gate log files present (missing)" "FAIL"
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
    echo "  Missing required log: $log" >&2
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
