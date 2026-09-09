#!/usr/bin/env bash
# Verify a release artifact's evidence bundle.
#
# Works standalone on an extracted archive — does NOT require .git.
#
# Usage: ./scripts/verify-release-artifact.sh [evidence-dir] [source-dir]
#   evidence-dir: directory containing qualification bundle (default: dist/release-evidence/)
#   source-dir:    directory containing the source tree to verify (default: repo root)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
EVIDENCE_DIR="${1:-$REPO_ROOT/dist/release-evidence}"
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

# 2b. Verify manifest against actual source tree (standalone, no .git required).
if [ -f "$EVIDENCE_DIR/source-tree-sha256.txt" ]; then
  MANIFEST_FILES="$(mktemp)"
  ACTUAL_FILES="$(mktemp)"
  MISMATCH_LOG="$(mktemp)"

  # Extract file paths from manifest. Format: <64-char-sha256>  <path>
  # SHA is 64 chars + 2 spaces = 66 chars, path starts at position 66.
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    path="${line:66}"
    echo "$path" >> "$MANIFEST_FILES"
  done < "$EVIDENCE_DIR/source-tree-sha256.txt"
  LC_ALL=C sort -o "$MANIFEST_FILES" "$MANIFEST_FILES"

  # Enumerate actual source files using find (no .git required).
  # Use the same exclusions as generate-source-manifest.sh.
  cd "$SOURCE_DIR"
  find . -type f | while IFS= read -r filepath; do
    relpath="${filepath#./}"
    # Skip excluded directories
    echo "$relpath" | grep -q "node_modules\|/\.git/\|/dist/\|/coverage/\|/tmp/\|/\.build/\|/bin/\|__pycache__" && continue
    # Skip release-evidence/ generated files (keep schemas/README)
    case "$relpath" in
      release-evidence/schemas/*|release-evidence/README.md) ;;
      release-evidence/*) continue ;;
    esac
    # Skip OS metadata
    [ "$(basename "$filepath")" = ".DS_Store" ] && continue
    echo "$relpath" | grep -q "\.pyc$\|\.pyo$\|\.swp$\|\.swo$\|~$\|^\.#" && continue
    printf '%s\n' "$relpath"
  done | LC_ALL=C sort > "$ACTUAL_FILES"

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

  [ -n "$MISSING" ] && echo "$MISSING" | head -20 | sed 's/^/    /' >&2
  [ -n "$EXTRA" ] && echo "$EXTRA" | head -20 | sed 's/^/    /' >&2
  [ "$MISMATCH_COUNT" -gt 0 ] && cat "$MISMATCH_LOG" | head -20 | sed 's/^/    /' >&2

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

# 4. qualification.json — independently recompute gate summary.
if [ -f "$EVIDENCE_DIR/qualification.json" ]; then
  # 4a. Validate against schema — no fallback. A missing validator is a
  # qualification failure, not a warning.
  SCHEMA_FILE="$EVIDENCE_DIR/schemas/qualification.schema.json"
  if [ ! -f "$SCHEMA_FILE" ]; then
    SCHEMA_FILE="$REPO_ROOT/release-evidence/schemas/qualification.schema.json"
  fi
  if [ ! -f "$SCHEMA_FILE" ]; then
    check "Qualification schema (missing)" "FAIL"
    echo "  ERROR: qualification.schema.json not found" >&2
    exit 1
  fi
  if ! command -v ajv >/dev/null 2>&1; then
    check "Qualification schema (ajv not installed)" "FAIL"
    echo "  ERROR: ajv is required for schema validation. Install with: npm install -g ajv-cli" >&2
    exit 1
  fi
  if ajv validate -s "$SCHEMA_FILE" -d "$EVIDENCE_DIR/qualification.json" >/dev/null 2>&1; then
    check "Qualification schema valid" "PASS"
  else
    check "Qualification schema valid" "FAIL"
    echo "  ERROR: qualification.json does not validate against schema" >&2
    ajv validate -s "$SCHEMA_FILE" -d "$EVIDENCE_DIR/qualification.json" >&2 || true
    exit 1
  fi

  # 4b. Independently recompute gate summary from individual gates.
  GATE_COUNT="$(jq '.gates | length' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo 0)"
  DERIVED_PASS="$(jq '[.gates[] | select(.status == "PASS")] | length' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo 0)"
  DERIVED_FAIL="$(jq '[.gates[] | select(.status == "FAIL")] | length' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo 0)"
  DERIVED_SKIP="$(jq '[.gates[] | select(.status == "SKIP")] | length' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo 0)"

  # Check every mandatory gate is PASS
  FAILED_MANDATORY="$(jq -r '.gates[] | select(.mandatory == true and .status != "PASS") | .id' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo "")"

  if [ "$GATE_COUNT" -gt 0 ] && [ -z "$FAILED_MANDATORY" ]; then
    check "All mandatory gates PASS ($GATE_COUNT)" "PASS"
  else
    echo "  Failed mandatory gates: $FAILED_MANDATORY" >&2
    check "All mandatory gates PASS" "FAIL"
  fi

  # 4c. Cross-check declared vs derived summary.
  DECLARED_TOTAL="$(jq -r '.gate_summary.total' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo 0)"
  DECLARED_PASSED="$(jq -r '.gate_summary.passed' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo 0)"
  DECLARED_FAILED="$(jq -r '.gate_summary.failed' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo 0)"

  if [ "$DECLARED_TOTAL" = "$GATE_COUNT" ] && \
     [ "$DECLARED_PASSED" = "$DERIVED_PASS" ] && \
     [ "$DECLARED_FAILED" = "$DERIVED_FAIL" ]; then
    check "Gate summary consistency" "PASS"
  else
    check "Gate summary consistency" "FAIL"
  fi

  # 4d. Cross-check release_status matches derived.
  RELEASE_STATUS="$(jq -r '.release_status' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo "")"
  if [ "$DERIVED_FAIL" -eq 0 ]; then
    DERIVED_STATUS="PASS"
  else
    DERIVED_STATUS="FAIL"
  fi
  if [ "$RELEASE_STATUS" = "$DERIVED_STATUS" ]; then
    check "Release status consistency" "PASS"
  else
    check "Release status consistency" "FAIL"
  fi

  # 4e. Cross-check artifact_promotable.
  PROMOTABLE="$(jq -r '.artifact_promotable' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo "false")"
  if [ "$RELEASE_STATUS" = "PASS" ] && [ "$PROMOTABLE" = "true" ]; then
    check "Artifact promotable" "PASS"
  elif [ "$RELEASE_STATUS" != "PASS" ] && [ "$PROMOTABLE" = "false" ]; then
    check "Artifact promotable (correctly blocked)" "PASS"
  else
    check "Artifact promotable (mismatch)" "FAIL"
  fi

  # 4f. Cross-check: mandatory gate with exit_code != 0 must not be PASS.
  INCONSISTENT_GATES="$(jq -r '.gates[] | select(.status == "PASS" and .exit_code != 0) | .id' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo "")"
  if [ -z "$INCONSISTENT_GATES" ]; then
    check "Gate exit-code consistency" "PASS"
  else
    echo "  PASS gates with nonzero exit: $INCONSISTENT_GATES" >&2
    check "Gate exit-code consistency" "FAIL"
  fi

  # 4g. Cross-check: mandatory gate with tests_executed == 0 must not be PASS (for test gates).
  ZERO_EXECUTION_GATES="$(jq -r '.gates[] | select(.mandatory == true and .tests_executed == 0 and .status == "PASS") | .id' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo "")"
  if [ -z "$ZERO_EXECUTION_GATES" ]; then
    check "Gate execution consistency" "PASS"
  else
    echo "  PASS gates with 0 executed tests: $ZERO_EXECUTION_GATES" >&2
    check "Gate execution consistency" "FAIL"
  fi

  # 4h. Verify each gate's evidence file exists.
  GATE_LOG_MISSING=false
  for log in $(jq -r '.gates[].evidence_file' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo ""); do
    if [ ! -f "$EVIDENCE_DIR/$log" ]; then
      GATE_LOG_MISSING=true
      echo "  Missing evidence file: $log" >&2
    fi
  done
  if [ "$GATE_LOG_MISSING" = false ]; then
    check "Gate evidence files present" "PASS"
  else
    check "Gate evidence files present" "FAIL"
  fi
else
  check "Qualification JSON (missing)" "FAIL"
fi

# 5. Artifact.json — verify archive digest if present.
if [ -f "$EVIDENCE_DIR/artifact.json" ]; then
  ARTIFACT_SHA="$(jq -r '.sha256' "$EVIDENCE_DIR/artifact.json" 2>/dev/null || echo "")"
  if [ -n "$ARTIFACT_SHA" ] && [[ "$ARTIFACT_SHA" =~ ^[0-9a-f]{64}$ ]]; then
    check "Artifact digest format" "PASS"
  else
    check "Artifact digest format" "FAIL"
  fi
else
  check "Artifact.json (missing)" "FAIL"
fi

# 6. Release invariants documented.
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
