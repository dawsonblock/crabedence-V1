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

# 2b. Verify manifest against actual source tree by delegating to
# verify-source-manifest.sh. This guarantees a single source of truth
# for exclusion logic — the artifact verifier no longer reimplements
# the bidirectional manifest check (which previously diverged from the
# generator's exclusions on nested bin/dist/node_modules paths).
if [ -f "$EVIDENCE_DIR/source-tree-sha256.txt" ]; then
  SOURCE_VERIFIER="$SCRIPT_DIR/verify-source-manifest.sh"
  if [ ! -x "$SOURCE_VERIFIER" ]; then
    check "Source manifest equality (verifier missing)" "FAIL"
    echo "  ERROR: verify-source-manifest.sh not found or not executable" >&2
  else
    # verify-source-manifest.sh prints a summary; capture and surface it.
    if "$SOURCE_VERIFIER" "$EVIDENCE_DIR/source-tree-sha256.txt" "$SOURCE_DIR" >"$EVIDENCE_DIR/.source-verify.tmp" 2>&1; then
      check "Source manifest equality" "PASS"
    else
      check "Source manifest equality" "FAIL"
    fi
    # Surface the verifier's detail (missing/mismatched/unexpected) to stderr.
    sed 's/^/    /' "$EVIDENCE_DIR/.source-verify.tmp" >&2
    rm -f "$EVIDENCE_DIR/.source-verify.tmp"
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
    SCHEMA_FILE="$REPO_ROOT/schemas/qualification.schema.json"
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

# 5. evidence-manifest.json — verify evidence bundle digest.
# The digest claim (digest_of: "SHA256SUMS") is independently verified:
# recompute SHA256(SHA256SUMS) and compare with the stored sha256.
if [ -f "$EVIDENCE_DIR/evidence-manifest.json" ]; then
  EVIDENCE_SHA="$(jq -r '.sha256' "$EVIDENCE_DIR/evidence-manifest.json" 2>/dev/null || echo "")"
  if [ -n "$EVIDENCE_SHA" ] && [[ "$EVIDENCE_SHA" =~ ^[0-9a-f]{64}$ ]]; then
    check "Evidence manifest digest format" "PASS"
    # Independently verify the digest claim: SHA256(SHA256SUMS) must match.
    if [ -f "$EVIDENCE_DIR/SHA256SUMS" ]; then
      ACTUAL_SHA="$(shasum -a 256 "$EVIDENCE_DIR/SHA256SUMS" | awk '{print $1}')"
      if [ "$EVIDENCE_SHA" = "$ACTUAL_SHA" ]; then
        check "Evidence manifest digest verified" "PASS"
      else
        check "Evidence manifest digest verified" "FAIL"
        echo "  ERROR: evidence-manifest.json claims sha256=$EVIDENCE_SHA but actual SHA256(SHA256SUMS)=$ACTUAL_SHA" >&2
      fi
    fi
  else
    check "Evidence manifest digest format" "FAIL"
  fi
else
  check "Evidence manifest (missing)" "FAIL"
fi

# 5b. Release manifest — verify release metadata is present and consistent.
if [ -f "$EVIDENCE_DIR/release-manifest.json" ]; then
  RM_STATUS="$(jq -r '.status' "$EVIDENCE_DIR/release-manifest.json" 2>/dev/null || echo "")"
  RM_COMMIT="$(jq -r '.provenance.commit' "$EVIDENCE_DIR/release-manifest.json" 2>/dev/null || echo "")"
  if [ "$RM_STATUS" = "PASS" ] && [ -n "$RM_COMMIT" ] && [[ "$RM_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
    check "Release manifest" "PASS"
  else
    check "Release manifest" "FAIL"
  fi
else
  check "Release manifest (missing)" "FAIL"
fi

# 5c. SBOM — verify Software Bill of Materials is present and valid JSON.
if [ -f "$EVIDENCE_DIR/sbom.spdx.json" ]; then
  SBOM_VER="$(jq -r '.spdxVersion' "$EVIDENCE_DIR/sbom.spdx.json" 2>/dev/null || echo "")"
  SBOM_PKG_COUNT="$(jq '.packages | length' "$EVIDENCE_DIR/sbom.spdx.json" 2>/dev/null || echo 0)"
  if [ "$SBOM_VER" = "SPDX-2.3" ] && [ "$SBOM_PKG_COUNT" -ge 1 ]; then
    check "SBOM (SPDX-2.3, $SBOM_PKG_COUNT packages)" "PASS"
  else
    check "SBOM (invalid)" "FAIL"
  fi
else
  check "SBOM (missing)" "FAIL"
fi

# 5d. Attestation — verify attestation reference is present.
if [ -f "$EVIDENCE_DIR/attestation/attestation.json" ]; then
  ATT_URL="$(jq -r '.attestation_url // empty' "$EVIDENCE_DIR/attestation/attestation.json" 2>/dev/null)"
  if [ -n "$ATT_URL" ]; then
    check "GitHub attestation" "PASS"
  else
    check "GitHub attestation (no URL)" "FAIL"
  fi
else
  check "GitHub attestation (missing)" "FAIL"
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
