#!/usr/bin/env bash
# Check release admission from qualification.json.
# Derives admission independently — does NOT trust release_status or
# artifact_promotable fields. Recomputes gate status from individual
# gate records and cross-checks consistency.
# Returns 0 if all mandatory gates PASS, 1 otherwise.
# Usage: ./scripts/check-release-admission.sh [qualification.json]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
QUAL_FILE="${1:-$REPO_ROOT/dist/release-evidence/qualification.json}"

if [ ! -f "$QUAL_FILE" ]; then
  echo "ERROR: qualification.json not found at $QUAL_FILE" >&2
  echo "Run scripts/generate-release-evidence.sh first." >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required for release admission checking" >&2
  exit 1
fi

echo ""
echo "=== Release Admission Check ==="
echo ""

# ─── Derive gate status independently ───────────────────────────────────
# Instead of trusting release_status, recompute from individual gates.

GATE_COUNT="$(jq '.gates | length' "$QUAL_FILE" 2>/dev/null || echo 0)"
if [ "$GATE_COUNT" -eq 0 ]; then
  echo "ERROR: no gates found in qualification.json" >&2
  exit 1
fi

DERIVED_PASS=0
DERIVED_FAIL=0
DERIVED_FAIL_NAMES=""

for i in $(seq 0 $((GATE_COUNT - 1))); do
  name="$(jq -r ".gates[$i].name" "$QUAL_FILE")"
  status="$(jq -r ".gates[$i].status" "$QUAL_FILE")"
  exit_code="$(jq -r ".gates[$i].exit_code" "$QUAL_FILE")"
  evidence_file="$(jq -r ".gates[$i].evidence_file" "$QUAL_FILE")"
  mandatory="$(jq -r ".gates[$i].mandatory" "$QUAL_FILE")"

  # Derive status from exit code if status field is missing
  if [ "$status" = "null" ] || [ -z "$status" ]; then
    if [ "$exit_code" = "0" ]; then
      status="PASS"
    else
      status="FAIL"
    fi
  fi

  # Cross-check: PASS status must have exit code 0
  if [ "$status" = "PASS" ] && [ "$exit_code" != "0" ]; then
    status="FAIL"
    echo "  INCONSISTENCY: $name claims PASS but exit_code=$exit_code" >&2
  fi

  # Cross-check: FAIL status must have non-zero exit code
  if [ "$status" = "FAIL" ] && [ "$exit_code" = "0" ]; then
    echo "  WARNING: $name claims FAIL but exit_code=0" >&2
  fi

  # Cross-check: evidence file must exist (if evidence dir is alongside).
  # A mandatory gate claiming PASS without proof is a FAIL — not a warning.
  EVIDENCE_DIR="$(dirname "$QUAL_FILE")"
  if [ -n "$evidence_file" ] && [ "$evidence_file" != "null" ] && [ ! -f "$EVIDENCE_DIR/$evidence_file" ]; then
    if [ "$status" = "PASS" ]; then
      status="FAIL"
      echo "  INCONSISTENCY: $name claims PASS but evidence file missing: $evidence_file" >&2
    else
      echo "  WARNING: $name references missing evidence: $evidence_file" >&2
    fi
  fi

  # Cross-check: test-suite gates claiming PASS must have executed tests.
  # Gates whose names contain "tests", start with "postgres-", or are
  # effect-fabric gates are test suites; a PASS with tests_executed == 0
  # means no tests actually ran.
  tests_executed="$(jq -r ".gates[$i].tests_executed // \"\"" "$QUAL_FILE")"
  is_test_gate=false
  case "$name" in
    *tests|postgres-*|effect-fabric-*|authority-*) is_test_gate=true ;;
  esac
  if [ "$is_test_gate" = true ] && [ "$status" = "PASS" ]; then
    if [ "$tests_executed" = "" ] || [ "$tests_executed" = "null" ] || [ "$tests_executed" = "0" ]; then
      status="FAIL"
      echo "  INCONSISTENCY: $name claims PASS but tests_executed=$tests_executed (test gate must execute >0 tests)" >&2
    fi
  fi

  if [ "$status" = "PASS" ]; then
    printf "  %-30s PASS (exit=%s)\n" "$name" "$exit_code"
    DERIVED_PASS=$((DERIVED_PASS + 1))
  else
    printf "  %-30s FAIL (exit=%s)\n" "$name" "$exit_code"
    DERIVED_FAIL=$((DERIVED_FAIL + 1))
    DERIVED_FAIL_NAMES="$DERIVED_FAIL_NAMES $name"
  fi
done

echo ""
echo "  Derived: $DERIVED_PASS passed, $DERIVED_FAIL failed, $GATE_COUNT total"

# ─── Cross-check declared vs derived ───────────────────────────────────
DECLARED_STATUS="$(jq -r '.release_status' "$QUAL_FILE" 2>/dev/null || echo "")"
DECLARED_PROMOTABLE="$(jq -r '.artifact_promotable' "$QUAL_FILE" 2>/dev/null || echo "")"
DECLARED_TOTAL="$(jq -r '.gate_summary.total' "$QUAL_FILE" 2>/dev/null || echo 0)"
DECLARED_PASSED="$(jq -r '.gate_summary.passed' "$QUAL_FILE" 2>/dev/null || echo 0)"
DECLARED_FAILED="$(jq -r '.gate_summary.failed' "$QUAL_FILE" 2>/dev/null || echo 0)"

echo "  Declared: $DECLARED_PASSED passed, $DECLARED_FAILED failed, $DECLARED_TOTAL total"
echo "  Declared release_status: $DECLARED_STATUS"
echo "  Declared artifact_promotable: $DECLARED_PROMOTABLE"

# Check consistency between declared and derived
CONSISTENT=true
if [ "$DECLARED_TOTAL" != "$GATE_COUNT" ]; then
  echo "  INCONSISTENCY: declared total ($DECLARED_TOTAL) != actual gate count ($GATE_COUNT)" >&2
  CONSISTENT=false
fi
if [ "$DECLARED_PASSED" != "$DERIVED_PASS" ]; then
  echo "  INCONSISTENCY: declared passed ($DECLARED_PASSED) != derived passed ($DERIVED_PASS)" >&2
  CONSISTENT=false
fi
if [ "$DECLARED_FAILED" != "$DERIVED_FAIL" ]; then
  echo "  INCONSISTENCY: declared failed ($DECLARED_FAILED) != derived failed ($DERIVED_FAIL)" >&2
  CONSISTENT=false
fi

# Derived release status
if [ "$DERIVED_FAIL" -eq 0 ]; then
  DERIVED_STATUS="PASS"
  DERIVED_PROMOTABLE="true"
else
  DERIVED_STATUS="FAIL"
  DERIVED_PROMOTABLE="false"
fi

# Check declared status matches derived
if [ "$DECLARED_STATUS" != "$DERIVED_STATUS" ]; then
  echo "  INCONSISTENCY: declared release_status ($DECLARED_STATUS) != derived ($DERIVED_STATUS)" >&2
  CONSISTENT=false
fi
if [ "$DECLARED_PROMOTABLE" != "$DERIVED_PROMOTABLE" ]; then
  echo "  INCONSISTENCY: declared artifact_promotable ($DECLARED_PROMOTABLE) != derived ($DERIVED_PROMOTABLE)" >&2
  CONSISTENT=false
fi

# ─── Check invariants ─────────────────────────────────────────────────
INV_COUNT="$(jq '.invariants | length' "$QUAL_FILE" 2>/dev/null || echo 0)"
if [ "$INV_COUNT" -gt 0 ]; then
  echo ""
  echo "  Release invariants ($INV_COUNT):"
  for i in $(seq 0 $((INV_COUNT - 1))); do
    inv_id="$(jq -r ".invariants[$i].id" "$QUAL_FILE")"
    inv_desc="$(jq -r ".invariants[$i].description" "$QUAL_FILE")"
    printf "    %-15s %s\n" "$inv_id" "$inv_desc"
  done
fi

# ─── Admission decision ────────────────────────────────────────────────
echo ""

if [ "$CONSISTENT" = false ]; then
  echo "RELEASE ADMISSION: REJECTED (qualification.json inconsistent)" >&2
  exit 1
fi

if [ "$DERIVED_FAIL" -eq 0 ]; then
  echo "RELEASE ADMISSION: PASS ($DERIVED_PASS/$GATE_COUNT gates)"
  exit 0
else
  echo "RELEASE ADMISSION: REJECTED ($DERIVED_FAIL failed gates:$DERIVED_FAIL_NAMES)" >&2
  exit 1
fi
