#!/usr/bin/env bash
# Check release admission from qualification.json.
#
# Derives admission independently — does NOT trust release_status or
# artifact_promotable. Gate semantics live in exactly one validator
# (scripts/lib/qualification-gates.sh), shared with the standalone
# artifact verifier: no consumer re-derives them from gate names or IDs.
#
# Returns 0 if the record satisfies admission, 1 otherwise.
# Usage: ./scripts/check-release-admission.sh [qualification.json]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
QUAL_FILE="${1:-$REPO_ROOT/dist/release-evidence/qualification.json}"

# shellcheck source=lib/qualification-gates.sh
source "$REPO_ROOT/scripts/lib/qualification-gates.sh"

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

GATE_COUNT="$(jq '.gates | length' "$QUAL_FILE" 2>/dev/null || echo 0)"
if [ "$GATE_COUNT" -eq 0 ]; then
  echo "ERROR: no gates found in qualification.json" >&2
  exit 1
fi

# ─── Gate semantics: the shared validator ────────────────────────────────
# mandatory && status != PASS, unknown gate_type, duplicate gate_id,
# test-bearing gates without honest counts, non-test gates claiming test
# counts, PASS with a nonzero exit code, malformed evidence digests.
SEMANTIC_FAILURES=0
if ! FINDINGS="$(validate_qualification_gates "$QUAL_FILE")"; then
  while IFS= read -r finding; do
    [ -z "$finding" ] && continue
    echo "  INCONSISTENCY: $finding" >&2
    SEMANTIC_FAILURES=$((SEMANTIC_FAILURES + 1))
  done <<< "$FINDINGS"
fi

# ─── Per-gate presentation + evidence binding ────────────────────────────
EVIDENCE_DIR="$(dirname "$QUAL_FILE")"
DERIVED_PASS=0
DERIVED_FAIL=0
DERIVED_FAIL_NAMES=""

for i in $(seq 0 $((GATE_COUNT - 1))); do
  gate_id="$(jq -r ".gates[$i].gate_id // \"\"" "$QUAL_FILE")"
  gate_type="$(jq -r ".gates[$i].gate_type // \"\"" "$QUAL_FILE")"
  status="$(jq -r ".gates[$i].status // \"\"" "$QUAL_FILE")"
  exit_code="$(jq -r ".gates[$i].exit_code // 0" "$QUAL_FILE")"
  evidence_file="$(jq -r ".gates[$i].evidence.file // empty" "$QUAL_FILE")"
  evidence_sha="$(jq -r ".gates[$i].evidence.sha256 // empty" "$QUAL_FILE")"

  printf "  %-28s %-16s %s (exit=%s)\n" "$gate_id" "$gate_type" "$status" "$exit_code"

  if [ "$status" = "PASS" ]; then
    DERIVED_PASS=$((DERIVED_PASS + 1))
  else
    DERIVED_FAIL=$((DERIVED_FAIL + 1))
    DERIVED_FAIL_NAMES="$DERIVED_FAIL_NAMES $gate_id"
  fi

  # A gate claiming PASS without intact proof is not admissible: the
  # evidence file must exist and match the digest the record binds.
  if [ -n "$evidence_file" ]; then
    if [ ! -f "$EVIDENCE_DIR/$evidence_file" ]; then
      echo "  INCONSISTENCY: $gate_id references missing evidence: $evidence_file" >&2
      SEMANTIC_FAILURES=$((SEMANTIC_FAILURES + 1))
    elif [ -n "$evidence_sha" ]; then
      actual_sha="$(shasum -a 256 "$EVIDENCE_DIR/$evidence_file" | awk '{print $1}')"
      if [ "$actual_sha" != "$evidence_sha" ]; then
        echo "  INCONSISTENCY: $gate_id evidence digest $actual_sha does not match the recorded $evidence_sha" >&2
        SEMANTIC_FAILURES=$((SEMANTIC_FAILURES + 1))
      fi
    fi
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
if [ "$DERIVED_FAIL" -eq 0 ] && [ "$SEMANTIC_FAILURES" -eq 0 ]; then
  DERIVED_STATUS="PASS"
  DERIVED_PROMOTABLE="true"
else
  DERIVED_STATUS="FAIL"
  DERIVED_PROMOTABLE="false"
fi

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

# ─── Toolchain binding (independent of the gate's self-report) ───────────
# When the release object exists, its declared toolchain must equal the
# toolchain the qualification actually ran on. A declaration without a
# matching runtime record — or no runtime record at all — rejects.
ARTIFACT_JSON="$EVIDENCE_DIR/artifact.json"
if [ -f "$ARTIFACT_JSON" ]; then
  artifact_go="$(jq -r '.toolchain.go // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"
  qual_go_raw="$(jq -r '.toolchains.go // empty' "$QUAL_FILE" 2>/dev/null || true)"
  qual_go=""
  if [[ "$qual_go_raw" =~ (go[0-9]+\.[0-9]+\.[0-9]+) ]]; then
    qual_go="${BASH_REMATCH[1]}"
  fi
  if ! [[ "$artifact_go" =~ ^go[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "  INCONSISTENCY: artifact.json toolchain.go is missing or malformed: '${artifact_go:-<empty>}'" >&2
    CONSISTENT=false
  elif [ -z "$qual_go" ]; then
    echo "  INCONSISTENCY: qualification.json records no actual Go toolchain version" >&2
    CONSISTENT=false
  elif [ "$artifact_go" != "$qual_go" ]; then
    echo "  INCONSISTENCY: artifact.json declares toolchain $artifact_go but qualification ran on $qual_go" >&2
    CONSISTENT=false
  else
    echo "  Toolchain binding: $artifact_go (declared = qualified)"
  fi
fi

# ─── Admission decision ────────────────────────────────────────────────
echo ""

if [ "$CONSISTENT" = false ] || [ "$SEMANTIC_FAILURES" -gt 0 ]; then
  echo "RELEASE ADMISSION: REJECTED (qualification record violates its own contract)" >&2
  exit 1
fi

if [ "$DERIVED_FAIL" -eq 0 ]; then
  echo "RELEASE ADMISSION: PASS ($DERIVED_PASS/$GATE_COUNT gates)"
  exit 0
else
  echo "RELEASE ADMISSION: REJECTED ($DERIVED_FAIL failed gates:$DERIVED_FAIL_NAMES)" >&2
  exit 1
fi
