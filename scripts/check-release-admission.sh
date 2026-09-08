#!/usr/bin/env bash
# Check release admission from qualification.json.
# Returns 0 if all mandatory gates PASS, 1 otherwise.
# Usage: ./scripts/check-release-admission.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
QUAL_FILE="$REPO_ROOT/release-evidence/qualification.json"

if [ ! -f "$QUAL_FILE" ]; then
  echo "ERROR: qualification.json not found at $QUAL_FILE" >&2
  echo "Run scripts/generate-release-evidence.sh first." >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required for release admission checking" >&2
  exit 1
fi

RELEASE_STATUS="$(jq -r '.release_status' "$QUAL_FILE")"
ARTIFACT_PROMOTABLE="$(jq -r '.artifact_promotable' "$QUAL_FILE")"
TOTAL_GATES="$(jq -r '.gate_summary.total' "$QUAL_FILE")"
PASSED_GATES="$(jq -r '.gate_summary.passed' "$QUAL_FILE")"
FAILED_GATES="$(jq -r '.gate_summary.failed' "$QUAL_FILE")"

echo ""
echo "=== Release Admission Check ==="
echo ""

# Print each gate status.
GATE_COUNT="$(jq '.gates | length' "$QUAL_FILE")"
for i in $(seq 0 $((GATE_COUNT - 1))); do
  name="$(jq -r ".gates[$i].name" "$QUAL_FILE")"
  status="$(jq -r ".gates[$i].status" "$QUAL_FILE")"
  if [ "$status" = "PASS" ]; then
    printf "  %-30s PASS\n" "$name"
  else
    printf "  %-30s FAIL\n" "$name"
  fi
done

echo ""
echo "  Gates: $PASSED_GATES passed, $FAILED_GATES failed, $TOTAL_GATES total"
echo "  Release status: $RELEASE_STATUS"
echo "  Artifact promotable: $ARTIFACT_PROMOTABLE"
echo ""

# Check invariants.
INV_COUNT="$(jq '.invariants | length' "$QUAL_FILE")"
if [ "$INV_COUNT" -gt 0 ]; then
  echo "  Release invariants ($INV_COUNT):"
  for i in $(seq 0 $((INV_COUNT - 1))); do
    inv_id="$(jq -r ".invariants[$i].id" "$QUAL_FILE")"
    inv_desc="$(jq -r ".invariants[$i].description" "$QUAL_FILE")"
    printf "    %-15s %s\n" "$inv_id" "$inv_desc"
  done
  echo ""
fi

# Admission decision.
if [ "$RELEASE_STATUS" = "PASS" ] && [ "$ARTIFACT_PROMOTABLE" = "true" ]; then
  echo "RELEASE ADMISSION: PASS"
  exit 0
else
  echo "RELEASE ADMISSION: REJECTED" >&2
  exit 1
fi
