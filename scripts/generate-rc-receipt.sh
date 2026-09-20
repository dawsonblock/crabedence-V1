#!/usr/bin/env bash
# Generate the RC qualification receipt: the human-facing index into a
# release's evidence.
#
# Every value is READ from the finalized evidence and the staged archives —
# nothing is copied by hand and nothing is re-derived from terminal output.
# Stages that have not run yet (clean room, attestation, public
# reverification) report PENDING unless the caller supplies their outcome,
# so the receipt can never claim a verification that did not happen.
#
# Usage:
#   ./scripts/generate-rc-receipt.sh [--evidence DIR] [--dist DIR]
#                                    [--clean-room PASS|FAIL|PENDING]
#                                    [--attestation PASS|FAIL|PENDING]
#                                    [--public-reverify PASS|FAIL|PENDING]
#                                    [--output FILE]
#
# Prints a human-readable summary and writes the machine-readable receipt
# (JSON) to --output, or to stdout when --output is omitted.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

EVIDENCE_DIR="$REPO_ROOT/dist/release-evidence"
DIST_DIR="$REPO_ROOT/dist"
CLEAN_ROOM="PENDING"
ATTESTATION="PENDING"
PUBLIC_REVERIFY="PENDING"
OUTPUT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --evidence) EVIDENCE_DIR="${2:-}"; shift 2 ;;
    --dist) DIST_DIR="${2:-}"; shift 2 ;;
    --clean-room) CLEAN_ROOM="${2:-}"; shift 2 ;;
    --attestation) ATTESTATION="${2:-}"; shift 2 ;;
    --public-reverify) PUBLIC_REVERIFY="${2:-}"; shift 2 ;;
    --output) OUTPUT="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "ERROR: unknown option: $1" >&2; exit 2 ;;
  esac
done

for value in "$CLEAN_ROOM" "$ATTESTATION" "$PUBLIC_REVERIFY"; do
  case "$value" in
    PASS|FAIL|PENDING) ;;
    *) echo "ERROR: stage outcomes must be PASS, FAIL, or PENDING (got: $value)" >&2; exit 2 ;;
  esac
done

ARTIFACT_JSON="$EVIDENCE_DIR/artifact.json"
QUAL_JSON="$EVIDENCE_DIR/qualification.json"
if [ ! -f "$ARTIFACT_JSON" ]; then
  echo "ERROR: artifact.json not found in $EVIDENCE_DIR" >&2
  exit 1
fi
if [ ! -f "$QUAL_JSON" ]; then
  echo "ERROR: qualification.json not found in $EVIDENCE_DIR" >&2
  exit 1
fi

digest_of_file() {
  [ -f "$1" ] && shasum -a 256 "$1" | cut -d ' ' -f1 || echo ""
}
sha_file_value() {
  [ -f "$1" ] && tr -d '[:space:]' < "$1" || echo ""
}

RELEASE="$(jq -r '.release // empty' "$ARTIFACT_JSON")"
COMMIT="$(jq -r '.source.commit // empty' "$ARTIFACT_JSON")"
TREE="$(jq -r '.source.tree // empty' "$ARTIFACT_JSON")"
TAR_SHA="$(jq -r '.artifact.sha256 // empty' "$ARTIFACT_JSON")"
ZIP_SHA="$(jq -r '.artifact.zip_sha256 // empty' "$ARTIFACT_JSON")"
RELEASE_REGISTRY_SHA="$(jq -r '.policy.registry_sha256 // empty' "$ARTIFACT_JSON")"
QUAL_SHA="$(jq -r '.qualification.sha256 // empty' "$ARTIFACT_JSON")"
SBOM_SHA="$(jq -r '.sbom.sha256 // empty' "$ARTIFACT_JSON")"
PROV_SHA="$(jq -r '.provenance.sha256 // empty' "$ARTIFACT_JSON")"

QUAL_REGISTRY_SHA="$(sha_file_value "$EVIDENCE_DIR/qualification-registry.sha256")"
EVIDENCE_BUNDLE_SHA="$(sha_file_value "$DIST_DIR/crabedence-${RELEASE}-release-evidence.tar.gz.sha256")"

QUAL_STATUS="$(jq -r '.release_status // empty' "$QUAL_JSON")"
PROMOTABLE="$(jq -r '.artifact_promotable // false' "$QUAL_JSON")"
GATE_TOTAL="$(jq -r '.gate_summary.total // 0' "$QUAL_JSON")"
GATE_PASSED="$(jq -r '.gate_summary.passed // 0' "$QUAL_JSON")"
GATE_FAILED="$(jq -r '.gate_summary.failed // 0' "$QUAL_JSON")"
MANDATORY="$(jq -r '[.gates[] | select(.mandatory == true)] | length' "$QUAL_JSON")"
TESTS_EXECUTED="$(jq -r '[.gates[].tests_executed // 0] | add // 0' "$QUAL_JSON")"
TESTS_FAILED="$(jq -r '[.gates[].tests_failed // 0] | add // 0' "$QUAL_JSON")"

RECEIPT="$(jq -n \
  --arg release "$RELEASE" \
  --arg commit "$COMMIT" \
  --arg tree "$TREE" \
  --arg release_registry_sha256 "$RELEASE_REGISTRY_SHA" \
  --arg qualification_registry_sha256 "$QUAL_REGISTRY_SHA" \
  --arg tar_sha256 "$TAR_SHA" \
  --arg zip_sha256 "$ZIP_SHA" \
  --arg evidence_bundle_sha256 "$EVIDENCE_BUNDLE_SHA" \
  --arg qualification_sha256 "$QUAL_SHA" \
  --arg sbom_sha256 "$SBOM_SHA" \
  --arg provenance_sha256 "$PROV_SHA" \
  --arg qualification_status "$QUAL_STATUS" \
  --argjson artifact_promotable "$PROMOTABLE" \
  --argjson gates_total "$GATE_TOTAL" \
  --argjson gates_passed "$GATE_PASSED" \
  --argjson gates_failed "$GATE_FAILED" \
  --argjson mandatory_gates "$MANDATORY" \
  --argjson tests_executed "$TESTS_EXECUTED" \
  --argjson tests_failed "$TESTS_FAILED" \
  --arg clean_room "$CLEAN_ROOM" \
  --arg attestation "$ATTESTATION" \
  --arg public_reverify "$PUBLIC_REVERIFY" \
  '{
    release: $release,
    commit: $commit,
    tree: $tree,
    release_registry_sha256: $release_registry_sha256,
    qualification_registry_sha256: $qualification_registry_sha256,
    tar_sha256: $tar_sha256,
    zip_sha256: $zip_sha256,
    evidence_bundle_sha256: $evidence_bundle_sha256,
    qualification_sha256: $qualification_sha256,
    sbom_sha256: $sbom_sha256,
    provenance_sha256: $provenance_sha256,
    qualification_status: $qualification_status,
    artifact_promotable: $artifact_promotable,
    gates: { total: $gates_total, passed: $gates_passed, failed: $gates_failed, mandatory: $mandatory_gates },
    tests: { executed: $tests_executed, failed: $tests_failed },
    clean_room: $clean_room,
    attestation: $attestation,
    public_reverify: $public_reverify
  }')"

if [ -n "$OUTPUT" ]; then
  printf '%s\n' "$RECEIPT" > "$OUTPUT"
else
  printf '%s\n' "$RECEIPT"
fi

{
  echo ""
  echo "=== RC qualification receipt: ${RELEASE:-<unknown>} ==="
  echo "  commit:            ${COMMIT:-<missing>}"
  echo "  tree:              ${TREE:-<missing>}"
  echo "  release registry:  ${RELEASE_REGISTRY_SHA:-<missing>}"
  echo "  qual registry:     ${QUAL_REGISTRY_SHA:-<missing>}"
  echo "  tar.gz:            ${TAR_SHA:-<missing>}"
  echo "  zip:               ${ZIP_SHA:-<missing>}"
  echo "  evidence bundle:   ${EVIDENCE_BUNDLE_SHA:-<missing>}"
  echo "  qualification:     ${QUAL_SHA:-<missing>} (${QUAL_STATUS:-?})"
  echo "  sbom:              ${SBOM_SHA:-<missing>}"
  echo "  provenance:        ${PROV_SHA:-<missing>}"
  echo "  gates:             ${GATE_PASSED}/${GATE_TOTAL} passed (${MANDATORY} mandatory), ${GATE_FAILED} failed"
  echo "  tests:             ${TESTS_EXECUTED} executed, ${TESTS_FAILED} failed"
  echo "  clean room:        ${CLEAN_ROOM}"
  echo "  attestation:       ${ATTESTATION}"
  echo "  public reverify:   ${PUBLIC_REVERIFY}"
} >&2
