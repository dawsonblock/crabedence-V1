#!/usr/bin/env bash
# Canonical qualification gate semantics — the single validator.
#
# Consumed by scripts/check-release-admission.sh (admission) and
# scripts/verify-release-artifact.sh (standalone verification). Gate
# semantics live HERE and nowhere else: no consumer may re-derive them
# from gate IDs, names, or hardcoded lists.
#
# Gate record (qualification schema version 2):
#
#   {
#     "gate_id": "effect-fabric-race",
#     "gate_type": "TEST",
#     "mandatory": true,
#     "status": "PASS",
#     "exit_code": 0,
#     "tests_executed": 428,
#     "tests_failed": 0,
#     "duration_ms": 81931,
#     "evidence": { "file": "gate-results/...", "sha256": "..." }
#   }
#
# Semantics:
#   - document schema_version must equal QUALIFICATION_SCHEMA_VERSION
#   - unknown gate_type -> FAIL CLOSED
#   - duplicate gate_id -> FAIL
#   - mandatory && status != PASS -> FAIL
#   - PASS && exit_code != 0 -> FAIL (contradictory record)
#   - test-bearing gate (TEST, INTEGRATION, SECURITY, FAULT_INJECTION):
#       PASS requires tests_executed > 0 and tests_failed == 0
#   - non-test-bearing gate must not report test counts
#   - evidence.sha256 must be a 64-character lowercase hex digest

# shellcheck disable=SC2034
QUALIFICATION_SCHEMA_VERSION=2

# Closed enum. Adding a type is a deliberate schema change.
QUALIFICATION_GATE_TYPES="TEST BUILD STATIC_ANALYSIS INTEGRATION SECURITY FAULT_INJECTION REPRODUCIBILITY PROVENANCE CLEAN_ROOM"

# Test-bearing types execute tests and must report honest counts.
qualification_gate_type_test_bearing() {
  case "$1" in
    TEST|INTEGRATION|SECURITY|FAULT_INJECTION) return 0 ;;
    *) return 1 ;;
  esac
}

qualification_gate_type_valid() {
  local candidate
  for candidate in $QUALIFICATION_GATE_TYPES; do
    if [ "$candidate" = "$1" ]; then
      return 0
    fi
  done
  return 1
}

# validate_qualification_gates <qualification.json>
#
# Prints one finding per line (empty output means the record satisfies
# every rule) and returns 1 when any rule is violated. Consumers count
# findings and decide how to present them.
validate_qualification_gates() {
  local qual="$1"
  local findings=0

  if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required for gate validation"
    return 1
  fi
  if [ ! -f "$qual" ]; then
    echo "qualification record not found: $qual"
    return 1
  fi

  local version
  version="$(jq -r '.schema_version // empty' "$qual" 2>/dev/null || true)"
  if [ "$version" != "$QUALIFICATION_SCHEMA_VERSION" ]; then
    echo "schema_version=${version:-missing} (want $QUALIFICATION_SCHEMA_VERSION)"
    return 1
  fi

  local rows
  if ! rows="$(jq -r '.gates[]? | [
      (.gate_id // ""),
      (.gate_type // ""),
      ((.mandatory // false) | tostring),
      (.status // ""),
      ((.exit_code // 0) | tostring),
      ((.tests_executed // 0) | tostring),
      ((.tests_failed // 0) | tostring),
      ((.evidence.sha256 // "") )
    ] | @tsv' "$qual" 2>/dev/null)"; then
    echo "gates are not readable as an array"
    return 1
  fi

  local seen_ids="|"
  local gate_id gate_type mandatory status exit_code executed failed evidence_sha
  while IFS=$'\t' read -r gate_id gate_type mandatory status exit_code executed failed evidence_sha; do
    [ -z "$gate_id" ] && continue

    if [ "${seen_ids#*"|$gate_id|"}" != "$seen_ids" ]; then
      echo "gate $gate_id: duplicate gate_id"
      findings=$((findings + 1))
    fi
    seen_ids="$seen_ids$gate_id|"

    if ! qualification_gate_type_valid "$gate_type"; then
      echo "gate $gate_id: unknown gate_type '$gate_type' — fail closed"
      findings=$((findings + 1))
      continue
    fi

    if [ "$mandatory" = "true" ] && [ "$status" != "PASS" ]; then
      echo "gate $gate_id: mandatory gate status=$status (want PASS)"
      findings=$((findings + 1))
    fi
    if [ "$status" = "PASS" ] && [ "$exit_code" != "0" ]; then
      echo "gate $gate_id: PASS with exit_code=$exit_code"
      findings=$((findings + 1))
    fi

    if qualification_gate_type_test_bearing "$gate_type"; then
      if [ "$status" = "PASS" ] && [ "$executed" -le 0 ]; then
        echo "gate $gate_id: $gate_type gate PASSed with tests_executed=$executed"
        findings=$((findings + 1))
      fi
      if [ "$failed" -ne 0 ]; then
        echo "gate $gate_id: tests_failed=$failed"
        findings=$((findings + 1))
      fi
    else
      if [ "$executed" -ne 0 ] || [ "$failed" -ne 0 ]; then
        echo "gate $gate_id: non-test gate ($gate_type) reports test counts (executed=$executed failed=$failed)"
        findings=$((findings + 1))
      fi
    fi

    if ! printf '%s' "$evidence_sha" | grep -qE '^[0-9a-f]{64}$'; then
      echo "gate $gate_id: evidence sha256 is missing or malformed"
      findings=$((findings + 1))
    fi
  done <<< "$rows"

  [ "$findings" -eq 0 ]
}
