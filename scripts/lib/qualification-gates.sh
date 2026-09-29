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
# Semantics (fail closed — a record that omits a field the validator
# depends on is rejected, never defaulted into a pass):
#   - document schema_version must equal QUALIFICATION_SCHEMA_VERSION
#   - gates must be a non-empty array of gate objects
#   - every gate must carry gate_id, gate_type, mandatory, status,
#     exit_code, and evidence{file,sha256} with the expected JSON types;
#     gate_id, gate_type, and evidence.file must be non-empty
#   - gate_id must be unique across the record
#   - unknown gate_type -> FAIL CLOSED
#   - mandatory && status != PASS -> FAIL
#   - PASS && exit_code != 0 -> FAIL (contradictory record)
#   - test-bearing gate (TEST, INTEGRATION, SECURITY, FAULT_INJECTION):
#       must report tests_executed and tests_failed
#       PASS requires tests_executed > 0 and tests_failed == 0
#   - non-test-bearing gate must not report nonzero test counts
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

# qualification_gate_structure_findings <qualification.json>
#
# Emits one finding per structural defect: the record is not an object,
# gates is missing / not an array / empty, a gate is not an object, or a
# field the semantic pass depends on is missing or the wrong JSON type.
# Empty output (and exit 0) means the record is structurally sound.
#
# This is deliberately not a re-implementation of the JSON Schema: it is
# defense in depth around exactly the fields the semantic pass reads, so
# that a missing field can never be defaulted into a passing value.
qualification_gate_structure_findings() {
  jq -r '
    def is_int: (type == "number") and (. == (. | floor));
    def req_str($o; $k; $p):
      if ($o | type) != "object" then empty
      elif ($o | has($k) | not) then "\($p).\($k) is missing"
      elif ($o[$k] | type) != "string" then "\($p).\($k) is not a string"
      elif ($o[$k] | length) == 0 then "\($p).\($k) is empty"
      else empty end;
    def req_bool($o; $k; $p):
      if ($o | type) != "object" then empty
      elif ($o | has($k) | not) then "\($p).\($k) is missing"
      elif ($o[$k] | type) != "boolean" then "\($p).\($k) is not a boolean"
      else empty end;
    def req_int($o; $k; $p):
      if ($o | type) != "object" then empty
      elif ($o | has($k) | not) then "\($p).\($k) is missing"
      elif ($o[$k] | is_int | not) then "\($p).\($k) is not an integer"
      else empty end;
    def opt_uint($o; $k; $p):
      if ($o | type) != "object" then empty
      elif ($o | has($k) | not) then empty
      elif ($o[$k] | is_int | not) then "\($p).\($k) is not an integer"
      elif ($o[$k] < 0) then "\($p).\($k) is negative"
      else empty end;
    if (type != "object") then "qualification record is not a JSON object"
    elif (has("gates") | not) then "gates is missing"
    elif (.gates | type) != "array" then "gates is not an array"
    elif (.gates | length) == 0 then "gates is empty (a qualification record must carry at least one gate)"
    else
      .gates | to_entries[] |
      .key as $i | .value as $g | "gates[\($i)]" as $p |
      if ($g | type) != "object" then "\($p) is not an object"
      else
        req_str($g; "gate_id"; $p),
        req_str($g; "gate_type"; $p),
        req_bool($g; "mandatory"; $p),
        req_str($g; "status"; $p),
        req_int($g; "exit_code"; $p),
        (if ($g | has("evidence") | not) then "\($p).evidence is missing"
         elif ($g.evidence | type) != "object" then "\($p).evidence is not an object"
         else req_str($g.evidence; "file"; "\($p).evidence"),
              req_str($g.evidence; "sha256"; "\($p).evidence")
         end),
        opt_uint($g; "tests_executed"; $p),
        opt_uint($g; "tests_failed"; $p),
        opt_uint($g; "duration_ms"; $p)
      end
    end
  ' "$1" 2>/dev/null
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

  # Structural pass first: fail closed before any semantic default can
  # turn a missing field into a passing value.
  local structure
  if ! structure="$(qualification_gate_structure_findings "$qual")"; then
    echo "qualification record is not valid JSON"
    return 1
  fi
  if [ -n "$structure" ]; then
    printf '%s\n' "$structure"
    return 1
  fi

  # The structural pass guarantees gates is a non-empty array of objects
  # carrying every field read below. tests_executed / tests_failed are
  # read without a default so that "absent" (null) stays distinguishable
  # from a legitimate zero.
  local rows
  if ! rows="$(jq -r '.gates[] | [
      (.gate_id // ""),
      (.gate_type // ""),
      ((.mandatory // false) | tostring),
      (.status // ""),
      ((.exit_code // 0) | tostring),
      (.tests_executed | tostring),
      (.tests_failed | tostring),
      (.evidence.sha256 // "")
    ] | @tsv' "$qual" 2>/dev/null)"; then
    echo "gates are not readable as an array"
    return 1
  fi

  local seen_ids="|"
  local gate_id gate_type mandatory status exit_code executed failed evidence_sha
  while IFS=$'\t' read -r gate_id gate_type mandatory status exit_code executed failed evidence_sha; do
    # Unreachable after the structural pass; kept as an explicit
    # fail-closed guard rather than a silent skip.
    if [ -z "$gate_id" ]; then
      echo "gate with empty gate_id passed structural validation (validator defect)"
      findings=$((findings + 1))
      continue
    fi

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
      if [ "$executed" = "null" ] || [ "$failed" = "null" ]; then
        echo "gate $gate_id: $gate_type gate must report tests_executed and tests_failed"
        findings=$((findings + 1))
      else
        if [ "$status" = "PASS" ] && [ "$executed" -le 0 ]; then
          echo "gate $gate_id: $gate_type gate PASSed with tests_executed=$executed"
          findings=$((findings + 1))
        fi
        if [ "$failed" -ne 0 ]; then
          echo "gate $gate_id: tests_failed=$failed"
          findings=$((findings + 1))
        fi
      fi
    else
      if { [ "$executed" != "null" ] && [ "$executed" -ne 0 ]; } || \
         { [ "$failed" != "null" ] && [ "$failed" -ne 0 ]; }; then
        echo "gate $gate_id: non-test gate ($gate_type) reports test counts (executed=${executed} failed=${failed})"
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
