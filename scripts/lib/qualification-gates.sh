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
#
# Optional extensions (fail closed when present, absent when unused):
#   - gate.test_suite: a per-test evidence binding
#       {"suite","lane","inventory":{file,sha256},
#        "results":{file,sha256},"raw":{file,sha256}}
#     The results file is validated case-by-case against the bundled
#     required-test inventory: every required case for the lane must
#     appear exactly once with status "pass"; absent, skipped,
#     duplicated, failed, or foreign-lane cases are findings; so are
#     identity drift (commit, toolchain, runner os/arch, lane, package),
#     aggregate inconsistency, and a results record that is not the exact
#     canonical re-derivation of the bound raw go test -json stream —
#     outcomes, terminal-event counts, durations, output digests,
#     package identity, and run completion are all recomputed from the
#     stream by the shared evidence parser, never trusted from the
#     record.
#   - qualification.claimed_lanes: the virtualization lanes this
#     release claims support for. Every claimed lane must be backed by
#     a passing mandatory gate carrying test_suite evidence for that
#     lane — a lane claim without lane evidence cannot admit.

# shellcheck disable=SC2034
QUALIFICATION_SCHEMA_VERSION=2

# The canonical case-evidence parser ships beside this library; the raw
# stream revalidation resolves it relative to the library's own path so
# admission, standalone verification, and the producer's self-check share
# exactly one parser — never a per-consumer approximation of it.
GATE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
    def opt_suite($g; $p):
      if ($g | has("test_suite") | not) then empty
      elif ($g.test_suite | type) != "object" then "\($p).test_suite is not an object"
      else
        req_str($g.test_suite; "suite"; "\($p).test_suite"),
        req_str($g.test_suite; "lane"; "\($p).test_suite"),
        (["inventory", "results", "raw"][] | . as $k |
          if ($g.test_suite | has($k) | not) then "\($p).test_suite.\($k) is missing"
          elif ($g.test_suite[$k] | type) != "object" then "\($p).test_suite.\($k) is not an object"
          else req_str($g.test_suite[$k]; "file"; "\($p).test_suite.\($k)"),
               req_str($g.test_suite[$k]; "sha256"; "\($p).test_suite.\($k)")
          end)
      end;
    if (type != "object") then "qualification record is not a JSON object"
    elif (has("gates") | not) then "gates is missing"
    elif (.gates | type) != "array" then "gates is not an array"
    elif (.gates | length) == 0 then "gates is empty (a qualification record must carry at least one gate)"
    else
      (if (has("release") | not) then "release is missing (the record must carry the release identity it evaluated)"
       elif (.release | type) != "string" then "release is not a string"
       elif (.release | length) == 0 then "release is empty"
       else empty end),
      (if (has("claimed_lanes") | not) then empty
       elif (.claimed_lanes | type) != "array" then "claimed_lanes is not an array"
       elif (.claimed_lanes | map(type == "string" and length > 0) | all | not)
            then "claimed_lanes must contain only non-empty strings"
       else empty end),
      (.gates | to_entries[] |
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
        opt_uint($g; "duration_ms"; $p),
        opt_suite($g; $p)
      end)
    end
  ' "$1" 2>/dev/null
}

# required_tests_case_findings <cases.json> <inventory.json> <lane>
#
# Prints one finding per violation of the required-test inventory for
# the given lane. A lane's required set is the common cases plus that
# lane's platform-specific cases; each must appear exactly once with
# status "pass". Absent, skipped, failed, duplicated, multi-event, or
# foreign-lane executions are all findings. Empty output is the pass.
required_tests_case_findings() {
  jq -n --slurpfile cases "$1" --slurpfile inv "$2" --arg lane "$3" '
    ($inv[0]) as $inv | ($cases[0].tests // []) as $tests |
    ((($inv.common_required_tests // []) +
      (($inv.platform_specific_tests // {})[$lane] // [])) | unique) as $required |
    ($tests | map(.name)) as $names |
    (
      $required[] | . as $t |
      ([ $names[] | select(. == $t) ] | length) as $n |
      if $n == 0 then "required test \($t) absent from results"
      elif $n > 1 then "required test \($t) recorded \($n) times"
      else empty end
    ),
    (
      $tests[] | . as $tc |
      if ($required | index($tc.name)) == null then empty
      else
        (if ($tc.status != "pass")
         then "required test \($tc.name) status=\($tc.status) (want pass)" else empty end),
        (if (($tc.terminal_events // 1) != 1)
         then "required test \($tc.name) recorded \($tc.terminal_events) terminal events"
         else empty end)
      end
    ),
    (
      $names | group_by(.)[] | select(length > 1) | .[0] |
      "test \(.) recorded more than once"
    ),
    (
      # An executed case the inventory does not require means the bound
      # inventory does not describe this run — either the inventory was
      # swapped to drop required cases or the suite outgrew it. The
      # record may not claim coverage it cannot account for.
      $tests[] | select(.status == "pass" or .status == "fail") | .name | split("/")[0] |
      select(. as $n | $required | index($n) == null) |
      "test \(.) executed but is not in the required inventory for lane \($lane)"
    ),
    (
      (($inv.platform_specific_tests // {}) | to_entries
        | map(select(.key != $lane) | .value[])) as $foreign |
      $tests[] | select(.status != "skip") | .name | split("/")[0] |
      select(. as $n | $foreign | index($n) != null) |
      "test \(.) is platform-specific to another lane and must not execute here"
    )
  '
}

# validate_test_suite_binding <qualification.json> <gate_index> <evidence_dir>
#
# Validates one gate's test_suite evidence binding: the bound files must
# exist inside the bundle, their digests must match the record, and the
# results must satisfy the inventory for the gate's lane with identity
# (commit, toolchain, runner os) matching the qualification record.
validate_test_suite_binding() {
  local qual="$1" idx="$2" dir="$3"
  local gid suite lane inv_file inv_sha res_file res_sha raw_file raw_sha
  gid="$(jq -r ".gates[$idx].gate_id" "$qual")"
  IFS=$'\t' read -r suite lane inv_file inv_sha res_file res_sha raw_file raw_sha \
    <<<"$(jq -r '.gates['"$idx"'].test_suite |
        [.suite, .lane,
         .inventory.file, .inventory.sha256,
         .results.file, .results.sha256,
         .raw.file, .raw.sha256] | @tsv' "$qual")"

  # Bundle confinement and existence: bound paths must stay inside the
  # evidence tree and exist.
  local defects=0 f
  for f in "$inv_file" "$res_file" "$raw_file"; do
    case "$f" in
      /*|*..*)
        echo "gate $gid: test_suite evidence path escapes the bundle: $f"
        defects=$((defects + 1)) ;;
      *)
        if [ ! -f "$dir/$f" ]; then
          echo "gate $gid: test_suite evidence file missing: $f"
          defects=$((defects + 1))
        fi ;;
    esac
  done
  [ "$defects" -gt 0 ] && return 0

  # Digest binding: every bound file must hash to the recorded digest.
  local actual
  actual="$(shasum -a 256 "$dir/$inv_file" | awk '{print $1}')"
  if [ "$actual" != "$inv_sha" ]; then
    echo "gate $gid: test_suite inventory digest $actual does not match the recorded $inv_sha"
    defects=$((defects + 1))
  fi
  actual="$(shasum -a 256 "$dir/$res_file" | awk '{print $1}')"
  if [ "$actual" != "$res_sha" ]; then
    echo "gate $gid: test_suite results digest $actual does not match the recorded $res_sha"
    defects=$((defects + 1))
  fi
  actual="$(shasum -a 256 "$dir/$raw_file" | awk '{print $1}')"
  if [ "$actual" != "$raw_sha" ]; then
    echo "gate $gid: test_suite raw digest $actual does not match the recorded $raw_sha"
    defects=$((defects + 1))
  fi
  [ "$defects" -gt 0 ] && return 0

  # Identity and aggregate consistency between the record, the results,
  # and the inventory. The lane's declared platform, the runner's
  # reported platform, and the toolchain's own os/arch tail are checked
  # as ONE identity — evidence naming a different CPU architecture or a
  # package outside the suite is rejected, not merely recorded.
  local commit go te tf
  commit="$(jq -r '.provenance.commit // empty' "$qual")"
  go="$(jq -r '.toolchains.go // empty' "$qual")"
  te="$(jq -r ".gates[$idx].tests_executed // 0" "$qual")"
  tf="$(jq -r ".gates[$idx].tests_failed // 0" "$qual")"
  jq -n --arg gid "$gid" --arg suite "$suite" --arg lane "$lane" \
    --arg commit "$commit" --arg go "$go" \
    --argjson te "$te" --argjson tf "$tf" \
    --slurpfile inv "$dir/$inv_file" --slurpfile res "$dir/$res_file" '
    def canon_arch:
      if . == "x86_64" or . == "amd64" then "amd64"
      elif . == "aarch64" or . == "arm64" then "arm64"
      else . end;
    ($inv[0]) as $i | ($res[0]) as $r |
    (($r.toolchain_go // "") | split(" ") | last) as $ttail |
    (($r.toolchain_go // "") | split(" ") | .[2] // "") as $rver |
    (($go // "") | split(" ") | .[2] // "") as $qver |
    (if ($i.schema_version != 1) then "gate \($gid): inventory schema_version \($i.schema_version // "missing") (want 1)" else empty end),
    (if ($i.suite != $suite) then "gate \($gid): inventory suite \($i.suite) != \($suite)" else empty end),
    (if (($i.lanes // {}) | has($lane) | not) then "gate \($gid): inventory has no lane \($lane)" else empty end),
    (if ($r.schema_version != 1) then "gate \($gid): results schema_version \($r.schema_version // "missing") (want 1)" else empty end),
    (if ($r.suite != $suite) then "gate \($gid): results suite \($r.suite) != \($suite)" else empty end),
    (if ($r.lane != $lane) then "gate \($gid): results lane \($r.lane) != \($lane)" else empty end),
    (if ($r.source_commit != $commit) then "gate \($gid): results commit \($r.source_commit) does not match the qualified commit \($commit)" else empty end),
    # The lane must run the qualified toolchain VERSION; the os/arch
    # tail legitimately differs — it is the lane identity itself, checked
    # below against the lane goos and the runner arch. Comparing the
    # whole string would reject any lane qualified on another platform.
    (if (($rver == "") or ($rver | startswith("go") | not) or ($rver != $qver))
     then "gate \($gid): results toolchain \($r.toolchain_go // "missing") does not run the qualified toolchain version \($go)" else empty end),
    (if (($i.lanes[$lane].goos // "") != ($r.runner.os // "")) then "gate \($gid): results runner os \($r.runner.os) is not the \($lane) lane os \($i.lanes[$lane].goos)" else empty end),
    (if (($r.runner.arch // "") == "") then "gate \($gid): results runner arch is missing" else empty end),
    (if ((($i.lanes[$lane].goarch // "") != "") and
         ((($r.runner.arch // "") | canon_arch) != ($i.lanes[$lane].goarch | canon_arch)))
     then "gate \($gid): results runner arch \($r.runner.arch // "missing") is not the \($lane) lane arch \($i.lanes[$lane].goarch)" else empty end),
    (if ($ttail | test("/") | not) then "gate \($gid): results toolchain \($r.toolchain_go // "missing") carries no os/arch identity" else empty end),
    (if (($ttail | test("/")) and (($ttail | split("/")[0]) != ($i.lanes[$lane].goos // "")))
     then "gate \($gid): toolchain os \($ttail | split("/")[0]) is not the \($lane) lane os \($i.lanes[$lane].goos)" else empty end),
    (if (($ttail | test("/")) and (($ttail | split("/")[1] | canon_arch) != (($r.runner.arch // "") | canon_arch)))
     then "gate \($gid): toolchain arch \($ttail | split("/")[1]) does not match the results runner arch \($r.runner.arch // "missing")" else empty end),
    (if (($i.package // "") == "") then "gate \($gid): inventory carries no suite package identity"
     elif (($r.packages | type) != "array" or ($r.packages | length) == 0) then "gate \($gid): results record no package identity"
     elif (($r.packages | map(type == "string" and (. == $i.package or endswith("/" + $i.package))) | all) | not)
     then "gate \($gid): results packages \($r.packages) are not the suite package \($i.package)"
     else empty end),
    (if (($r.tests // []) | map(select(.status == "pass" or .status == "fail")) | length) != $te
     then "gate \($gid): tests_executed=\($te) inconsistent with case results" else empty end),
    (if (($r.tests // []) | map(select(.status == "fail")) | length) != $tf
     then "gate \($gid): tests_failed=\($tf) inconsistent with case results" else empty end)
  '

  # Per-case coverage against the inventory.
  required_tests_case_findings "$dir/$res_file" "$dir/$inv_file" "$lane" \
    | sed "s/^/gate $gid: /"

  # The normalized results must be the canonical re-derivation of the
  # bound raw stream: the shared evidence parser recomputes every case
  # outcome, terminal-event count, duration, output digest, the
  # aggregate counts, the package identities, and the run's own terminal
  # completeness — and reports every point the record disagrees with the
  # stream and every way the stream itself is malformed. A digest-bound
  # results file whose precomputed fields were supplied rather than
  # derived is fabricated evidence; only re-derivation proves the record
  # describes the run.
  local normalizer="$GATE_LIB_DIR/../go-test-case-evidence.py"
  local expected_pkg stream_findings rc=0
  expected_pkg="$(jq -r '.package // empty' "$dir/$inv_file")"
  if ! command -v python3 >/dev/null 2>&1; then
    echo "gate $gid: python3 is required to re-derive case evidence from the raw go test -json stream"
  elif [ ! -f "$normalizer" ]; then
    echo "gate $gid: canonical evidence parser not found: $normalizer"
  else
    stream_findings="$(python3 "$normalizer" --verify \
      --stream "$dir/$raw_file" --results "$dir/$res_file" \
      --expect-package "$expected_pkg" 2>&1)" || rc=$?
    if [ -z "$stream_findings" ] && [ "$rc" -ne 0 ]; then
      stream_findings="raw stream re-derivation could not run (exit $rc)"
    fi
    printf '%s\n' "$stream_findings" | sed '/^$/d; '"s/^/gate $gid: /"
  fi
  return 0
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

  # ─── Per-test suite bindings ─────────────────────────────────────────
  # A gate carrying test_suite claims per-test evidence; the bound files
  # live in the same evidence directory as the record and must satisfy
  # the required-test inventory for the gate's lane.
  local evidence_dir
  evidence_dir="$(dirname "$qual")"
  local idx finding
  for idx in $(jq -r '.gates | to_entries[] | select(.value.test_suite != null) | .key' "$qual" 2>/dev/null); do
    while IFS= read -r finding; do
      [ -z "$finding" ] && continue
      echo "$finding"
      findings=$((findings + 1))
    done < <(validate_test_suite_binding "$qual" "$idx" "$evidence_dir")
  done

  # ─── Claimed lanes ───────────────────────────────────────────────────
  # Every lane the release claims support for must be backed by a
  # passing mandatory gate carrying test_suite evidence for that lane.
  local lane
  while IFS= read -r lane; do
    [ -z "$lane" ] && continue
    if ! jq -e --arg lane "$lane" \
      '[.gates[] | select(.test_suite.lane == $lane and .status == "PASS" and .mandatory == true)] | length > 0' \
      "$qual" >/dev/null 2>&1; then
      echo "claimed lane $lane has no passing mandatory lane gate"
      findings=$((findings + 1))
    fi
  done < <(jq -r '.claimed_lanes // [] | .[]' "$qual" 2>/dev/null)

  [ "$findings" -eq 0 ]
}
