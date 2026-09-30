#!/usr/bin/env bash
# Live-database gate helpers for the release evidence generator.
#
# A gate that requires a live PostgreSQL must record the database's
# absence as its own FAIL. Running the underlying suite with an empty
# database URL lets the suite skip and exit 0, which a generic runner
# records as a PASS with zero executed tests — a semantically dishonest
# record that only the downstream gate validator would later reject.
# Fail closed here instead, so the stored gate status is truthful.
#
# Sourced by scripts/generate-release-evidence.sh. The functions below
# depend on the generator's EVIDENCE_DIR, now_ms, record_gate, and
# run_gate; bash resolves those at call time, so definition order is not
# significant.

# run_required_live_go_gate <name> <type> <command...>
#
#   database absent  -> record FAIL without running the suite
#   database present -> run the suite through run_gate, whose exit
#                       status decides PASS/FAIL
run_required_live_go_gate() {
  local name="$1" type="$2"
  shift 2
  local log="$EVIDENCE_DIR/gate-results/${name}.log"
  if [ -z "${CRABBOX_TEST_DATABASE_URL:-}" ]; then
    {
      echo "command=run_required_live_go_gate $name $*"
      echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      echo "---"
      echo "FAIL: CRABBOX_TEST_DATABASE_URL not set — a live PostgreSQL is required for this gate"
      echo "exit=1"
      echo "finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$log"
    GATE_START_MS="$(now_ms)"
    record_gate "$name" "$type" "FAIL" 1 "$log"
    echo "  FAIL  $name (CRABBOX_TEST_DATABASE_URL not set)"
    return
  fi
  run_gate "$name" "$type" env CRABBOX_TEST_DATABASE_URL="$CRABBOX_TEST_DATABASE_URL" "$@"
}
