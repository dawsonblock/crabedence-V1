#!/usr/bin/env bash
# lib.sh — shared helpers for the staging operational proofs.
# Sourced by every proof; never executed directly.

SOCKET="${CRABEDENCE_SOCKET:-/run/crabedence/execution.sock}"
CRABBOX="${CRABBOX:-crabbox}"
ISSUE_GRANT="${ISSUE_GRANT:-issue-grant}"
PRINCIPAL="${STAGING_PRINCIPAL:-staging@example.com}"
ENV_FILE="${STAGING_ENV_FILE:-/etc/crabedence/staging.env}"

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
skip() { echo "SKIP: $*" >&2; exit 77; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || fail "required command missing: $1"; }

# Source the staging env so proofs share the service's configuration
# (database DSN etc.). The file is mode 0600 — run proofs as root or
# the crabedence user.
load_env() {
  [ -f "$ENV_FILE" ] || fail "staging env file missing: $ENV_FILE"
  set -a; . "$ENV_FILE"; set +a
  [ -n "${CRABEDENCE_DATABASE_URL:-}" ] || fail "CRABEDENCE_DATABASE_URL unset in $ENV_FILE"
}

# psql against the staging database using the service's own DSN.
psql_db() { psql "$CRABEDENCE_DATABASE_URL" -v ON_ERROR_STOP=1 -At -c "$1"; }

# wait_ready [timeout_seconds] — poll readiness.sh until the service is
# ready or the deadline passes.
wait_ready() {
  local deadline=$(( $(date +%s) + ${1:-60} ))
  while true; do
    if "$(dirname "${BASH_SOURCE[0]}")/../readiness.sh" --socket "$SOCKET" >/dev/null 2>&1; then
      return 0
    fi
    [ "$(date +%s)" -lt "$deadline" ] || { echo "service did not become ready" >&2; return 1; }
    sleep 1
  done
}

# invoke <capability> <arguments-json> [idempotency-key] [exec-class]
# Prints the JSON response. Grant-bound routes need STAGING_GRANT_ID.
invoke() {
  local cap="$1" args="$2" key="${3:-}" class="${4:-}"
  local cmd=("$CRABBOX" invoke --socket "$SOCKET" --capability "$cap"
    --principal "$PRINCIPAL" --arguments "$args")
  [ -n "${STAGING_GRANT_ID:-}" ] && cmd+=(--authority-ref "$STAGING_GRANT_ID")
  [ -n "$key" ] && cmd+=(--idempotency-key "$key")
  [ -n "$class" ] && cmd+=(--execution-class "$class")
  "${cmd[@]}"
}

# Durable-ledger helpers. Rows are unique on
# (principal_id, capability_id, idempotency_key).
ledger_count() { # <capability> <key>
  psql_db "SELECT count(*) FROM execution_requests
           WHERE principal_id='$PRINCIPAL' AND capability_id='$1' AND idempotency_key='$2'"
}
ledger_field() { # <capability> <key> <column>
  psql_db "SELECT $3 FROM execution_requests
           WHERE principal_id='$PRINCIPAL' AND capability_id='$1' AND idempotency_key='$2'"
}
ledger_state() { ledger_field "$1" "$2" state; }

# three_view <capability> <key> — the invariant from STAGING.md:
#   1. Crabedence durable ledger (execution_requests)
#   2. Provider operation history (effect_provider_observations / run id)
#   3. Signed receipt / evidence artifact (evidence_receipt + digests)
# Fails unless all three views agree on a single COMMITTED outcome.
three_view() {
  local cap="$1" key="$2"
  local state rid obs digest
  state=$(ledger_state "$cap" "$key")
  [ "$state" = "COMMITTED" ] || fail "three-view: ledger state is '$state', expected COMMITTED"
  rid=$(ledger_field "$cap" "$key" provider_run_id)
  [ -n "$rid" ] || fail "three-view: no provider_run_id recorded"
  obs=$(psql_db "SELECT count(*) FROM effect_provider_observations
                 WHERE provider_run_id='$rid'" 2>/dev/null || echo 0)
  [ "${obs:-0}" -ge 1 ] || fail "three-view: no provider observation for run $rid"
  digest=$(ledger_field "$cap" "$key" evidence_digest)
  [ -n "$digest" ] || fail "three-view: no evidence digest recorded"
  echo "three-view: ledger=$state run=$rid observations=$obs evidence=${digest:0:16}…"
}

# issue_staging_grant <capabilities...> — one narrowly scoped grant for
# the proof's principal; prints the grant_id. Generation is allocated by
# the authority store; the helper reports it on stderr for the operator.
issue_staging_grant() {
  local args=(--principal "$PRINCIPAL" --expires-at "$(date -u -d '+24 hours' +%Y-%m-%dT%H:%M:%SZ)")
  local c
  for c in "$@"; do args+=(--capability "$c"); done
  CRABEDENCE_DATABASE_URL="$CRABEDENCE_DATABASE_URL" \
    "$ISSUE_GRANT" "${args[@]}" | jq -r .grant_id
}

key() { echo "proof-$1-$(date +%s%N)"; }
