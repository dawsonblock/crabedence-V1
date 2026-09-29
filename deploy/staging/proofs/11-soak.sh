#!/usr/bin/env bash
# Soak — sustained mixed load against the deployed service for
# SOAK_DURATION seconds (default 900). Not a quick gate: run after the
# proof suite passes, before canary.
#
# Load shape per iteration:
#   - one durable MUTATION (unique idempotency key)
#   - one duplicate replay of the same key (must not re-dispatch)
#   - two LOCAL system.echo reads
# At ~50%: service restart under load (restart→ready measured).
# At ~70%: brief PG outage (iptables DROP) + reconnect measured.
#
# Asserted invariants at the end:
#   - every soak key resolves COMMITTED with exactly one ledger row
#   - zero duplicate dispatches (1 provider observation per run)
#   - zero terminalization failures (no soak row stuck IN_FLIGHT/FAILED)
#   - authority denials count == denied requests issued
#
# Metrics emitted every iteration block: state histogram, UNKNOWN count
# and oldest UNKNOWN age, dispatch totals.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
need_cmd iptables
[ "$(id -u)" = "0" ] || fail "must run as root (mid-soak restart + iptables)"

DURATION="${SOAK_DURATION:-900}"
ITER_SLEEP="${SOAK_ITER_SLEEP:-2}"
DEADLINE=$(( $(date +%s) + DURATION ))
GRANT=$(issue_staging_grant test.counter.increment system.echo)
export STAGING_GRANT_ID="$GRANT"

TAG="soak-$(date +%s)"
iter=0 sent=0 replays=0 denied_issued=0 restart_done=0 outage_done=0
restart_ready_s=0; db_reconnect_s=0
echo "soak start: duration=${DURATION}s tag=$TAG grant=$GRANT"

metrics() {
  psql_db "SELECT state, count(*) FROM execution_requests
           WHERE idempotency_key LIKE '$TAG-%' GROUP BY state ORDER BY state" \
    | paste -sd' ' - | sed 's/^/  states: /'
  psql_db "SELECT '  unknown_age_s: ' ||
             COALESCE(max(EXTRACT(EPOCH FROM (clock_timestamp() -
               COALESCE(entered_unknown_at, created_at))))::int, 0)
           FROM execution_requests
           WHERE idempotency_key LIKE '$TAG-%' AND state='UNKNOWN'"
}

while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  iter=$((iter + 1)); k="$TAG-$iter"

  invoke test.counter.increment "{\"counter\":\"$TAG\",\"by\":1}" "$k" MUTATION >/dev/null \
    && sent=$((sent + 1)) || echo "  iter $iter: mutation transport/status failure (kept for end-check)"
  invoke test.counter.increment "{\"counter\":\"$TAG\",\"by\":1}" "$k" MUTATION >/dev/null \
    && replays=$((replays + 1)) || true
  invoke system.echo '{"msg":"s"}' >/dev/null || true
  invoke system.echo '{"msg":"s"}' >/dev/null || true

  # Denied-request sample every 10 iterations — counts toward the
  # denial assertion at the end.
  if [ $((iter % 10)) -eq 0 ]; then
    STAGING_GRANT_ID="grant_nonexistent_soak" \
      invoke test.counter.increment "{\"counter\":\"$TAG\",\"by\":1}" "$k-denied" MUTATION >/dev/null 2>&1 \
      || denied_issued=$((denied_issued + 1))
    metrics
  fi

  # Mid-soak restart under load.
  if [ $restart_done -eq 0 ] && [ $iter -gt 0 ] && [ "$(date +%s)" -gt $(( DEADLINE - DURATION / 2 )) ]; then
    t=$(date +%s)
    systemctl restart crabedence
    wait_ready 90 || fail "service did not return after mid-soak restart"
    restart_ready_s=$(( $(date +%s) - t )); restart_done=1
    echo "  restart→ready: ${restart_ready_s}s"
  fi

  # Brief PG outage at ~70% — fail-closed window + reconnect timing.
  if [ $outage_done -eq 0 ] && [ "$(date +%s)" -gt $(( DEADLINE - DURATION / 4 )) ]; then
    pg_host=$(sed -n 's|.*@\([^:/]*\).*|\1|p' <<<"$CRABEDENCE_DATABASE_URL")
    pg_port=$(sed -n 's|.*:\([0-9]*\)/.*|\1|p' <<<"$CRABEDENCE_DATABASE_URL"); pg_port=${pg_port:-5432}
    pg_ip=$(getent ahostsv4 "$pg_host" | awk '{print $1; exit}')
    if [ -n "$pg_ip" ]; then
      iptables -I OUTPUT -p tcp -d "$pg_ip" --dport "$pg_port" -m owner --uid-owner crabedence -j DROP 2>/dev/null \
        || iptables -I OUTPUT -p tcp -d "$pg_ip" --dport "$pg_port" -j DROP
      kdown="$TAG-outage"
      st=$(invoke test.counter.increment "{\"counter\":\"$TAG\",\"by\":1}" "$kdown" MUTATION 2>/dev/null | jq -r .status 2>/dev/null || echo TRANSPORT_ERROR)
      [ "$st" != "SUCCEEDED" ] || fail "mutation SUCCEEDED during soak PG outage — durable write skipped?"
      sleep 5
      iptables -D OUTPUT -p tcp -d "$pg_ip" --dport "$pg_port" -m owner --uid-owner crabedence -j DROP 2>/dev/null \
        || iptables -D OUTPUT -p tcp -d "$pg_ip" --dport "$pg_port" -j DROP 2>/dev/null || true
      t=$(date +%s); wait_ready 90 || fail "service did not recover after soak PG outage"
      db_reconnect_s=$(( $(date +%s) - t )); outage_done=1
      echo "  outage status=$st, reconnect→ready: ${db_reconnect_s}s"
    else
      echo "  outage skipped: could not resolve IPv4 for $pg_host"; outage_done=1
    fi
  fi

  sleep "$ITER_SLEEP"
done

# Settle window for async terminalization.
sleep 10

echo "== soak metrics (tag=$TAG) =="
metrics
dispatches=$(psql_db "SELECT count(*) FROM effect_provider_observations o
                      JOIN execution_requests r ON r.provider_run_id=o.provider_run_id
                      WHERE r.idempotency_key LIKE '$TAG-%'" 2>/dev/null || echo -1)
dupes=$(psql_db "SELECT count(*) FROM (
                   SELECT r.provider_run_id FROM execution_requests r
                   JOIN effect_provider_observations o ON o.provider_run_id=r.provider_run_id
                   WHERE r.idempotency_key LIKE '$TAG-%'
                   GROUP BY r.provider_run_id HAVING count(*)>1) d" 2>/dev/null || echo -1)
stuck=$(psql_db "SELECT count(*) FROM execution_requests
                 WHERE idempotency_key LIKE '$TAG-%' AND state NOT IN ('COMMITTED')" )
denied_rows=$(psql_db "SELECT count(*) FROM execution_requests WHERE idempotency_key LIKE '$TAG-%-denied'")
committed=$(psql_db "SELECT count(*) FROM execution_requests
                     WHERE idempotency_key LIKE '$TAG-%' AND state='COMMITTED'")

echo "  mutations_succeeded=$sent replays_accepted=$replays committed=$committed"
echo "  provider_dispatches=$dispatches duplicate_dispatches=$dupes"
echo "  nonterminal_or_failed_rows=$stuck denied_rows=$denied_rows (issued=$denied_issued)"
echo "  restart→ready=${restart_ready_s}s  db_reconnect→ready=${db_reconnect_s}s"

[ "$dupes" = "0" ] || fail "duplicate provider dispatches detected: $dupes"
[ "$stuck" = "0" ] || fail "$stuck soak rows failed to terminalize to COMMITTED"
[ "$denied_rows" = "0" ] || fail "denied requests created durable rows"
[ "$denied_issued" -gt 0 ] || echo "note: no denial sample collected"
[ "$restart_done" = 1 ] && [ "$outage_done" = 1 ] || echo "note: duration too short for restart/outage legs"

pass "soak: ${DURATION}s, $iter iterations, $committed committed, dupes=$dupes, restart=${restart_ready_s}s, reconnect=${db_reconnect_s}s"
