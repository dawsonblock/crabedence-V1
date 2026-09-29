#!/usr/bin/env bash
# Proof 4 — PostgreSQL interruption. Blocks traffic to the PG port with
# iptables (owner-scoped to the crabedence uid), issues a request (which
# must fail closed — never silently succeed), restores connectivity, and
# verifies the service recovers and the ledger is consistent.
#
# Requires root (iptables) and CRABEDENCE_DATABASE_URL pointing at the
# real PG host. If PG is co-located on this VM the rule targets
# loopback too.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
need_cmd iptables
[ "$(id -u)" = "0" ] || fail "must run as root (iptables)"

pg_host=$(sed -n 's|.*@\([^:/]*\).*|\1|p' <<<"$CRABEDENCE_DATABASE_URL")
pg_port=$(sed -n 's|.*:\([0-9]*\)/.*|\1|p' <<<"$CRABEDENCE_DATABASE_URL"); pg_port=${pg_port:-5432}
[ -n "$pg_host" ] || fail "could not parse PG host from DSN"
# IPv4 only — the service's PG connection and our iptables rule are
# IPv4-scoped; getent may return ::1 first for localhost.
pg_ip=$(getent ahostsv4 "$pg_host" | awk '{print $1; exit}')
[ -n "$pg_ip" ] || fail "could not resolve $pg_host"

export STAGING_GRANT_ID
STAGING_GRANT_ID=$(issue_staging_grant test.counter.increment)

# Baseline mutation succeeds.
k0=$(key pgbase)
invoke test.counter.increment '{"counter":"pg","by":1}' "$k0" MUTATION | jq -e '.status=="SUCCEEDED"' >/dev/null \
  || fail "baseline mutation failed before interruption"

# Drop outbound to PG for the crabedence uid.
iptables -I OUTPUT -p tcp -d "$pg_ip" --dport "$pg_port" -m owner --uid-owner crabedence -j DROP \
  || iptables -I OUTPUT -p tcp -d "$pg_ip" --dport "$pg_port" -j DROP
cleanup() { iptables -D OUTPUT -p tcp -d "$pg_ip" --dport "$pg_port" -m owner --uid-owner crabedence -j DROP 2>/dev/null \
            || iptables -D OUTPUT -p tcp -d "$pg_ip" --dport "$pg_port" -j DROP 2>/dev/null || true; }
trap cleanup EXIT

# A request during the outage must fail closed — SUCCEEDED would mean a
# durable write was skipped.
k1=$(key pgdown)
resp=$(invoke test.counter.increment '{"counter":"pg","by":1}' "$k1" MUTATION || true)
status=$(jq -r .status <<<"$resp" 2>/dev/null || echo "TRANSPORT_ERROR")
[ "$status" != "SUCCEEDED" ] || fail "mutation reported SUCCEEDED during PG outage — durable write skipped?"
echo "outage request status: $status (fail-closed: OK)"

sleep 3
cleanup; trap - EXIT

# Recovery: the service must answer again. If systemd restarted it,
# wait_ready handles the gap; journald shows the DB error window.
wait_ready 90 || fail "service did not recover after PG restoration"
k2=$(key pgup)
invoke test.counter.increment '{"counter":"pg","by":1}' "$k2" MUTATION | jq -e '.status=="SUCCEEDED"' >/dev/null \
  || fail "mutation failed after PG restored"
three_view test.counter.increment "$k2"

pass "proof 4: PG interruption fails closed and recovers"
