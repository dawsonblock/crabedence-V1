#!/usr/bin/env bash
# Proof 8 — duplicate request storm. 100 concurrent identical mutations
# (same principal, capability, idempotency key) must produce exactly one
# durable row and exactly one provider dispatch.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env

N="${STORM_N:-100}"
export STAGING_GRANT_ID
STAGING_GRANT_ID=$(issue_staging_grant test.counter.increment)

k=$(key storm)
for i in $(seq "$N"); do
  invoke test.counter.increment '{"counter":"storm","by":1}' "$k" MUTATION >/dev/null 2>&1 &
done
wait

sleep 2
rows=$(ledger_count test.counter.increment "$k")
[ "$rows" = "1" ] || fail "storm produced $rows durable rows, expected 1"
three_view test.counter.increment "$k"

pass "proof 8: $N-way duplicate storm → 1 row, 1 dispatch"
