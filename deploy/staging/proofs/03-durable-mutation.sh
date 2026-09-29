#!/usr/bin/env bash
# Gate 4 — first durable MUTATION. test.counter.increment exercises the
# full EffectStore path (PREPARED → IN_FLIGHT → COMMITTED) with an
# in-process test provider: the ledger, observation, and receipt
# machinery is real even though no external side effect occurs.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env

export STAGING_GRANT_ID
STAGING_GRANT_ID=$(issue_staging_grant test.counter.increment)

k=$(key mut)
resp=$(invoke test.counter.increment '{"counter":"staging","by":1}' "$k" MUTATION)
[ "$(jq -r .status <<<"$resp")" = "SUCCEEDED" ] || fail "counter increment: $resp"

[ "$(ledger_count test.counter.increment "$k")" = "1" ] || fail "expected exactly one durable row for $k"
three_view test.counter.increment "$k"

# Replay with the same idempotency key must return the recorded outcome
# without a second dispatch.
resp2=$(invoke test.counter.increment '{"counter":"staging","by":1}' "$k" MUTATION)
[ "$(jq -r .status <<<"$resp2")" = "SUCCEEDED" ] || fail "idempotent replay: $resp2"
[ "$(ledger_count test.counter.increment "$k")" = "1" ] || fail "replay created a second durable row"

pass "gate 4: durable MUTATION + idempotent replay"
