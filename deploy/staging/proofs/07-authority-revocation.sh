#!/usr/bin/env bash
# Proof 7 — authority revocation before dispatch. A request carrying a
# revoked (or never-issued) authority reference must be DENIED and must
# leave zero durable rows and zero provider dispatches.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env

# Case A: nonexistent grant — the resolver returns nil → denial.
k=$(key revoked)
resp=$(STAGING_GRANT_ID=grant_never_issued invoke test.counter.increment \
  '{"counter":"rev","by":1}' "$k" MUTATION || true)
status=$(jq -r .status <<<"$resp" 2>/dev/null || echo TRANSPORT_ERROR)
[ "$status" = "DENIED" ] || fail "nonexistent grant produced status $status (expected DENIED): $resp"
[ "$(ledger_count test.counter.increment "$k")" = "0" ] \
  || fail "denied request left a durable row — dispatch reached the store"

# Case B: a real grant revoked before dispatch. Revocation is SQL on the
# head generation (authority_grants.revoked=true) — the store treats
# revoked heads as unresolvable.
export STAGING_GRANT_ID
STAGING_GRANT_ID=$(issue_staging_grant test.counter.increment)
psql_db "UPDATE authority_grants SET revoked=true
         WHERE grant_id='$STAGING_GRANT_ID'
           AND generation=(SELECT max(generation) FROM authority_grants WHERE grant_id='$STAGING_GRANT_ID')" >/dev/null

k2=$(key revoked2)
resp2=$(invoke test.counter.increment '{"counter":"rev","by":1}' "$k2" MUTATION || true)
status2=$(jq -r .status <<<"$resp2" 2>/dev/null || echo TRANSPORT_ERROR)
[ "$status2" = "DENIED" ] || fail "revoked grant produced status $status2 (expected DENIED): $resp2"
[ "$(ledger_count test.counter.increment "$k2")" = "0" ] \
  || fail "revoked-grant request left a durable row"

pass "proof 7: nonexistent + revoked grants denied before dispatch, zero durable rows"
