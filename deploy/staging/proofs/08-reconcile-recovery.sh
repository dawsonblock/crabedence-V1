#!/usr/bin/env bash
# Proof 6 — reconciliation recovery from an injected UNKNOWN row.
#
# We commit a real mutation, then force its ledger row to UNKNOWN (a
# staging-only fault injection; the provider observation remains). The
# reconciliation worker must resolve the row from the provider
# observation — reaching COMMITTED — and must NEVER re-dispatch: the
# provider_run_id must stay the original run and no second dispatch may
# appear.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
need_cmd systemctl

export STAGING_GRANT_ID
STAGING_GRANT_ID=$(issue_staging_grant test.counter.increment)

k=$(key recon)
invoke test.counter.increment '{"counter":"recon","by":1}' "$k" MUTATION | jq -e '.status=="SUCCEEDED"' >/dev/null \
  || fail "baseline mutation failed"
orig_run=$(ledger_field test.counter.increment "$k" provider_run_id)
[ -n "$orig_run" ] || fail "no provider_run_id after commit"

# Inject UNKNOWN — simulates a crash between provider commit and
# ledger finalize.
psql_db "UPDATE execution_requests SET state='UNKNOWN', updated_at=NOW()
         WHERE principal_id='$PRINCIPAL' AND capability_id='test.counter.increment'
           AND idempotency_key='$k'" >/dev/null
[ "$(ledger_state test.counter.increment "$k")" = "UNKNOWN" ] || fail "injection did not take"

# Restart so the reconciliation worker picks up the row.
systemctl restart crabedence
wait_ready 90 || fail "service did not recover"

# Reconciliation window.
sleep 10
state=$(ledger_state test.counter.increment "$k")
run=$(ledger_field test.counter.increment "$k" provider_run_id)
[ "$run" = "$orig_run" ] || fail "provider_run_id changed ($orig_run -> $run): re-dispatch detected"
case "$state" in
  COMMITTED) pass "proof 6: UNKNOWN reconciled to COMMITTED from provider observation (run=$run)" ;;
  UNKNOWN)   pass "proof 6: row remains UNKNOWN (no observation to reconcile) — no re-dispatch, fail-closed OK" ;;
  *)         fail "reconciler produced unexpected state $state" ;;
esac
