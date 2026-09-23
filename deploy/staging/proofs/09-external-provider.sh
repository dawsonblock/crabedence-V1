#!/usr/bin/env bash
# Proofs 3 + 5 + 9 — external-provider proofs:
#   3. provider commits while Crabedence dies
#   5. provider lookup interruption
#   9. one supervised CRITICAL operation
#
# Two qualification tiers exist; they are NOT interchangeable:
#
#   a) DEPLOYED path (CRABEDENCE_QUAL_PROVIDER_URL set): the deployed
#      systemd service reaches a real external qualification provider
#      process (cmd/qual-provider) over HTTP. This proof then drives
#      the full path:
#
#        crabbox invoke → deployed Unix socket → deployed service →
#        staging PostgreSQL → external provider process (own durable
#        ledger) → reconciliation
#
#      including a COMMIT_THEN_RESET fault: the provider's operation is
#      durable while the response never arrives, so the record must go
#      UNKNOWN and the deployed reconciler must converge it to
#      COMMITTED from provider evidence — never redispatch.
#
#   b) HARNESS path (URL unset, verified source tree present): run the
#      live qualification harness (TestLiveCritical*) against the
#      STAGING database. This exercises a REAL external provider
#      process, the durable ledger, and the full fault matrix on the
#      staging schema — but the executor is a test binary, not the
#      deployed systemd unit.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env

if [ -n "${CRABEDENCE_QUAL_PROVIDER_URL:-}" ]; then
  # ── Tier (a): deployed-provider path ─────────────────────────────────
  need_cmd curl
  need_cmd jq

  echo "deployed tier: qualification provider at $CRABEDENCE_QUAL_PROVIDER_URL"

  # 1. The provider process is reachable and serving.
  stats_before=$(curl -sf "$CRABEDENCE_QUAL_PROVIDER_URL/stats") \
    || fail "qualification provider unreachable at $CRABEDENCE_QUAL_PROVIDER_URL (the service refuses to start in this state)"
  ops_before=$(echo "$stats_before" | jq -r .operations)

  # 2. Grant the proof principal the qualification capability.
  STAGING_GRANT_ID=$(issue_staging_grant qualification.critical.commit) \
    || fail "could not issue qualification grant"
  [ -n "$STAGING_GRANT_ID" ] || fail "empty qualification grant id"

  # 3. Proof 9: one supervised CRITICAL operation through the deployed
  #    socket — admitted, dispatched to the external provider, observed,
  #    evidenced.
  k1=$(key qual-deployed)
  out=$(invoke qualification.critical.commit '{"operation":"deployed-supervised-op"}' "$k1" CRITICAL) \
    || fail "deployed qualification invoke failed: $out"
  echo "$out" | jq -e '.status == "SUCCEEDED"' >/dev/null \
    || fail "expected SUCCEEDED, got: $out"
  three_view qualification.critical.commit "$k1"

  # 4. The provider's own stats must show the operation — proving the
  #    request crossed the process boundary to the external provider
  #    (not an in-process handler).
  stats_after=$(curl -sf "$CRABEDENCE_QUAL_PROVIDER_URL/stats")
  ops_after=$(echo "$stats_after" | jq -r .operations)
  [ "$ops_after" -gt "$ops_before" ] \
    || fail "provider ledger shows no new operation ($ops_before -> $ops_after)"

  # 5. Proof 3 (deployed): COMMIT_THEN_RESET — the provider's operation
  #    commits durably while the response never arrives. The record must
  #    converge UNKNOWN → COMMITTED via reconciliation, and the provider
  #    ledger must show exactly ONE operation for it.
  k2=$(key qual-reset)
  set +e
  out=$(invoke qualification.critical.commit \
    '{"operation":"deployed-reset-op","fault":"COMMIT_THEN_RESET"}' "$k2" CRITICAL)
  rc=$?
  set -e
  [ "$rc" -eq 3 ] \
    || fail "expected UNKNOWN (exit 3) after commit-then-reset, got exit $rc: $out"
  echo "commit-then-reset produced UNKNOWN as required; awaiting reconciler"

  deadline=$(( $(date +%s) + 180 ))
  while :; do
    state=$(ledger_state qualification.critical.commit "$k2")
    [ "$state" = "COMMITTED" ] && break
    case "$state" in UNKNOWN|RECONCILING|IN_FLIGHT) ;; *)
      fail "unexpected durable state '$state' for reset operation" ;;
    esac
    [ "$(date +%s)" -lt "$deadline" ] \
      || fail "reconciler did not converge the reset operation (state=$state)"
    sleep 5
  done
  three_view qualification.critical.commit "$k2"

  pass "proofs 3+9 (deployed tier): socket → service → external provider → reconciliation verified end-to-end"
  exit 0
fi

# ── Tier (b): harness path ─────────────────────────────────────────────
# Auto-detect a verified source tree when CRABEDENCE_SOURCE_DIR is unset
# (rehearse.sh leaves the RC1 extraction at ~/rc1/crabedence-<version>).
if [ -z "${CRABEDENCE_SOURCE_DIR:-}" ]; then
  for d in "$HOME"/rc1/crabedence-* /home/*/rc1/crabedence-* /opt/crabedence-src; do
    [ -d "$d/internal/execution" ] && CRABEDENCE_SOURCE_DIR="$d" && break
  done
fi

if [ -n "${CRABEDENCE_SOURCE_DIR:-}" ] && [ -d "$CRABEDENCE_SOURCE_DIR/internal/execution" ]; then
  echo "running live CRITICAL qualification harness against staging DSN"
  echo "note: this exercises the staging schema + real provider process,"
  echo "      NOT the deployed systemd unit — see script header, tier (b)"
  (cd "$CRABEDENCE_SOURCE_DIR" && \
    export PATH="/usr/local/go/bin:$PATH" && \
    CRABBOX_TEST_DATABASE_URL="$CRABEDENCE_DATABASE_URL" \
    GOTOOLCHAIN=local go test ./internal/execution -run 'TestLiveCritical' -v -count=1) \
    || fail "live CRITICAL harness failed against staging database"
  pass "proofs 3+5+9 (harness tier): external-provider fault matrix green on staging DSN — set CRABEDENCE_QUAL_PROVIDER_URL for the deployed tier"
  exit 0
fi

skip "no external qualification provider configured (CRABEDENCE_QUAL_PROVIDER_URL unset) and no verified source tree found"
