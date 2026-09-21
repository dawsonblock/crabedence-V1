#!/usr/bin/env bash
# Proofs 3 + 5 + 9 — external-provider proofs:
#   3. provider commits while Crabedence dies
#   5. provider lookup interruption
#   9. one supervised CRITICAL operation
#
# These require the external CRITICAL qualification provider process,
# which is a test-harness component — it is NOT shipped in the RC1
# release artifacts. Two ways to run them:
#
#   a) Deploy a qualification provider separately and set
#      CRABEDENCE_QUAL_PROVIDER_URL, then re-run this script (TODO once
#      a provider image/binary exists — see STAGING.md "Known gaps").
#
#   b) Run the live qualification harness against the STAGING database
#      from a verified RC1 source tree:
#         CRABBOX_TEST_DATABASE_URL="$CRABEDENCE_DATABASE_URL" \
#           go test ./internal/execution -run 'TestLiveCritical' -v
#      That exercises the real external provider process, durable
#      ledger, and fault matrix on the staging schema — it does not
#      exercise the deployed systemd unit.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env

if [ -n "${CRABEDENCE_QUAL_PROVIDER_URL:-}" ]; then
  fail "qual provider URL is set but no deployed-provider proof flow is implemented yet — see STAGING.md"
fi

if [ -n "${CRABEDENCE_SOURCE_DIR:-}" ] && [ -d "$CRABEDENCE_SOURCE_DIR/internal/execution" ]; then
  echo "running live CRITICAL qualification harness against staging DSN"
  (cd "$CRABEDENCE_SOURCE_DIR" && \
    CRABBOX_TEST_DATABASE_URL="$CRABEDENCE_DATABASE_URL" \
    GOTOOLCHAIN=local go test ./internal/execution -run 'TestLiveCritical' -v -count=1) \
    || fail "live CRITICAL harness failed against staging database"
  pass "proofs 3+5+9 (harness): external-provider fault matrix green on staging DSN"
fi

skip "no external qualification provider deployed (proofs 3, 5, 9 blocked — STAGING.md known gap)"
