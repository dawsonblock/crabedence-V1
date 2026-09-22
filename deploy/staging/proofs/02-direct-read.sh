#!/usr/bin/env bash
# Gate 3 — DIRECT READ against the real staging provider.
# Requires: CRABBOX_GITHUB_ENABLED=true, a staging-scoped token, a grant
# covering github.issue.get, and STAGING_TEST_ISSUE="owner/repo#N".
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env

[ "${CRABBOX_GITHUB_ENABLED:-}" = "true" ] || skip "github adapter not enabled (staging token not provisioned)"
[ -n "${STAGING_TEST_ISSUE:-}" ] || skip "set STAGING_TEST_ISSUE=owner/repo#N for the read probe"
repo="${STAGING_TEST_ISSUE%#*}"; number="${STAGING_TEST_ISSUE##*#}"
[ "$repo" != "$STAGING_TEST_ISSUE" ] && [ -n "$number" ] \
  || fail "STAGING_TEST_ISSUE must be owner/repo#N, got '$STAGING_TEST_ISSUE'"

export STAGING_GRANT_ID
STAGING_GRANT_ID=$(issue_staging_grant github.issue.get)

# No --execution-class: the registry pins github.issue.get as READ and
# denies a mismatched caller assertion.
resp=$(invoke github.issue.get "{\"repo\":\"$repo\",\"number\":$number}" "$(key read)")
status=$(jq -r .status <<<"$resp")
[ "$status" = "SUCCEEDED" ] || fail "github.issue.get returned $status: $resp"

pass "gate 3: DIRECT READ (issue $STAGING_TEST_ISSUE)"
