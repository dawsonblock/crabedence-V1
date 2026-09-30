#!/usr/bin/env bash
# Exercise the runtime instance end to end, against a live service.
#
# The bridge has live coverage (`tests/live_socket.rs`) and the router has its
# own tests; what had none is the binary that composes them,
# `nemo-crabedence-runtime` — the process a caller actually runs. Its
# invocation-identity policy is only observable through it: a MUTATION or
# CRITICAL invocation without a caller-supplied idempotency key must be refused
# before dispatch, and one key must replay rather than duplicate.
#
# This script starts a real `serve-exec`, issues a real grant, and drives the
# real binary:
#
#   PURE                      → routed locally, no socket hop
#   MUTATION without a key    → refused before dispatch, exit 2
#   MUTATION with grant + key → committed with evidence
#   the same key again        → replayed, exactly one effect
#   MUTATION without a grant  → UNAUTHORIZED, definitive and non-retryable
#   unregistered capability   → refused before any socket hop
#
# Usage: scripts/test-nemo-runtime-e2e.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# Short on purpose: macOS caps Unix socket paths at ~104 bytes.
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/nemo-rt.XXXXXX")"
service_pid=""
cleanup() {
  if [[ -n "$service_pid" ]]; then
    kill "$service_pid" 2>/dev/null || true
    wait "$service_pid" 2>/dev/null || true
  fi
  rm -rf "$work_dir"
}
trap cleanup EXIT

chmod 700 "$work_dir"
store="$work_dir/crabedence.db"
socket="$work_dir/crabedence/execution.sock"
snapshot="$work_dir/crabedence/capabilities.json"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'ok: %s\n' "$*"; }

printf 'building the CLI…\n'
go build -o "$work_dir/crabbox" ./cmd/crabbox

printf 'building the runtime instance…\n'
(cd runtimes/nemo-relay && cargo build -p nemo-crabedence-runtime)
runtime_bin="runtimes/nemo-relay/target/debug/nemo-crabedence-runtime"

printf 'issuing a grant for the runtime principal…\n'
CRABEDENCE_STORE_PATH="$store" go run ./cmd/issue-grant \
  --principal alice@example.com \
  --capability test.counter.increment \
  --grant-id runtime-e2e-grant >/dev/null

printf 'starting the service…\n'
CRABEDENCE_STORE_PATH="$store" CRABEDENCE_STORE_BACKEND=sqlite \
  XDG_RUNTIME_DIR="$work_dir" "$work_dir/crabbox" serve-exec \
  >"$work_dir/serve.log" 2>&1 &
service_pid=$!
for _ in $(seq 1 60); do
  [[ -S "$socket" && -f "$snapshot" ]] && break
  sleep 0.25
done
if [[ ! -S "$socket" || ! -f "$snapshot" ]]; then
  printf 'the service did not publish its socket and snapshot; log follows:\n' >&2
  cat "$work_dir/serve.log" >&2
  exit 1
fi
pass "service is up with a verified snapshot"

run_runtime() {
  "$runtime_bin" --socket "$socket" --snapshot "$snapshot" \
    --principal alice@example.com "$@"
}

# 1. PURE executes locally: the route comes from the verified registry, and
#    the local backend answers without a socket hop.
out="$(run_runtime --capability system.echo --arguments '{"probe":"runtime-e2e"}')" \
  || fail "the PURE invocation must succeed: $out"
printf '%s' "$out" | jq -e '.status=="SUCCEEDED" and .result.local==true' >/dev/null \
  || fail "system.echo did not route locally: $out"
pass "PURE routed locally"

# 2. A consequential invocation without a caller key is refused before
#    dispatch — no capability-derived default.
set +e
out="$(run_runtime --capability test.counter.increment \
  --arguments '{"counter":"refused","by":1}' 2>&1)"
status=$?
set -e
[[ $status -eq 2 ]] || fail "a MUTATION without --idempotency-key must exit 2, got $status: $out"
[[ "$out" == *"--idempotency-key is required"* ]] \
  || fail "the refusal must name the missing key: $out"
pass "MUTATION without a key refused before dispatch"

# 3. With a grant and a key it commits, with evidence.
counter="runtime-e2e-$$"
key="runtime-e2e-key-$$"
out="$(run_runtime --capability test.counter.increment \
  --arguments "{\"counter\":\"$counter\",\"by\":1}" \
  --idempotency-key "$key" --grant runtime-e2e-grant)" \
  || fail "the granted mutation must commit: $out"
printf '%s' "$out" | jq -e '.status=="SUCCEEDED" and .result.value==1 and (.receipt_digest != null)' >/dev/null \
  || fail "the mutation did not commit with evidence: $out"
pass "MUTATION committed with evidence (value 1)"

# 4. The same logical action replays: a second effect would read 2.
out="$(run_runtime --capability test.counter.increment \
  --arguments "{\"counter\":\"$counter\",\"by\":1}" \
  --idempotency-key "$key" --grant runtime-e2e-grant)" \
  || fail "the replay must answer from the durable record: $out"
printf '%s' "$out" | jq -e '.status=="SUCCEEDED" and .result.value==1' >/dev/null \
  || fail "a repeated key duplicated the effect: $out"
pass "the repeated key replayed (still value 1)"

# 5. Without a grant the mutation is denied — definitive, not retryable.
out="$(run_runtime --capability test.counter.increment \
  --arguments "{\"counter\":\"$counter\",\"by\":1}" \
  --idempotency-key "${key}-ungranted")" || true
printf '%s' "$out" | jq -e '.status=="FAILED" and .code=="UNAUTHORIZED" and .retryable==false' >/dev/null \
  || fail "a mutation without a grant must be a definitive refusal: $out"
pass "MUTATION without a grant refused (non-retryable)"

# 6. An unregistered capability never reaches the socket.
set +e
out="$(run_runtime --capability no.such.capability --arguments '{}' 2>&1)"
status=$?
set -e
[[ $status -ne 0 ]] || fail "an unregistered capability must be refused"
[[ "$out" == *"not in the verified registry"* ]] \
  || fail "the refusal must say the capability is unregistered: $out"
pass "unregistered capability refused before routing"

printf 'runtime e2e: six checks passed\n'
