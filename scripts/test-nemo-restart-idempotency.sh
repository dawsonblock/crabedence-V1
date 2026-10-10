#!/usr/bin/env bash
# Prove that a restart cannot duplicate a committed effect.
#
# The property is the one the whole consolidation exists to preserve: no
# repeated idempotency key may produce a second real-world effect, and a planner
# restart must not change that. The live suite asserts it *within* one process —
# first and second dispatch agree — but the case that matters is across a
# restart, where a fresh planner meets a restarted kernel and the durable record
# is the only thing standing between the caller and a second effect.
#
# That needs process orchestration the Rust test cannot own, so it lives here:
#
#   issue a grant
#   start the kernel
#   dispatch twice with one key           → expect exactly one increment
#   restart the kernel on the same store
#   dispatch twice again with the same key → still exactly one increment
#
# A fresh counter name per run makes the expected value 1, so a second effect
# would show up as 2 rather than hiding behind a repeated read.
#
# Usage: scripts/test-nemo-restart-idempotency.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# Short on purpose: macOS caps Unix socket paths at ~104 bytes.
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/nemo-rst.XXXXXX")"
service_pid=""
cleanup() {
  stop_service
  rm -rf "$work_dir"
}
trap cleanup EXIT

chmod 700 "$work_dir"
store="$work_dir/crabedence.db"
socket="$work_dir/crabedence/execution.sock"

stop_service() {
  if [[ -n "$service_pid" ]]; then
    kill "$service_pid" 2>/dev/null || true
    wait "$service_pid" 2>/dev/null || true
    service_pid=""
  fi
}

start_service() {
  CRABBOX_MODE=development CRABEDENCE_STORE_PATH="$store" CRABEDENCE_STORE_BACKEND=sqlite \
    XDG_RUNTIME_DIR="$work_dir" "$crabbox_bin" serve-exec \
    >>"$work_dir/serve.log" 2>&1 &
  service_pid=$!
  for _ in $(seq 1 40); do
    [[ -S "$socket" ]] && return 0
    sleep 0.25
  done
  printf 'the service did not publish its socket; log follows:\n' >&2
  cat "$work_dir/serve.log" >&2
  exit 1
}

# dispatch_once runs the live replay check and echoes the value it observed.
dispatch_once() {
  local output
  output="$(
    cd runtimes/nemo-relay
    NEMO_CRABEDENCE_LIVE_SOCKET="$socket" \
    NEMO_CRABEDENCE_LIVE_GRANT="restart-grant" \
    NEMO_CRABEDENCE_LIVE_REPLAY_KEY="$key" \
    NEMO_CRABEDENCE_LIVE_REPLAY_COUNTER="$counter" \
      cargo test -p nemo-crabedence-bridge --test live_socket \
        a_repeated_idempotency_key_replays_rather_than_duplicating -- --nocapture 2>&1
  )"
  printf '%s\n' "$output" >&2
  printf '%s\n' "$output" | sed -n 's/.*observed value \([0-9][0-9]*\) twice.*/\1/p' | tail -1
}

printf 'building the CLI…\n'
if [[ -n "${NEMO_E2E_CRABBOX:-}" ]]; then
  crabbox_bin="$NEMO_E2E_CRABBOX"
else
  go build -o "$work_dir/crabbox" ./cmd/crabbox
  crabbox_bin="$work_dir/crabbox"
fi

printf 'issuing a grant…\n'
CRABEDENCE_STORE_PATH="$store" go run ./cmd/issue-grant \
  --principal alice@example.com \
  --capability test.counter.increment \
  --grant-id restart-grant >/dev/null

# One key and one counter for the whole run, so the second phase re-issues
# exactly the request the first phase committed.
key="restart-key-$$"
counter="restart-counter-$$"

printf 'starting the kernel…\n'
start_service

printf 'dispatching before the restart…\n'
before="$(dispatch_once)"
printf 'before restart: value=%s\n' "${before:-<none>}"

printf 'restarting the kernel on the same store…\n'
stop_service
start_service

printf 'dispatching after the restart…\n'
after="$(dispatch_once)"
printf 'after restart: value=%s\n' "${after:-<none>}"

if [[ -z "$before" || -z "$after" ]]; then
  printf 'FAIL: could not read the observed value from both phases\n' >&2
  exit 1
fi
if [[ "$before" != "1" ]]; then
  printf 'FAIL: the first phase observed %s, expected a single increment\n' "$before" >&2
  exit 1
fi
if [[ "$after" != "$before" ]]; then
  printf 'FAIL: the restart changed the outcome (%s then %s) — an effect was duplicated\n' \
    "$before" "$after" >&2
  exit 1
fi

printf 'restart idempotency: one effect across a restart (value=%s)\n' "$after"
