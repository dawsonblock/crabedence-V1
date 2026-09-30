#!/usr/bin/env bash
# Exercise the expired-authority scenario against a real service.
#
# The NEMO integration's live suite covers the refusals the kernel makes at
# admission. Expired authority is the one that cannot be asserted in place: the
# issuing tool refuses to mint a grant whose expiry is already in the past, so
# the reference has to be issued with a short future expiry and then allowed to
# lapse. That timing lives here, where it is explicit and bounded, rather than
# inside the Rust test — a test that slept on a clock would be flaky and slow.
#
# The assertion itself is the ordinary live suite:
#
#   refuses_an_expired_authority_reference
#
# Usage: scripts/test-nemo-expired-authority.sh [--ttl-seconds N]
set -euo pipefail

cd "$(dirname "$0")/.."

ttl_seconds=8
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ttl-seconds) ttl_seconds="$2"; shift 2 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

# A short directory name on purpose: macOS caps Unix socket paths at ~104 bytes,
# and the socket lives several segments below this one.
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/nemo-exp.XXXXXX")"
cleanup() {
  if [[ -n "${service_pid:-}" ]]; then
    kill "$service_pid" 2>/dev/null || true
    wait "$service_pid" 2>/dev/null || true
  fi
  rm -rf "$work_dir"
}
trap cleanup EXIT

# The service creates and secures its own socket directory; this only has to
# exist and be owner-only.
chmod 700 "$work_dir"

store="$work_dir/crabedence.db"
socket="$work_dir/crabedence/execution.sock"

printf 'building the CLI…\n'
go build -o "$work_dir/crabbox" ./cmd/crabbox

# Issue a grant that lapses shortly. The tool reads the target from the
# environment, exactly as the service does.
expiry="$(date -u -v+"${ttl_seconds}"S +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
  || date -u -d "+${ttl_seconds} seconds" +%Y-%m-%dT%H:%M:%SZ)"
printf 'issuing a grant expiring at %s…\n' "$expiry"
CRABEDENCE_STORE_PATH="$store" go run ./cmd/issue-grant \
  --principal alice@example.com \
  --capability test.counter.increment \
  --grant-id expired-authority-check \
  --expires-at "$expiry" >/dev/null

printf 'starting the service…\n'
CRABEDENCE_STORE_PATH="$store" CRABEDENCE_STORE_BACKEND=sqlite \
  XDG_RUNTIME_DIR="$work_dir" "$work_dir/crabbox" serve-exec >"$work_dir/serve.log" 2>&1 &
service_pid=$!

for _ in $(seq 1 40); do
  [[ -S "$socket" ]] && break
  sleep 0.25
done
if [[ ! -S "$socket" ]]; then
  printf 'the service did not publish its socket; log follows:\n' >&2
  cat "$work_dir/serve.log" >&2
  exit 1
fi

# Wait for the grant to lapse, then let the store's own clock be authoritative.
# The margin is deliberately more than a second: expiry is evaluated on the
# store's clock, not this script's.
printf 'waiting %ss for the grant to lapse…\n' "$((ttl_seconds + 2))"
sleep "$((ttl_seconds + 2))"

printf 'asserting the refusal…\n'
(
  cd runtimes/nemo-relay
  NEMO_CRABEDENCE_LIVE_SOCKET="$socket" \
  NEMO_CRABEDENCE_LIVE_EXPIRED_GRANT=expired-authority-check \
    cargo test -p nemo-crabedence-bridge --test live_socket \
      refuses_an_expired_authority_reference -- --nocapture
)

printf 'expired authority: refused definitively\n'
