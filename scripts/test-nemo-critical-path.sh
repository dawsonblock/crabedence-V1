#!/usr/bin/env bash
# Exercise the CRITICAL path end to end, through the Rust bridge.
#
# The built-in registry carries no CRITICAL capability, so the bridge's
# `requires_evidence` rule — a CRITICAL SUCCEEDED without a valid digest,
# receipt version 3, and run id maps to UNKNOWN — was only ever asserted against
# fixtures. It is the one part of the bridge's outcome mapping that a real commit
# can falsify.
#
# The service can already serve it: `CRABEDENCE_QUAL_PROVIDER_URL` wires the
# external qualification provider, which registers
# `qualification.critical.commit` as an explicit extension of the release
# registry. This script starts that provider and a service that uses it, issues
# a grant, and lets the live suite assert the commit.
#
# Usage: scripts/test-nemo-critical-path.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# Short on purpose: macOS caps Unix socket paths at ~104 bytes.
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/nemo-crit.XXXXXX")"
provider_pid=""
service_pid=""
cleanup() {
  for pid in "$service_pid" "$provider_pid"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  rm -rf "$work_dir"
}
trap cleanup EXIT

chmod 700 "$work_dir"
store="$work_dir/crabedence.db"
socket="$work_dir/crabedence/execution.sock"

printf 'building the CLI and the qualification provider…\n'
if [[ -n "${NEMO_E2E_CRABBOX:-}" ]]; then
  crabbox_bin="$NEMO_E2E_CRABBOX"
else
  go build -o "$work_dir/crabbox" ./cmd/crabbox
  crabbox_bin="$work_dir/crabbox"
fi
go build -o "$work_dir/qual-provider" ./cmd/qual-provider

printf 'starting the qualification provider…\n'
"$work_dir/qual-provider" \
  --dir "$work_dir/qual" \
  --listen 127.0.0.1:0 \
  --addr-file "$work_dir/qual.addr" >"$work_dir/qual.log" 2>&1 &
provider_pid=$!

for _ in $(seq 1 40); do
  [[ -s "$work_dir/qual.addr" ]] && break
  sleep 0.25
done
if [[ ! -s "$work_dir/qual.addr" ]]; then
  printf 'the qualification provider did not publish an address; log follows:\n' >&2
  cat "$work_dir/qual.log" >&2
  exit 1
fi
provider_url="http://$(cat "$work_dir/qual.addr")"
printf 'qualification provider at %s\n' "$provider_url"

printf 'issuing a CRITICAL grant…\n'
CRABEDENCE_STORE_PATH="$store" go run ./cmd/issue-grant \
  --principal alice@example.com \
  --capability qualification.critical.commit \
  --grant-id critical-grant >/dev/null

printf 'starting the service with the qualification extension…\n'
CRABBOX_MODE=development CRABEDENCE_STORE_PATH="$store" CRABEDENCE_STORE_BACKEND=sqlite \
  CRABEDENCE_QUAL_PROVIDER_URL="$provider_url" \
  XDG_RUNTIME_DIR="$work_dir" "$crabbox_bin" serve-exec \
  >"$work_dir/serve.log" 2>&1 &
service_pid=$!

for _ in $(seq 1 60); do
  [[ -S "$socket" ]] && break
  sleep 0.25
done
if [[ ! -S "$socket" ]]; then
  printf 'the service did not publish its socket; log follows:\n' >&2
  cat "$work_dir/serve.log" >&2
  exit 1
fi

# The service must actually be serving the extension, not silently the release
# registry: if the capability is absent, the assertion below would be testing
# nothing.
if ! grep -q "qualification.critical.commit" "$work_dir/serve.log"; then
  printf 'the service did not register the qualification extension; log follows:\n' >&2
  cat "$work_dir/serve.log" >&2
  exit 1
fi
printf 'service serves the qualification extension\n'

printf 'asserting the CRITICAL commit…\n'
(
  cd runtimes/nemo-relay
  NEMO_CRABEDENCE_LIVE_SOCKET="$socket" \
  NEMO_CRABEDENCE_LIVE_CRITICAL_GRANT=critical-grant \
    cargo test -p nemo-crabedence-bridge --test live_socket \
      commits_a_critical_mutation_with_evidence -- --nocapture
)

printf 'critical path: committed with evidence\n'
