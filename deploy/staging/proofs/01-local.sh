#!/usr/bin/env bash
# Gate 2 — LOCAL capabilities only. system.echo and system.info are PURE:
# no durable store, no provider, no grant required.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

resp=$(invoke system.echo '{"probe":"gate2"}')
[ "$(jq -r .status <<<"$resp")" = "SUCCEEDED" ] || fail "system.echo: $resp"

resp=$(invoke system.info '{}')
[ "$(jq -r .status <<<"$resp")" = "SUCCEEDED" ] || fail "system.info: $resp"

pass "gate 2: LOCAL capabilities"
