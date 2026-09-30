#!/usr/bin/env bash
# Gate 1 — boot + readiness only. Passes when the service is active, the
# socket answers a LOCAL probe end-to-end, and the live registry digest
# equals the qualified release registry.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

need_cmd systemctl
wait_ready 90 || fail "service did not reach readiness (see readiness.sh output above)"
pass "gate 1: boot + readiness"
