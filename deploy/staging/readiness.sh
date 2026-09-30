#!/usr/bin/env bash
# readiness.sh — the staging readiness probe.
#
# "Ready" means ALL of: systemd unit active, socket exists, an end-to-end
# LOCAL invocation succeeds over the socket, and the registry digest in
# the service journal equals the qualified release registry. Process
# liveness alone is not readiness.
#
# Usage: ./readiness.sh [--socket PATH] [--expect-registry-sha256 HEX]
set -euo pipefail

SOCKET="${CRABEDENCE_SOCKET:-/run/crabedence/execution.sock}"
EXPECT_REGISTRY="${CRABEDENCE_EXPECT_REGISTRY_SHA256:-d1de25e9e8f1d7b148c3d8aa19dd6bec64b3573bf22617ac8fbcab36b8d71e41}"
CRABBOX="${CRABBOX:-crabbox}"

while [ $# -gt 0 ]; do
  case "$1" in
    --socket) SOCKET="$2"; shift 2 ;;
    --expect-registry-sha256) EXPECT_REGISTRY="$2"; shift 2 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

fail() { echo "NOT READY: $*" >&2; exit 1; }

systemctl is-active --quiet crabedence || fail "systemd unit crabedence is not active"
[ -S "$SOCKET" ] || fail "socket $SOCKET does not exist or is not a socket"

# End-to-end LOCAL probe: PURE capability, no durable store, no provider.
"$CRABBOX" invoke --socket "$SOCKET" \
  --capability system.echo \
  --principal staging-readiness@example.com \
  --arguments '{"probe":"readiness"}' >/dev/null \
  || fail "system.echo probe did not succeed over $SOCKET"

# Registry identity: the deployed process must serve the qualified
# registry, not a lookalike. The digest is logged at startup and stamped
# into capabilities.json next to the socket.
digest="$(journalctl -u crabedence --no-pager -o cat | grep -oE 'sha256 [0-9a-f]{64}|Registry SHA-256: [0-9a-f]{64}' | grep -oE '[0-9a-f]{64}' | tail -1)"
if [ -z "$digest" ] && [ -f "$(dirname "$SOCKET")/capabilities.json" ]; then
  digest="$(jq -r '.registry_sha256 // empty' "$(dirname "$SOCKET")/capabilities.json" 2>/dev/null || true)"
fi
[ -n "$digest" ] || fail "could not determine the live registry digest"
[ "$digest" = "$EXPECT_REGISTRY" ] \
  || fail "registry digest $digest does not match qualified $EXPECT_REGISTRY"

echo "READY: socket=$SOCKET registry=$digest"
