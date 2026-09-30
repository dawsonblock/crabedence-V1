#!/usr/bin/env bash
# The Phase 9 dependency-graph invariant.
#
# The shipping NeMo Relay runtime must not depend on the crates whose
# responsibilities Crabedence owns. Those crates still compile — NeMo Relay
# needs them for its own qualification and for the executor contract the
# integration crates implement — but nothing on the production runtime path may
# pull them in, because "reachable from the runtime" is how a second authority,
# ledger, or execution-class system quietly becomes live again.
#
# Two further assertions, because "the plugin path cannot reach the authority"
# is stronger than a dependency graph:
#
#   - the integration crates (`nemo-crabedence-bridge`, `nemo-effect-router`)
#     are themselves forbidden to the runtime path: only the runtime instance
#     composes them, and a runtime crate that depended on them would have the
#     socket client reachable from inside the runtime;
#   - the plugin isolation path (plugin host, native loader) must not even
#     name the authority socket or its service. A plugin that can address
#     serve-exec directly sits outside the supervisor's session, and the
#     composition puts the router between the plugin and the kernel.
#
# What this does NOT cover: the integration crates
# (`nemo-crabedence-bridge`, `nemo-effect-router`) do depend on
# `nemo-relay-executor`, and therefore on `nemo-relay-ledger`, because
# `ExecutionBackend`, `ExecutionRequest`, and `ExecutionResult` — the seam the
# integration implements — live there. That dependency is structural and
# recorded in docs/plan/nemo-runtime-transfer.md; it is deliberately not
# asserted here so the exception stays visible instead of being papered over.
set -euo pipefail

cd "$(dirname "$0")/../runtimes/nemo-relay"

FORBIDDEN='nemo-relay-authority|nemo-relay-ledger|nemo-relay-executor|nemo-effect-runtime|nemo-effect-qualification|nemo-crabedence-bridge|nemo-effect-router'

RUNTIME_CRATES=(
  nemo-relay
  nemo-relay-types
  nemo-relay-adaptive
  nemo-relay-plugin
  nemo-relay-plugin-protocol
  nemo-relay-plugin-proto
  nemo-relay-plugin-host
  nemo-relay-native-loader
  nemo-relay-native-abi
  nemo-relay-worker
  nemo-relay-worker-proto
  nemo-relay-pii-redaction
)

status=0
for crate in "${RUNTIME_CRATES[@]}"; do
  if ! tree="$(cargo tree -p "$crate" -e normal 2>&1)"; then
    printf 'FAIL: could not resolve %s:\n%s\n' "$crate" "$tree" >&2
    status=1
    continue
  fi
  if violations="$(printf '%s\n' "$tree" | grep -E "$FORBIDDEN")"; then
    printf 'FAIL: %s depends on a crate whose responsibilities Crabedence owns:\n%s\n' \
      "$crate" "$violations" >&2
    status=1
  else
    printf 'ok: %s\n' "$crate"
  fi
done

SOCKET_REFERENCES='execution\.sock|CRABEDENCE_SOCKET|serve-exec'
for path in crates/plugin-host/src crates/native-loader/src; do
  if hits="$(grep -rn -E "$SOCKET_REFERENCES" "$path" 2>/dev/null)"; then
    printf 'FAIL: %s names the authority socket:\n%s\n' "$path" "$hits" >&2
    status=1
  else
    printf 'ok: %s names no authority socket\n' "$path"
  fi
done

exit "$status"
