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
# What this does NOT cover: the integration crates
# (`nemo-crabedence-bridge`, `nemo-effect-router`) do depend on
# `nemo-relay-executor`, and therefore on `nemo-relay-ledger`, because
# `ExecutionBackend`, `ExecutionRequest`, and `ExecutionResult` — the seam the
# integration implements — live there. That dependency is structural and
# recorded in docs/plan/nemo-runtime-transfer.md; it is deliberately not
# asserted here so the exception stays visible instead of being papered over.
set -euo pipefail

cd "$(dirname "$0")/../runtimes/nemo-relay"

FORBIDDEN='nemo-relay-authority|nemo-relay-ledger|nemo-relay-executor|nemo-effect-runtime|nemo-effect-qualification'

RUNTIME_CRATES=(
  nemo-relay
  nemo-relay-types
  nemo-relay-adaptive
  nemo-relay-plugin
  nemo-relay-plugin-protocol
  nemo-relay-plugin-proto
  nemo-relay-plugin-host
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

exit "$status"
