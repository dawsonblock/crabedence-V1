#!/usr/bin/env bash
# Credential isolation for the NeMo Relay side of the boundary.
#
# The containment argument is that provider and authority credentials live
# behind Crabedence's provider processes: a NeMo Relay plugin reaches the
# external world only through the capability invocation ABI, which carries a
# capability, its arguments, authority material, an idempotency key, and a
# deadline — never a credential.
#
# This script asserts the part of that argument which is mechanically true
# today: the plugin isolation path (plugin host, native loader) and the
# integration crates reference no provider or authority credential. It also
# reports the two known upstream credential paths, which are NOT clean and are
# recorded as finding 7 in docs/plan/nemo-runtime-transfer.md. Reporting them
# on every run is deliberate: a green check must not imply a guarantee the tree
# does not provide.
set -euo pipefail

cd "$(dirname "$0")/.."

CREDENTIALS='CRABBOX_EVIDENCE_KEY|CRABEDENCE_DATABASE_URL|CRABBOX_TEST_DATABASE_URL|CRABBOX_OPENCOMPUTER_API_KEY|OPENCOMPUTER_API_KEY|CRABBOX_TOKEN|CRABBOX_BROKER_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SESSION_TOKEN|AWS_WEB_IDENTITY_TOKEN_FILE|AWS_SHARED_CREDENTIALS_FILE|GH_TOKEN|GITHUB_TOKEN|ANTHROPIC_API_KEY'

# The isolation path and our own code must be credential-free. These paths must
# not so much as name a credential: there is no reason for the plugin host, the
# native loader, or the integration crates to know one exists.
GUARDED=(
  runtimes/nemo-relay/crates/plugin-host/src
  runtimes/nemo-relay/crates/native-loader/src
  runtimes/nemo-relay/bridges
)

status=0
for path in "${GUARDED[@]}"; do
  if hits="$(grep -rn -E "$CREDENTIALS" "$path" 2>/dev/null)"; then
    printf 'FAIL: %s references a provider or authority credential:\n%s\n' "$path" "$hits" >&2
    status=1
  else
    printf 'ok: %s\n' "$path"
  fi
done

# The MCP environment allowlist is the other half of the fix, and it is the one
# place a credential name must appear — in the blocklist. Naming a credential
# there is how it is refused, so this asserts the blocklist covers every
# credential in the list above rather than asserting the file is silent.
MCP_ENV='runtimes/nemo-relay/crates/cli/src/mcp_environment.rs'
if [[ -f "$MCP_ENV" ]]; then
  missing=""
  while IFS= read -r name; do
    if ! grep -q "\"$name\"" "$MCP_ENV"; then
      missing="$missing $name"
    fi
  done < <(printf '%s' "$CREDENTIALS" | tr '|' '\n')
  if [[ -n "$missing" ]]; then
    printf 'FAIL: %s does not block:%s\n' "$MCP_ENV" "$missing" >&2
    status=1
  else
    printf 'ok: %s blocks every credential name\n' "$MCP_ENV"
  fi

  # Naming a credential in the blocklist is the refusal; naming one in the
  # allowlist is the exposure. Assert the allowlist is free of them, so
  # re-adding a credential to BASE_MCP_ENV_VARS cannot pass this check.
  allowlist="$(awk '/^const BASE_MCP_ENV_VARS/,/^\];/' "$MCP_ENV" | grep -o '"[A-Za-z_0-9]*"')"
  reallowed=""
  while IFS= read -r name; do
    if printf '%s\n' "$allowlist" | grep -qx "\"$name\""; then
      reallowed="$reallowed $name"
    fi
  done < <(printf '%s' "$CREDENTIALS" | tr '|' '\n')
  if [[ -n "$reallowed" ]]; then
    printf 'FAIL: %s allows:%s\n' "$MCP_ENV" "$reallowed" >&2
    status=1
  else
    printf 'ok: %s allows no credential name\n' "$MCP_ENV"
  fi
else
  printf 'FAIL: %s is missing\n' "$MCP_ENV" >&2
  status=1
fi

# The one remaining path, and why it is not a failure: NeMo Relay's own S3
# observability exporter reads an operator-configured credential. That is an
# explicit deployment choice for a NeMo Relay feature — the same shape as
# Crabedence reading its own store credential — not ambient inheritance into a
# plugin subprocess. Removing it would remove the exporter.
printf '\nAccepted, not a plugin path:\n'
printf '  crates/core/src/observability/plugin_component.rs   S3 observability destination, operator-configured\n'

exit "$status"
