#!/usr/bin/env bash
# Qualify the installed NEMO-CONTROL artifact — the bytes a user receives, not
# the workspace that built them.
#
#   scripts/test-nemo-installed-distribution.sh <dist-root-or-tarball>
#
# The argument is either a verified root (dist/nemo-control_<v>_<target>) or a
# packed archive of one. The suite:
#   1. verifies the root against its component manifest and .sha256 sidecar,
#      exhaustively — an undeclared file is a failure;
#   2. asserts the platform matches the host and the reported versions match
#      the manifest's declared versions;
#   3. runs the live execution chain against the shipped binaries: service
#      startup, managed PURE, plugin middleware, synthetic MUTATION with a
#      receipt, logical replay, idempotency conflict, dispatch-bypass refusal,
#      the plugin-host pin (bound to the manifest's declared digest), and the
#      fail-closed composition cases;
#   4. runs the authority/restart suites against the shipped crabbox.
#
# The fixture plugin is rebuilt from the vendored workspace — it is the
# qualification probe, not a shipped component. Everything else under test is
# the unpacked artifact itself.
set -euo pipefail

cd "$(dirname "$0")/.."

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'ok: %s\n' "$*"; }

input="${1:?usage: $0 <dist-root-or-tarball>}"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/nemo-dist.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT
chmod 700 "$work_dir"

# ─── Unpack what the user receives ──────────────────────────────────────────

if [[ -d "$input" ]]; then
  root="$input"
elif [[ -f "$input" ]]; then
  printf 'unpacking %s…\n' "$input"
  tar -xzf "$input" -C "$work_dir"
  # The archive may carry the root flat (bin/ at top) or wrapped in a named
  # directory — find the level that holds bin/ and manifests/.
  root="$(find "$work_dir" -mindepth 1 -maxdepth 3 -type d -name bin -exec dirname {} \; | while read -r candidate; do
    [[ -d "$candidate/manifests" ]] && printf '%s\n' "$candidate"
  done | head -1)"
  [[ -n "$root" && -d "$root/bin" ]] || fail "the archive carries no distribution root"
else
  fail "no such distribution: $input"
fi
root="$(cd "$root" && pwd)"
printf 'distribution root: %s\n' "$root"

# ─── 1. The root proves itself ──────────────────────────────────────────────

transfer="$root/manifests/nemo-transfer-manifest.json"
go run ./cmd/nemo-component-manifest \
  -root "$root" -transfer-manifest "$transfer" -verify \
  || fail "the component manifest does not verify the shipped bytes"
pass "component manifest verifies the unpacked root, exhaustively"

# ─── 2. Identity: platform and reported versions are the declared ones ───────

manifest="$root/manifests/component-manifest.json"
platform="$(jq -r .platform "$manifest")"
# NEMO_QUALIFY_HOST declares the architecture the artifact will execute as —
# a translated host (Rosetta) qualifies a foreign-arch distribution because
# the shipped binaries genuinely run there; the fixture still has to be built
# for the artifact's own arch via NEMO_E2E_FIXTURE.
host="${NEMO_QUALIFY_HOST:-$(go env GOOS)_$(go env GOARCH)}"
[[ "$platform" == "$host" ]] \
  || fail "this distribution is for $platform, cannot qualify on $host"
pass "platform $platform matches this host"

reported="$("$root/bin/crabbox" --version | tail -1 | tr -d '[:space:]')"
declared="$(jq -r .crabbox_version "$manifest")"
[[ "$reported" == "$declared" ]] \
  || fail "crabbox reports $reported, the manifest declares $declared"
[[ "$reported" != "dev" ]] \
  || fail "crabbox reports dev — the release stamp is missing"
pass "crabbox reports the declared version $reported"

# The plugin-host pin the runtime will enforce is the manifest's own digest —
# the release's declaration bound into the running system.
host_sha="$(jq -r '.components[] | select(.path=="bin/nemo-plugin-host") | .sha256' "$manifest")"
[[ "$host_sha" =~ ^[0-9a-f]{64}$ ]] || fail "the manifest does not bind a plugin-host digest"
pass "the manifest binds the plugin host at $host_sha"

export NEMO_E2E_CRABBOX="$root/bin/crabbox"
export NEMO_E2E_RUNTIME="$root/bin/nemo-crabedence-runtime"
export NEMO_E2E_PLUGIN_HOST="$root/bin/nemo-plugin-host"
export NEMO_RELAY_PLUGIN_HOST="$root/bin/nemo-plugin-host"
export NEMO_RELAY_PLUGIN_HOST_SHA256="$host_sha"

# ─── 3. The full chain on shipped bytes ──────────────────────────────────────

printf '\n── runtime chain ──\n'
scripts/test-nemo-runtime-e2e.sh

# ─── 4. Authority boundary on shipped bytes ──────────────────────────────────

printf '\n── authority and restart ──\n'
scripts/test-nemo-critical-path.sh
scripts/test-nemo-expired-authority.sh
scripts/test-nemo-restart-idempotency.sh

printf '\ninstalled distribution %s: qualified\n' "$(basename "$root")"
