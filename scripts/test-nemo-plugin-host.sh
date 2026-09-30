#!/usr/bin/env bash
# Prove the plugin-host composition end to end, from the runtime binary.
#
# The runtime starts the real `nemo-plugin-host` child, loads a native plugin
# through it, activates the component — its register callbacks run where its
# library is, in the child — installs the proxies the registrations report, and
# runs one managed tool call whose chain reaches the plugin's registration
# inside the child. The plugin's rewrite coming back is the proof that the
# process boundary served the call, not an in-process stand-in.
#
# The trailing checks prove the deployment's isolation policy is honored:
# NEMO_RELAY_NATIVE_ISOLATION resolves through the same from_environment()
# path the other bindings use — unset selects the documented default the run
# above exercised, malformed fails startup, and an unhonorable policy fails
# closed. Under the frozen integration-closure model plugins are middleware
# only; nothing here routes a capability.
#
# Usage: scripts/test-nemo-plugin-host.sh
set -euo pipefail

cd "$(dirname "$0")/.."

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/nemo-ph.XXXXXX")"
cleanup() { rm -rf "$work_dir"; }
trap cleanup EXIT
chmod 700 "$work_dir"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'ok: %s\n' "$*"; }

printf 'building the runtime, the host, and the fixture plugin…\n'
(
  cd runtimes/nemo-relay
  cargo build --quiet -p nemo-crabedence-runtime -p nemo-relay-native-loader
  cargo build --quiet --locked \
    --manifest-path crates/core/tests/fixtures/native_intercept_plugin/Cargo.toml \
    --target-dir target/test-plugin-fixtures
)

runtime_bin="runtimes/nemo-relay/target/debug/nemo-crabedence-runtime"
host_bin="runtimes/nemo-relay/target/debug/nemo-plugin-host"
[[ -x "$runtime_bin" && -x "$host_bin" ]] || fail "the runtime or the host binary is missing"

# The exact library name, never a glob: the build directory also holds the
# dep-info file beside it, and a `.d` picked as the artifact fails in dlopen
# with a message about the wrong thing.
case "$(uname -s 2>/dev/null || true)" in
  Darwin) fixture_name="libnemo_relay_native_intercept_fixture.dylib" ;;
  MINGW*|MSYS*|CYGWIN*|Windows*) fixture_name="nemo_relay_native_intercept_fixture.dll" ;;
  *) fixture_name="libnemo_relay_native_intercept_fixture.so" ;;
esac
library="runtimes/nemo-relay/target/test-plugin-fixtures/debug/$fixture_name"
[[ -f "$library" ]] || fail "the intercept fixture did not build: $library"

relay_version="$(sed -n 's/^version = "\(.*\)"/\1/p' runtimes/nemo-relay/Cargo.toml | head -1)"
[[ -n "$relay_version" ]] || fail "the vendored workspace version could not be read"

# Stage the fixture beside a manifest, the way a deployment ships one.
install -m 0644 "$library" "$work_dir/$(basename "$library")"
cat > "$work_dir/relay-plugin.toml" <<TOML
manifest_version = 1

[plugin]
id = "fixture_intercept"
kind = "rust_dynamic"

[compat]
relay = "=$relay_version"
native_api = "1"

[defaults]
enabled = false

[capabilities]
items = ["plugin_native"]

[load]
library = "$(basename "$library")"
symbol = "nemo_relay_native_intercept_fixture"
TOML

printf 'hosting the plugin through the runtime…\n'
export NEMO_RELAY_PLUGIN_HOST="$host_bin"
out="$("$runtime_bin" --plugin "$work_dir" --plugin-id fixture_intercept \
  --component fixture_intercept --tool example_tool --arguments '{"input":true}')"
printf '%s\n' "$out"

printf '%s' "$out" | jq -e '.status=="INVOKED"' >/dev/null \
  || fail "the runtime did not report an invocation: $out"
printf '%s' "$out" | jq -e '.host.process_id != null' >/dev/null \
  || fail "the host process is not reported: $out"
printf '%s' "$out" | jq -e '.tool_call.result.native_intercept == true' >/dev/null \
  || fail "the plugin's registration did not run in the host: $out"
pass "the plugin's registration executed in the host process"

printf '%s' "$out" | jq -e '(.plugin.registrations | length) >= 1' >/dev/null \
  || fail "the activation reported no registrations: $out"
pass "activation reported the plugin's registrations"

# The isolation-policy gates (integration closure): the run above proves the
# documented default — NEMO_RELAY_NATIVE_ISOLATION was unset — and the two
# cases below prove the resolution cannot be bypassed or silently weakened.
printf 'checking the isolation policy gates…\n'

if NEMO_RELAY_NATIVE_ISOLATION=not-a-policy "$runtime_bin" --plugin "$work_dir" \
    --plugin-id fixture_intercept --component fixture_intercept 2>"$work_dir/err"; then
  fail "a malformed isolation policy did not fail startup"
fi
grep -q "NEMO_RELAY_NATIVE_ISOLATION" "$work_dir/err" \
  || fail "the malformed-policy failure did not name the variable: $(cat "$work_dir/err")"
pass "a malformed isolation policy fails startup"

if NEMO_RELAY_NATIVE_ISOLATION=restricted-macos "$runtime_bin" --plugin "$work_dir" \
    --plugin-id fixture_intercept --component fixture_intercept 2>"$work_dir/err"; then
  fail "an unhonorable isolation policy did not fail closed"
fi
grep -q "restricted-macos" "$work_dir/err" \
  || fail "the unhonorable-policy failure did not name the policy: $(cat "$work_dir/err")"
pass "an unhonorable isolation policy fails closed"

printf 'plugin host: composition proven end to end\n'
