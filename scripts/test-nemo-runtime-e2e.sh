#!/usr/bin/env bash
# Exercise the runtime instance end to end, against a live service.
#
# The bridge has live coverage (`tests/live_socket.rs`) and the router has its
# own tests; what had none is the binary that composes them,
# `nemo-crabedence-runtime` — the process a caller actually runs. Its
# invocation-identity policy is only observable through it: a MUTATION or
# CRITICAL invocation without a caller-supplied idempotency key must be refused
# before dispatch, and one key must replay rather than duplicate.
#
# This script starts a real `serve-exec`, issues a real grant, and drives the
# real binary:
#
#   PURE                      → routed locally, no socket hop
#   MUTATION without a key    → refused before dispatch, exit 2
#   MUTATION with key, brokered authority → committed with evidence
#   the same key again        → replayed, exactly one effect
#   MUTATION by a grantless principal → UNAUTHORIZED, definitive and non-retryable
#   unregistered capability   → refused before any socket hop
#
# Usage: scripts/test-nemo-runtime-e2e.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# Short on purpose: macOS caps Unix socket paths at ~104 bytes.
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/nemo-rt.XXXXXX")"
service_pid=""
cleanup() {
  if [[ -n "$service_pid" ]]; then
    kill "$service_pid" 2>/dev/null || true
    wait "$service_pid" 2>/dev/null || true
  fi
  rm -rf "$work_dir"
}
trap cleanup EXIT

chmod 700 "$work_dir"
store="$work_dir/crabedence.db"
socket="$work_dir/crabedence/execution.sock"
snapshot="$work_dir/crabedence/capabilities.json"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
check_count=0
pass() { check_count=$((check_count + 1)); printf 'ok: %s\n' "$*"; }

# NEMO_E2E_CRABBOX / NEMO_E2E_RUNTIME / NEMO_E2E_PLUGIN_HOST point the suite at
# already-built binaries — the installed-artifact qualification uses them so
# the bytes under test are the ones a user unpacks. Unset means build from the
# workspace.
if [[ -n "${NEMO_E2E_CRABBOX:-}" ]]; then
  crabbox_bin="$NEMO_E2E_CRABBOX"
else
  printf 'building the CLI…\n'
  go build -o "$work_dir/crabbox" ./cmd/crabbox
  crabbox_bin="$work_dir/crabbox"
fi

if [[ -n "${NEMO_E2E_RUNTIME:-}" ]]; then
  runtime_bin="$NEMO_E2E_RUNTIME"
else
  printf 'building the runtime instance…\n'
  (cd runtimes/nemo-relay && cargo build -p nemo-crabedence-runtime)
  runtime_bin="runtimes/nemo-relay/target/debug/nemo-crabedence-runtime"
fi

printf 'issuing a grant for the runtime principal…\n'
CRABEDENCE_STORE_PATH="$store" go run ./cmd/issue-grant \
  --principal alice@example.com \
  --capability test.counter.increment \
  --grant-id runtime-e2e-grant >/dev/null

printf 'starting the service…\n'
# The peer map authenticates this user to claim any principal, which is
# what lets the invocations below carry no authority reference at all:
# the service brokers the authenticated principal's grants itself. The
# wildcard is declared twice, the way production requires it — once in
# the peer map and once in the trusted-proxy set.
CRABEDENCE_STORE_PATH="$store" CRABEDENCE_STORE_BACKEND=sqlite \
  CRABEDENCE_PEER_PRINCIPALS="$(id -u):*" \
  CRABEDENCE_TRUSTED_PROXY_UIDS="$(id -u)" \
  XDG_RUNTIME_DIR="$work_dir" "$crabbox_bin" serve-exec \
  >"$work_dir/serve.log" 2>&1 &
service_pid=$!
for _ in $(seq 1 60); do
  [[ -S "$socket" && -f "$snapshot" ]] && break
  sleep 0.25
done
if [[ ! -S "$socket" || ! -f "$snapshot" ]]; then
  printf 'the service did not publish its socket and snapshot; log follows:\n' >&2
  cat "$work_dir/serve.log" >&2
  exit 1
fi
pass "service is up with a verified snapshot"

run_runtime() {
  "$runtime_bin" --socket "$socket" --snapshot "$snapshot" \
    --principal alice@example.com "$@"
}

# 1. PURE executes locally: the route comes from the verified registry, and
#    the local backend answers without a socket hop.
out="$(run_runtime --capability system.echo --arguments '{"probe":"runtime-e2e"}')" \
  || fail "the PURE invocation must succeed: $out"
printf '%s' "$out" | jq -e '.status=="SUCCEEDED" and .result.local==true' >/dev/null \
  || fail "system.echo did not route locally: $out"
pass "PURE routed locally"

# 1c. DIRECT crosses the socket: system.info is pinned READ + DIRECT, so the
#     runtime dispatches it to the service, whose own dispatcher resolves the
#     non-durable read route. The answer carries the service's read (system
#     fields, no `local` marker) and no durable receipt — evidence it crossed
#     the boundary rather than executing in-process.
out="$(run_runtime --capability system.info --arguments '{}')" \
  || fail "the DIRECT read must succeed: $out"
printf '%s' "$out" | jq -e '
    .status=="SUCCEEDED"
    and .result.go_version
    and (.result.local | not)
    and (.receipt_digest == null)' >/dev/null \
  || fail "system.info did not execute over the DIRECT socket path: $out"
pass "READ pinned DIRECT dispatched over the socket (no durable receipt)"

# 1b. When the bytes under test are an installed distribution, the runtime
#     must have bound itself to the release root: every report carries the
#     component-manifest digest it discovered beside its own binary.
if [[ -n "${NEMO_E2E_EXPECT_RELEASE_ROOT:-}" ]]; then
  printf '%s' "$out" | jq -e --arg d "$NEMO_E2E_EXPECT_RELEASE_ROOT" '
      .identity.release.release_root_digest==$d' >/dev/null \
    || fail "the runtime did not report the release root it shipped in: $out"
  pass "runtime reports the release-root identity from its component manifest"
fi

# 2. A consequential invocation without a caller key is refused before
#    dispatch — no capability-derived default.
set +e
out="$(run_runtime --capability test.counter.increment \
  --arguments '{"counter":"refused","by":1}' 2>&1)"
status=$?
set -e
[[ $status -eq 2 ]] || fail "a MUTATION without --idempotency-key must exit 2, got $status: $out"
[[ "$out" == *"--idempotency-key is required"* ]] \
  || fail "the refusal must name the missing key: $out"
pass "MUTATION without a key refused before dispatch"

# 3. With the peer principal holding a grant it commits, with evidence —
#    the runtime carries no authority reference; the service resolved the
#    grant for the authenticated principal itself.
counter="runtime-e2e-$$"
key="runtime-e2e-key-$$"
out="$(run_runtime --capability test.counter.increment \
  --arguments "{\"counter\":\"$counter\",\"by\":1}" \
  --idempotency-key "$key")" \
  || fail "the brokered mutation must commit: $out"
printf '%s' "$out" | jq -e '.status=="SUCCEEDED" and .result.value==1 and (.receipt_digest != null)' >/dev/null \
  || fail "the mutation did not commit with evidence: $out"
pass "MUTATION committed with evidence (value 1, brokered authority)"

# 4. The same logical action replays: a second effect would read 2.
out="$(run_runtime --capability test.counter.increment \
  --arguments "{\"counter\":\"$counter\",\"by\":1}" \
  --idempotency-key "$key")" \
  || fail "the replay must answer from the durable record: $out"
printf '%s' "$out" | jq -e '.status=="SUCCEEDED" and .result.value==1' >/dev/null \
  || fail "a repeated key duplicated the effect: $out"
pass "the repeated key replayed (still value 1)"

# 5. A principal holding no grant is denied — definitive, not retryable.
#    The peer map lets this caller claim any principal, and the brokered
#    resolution for one holding no grants still answers unauthorized.
out="$(run_runtime --capability test.counter.increment \
  --principal mallory@example.com \
  --arguments "{\"counter\":\"$counter\",\"by\":1}" \
  --idempotency-key "${key}-ungranted")" || true
printf '%s' "$out" | jq -e '.status=="FAILED" and .code=="UNAUTHORIZED" and .retryable==false' >/dev/null \
  || fail "a mutation by a grantless principal must be a definitive refusal: $out"
pass "MUTATION by a principal holding no grant refused (non-retryable)"

# 6. An unregistered capability never reaches the socket.
set +e
out="$(run_runtime --capability no.such.capability --arguments '{}' 2>&1)"
status=$?
set -e
[[ $status -ne 0 ]] || fail "an unregistered capability must be refused"
[[ "$out" == *"not in the verified registry"* ]] \
  || fail "the refusal must say the capability is unregistered: $out"
pass "unregistered capability refused before routing"

# 6b. A registered capability whose adapter this deployment did not wire
# resolves through the registry (it IS known — the snapshot carries it)
# and fails at the deployment boundary as CAPABILITY_UNAVAILABLE, not
# NOT_FOUND and not a route change. The e2e service has no GitHub
# adapter, so the new DIRECT read exercises exactly that seam.
out="$(run_runtime --capability github.issue.list \
  --arguments '{"repo":"example-org/my-app"}')" || true
printf '%s' "$out" | jq -e '.status=="FAILED" and .code=="CAPABILITY_UNAVAILABLE" and .reconciliation_required==false' >/dev/null \
  || fail "a registered capability with an unwired adapter must fail unavailable: $out"
pass "registered capability with unwired adapter fails CAPABILITY_UNAVAILABLE"

# ─── The joined path: a real plugin host mediating managed invocations ──────
#
# The runtime starts the real `nemo-plugin-host` child under the deployment's
# isolation policy, loads and activates the intercept fixture, installs the
# registration proxies into its own chains, and runs managed invocations whose
# middleware executes in the child. The frozen model: plugins are middleware
# only — they may inspect, deny, or rewrite arguments; the capability, class,
# route, authority, and identity stay the runtime's.
host_bin="${NEMO_E2E_PLUGIN_HOST:-runtimes/nemo-relay/target/debug/nemo-plugin-host}"
printf 'building the fixture plugin%s…\n' \
  "$([[ -n "${NEMO_E2E_PLUGIN_HOST:-}" ]] && printf ' (host supplied)' || printf ' and the plugin host')"
(
  cd runtimes/nemo-relay
  [[ -n "${NEMO_E2E_PLUGIN_HOST:-}" ]] || cargo build --quiet -p nemo-relay-native-loader
  # The fixture is qualification tooling — the loaded plugin under test — so
  # it always builds from the workspace; the host executing it is the shipped
  # binary when NEMO_E2E_PLUGIN_HOST is set.
  cargo build --quiet --locked \
    --manifest-path crates/core/tests/fixtures/native_intercept_plugin/Cargo.toml \
    --target-dir target/test-plugin-fixtures
)
case "$(uname -s 2>/dev/null || true)" in
  Darwin) fixture_name="libnemo_relay_native_intercept_fixture.dylib" ;;
  *) fixture_name="libnemo_relay_native_intercept_fixture.so" ;;
esac
# The fixture must match the host's architecture — a translated host needs a
# translated plugin (NEMO_E2E_FIXTURE for cross-arch qualification).
library="${NEMO_E2E_FIXTURE:-runtimes/nemo-relay/target/test-plugin-fixtures/debug/$fixture_name}"
[[ -x "$host_bin" && -f "$library" ]] \
  || fail "the plugin host or the fixture library is missing"

# Stage the fixture beside a manifest, the way a deployment ships one.
plugin_dir="$work_dir/plugin"
mkdir -p "$plugin_dir"
install -m 0644 "$library" "$plugin_dir/$(basename "$library")"
relay_version="$(sed -n 's/^version = "\(.*\)"/\1/p' runtimes/nemo-relay/Cargo.toml | head -1)"
cat > "$plugin_dir/relay-plugin.toml" <<TOML
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
export NEMO_RELAY_PLUGIN_HOST="$host_bin"
# This tree is a development deployment: it names the host by ambient path and
# has no release manifest or digest to pin its bytes, so it acknowledges the
# unverified host explicitly — the composition refuses the override otherwise.
export NEMO_RELAY_PLUGIN_HOST_ALLOW_UNPINNED=1
pass "plugin host and fixture staged"

# 7. A managed PURE invocation through the plugin: the chain's request and
#    execution intercepts rewrite the arguments inside the child process, the
#    binding proves original → effective, and the FunctionHooks backend — the
#    real NEMO local path — answers. No Crabedence involvement for LOCAL.
out="$(run_runtime --plugin "$plugin_dir" --plugin-id fixture_intercept \
  --component fixture_intercept --capability system.echo \
  --arguments '{"probe":"joined"}')" \
  || fail "the joined PURE invocation must succeed: $out"
printf '%s' "$out" | jq -e '
    .status=="SUCCEEDED"
    and .result.backend=="function-hooks" and .result.local==true
    and .result.arguments.native_intercept==true
    and .result.arguments.native_intercept_execution_request==true
    and .result.arguments.probe=="joined"
    and .plugin.process_id != null
    and (.identity.middleware_set_digest != null)
    and (.identity.mediation.plugin_manifest_sha256 | length) == 64
    and (.identity.mediation.plugin_library_sha256 | length) == 64
    and (.identity.mediation.activation_config_sha256 | length) == 64
    and .identity.original_args_digest != .attempts[0].effective_args_digest
    and (.attempts | length) == 1' >/dev/null \
  || fail "the joined PURE invocation did not prove middleware + function hooks: $out"
pass "PURE mediated by the child's middleware, executed by the function-hook backend"

# 8. A MUTATION through the same chain. The counter's argument schema is
#    closed, so the plugin runs with its argument markers off — its execution
#    intercept still wraps the call, and the marker it writes into the result
#    it returns is the proof the child's middleware held the continuation
#    around the Crabedence dispatch. That marked payload is not the report —
#    the routed outcome is — so it lands in `middleware_result`.
counter_joined="runtime-e2e-joined-$$"
key_joined="runtime-e2e-joined-key-$$"
out="$(run_runtime --plugin "$plugin_dir" --plugin-id fixture_intercept \
  --component fixture_intercept \
  --plugin-config '{"arg_marks":false}' \
  --capability test.counter.increment \
  --arguments "{\"counter\":\"$counter_joined\",\"by\":1}" \
  --idempotency-key "$key_joined")" \
  || fail "the joined MUTATION must commit: $out"
printf '%s' "$out" | jq -e '
    .status=="SUCCEEDED" and .result.value==1
    and .middleware_result.native_intercept_execution==true
    and (.receipt_digest != null)
    and .plugin.process_id != null
    and (.attempts | length) == 1' >/dev/null \
  || fail "the joined MUTATION did not commit with evidence: $out"
pass "MUTATION through plugin middleware committed with a receipt"

# 9. The same logical action replays through the same chain: a second external
#    effect would read 2.
out="$(run_runtime --plugin "$plugin_dir" --plugin-id fixture_intercept \
  --component fixture_intercept \
  --plugin-config '{"arg_marks":false}' \
  --capability test.counter.increment \
  --arguments "{\"counter\":\"$counter_joined\",\"by\":1}" \
  --idempotency-key "$key_joined")" \
  || fail "the replay must answer from the durable record: $out"
printf '%s' "$out" | jq -e '
    .status=="SUCCEEDED" and .result.value==1
    and .middleware_result.native_intercept_execution==true' >/dev/null \
  || fail "a repeated key duplicated the effect: $out"
pass "the repeated logical action replayed (still value 1)"

# 10. The same durable key with different arguments is an identity conflict —
#     never a second effect.
out="$(run_runtime --capability test.counter.increment \
  --arguments "{\"counter\":\"$counter_joined\",\"by\":99}" \
  --idempotency-key "$key_joined" || true)"
printf '%s' "$out" | jq -e '.status=="FAILED" and (.code | test("IDEMPOTENCY"))' >/dev/null \
  || fail "same key with different arguments must be an identity conflict: $out"
pass "same durable key + changed arguments → identity conflict"

# 10b. The authority boundary at the process level: the child's environment is
#      cleared at spawn, so it carries only the session variables it needs —
#      never the service's socket, store, runtime dir, home, or any other
#      variable the parent happens to have. The fixture writes the *names* it
#      sees (never values), which is what a witness may report.
env_dump="$work_dir/child-env.txt"
sentinel="leak-probe-$$"
CRABEDENCE_LEAK_PROBE="$sentinel" run_runtime --plugin "$plugin_dir" \
  --plugin-id fixture_intercept --component fixture_intercept \
  --plugin-config "{\"env_dump\":\"$env_dump\"}" \
  --capability system.echo --arguments '{"probe":"env-boundary"}' >/dev/null \
  || fail "the env-boundary invocation must succeed: $out"
[[ -s "$env_dump" ]] || fail "the child never wrote its environment names"
grep -qx 'NEMO_RELAY_PLUGIN_HOST_SOCKET' "$env_dump" \
  || fail "the child is missing its session socket: $(cat "$env_dump")"
grep -qx 'NEMO_RELAY_PLUGIN_HOST_CREDENTIAL' "$env_dump" \
  || fail "the child is missing its session credential"
if grep -qE '^(HOME|XDG_RUNTIME_DIR|CRABEDENCE_|CRABBOX_)' "$env_dump"; then
  fail "the child inherited environment it must not see: $(grep -E '^(HOME|XDG_RUNTIME_DIR|CRABEDENCE_|CRABBOX_)' "$env_dump")"
fi
grep -q "$sentinel" "$env_dump" && fail "the leak probe reached the child"
pass "the plugin child sees only its session environment"

# 11. Adversarial: middleware that answers without ever reaching the dispatch
#     is refused — a capability result that did not cross the router is not
#     evidence of execution.
out="$(run_runtime --plugin "$plugin_dir" --plugin-id fixture_intercept \
  --component fixture_intercept --capability system.echo \
  --arguments '{"skip_next":true}' || true)"
printf '%s' "$out" | jq -e '.status=="FAILED" and .code=="DISPATCH_BYPASSED"' >/dev/null \
  || fail "a plugin-replaced dispatch must fail closed: $out"
pass "middleware bypass of the routed dispatch refused"

# ─── Plugin-host binary binding ─────────────────────────────────────────────
#
# The distribution's component manifest declares the host's SHA-256 — a
# qualified layout binds it automatically, and outside a release a deployment
# pins it through NEMO_RELAY_PLUGIN_HOST_SHA256. The digest is computed over
# the bytes the supervisor actually spawns — an override cannot substitute a
# different host than the one it named.

host_sha256() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}
pinned_host_digest="$(host_sha256 "$host_bin")"

# 12. The pinned host runs, and its identity is in the evidence.
out="$(NEMO_RELAY_PLUGIN_HOST_SHA256="$pinned_host_digest" run_runtime \
  --plugin "$plugin_dir" --plugin-id fixture_intercept \
  --component fixture_intercept --capability system.echo \
  --arguments '{"probe":"pinned-host"}')" \
  || fail "a correctly pinned host must run: $out"
printf '%s' "$out" | jq -e --arg d "$pinned_host_digest" '
    .status=="SUCCEEDED"
    and .plugin.host.pinned==true
    and .plugin.host.sha256==$d
    and (.plugin.host.executable | endswith("nemo-plugin-host"))' >/dev/null \
  || fail "the pinned host's identity is not in the evidence: $out"
pass "the pinned plugin host ran, its digest recorded in evidence"

# 13. A pin the resolved binary does not satisfy fails the session — the
#     override chose a host, and the pin proves it is not the released one.
set +e
out="$(NEMO_RELAY_PLUGIN_HOST_SHA256="$(printf '0%.0s' $(seq 64))" run_runtime \
  --plugin "$plugin_dir" --plugin-id fixture_intercept \
  --component fixture_intercept --capability system.echo \
  --arguments '{"probe":"wrong-pin"}' 2>&1)"
status=$?
set -e
[[ $status -ne 0 ]] || fail "a wrong host pin must fail the invocation: $out"
printf '%s' "$out" | grep -q 'NEMO_RELAY_PLUGIN_HOST_SHA256' \
  || fail "the refusal must name the pin: $out"
pass "a host digest the pin does not declare fails closed"

# 14. A malformed pin is a deployment error, not a disabled pin.
set +e
out="$(NEMO_RELAY_PLUGIN_HOST_SHA256="not-a-digest" run_runtime \
  --plugin "$plugin_dir" --plugin-id fixture_intercept \
  --component fixture_intercept --capability system.echo \
  --arguments '{"probe":"bad-pin"}' 2>&1)"
status=$?
set -e
[[ $status -ne 0 && "$out" == *"NEMO_RELAY_PLUGIN_HOST_SHA256"* ]] \
  || fail "a malformed pin must name the variable: $out"
pass "a malformed host pin fails startup"

# ─── Fail-closed plugin composition ─────────────────────────────────────────
#
# A declared plugin is required middleware — for the integration RC there is
# no "optional" plugin path. If the host cannot be launched, the artifact
# cannot load, the component cannot activate, or the middleware dies or hangs
# mid-call, the invocation fails; it never continues unmediated.

# 15. Missing host binary: the deployment names a host that does not exist.
set +e
out="$(NEMO_RELAY_PLUGIN_HOST="$work_dir/no-such-host" run_runtime \
  --plugin "$plugin_dir" --plugin-id fixture_intercept \
  --component fixture_intercept --capability system.echo \
  --arguments '{"probe":"missing-host"}' 2>&1)"
status=$?
set -e
[[ $status -ne 0 ]] || fail "a missing plugin host must fail the invocation: $out"
printf '%s' "$out" | grep -qi 'host' \
  || fail "the refusal must name the host: $out"
pass "missing plugin host fails the invocation"

# 16. Invalid artifact: a manifest that names a library the deployment does
#     not ship.
bad_plugin_dir="$work_dir/plugin-bad"
mkdir -p "$bad_plugin_dir"
sed 's|^library = .*|library = "missing-library.so"|' \
  "$plugin_dir/relay-plugin.toml" > "$bad_plugin_dir/relay-plugin.toml"
set +e
out="$(run_runtime --plugin "$bad_plugin_dir" --plugin-id fixture_intercept \
  --component fixture_intercept --capability system.echo \
  --arguments '{"probe":"bad-artifact"}' 2>&1)"
status=$?
set -e
[[ $status -ne 0 ]] || fail "an unloadable artifact must fail the invocation: $out"
pass "invalid plugin artifact fails the invocation"

# 17. Activation failure: the plugin is asked for a component it does not have.
set +e
out="$(run_runtime --plugin "$plugin_dir" --plugin-id fixture_intercept \
  --component no.such.component --capability system.echo \
  --arguments '{"probe":"bad-component"}' 2>&1)"
status=$?
set -e
[[ $status -ne 0 ]] || fail "an unactivatable component must fail the invocation: $out"
pass "activation failure fails the invocation"

# 18. Host death inside its own middleware: the child aborts mid-call. The
#     invocation fails — a dead plugin is a failed call, never a chain that
#     quietly continued without it.
set +e
out="$(run_runtime --plugin "$plugin_dir" --plugin-id fixture_intercept \
  --component fixture_intercept \
  --plugin-config '{"die_on_invoke":true}' --capability system.echo \
  --arguments '{"probe":"crash"}' 2>&1)"
status=$?
set -e
[[ $status -ne 0 ]] || fail "a host that dies mid-call must fail the invocation: $out"
printf '%s' "$out" | jq -e '.status=="FAILED" and (.attempts | length) == 0' >/dev/null \
  || fail "a crashed host must not produce a dispatch: $out"
pass "plugin host death mid-call fails the invocation"

# 19. Middleware that runs the continuation and *then* fails: the dispatch
#     verdict stays authoritative — a committed effect is not relabeled by a
#     middleware error, and the report still records that the chain erred.
counter_fail_after="runtime-e2e-failafter-$$"
out="$(run_runtime --plugin "$plugin_dir" --plugin-id fixture_intercept \
  --component fixture_intercept \
  --plugin-config '{"arg_marks":false,"fail_after_next":true}' --capability test.counter.increment \
  --arguments "{\"counter\":\"$counter_fail_after\",\"by\":1}" \
  --idempotency-key "runtime-e2e-failafter-key-$$")" \
  || fail "a post-dispatch middleware error must not uncommit the effect: $out"
printf '%s' "$out" | jq -e '
    .status=="SUCCEEDED" and .result.value==1
    and (.receipt_digest != null)
    and (.post_dispatch_middleware_error | length) > 0
    and (.attempts | length) == 1' >/dev/null \
  || fail "the dispatch verdict must survive a post-dispatch middleware failure: $out"
pass "post-dispatch middleware failure cannot relabel a committed effect"

# 20. Concurrent continuation: the ABI lets an intercept fan its continuation
#     out, but a consequential operation may dispatch only once — the second
#     call is refused before it can reach the router. The first routed verdict
#     stays authoritative, the refusal is evidence, and the middleware error
#     the second call raised is recorded without relabeling the commit.
counter_concurrent="runtime-e2e-concurrent-$$"
out="$(run_runtime --plugin "$plugin_dir" --plugin-id fixture_intercept \
  --component fixture_intercept \
  --plugin-config '{"arg_marks":false,"use_concurrent_next":true}' --capability test.counter.increment \
  --arguments "{\"counter\":\"$counter_concurrent\",\"by\":1}" \
  --idempotency-key "runtime-e2e-concurrent-key-$$")" \
  || fail "a refused second dispatch must not uncommit the first: $out"
printf '%s' "$out" | jq -e '
    .status=="SUCCEEDED" and .result.value==1
    and (.receipt_digest != null)
    and (.attempts | length) == 1
    and (.refused_dispatches | length) == 1
    and .refused_dispatches[0].reason=="MULTIPLE_DISPATCH_ATTEMPTS"
    and .refused_dispatches[0].attempt==2
    and (.refused_dispatches[0].effective_args_digest | length) == 64
    and (.post_dispatch_middleware_error | length) > 0' >/dev/null \
  || fail "a fanned continuation must dispatch once and record the refusal: $out"
pass "concurrent continuation: first dispatch authoritative, second refused and recorded"

# 21. Middleware timeout: a plugin that holds the call past the managed
#     deadline fails the invocation — the deadline is the deployment's bound
#     on how long middleware may hold a call.
set +e
out="$(NEMO_RELAY_MANAGED_CALL_BUDGET_MS=2000 run_runtime \
  --plugin "$plugin_dir" --plugin-id fixture_intercept \
  --component fixture_intercept \
  --plugin-config '{"sleep_ms":15000}' --capability system.echo \
  --arguments '{"probe":"timeout"}' 2>&1)"
status=$?
set -e
[[ $status -ne 0 ]] || fail "a middleware that outruns the budget must fail: $out"
printf '%s' "$out" | jq -e '.status=="FAILED" and (.attempts | length) == 0' >/dev/null \
  || fail "a timed-out chain must not dispatch: $out"
pass "middleware timeout fails the invocation before dispatch"

# 22. Malformed deployment configuration fails startup, like every other
#     env-resolved setting in this composition.
set +e
out="$(NEMO_RELAY_MANAGED_CALL_BUDGET_MS=soon run_runtime \
  --plugin "$plugin_dir" --plugin-id fixture_intercept \
  --component fixture_intercept --capability system.echo \
  --arguments '{"probe":"bad-budget"}' 2>&1)"
status=$?
set -e
[[ $status -ne 0 && "$out" == *"NEMO_RELAY_MANAGED_CALL_BUDGET_MS"* ]] \
  || fail "a malformed call budget must name the variable: $out"
pass "malformed managed-call budget fails startup"

# ─── Trust-class and ambient-override gates ─────────────────────────────────
#
# Two rules keep the ambient knobs from becoming ambient authority: an
# environment variable that names the host must have its bytes pinned or be
# explicitly acknowledged as development, and an artifact that declares
# confinement cannot be hosted by a policy that does not confine it.

# 23. The ambient override alone is not enough: unsetting the development
#     acknowledgement leaves a path nobody pinned, and the composition must
#     refuse it rather than execute whichever binary the path resolves to.
set +e
out="$(
  unset NEMO_RELAY_PLUGIN_HOST_ALLOW_UNPINNED
  export NEMO_RELAY_PLUGIN_HOST_SHA256=
  run_runtime \
    --plugin "$plugin_dir" --plugin-id fixture_intercept \
    --component fixture_intercept --capability system.echo \
    --arguments '{"probe":"unpinned-override"}' 2>&1
)"
status=$?
set -e
[[ $status -ne 0 ]] || fail "an unpinned ambient override must be refused: $out"
printf '%s' "$out" | grep -q 'NEMO_RELAY_PLUGIN_HOST_ALLOW_UNPINNED' \
  || fail "the refusal must name the acknowledgement: $out"
pass "an ambient host override with nothing pinning it is refused"

# 24. An artifact that requires confinement refuses trusted-process: the
#     manifest's declaration is inside the digest that approved it, so a
#     deployment that offers a non-confining policy gets a refusal, not a
#     silently downgraded host.
confined_plugin_dir="$work_dir/plugin-confined"
mkdir -p "$confined_plugin_dir"
install -m 0644 "$library" "$confined_plugin_dir/$(basename "$library")"
cat > "$confined_plugin_dir/relay-plugin.toml" <<TOML
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

[security]
requires_confinement = true
TOML

set +e
out="$(NEMO_RELAY_NATIVE_ISOLATION=trusted-process run_runtime \
  --plugin "$confined_plugin_dir" --plugin-id fixture_intercept \
  --component fixture_intercept --capability system.echo \
  --arguments '{"probe":"requires-confinement"}' 2>&1)"
status=$?
set -e
[[ $status -ne 0 ]] || fail "a confinement-required plugin must refuse trusted-process: $out"
printf '%s' "$out" | grep -q 'requires_confinement' \
  || fail "the refusal must name the manifest's declaration: $out"
pass "a confinement-required plugin refuses a non-confining policy"

printf 'runtime e2e: %d checks passed\n' "$check_count"
