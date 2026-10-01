#!/usr/bin/env bash
# Qualify the installed NEMO-CONTROL artifact — the bytes a user receives, not
# the workspace that built them.
#
#   scripts/test-nemo-installed-distribution.sh <dist-root-or-tarball>
#
# The argument is either a verified root (dist/nemo-control_<v>_<target>) or a
# packed archive of one. An archive is unpacked by cmd/nemo-archive-extract,
# which preflights every member — in-directory regular files and directories
# only — before writing a byte, so a hostile tarball cannot reach outside the
# scratch. The suite:
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
  # Qualifying an archive must never let the archive reach outside the
  # scratch: members are preflighted — in-directory names, directories and
  # regular files only — before anything is written.
  mkdir -p "$work_dir/unpacked"
  go run ./cmd/nemo-archive-extract -archive "$input" -dest "$work_dir/unpacked"
  work_dir="$work_dir/unpacked"
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
# Release-origin: with an allowed-signers file configured, the sidecar
# signature must authenticate under the named principal. A signature file
# without configured signers is evidence nobody can check — fail rather than
# let an unverifiable artifact pass as released.
signer_args=()
if [[ -n "${NEMO_RELEASE_ALLOWED_SIGNERS:-}" ]]; then
  [[ -n "${NEMO_RELEASE_SIGNER:-}" ]] \
    || fail "NEMO_RELEASE_ALLOWED_SIGNERS is set but NEMO_RELEASE_SIGNER does not name the expected principal"
  signer_args=(-allowed-signers "$NEMO_RELEASE_ALLOWED_SIGNERS" -signer-identity "$NEMO_RELEASE_SIGNER")
elif [[ -f "$root/manifests/component-manifest.sha256.sig" ]]; then
  fail "the distribution carries a release signature but no NEMO_RELEASE_ALLOWED_SIGNERS is configured to verify it"
fi
go run ./cmd/nemo-component-manifest \
  -root "$root" -transfer-manifest "$transfer" -verify \
  ${signer_args[@]+"${signer_args[@]}"} \
  || fail "the component manifest does not verify the shipped bytes"
pass "component manifest verifies the unpacked root, exhaustively"
if [[ ${#signer_args[@]} -gt 0 ]]; then
  pass "release signature authenticates the root under $NEMO_RELEASE_SIGNER"
else
  printf 'note: release root is unsigned (set NEMO_RELEASE_ALLOWED_SIGNERS+NEMO_RELEASE_SIGNER to require it)\n'
fi

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

# The plugin-host pin the runtime enforces is the manifest's own digest. It is
# exported *not*: the shipped runtime discovers the component manifest beside
# its own binary, verifies it against the sidecar, and binds the host itself —
# exporting the pin here would leave the auto-binding untested.
host_sha="$(jq -r '.components[] | select(.path=="bin/nemo-plugin-host") | .sha256' "$manifest")"
[[ "$host_sha" =~ ^[0-9a-f]{64}$ ]] || fail "the manifest does not bind a plugin-host digest"
pass "the manifest binds the plugin host at $host_sha"

export NEMO_E2E_CRABBOX="$root/bin/crabbox"
export NEMO_E2E_RUNTIME="$root/bin/nemo-crabedence-runtime"
export NEMO_E2E_PLUGIN_HOST="$root/bin/nemo-plugin-host"
# The e2e suite asserts every report names this release-root digest — proof
# the runtime bound itself to this manifest rather than running unqualified.
export NEMO_E2E_EXPECT_RELEASE_ROOT="$(awk '{print $1}' "$root/manifests/component-manifest.sha256")"

# ─── 3. The full chain on shipped bytes ──────────────────────────────────────

printf '\n── runtime chain ──\n'
scripts/test-nemo-runtime-e2e.sh

# ─── 4. Authority boundary on shipped bytes ──────────────────────────────────

printf '\n── authority and restart ──\n'
scripts/test-nemo-critical-path.sh
scripts/test-nemo-expired-authority.sh
scripts/test-nemo-restart-idempotency.sh

# ─── 5. Qualification attestation ───────────────────────────────────────────
#
# Passing the suite emits a bound record: which gates ran, at which source
# commit, against which exact bytes (manifest, transfer manifest, and the
# packed archive when the input was one). NEMO_ATTESTATION_OUT overrides the
# default <input>.qualification.json beside the artifact; emit is sequenced
# after every check, so the record can only claim gates that ran.
commit="$(git rev-parse HEAD 2>/dev/null || true)"
[[ -n "$commit" ]] || fail "the suite must run from a checkout — the attestation binds the source commit"
archive_arg=()
[[ -f "$input" ]] && archive_arg=(-archive "$input")
attestation_out="${NEMO_ATTESTATION_OUT:-$input.qualification.json}"
go run ./cmd/nemo-qualification-attestation \
  -root "$root" ${archive_arg[@]+"${archive_arg[@]}"} -commit "$commit" \
  -gates nemo-component-manifest-verify,nemo-runtime-e2e,nemo-critical-path,nemo-expired-authority,nemo-restart-idempotency \
  -out "$attestation_out" || fail "the qualification attestation did not emit"
# And the record must verify against the bytes it claims — the emit path is
# exercised, the verify path proves the binding holds.
go run ./cmd/nemo-qualification-attestation -verify -root "$root" \
  -attestation "$attestation_out" || fail "the emitted attestation does not verify"
pass "qualification attestation emitted and verified: $attestation_out"

printf '\ninstalled distribution %s: qualified\n' "$(basename "$root")"
