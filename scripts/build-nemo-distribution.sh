#!/usr/bin/env bash
# Assemble the NEMO-CONTROL distribution.
#
# The source repository holds two runtimes; a binary distribution has to carry
# both, plus the capability schema and the registry envelope the runtime
# serves, plus the transfer manifest that says which NEMO source the vendored
# tree came from — bound together by one component manifest whose digest is
# what a release signs.
#
#   bin/       crabbox, nemo-crabedence-runtime, nemo-plugin-host
#   share/     capability-invocation-v1.json, capability-registry-envelope.json
#   manifests/ nemo-transfer-manifest.json, component-manifest.json (+ .sha256)
#
# What this does not assemble yet, stated rather than implied: an SBOM for the
# Rust components, and the qualification evidence package. Both are release
# pipeline steps with their own tooling — the Go evidence bundle already
# carries `sbom.spdx.json` — and this script assembles the runtimes, the
# schemas, and the binding.
#
# Usage: scripts/build-nemo-distribution.sh [dist/<name>]
#
# The profile is release by default; NEMO_DIST_PROFILE=debug assembles a
# development distribution, which is what CI does because its binaries are
# already built in debug.
#
# NEMO_DIST_TARGET names the integrated target as <os>_<arch>
# (linux_amd64, linux_arm64, darwin_amd64, darwin_arm64); unset means the
# host's target. Each target is its own verified root,
# dist/nemo-control_<version>_<target>, assembled on a machine with the
# toolchain for it — the script does not cross-install toolchains, it fails
# when asked for a target the toolchain cannot produce. Windows is not a
# supported integrated target: the authority transport and native-plugin
# isolation story do not exist there.
set -euo pipefail

cd "$(dirname "$0")/.."

profile="${NEMO_DIST_PROFILE:-release}"
# NEMO_DIST_VERSION/NEMO_DIST_CRABBOX let a downstream packager (the
# GoReleaser post-build hook) supply the release version and an
# already-built crabbox it produced for this target, so the manifest binds
# the same bytes that ship rather than a second compilation of them.
version="${NEMO_DIST_VERSION:-$(cat VERSION)}"
host_target="$(go env GOOS)_$(go env GOARCH)"
target="${NEMO_DIST_TARGET:-$host_target}"

case "$target" in
  linux_amd64)   goos=linux;  goarch=amd64; rust_target=x86_64-unknown-linux-gnu ;;
  linux_arm64)   goos=linux;  goarch=arm64; rust_target=aarch64-unknown-linux-gnu ;;
  darwin_amd64)  goos=darwin; goarch=amd64; rust_target=x86_64-apple-darwin ;;
  darwin_arm64)  goos=darwin; goarch=arm64; rust_target=aarch64-apple-darwin ;;
  windows_*)
    printf 'FAIL: Windows is not a supported integrated NEMO-CONTROL target —\n' >&2
    printf '      the authority transport and native-plugin isolation story do not exist there.\n' >&2
    exit 2 ;;
  *) printf 'FAIL: unsupported NEMO_DIST_TARGET %q\n' "$target" >&2; exit 2 ;;
esac

out="${1:-dist/nemo-control_${version}_${target}}"
manifest=runtimes/nemo-transfer-manifest.json

case "$out" in
  dist/*) ;;
  *) printf 'FAIL: the output directory must be under dist/ (got %s)\n' "$out" >&2; exit 2 ;;
esac
case "$profile" in
  release) target_dir=release ;;
  dev|debug) profile=dev; target_dir=debug ;;
  *) printf 'FAIL: unknown NEMO_DIST_PROFILE %q (want release or debug)\n' "$profile" >&2; exit 2 ;;
esac

# The declaration must hold before anything is assembled.
go run ./cmd/nemo-runtime-digest -manifest "$manifest" >/dev/null

rm -rf "$out"
mkdir -p "$out/bin" "$out/share" "$out/manifests"

if [[ -n "${NEMO_DIST_CRABBOX:-}" ]]; then
  printf 'installing the built CLI for %s…\n' "$target"
  [[ -f "$NEMO_DIST_CRABBOX" ]] \
    || { printf 'FAIL: NEMO_DIST_CRABBOX %s does not exist\n' "$NEMO_DIST_CRABBOX" >&2; exit 1; }
  install -m 0755 "$NEMO_DIST_CRABBOX" "$out/bin/crabbox"
else
  printf 'building the CLI for %s…\n' "$target"
  # The same ldflags the release pipeline uses (.goreleaser.yaml): a
  # distribution binary that reports "dev" does not carry the release's
  # identity, and the check below asserts the report rather than trusting the
  # flag spelling.
  GOOS="$goos" GOARCH="$goarch" go build -trimpath \
    -ldflags "-s -w -X github.com/openclaw/crabbox/internal/cli.version=${version}" \
    -o "$out/bin/crabbox" ./cmd/crabbox
fi
if [[ "$target" == "$host_target" ]]; then
  reported_version="$("$out/bin/crabbox" --version 2>&1 | tail -1 | tr -d '[:space:]')"
  [[ "$reported_version" == "$version" ]] \
    || { printf 'FAIL: the built crabbox reports version %q, not %q\n' "$reported_version" "$version" >&2; exit 1; }
  printf 'crabbox reports %s\n' "$reported_version"
fi

builds="$(jq -r '.binaries[] | select(.role=="runtime" or .role=="plugin-host") | [.package, .binary, (.features // [] | join(","))] | @tsv' "$manifest")"
if [[ -z "$builds" ]]; then
  printf 'FAIL: %s declares no shipping binaries (runtime, plugin-host)\n' "$manifest" >&2
  exit 1
fi
# --target only when crossing: a host-target build shares target/<profile>/
# with the rest of the toolchain (and earlier build steps); a cross build
# lands in target/<triple>/<profile>/ and requires that toolchain installed.
cargo_target_args=()
rust_out_dir="runtimes/nemo-relay/target/$target_dir"
if [[ "$target" != "$host_target" ]]; then
  # Preflight: the pinned toolchain must carry the target's std, and crates
  # with vendored C (ring, aws-lc) still need the target's linker on PATH —
  # that is a system toolchain, not something this script installs.
  if command -v rustup >/dev/null 2>&1; then
    pinned_toolchain="$(cd runtimes/nemo-relay && rustup show active-toolchain | awk '{print $1}')"
    rustup target list --installed --toolchain "$pinned_toolchain" 2>/dev/null | grep -qx "$rust_target" \
      || { printf 'FAIL: target %s is not installed for toolchain %s.\n       Fix: rustup target add %s --toolchain %s\n' \
           "$rust_target" "$pinned_toolchain" "$rust_target" "$pinned_toolchain" >&2; exit 1; }
  fi
  cargo_target_args=(--target "$rust_target")
  rust_out_dir="runtimes/nemo-relay/target/$rust_target/$target_dir"
fi
while IFS=$'\t' read -r package binary features; do
  printf 'building %s (%s, %s, %s)…\n' "$binary" "$package" "$rust_target" "$profile"
  if [[ -n "$features" ]]; then
    (cd runtimes/nemo-relay && cargo build --profile "$profile" ${cargo_target_args[@]+"${cargo_target_args[@]}"} -p "$package" --bin "$binary" --features "$features")
  else
    (cd runtimes/nemo-relay && cargo build --profile "$profile" ${cargo_target_args[@]+"${cargo_target_args[@]}"} -p "$package" --bin "$binary")
  fi
  install -m 0755 "$rust_out_dir/$binary" "$out/bin/$binary"
done <<< "$builds"

printf 'assembling the schemas and the registry envelope…\n'
install -m 0644 schemas/capability-invocation-v1.json "$out/share/capability-invocation-v1.json"
go run ./cmd/registry-digest -envelope > "$out/share/capability-registry-envelope.json"
install -m 0644 "$manifest" "$out/manifests/nemo-transfer-manifest.json"

rust_version="$(cd runtimes/nemo-relay && rustc --version 2>/dev/null || rustc --version)"
platform="$target"

printf 'binding the components…\n'
# The manifest is the release root: every component's digest plus the
# identities the bytes cannot carry — the platform, the toolchains, and the
# qualification gates. Its .sha256 sidecar is the release-root digest a
# signature binds.
go run ./cmd/nemo-component-manifest \
  -root "$out" \
  -transfer-manifest "$out/manifests/nemo-transfer-manifest.json" \
  -crabbox-version "$version" \
  -platform "$platform" \
  -rust-version "$rust_version" \
  -profile "$profile" \
  -qualification "nemo-runtime-e2e,nemo-critical-path,nemo-expired-authority,nemo-restart-idempotency,nemo-plugin-host"

printf 'verifying the binding…\n'
# Exhaustive: verification also rejects a file the manifest never declared,
# and requires the .sha256 sidecar to say what the manifest digests to.
go run ./cmd/nemo-component-manifest \
  -root "$out" \
  -transfer-manifest "$out/manifests/nemo-transfer-manifest.json" \
  -verify

# Release-origin authentication: when NEMO_RELEASE_SIGNING_KEY names a
# private key, sign the release-root sidecar so the packed artifact carries
# proof of who released it. The .sig cannot be declared inside the manifest
# (it signs the sidecar that binds the manifest), so it joins the manifest's
# own artifacts in the exhaustive check's exempt set.
if [[ -n "${NEMO_RELEASE_SIGNING_KEY:-}" ]]; then
  [[ -f "$NEMO_RELEASE_SIGNING_KEY" ]] \
    || { printf 'FAIL: NEMO_RELEASE_SIGNING_KEY %s is not a file\n' "$NEMO_RELEASE_SIGNING_KEY" >&2; exit 1; }
  ssh-keygen -Y sign -n nemo-control-release \
    -f "$NEMO_RELEASE_SIGNING_KEY" \
    "$out/manifests/component-manifest.sha256" \
    || { printf 'FAIL: release-root signing failed\n' >&2; exit 1; }
  printf 'signed the release root: %s\n' "$out/manifests/component-manifest.sha256.sig"
  # A signed artifact is immediately verified against the allowed-signers
  # file — a release signature that does not authenticate is a failure,
  # not a ship.
  if [[ -n "${NEMO_RELEASE_ALLOWED_SIGNERS:-}" && -n "${NEMO_RELEASE_SIGNER:-}" ]]; then
    go run ./cmd/nemo-component-manifest \
      -root "$out" \
      -transfer-manifest "$out/manifests/nemo-transfer-manifest.json" \
      -verify -allowed-signers "$NEMO_RELEASE_ALLOWED_SIGNERS" \
      -signer-identity "$NEMO_RELEASE_SIGNER" \
      || { printf 'FAIL: the signed release root does not authenticate\n' >&2; exit 1; }
  fi
elif [[ -f "$out/manifests/component-manifest.sha256.sig" ]]; then
  printf 'FAIL: %s carries a signature but no signing key was configured — the artifact is stale or tampered\n' "$out" >&2
  exit 1
else
  printf 'note: unsigned release root (set NEMO_RELEASE_SIGNING_KEY to sign)\n'
fi

printf 'distribution assembled at %s\n' "$out"
