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
set -euo pipefail

cd "$(dirname "$0")/.."

profile="${NEMO_DIST_PROFILE:-release}"
out="${1:-dist/nemo-control}"
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

printf 'building the CLI…\n'
go build -trimpath -o "$out/bin/crabbox" ./cmd/crabbox

builds="$(jq -r '.binaries[] | select(.role=="runtime" or .role=="plugin-host") | [.package, .binary, (.features // [] | join(","))] | @tsv' "$manifest")"
if [[ -z "$builds" ]]; then
  printf 'FAIL: %s declares no shipping binaries (runtime, plugin-host)\n' "$manifest" >&2
  exit 1
fi
while IFS=$'\t' read -r package binary features; do
  printf 'building %s (%s, %s)…\n' "$binary" "$package" "$profile"
  if [[ -n "$features" ]]; then
    (cd runtimes/nemo-relay && cargo build --profile "$profile" -p "$package" --bin "$binary" --features "$features")
  else
    (cd runtimes/nemo-relay && cargo build --profile "$profile" -p "$package" --bin "$binary")
  fi
  install -m 0755 "runtimes/nemo-relay/target/$target_dir/$binary" "$out/bin/$binary"
done <<< "$builds"

printf 'assembling the schemas and the registry envelope…\n'
install -m 0644 schemas/capability-invocation-v1.json "$out/share/capability-invocation-v1.json"
go run ./cmd/registry-digest -envelope > "$out/share/capability-registry-envelope.json"
install -m 0644 "$manifest" "$out/manifests/nemo-transfer-manifest.json"

printf 'binding the components…\n'
go run ./cmd/nemo-component-manifest \
  -root "$out" \
  -transfer-manifest "$out/manifests/nemo-transfer-manifest.json" \
  -crabbox-version "$(cat VERSION)"

printf 'verifying the binding…\n'
go run ./cmd/nemo-component-manifest \
  -root "$out" \
  -transfer-manifest "$out/manifests/nemo-transfer-manifest.json" \
  -verify

printf 'distribution assembled at %s\n' "$out"
