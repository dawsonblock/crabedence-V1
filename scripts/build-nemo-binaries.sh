#!/usr/bin/env bash
# Build every binary the transfer manifest declares.
#
# The manifest is the single source of truth: it names each binary, the
# package that declares it, the source it is built from, and the features it
# requires. Verification runs first and fails closed — a declared binary whose
# source is absent, whose package does not declare it, or whose features do
# not exist is a release defect, and the digest tool refuses it. Then this
# script compiles them, so the declared set is a build, not a claim.
#
# The check exists because it was missing once: `nemo-plugin-host` and both
# ledger fixtures were declared by their packages but their sources were
# absent from the vendored copy, and nothing compiled them, so nothing failed.
#
# Usage: scripts/build-nemo-binaries.sh
set -euo pipefail

cd "$(dirname "$0")/.."
repo_root="$(pwd)"
manifest="$repo_root/runtimes/nemo-transfer-manifest.json"

go run ./cmd/nemo-runtime-digest -manifest "$manifest" >/dev/null

# Resolve the declared set before building anything: an empty or unreadable
# declaration must fail, never report a build that did not happen.
builds="$(jq -r '.binaries[] | [.package, .binary, (.features // [] | join(","))] | @tsv' "$manifest")"
if [[ -z "$builds" ]]; then
  printf 'FAIL: %s declares no binaries to build\n' "$manifest" >&2
  exit 1
fi

cd runtimes/nemo-relay
while IFS=$'\t' read -r package binary features; do
  if [[ -n "$features" ]]; then
    printf 'building %s (%s, features %s)…\n' "$binary" "$package" "$features"
    cargo build -p "$package" --bin "$binary" --features "$features"
  else
    printf 'building %s (%s)…\n' "$binary" "$package"
    cargo build -p "$package" --bin "$binary"
  fi
done <<< "$builds"

printf 'declared binaries built\n'
