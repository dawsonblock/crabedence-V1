#!/usr/bin/env bash
# Verify the release toolchain is EXACTLY the declared one.
#
# The release must execute on the precise toolchain go.mod declares — not
# merely some Go 1.26.x — and GOTOOLCHAIN=local must prevent the go command
# from silently substituting a different toolchain mid-qualification.
#
# Establishes, failing closed on any mismatch:
#   declared toolchain (go.mod directive) == installed == runtime GOVERSION
#   GOTOOLCHAIN == local
#
# Usage: ./scripts/verify-go-toolchain.sh [repo-root]
set -euo pipefail

REPO_ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
GOMOD="$REPO_ROOT/go.mod"

if [ ! -f "$GOMOD" ]; then
  echo "ERROR: go.mod not found at $GOMOD" >&2
  exit 1
fi

# The `toolchain` directive is the single declaration of the exact release
# toolchain. A `go` line is a language version floor, not a toolchain pin.
declared="$(sed -n 's/^toolchain \(go[0-9][0-9.]*\).*/\1/p' "$GOMOD")"
declared="${declared%%$'\n'*}"
echo "go_mod=$GOMOD"
echo "declared_toolchain=${declared:-<none>}"
if ! [[ "$declared" =~ ^go[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "ERROR: go.mod does not declare an exact toolchain (want 'toolchain goX.Y.Z')" >&2
  exit 1
fi

go_version_out="$(go version 2>/dev/null || true)"
runtime_gov="$(go env GOVERSION 2>/dev/null || true)"
gotoolchain="$(go env GOTOOLCHAIN 2>/dev/null || true)"

# The full toolchain evidence a qualification record ships.
echo "go_version=${go_version_out:-unavailable}"
echo "goversion=${runtime_gov:-unavailable}"
echo "gotoolchain=${gotoolchain:-unavailable}"

if [ -z "$runtime_gov" ]; then
  echo "ERROR: 'go env GOVERSION' produced no version" >&2
  exit 1
fi
if [ "$runtime_gov" != "$declared" ]; then
  echo "ERROR: installed toolchain GOVERSION=$runtime_gov != declared $declared" >&2
  exit 1
fi
# 'go version' prints "go version goX.Y.Z os/arch" — the third word is the
# runtime's own report; it must agree with GOVERSION, not just be nearby.
read -r _ _ version_word _ <<< "$go_version_out"
if [ "$version_word" != "$declared" ]; then
  echo "ERROR: 'go version' reports ${version_word:-<unparseable>} != declared $declared" >&2
  exit 1
fi
if [ "$gotoolchain" != "local" ]; then
  echo "ERROR: GOTOOLCHAIN=${gotoolchain:-<unset>} (want local) — the go command could silently substitute a different toolchain" >&2
  exit 1
fi

echo "toolchain=$declared verified (declared = installed = runtime, GOTOOLCHAIN=local)"
