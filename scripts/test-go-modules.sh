#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
found=0
modules_file="$(mktemp)"
cleanup() {
  rm -f "$modules_file"
}
trap cleanup EXIT

# The vendored NeMo Relay tree is pruned deliberately: its Go binding is a CGo
# module over the FFI library, which this repository does not build, and the
# tree's own toolchain (`just test-go` inside it) owns those tests. Discovery
# here covers this repository's own modules.
if ! find "$ROOT" \
  \( -path "$ROOT/.git" -o -path "*/node_modules" -o -path "*/dist" -o -path "*/dist-cloudflare" \
     -o -path "$ROOT/runtimes/nemo-relay" \) -prune \
  -o -type f -name go.mod -print0 >"$modules_file"; then
  printf 'failed to discover go.mod files under %s\n' "$ROOT" >&2
  exit 1
fi

while IFS= read -r -d '' modfile; do
  dir="$(dirname "$modfile")"
  rel="${dir#"$ROOT"/}"
  if [[ "$dir" == "$ROOT" ]]; then
    rel="."
  fi
  found=1
  printf '+ (cd %q && go test -timeout=15m ./...)\n' "$rel"
  (cd "$dir" && go test -timeout=15m ./...)
done <"$modules_file"

if [[ "$found" -eq 0 ]]; then
  printf 'no go.mod files found under %s\n' "$ROOT" >&2
  exit 1
fi
