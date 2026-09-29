#!/usr/bin/env bash
# compare-source-trees.sh <tree-a> <tree-b>
#
# Requires that two extracted source trees carry the SAME normalized
# inventory: every regular file (by relative path, executable mode, and
# content digest) and every symlink (by relative path and link-target
# digest). This catches format-specific packaging drift between the tar
# and ZIP release archives — mode loss, symlink flattening, dropped or
# extra entries — that a digest comparison of the container bytes cannot
# see.
#
# The comparison is fully materialized on both sides before diffing: no
# producer is piped into an early-terminating consumer, so a large diff
# cannot be truncated into a pass.
#
# Exit 0: inventories identical. Exit 1: usage error or mismatch.

set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <tree-a> <tree-b>" >&2
  exit 1
fi

tree_a="$1"
tree_b="$2"

for tree in "$tree_a" "$tree_b"; do
  if [ ! -d "$tree" ]; then
    echo "ERROR: source tree $tree does not exist" >&2
    exit 1
  fi
done

normalize() {
  local root="$1"
  find "$root" -mindepth 1 \( -type f -o -type l \) -print0 \
    | while IFS= read -r -d '' path; do
        local rel="${path#"$root"/}"
        if [ -L "$path" ]; then
          printf 'symlink 120000 %s %s\n' \
            "$(printf '%s' "$(readlink "$path")" | shasum -a 256 | cut -d ' ' -f1)" "$rel"
        else
          local mode=100644
          [ -x "$path" ] && mode=100755
          printf 'file %s %s %s\n' "$mode" "$(shasum -a 256 "$path" | cut -d ' ' -f1)" "$rel"
        fi
      done | LC_ALL=C sort
}

norm_a="$(mktemp)"
norm_b="$(mktemp)"
trap 'rm -f "$norm_a" "$norm_b"' EXIT

normalize "$tree_a" > "$norm_a"
normalize "$tree_b" > "$norm_b"

if ! diff -u "$norm_a" "$norm_b"; then
  echo "ERROR: source inventories differ" >&2
  exit 1
fi

echo "source trees carry identical inventories ($(wc -l < "$norm_a" | tr -d ' ') entries)"
