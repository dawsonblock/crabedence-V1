#!/usr/bin/env bash
# The documentation-drift gate.
#
# Documentation that restates provenance statistics is evidence only when it
# cannot drift: this check reads the transfer manifest — the single source of
# truth — and fails if a dependent document names a different identity. The
# in-tree provenance record's generated blocks are covered by
# nemo-runtime-digest itself; this gate covers the hand-edited documents one
# level up that restate the numbers (PROVENANCE.md, README.md of the
# NEMO-CONTROL workspace). A standalone checkout that does not carry those
# outer documents skips them — the gate binds what exists.
set -euo pipefail

cd "$(dirname "$0")/.."
manifest="runtimes/nemo-transfer-manifest.json"
[[ -f "$manifest" ]] || { echo "check-provenance-docs: no manifest at $manifest" >&2; exit 1; }

field() { python3 -c "
import json, sys
m = json.load(open('$manifest'))
$1" ; }

shipped="$(field 'print(m["shipped_tree_sha256"])')"
files="$(field 'print(m["file_count"])')"
links="$(field 'print(m.get("symlink_count") or 0)')"
source_sha="$(field 'print(m["source"]["sha256"])')"
source_files="$(field 'print(m["source"]["file_count"])')"
source_links="$(field 'print(m["source"].get("symlink_count") or 0)')"
delta="$(field '
d = m.get("delta") or {}
print(" ".join(f"{k}={len(v)}" for k, v in sorted(d.items())))')"

fail=0
check() { # doc, needle, label
  local doc="$1" needle="$2" label="$3"
  [[ -f "$doc" ]] || { printf 'note: %s absent — skipped\n' "$doc"; return; }
  if ! grep -qF "$needle" "$doc"; then
    printf 'check-provenance-docs: %s is stale — missing %s (%s)\n' "$doc" "$label" "$needle" >&2
    fail=1
  fi
}

# PROVENANCE.md restates the full identity table; every bound value must match.
check ../PROVENANCE.md "$shipped" "shipped digest"
check ../PROVENANCE.md "$source_sha" "source digest"
check ../PROVENANCE.md "$files files, $links symlinks" "shipped counts"
check ../PROVENANCE.md "$source_files files, $source_links symlinks" "source counts"
check ../PROVENANCE.md "$(field 'print(m["policy"]["sha256"])')" "policy digest"

# README.md restates the delta summary.
mod="$(field 'print(len((m.get("delta") or {}).get("modified_files") or m.get("local_modifications") or []))')"
removed="$(field 'print(len((m.get("delta") or {}).get("removed_files") or m.get("removed_paths") or []))')"
added_actual="$(field '
# The delta summary counts actual additions; directory prefixes cover subtrees.
import json
d = (m.get("delta") or {})
print(len(d.get("added_files") or m.get("added_paths") or []))')"
check ../README.md "$mod modified" "delta modification count"

[[ "$fail" == 0 ]] && echo "ok: provenance statistics in dependent docs match $manifest"
exit "$fail"
