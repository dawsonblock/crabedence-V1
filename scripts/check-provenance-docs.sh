#!/usr/bin/env bash
# The documentation-drift gate.
#
# Documentation that restates provenance statistics is evidence only when it
# cannot drift: this check reads the transfer manifest — the single source of
# truth — and fails if a dependent document names a different identity. The
# in-tree provenance record's generated blocks are covered by
# nemo-runtime-digest itself; this gate covers the hand-edited documents one
# level up that restate the numbers (PROVENANCE.md, README.md, and
# FINAL_QUALIFICATION_REPORT.md of the NEMO-CONTROL workspace). A standalone
# checkout that does not carry those outer documents skips them — the gate
# binds what exists.
#
# The delta has two count layers and a document may state either:
# declared entries (the manifest's delta object, where a directory
# prefix covers a subtree) and expanded counts (what the verifier
# prints, the prefixes resolved against the real trees). Both are
# computed here — never trusted from a document — and the expansion
# uses the same canonical enumeration the transfer verifier uses,
# imported so this gate cannot drift from the definition it enforces.
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
version="$(field 'print(m.get("runtime_version") or "")')"
source_sha="$(field 'print(m["source"]["sha256"])')"
source_files="$(field 'print(m["source"]["file_count"])')"
source_links="$(field 'print(m["source"].get("symlink_count") or 0)')"

# Delta statistics: declared entry counts from the manifest, expanded
# counts against the real trees. With the frozen baseline present the
# expansion is the verifier's own diff; without it, declared prefixes
# resolve over the runtime's canonical enumeration (exact whenever a
# prefix covers a pure addition — the verified-declaration invariant).
counts="$(python3 - <<'PY'
import importlib.util, json, os

spec = importlib.util.spec_from_file_location(
    "verify_nemo_transfer",
    os.path.join("scripts", "verify-nemo-transfer.py"),
)
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)

m = json.load(open("runtimes/nemo-transfer-manifest.json"))
d = m.get("delta") or {}
policy = v.read_policy(m["policy"]["path"])

out = {
    "mod": len(d.get("modified_files") or []),
    "declared_added": len(d.get("added_files") or []),
    "removed": len(d.get("removed_files") or []),
    "added_links": len(d.get("added_symlinks") or []),
    "removed_links": len(d.get("removed_symlinks") or []),
    "retargeted": len(d.get("retargeted_symlinks") or []),
    "retyped": len(d.get("retyped_paths") or []),
    "mode_changes": len(d.get("mode_changes") or []),
}

source = (m.get("source") or {}).get("path")
if source and os.path.isdir(source):
    out["added"] = len(v.diff_trees_v2(source, m["tree"], policy)["added_files"])
else:
    vend = {e[0].removeprefix("./") for e in v.canonical_entries(m["tree"], policy)}
    covered = set()
    for p in d.get("added_files") or []:
        if p.endswith("/"):
            covered.update(x for x in vend if x.startswith(p))
        elif p in vend:
            covered.add(p)
    out["added"] = len(covered)

print(" ".join(f"{k}={n}" for k, n in out.items()))
PY
)"
eval "$counts"

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
check ../PROVENANCE.md "$version" "runtime version"
check ../PROVENANCE.md \
  "$mod modified / $declared_added declared added entries covering $added files / $removed removed" \
  "declared delta summary"
if [[ "$added_links" == 0 && "$removed_links" == 0 && "$retargeted" == 0 \
   && "$retyped" == 0 && "$mode_changes" == 0 ]]; then
  check ../PROVENANCE.md "0 symlink deltas / 0 retyped / 0 mode changes" "empty delta classes"
fi

# README.md restates the expanded delta summary.
check ../README.md "$mod modified / $added added / $removed removed files" "delta summary"

# FINAL_QUALIFICATION_REPORT.md names the bytes its verdict binds: the
# report is current-state evidence, so a tree that moved past the
# identity it qualified fails this gate until the report is
# regenerated — a stale QUALIFIED verdict can never ride forward.
check ../FINAL_QUALIFICATION_REPORT.md "$shipped" "qualified runtime digest"
check ../FINAL_QUALIFICATION_REPORT.md "$files files, $links symlinks" "qualified runtime counts"
check ../FINAL_QUALIFICATION_REPORT.md "$source_sha" "qualified source digest"
check ../FINAL_QUALIFICATION_REPORT.md "$version" "qualified runtime version"
check ../FINAL_QUALIFICATION_REPORT.md "$mod modified" "qualified delta modification count"
check ../FINAL_QUALIFICATION_REPORT.md "$added added" "qualified delta expansion count"
check ../FINAL_QUALIFICATION_REPORT.md "$removed removed" "qualified delta removal count"

[[ "$fail" == 0 ]] && echo "ok: provenance statistics in dependent docs match $manifest"
exit "$fail"
