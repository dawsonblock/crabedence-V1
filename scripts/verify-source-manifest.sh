#!/usr/bin/env bash
# Verify the release source manifest against the actual source tree.
# Bidirectional:
#   1. Every manifest record must exist and match (manifest -> source):
#      the Git mode/type is checked, and the digest is recomputed from the
#      exact bytes the record covers — for a symlink, its TARGET BYTES,
#      never the contents of the file it points to.
#   2. Every packaged source entry must appear in the manifest
#      (source -> manifest).
#
# The packaged source set is the Git HEAD tree — the same tree
# `git archive HEAD` produces — so there are no hand-maintained exclusion
# lists that could diverge from the archive. When the root under test is
# not a work-tree toplevel (the clean room extracts an archive with no
# .git) the walk falls back to `find`, including symlinks.
#
# Returns 0 if all records match and no unexpected entries exist, 1 otherwise.
# Usage: ./scripts/verify-source-manifest.sh [manifest] [source-root]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="${1:-$REPO_ROOT/release-evidence/source-tree-sha256.txt}"
ROOT="${2:-$REPO_ROOT}"

if [ ! -f "$MANIFEST" ]; then
  echo "ERROR: source manifest not found: $MANIFEST" >&2
  exit 1
fi

missing=0
mismatched=0
checked=0
unexpected=0
malformed=0

# Build a set of manifest paths for the inverse check
manifest_paths_file="$(mktemp)"
trap 'rm -f "$manifest_paths_file"' EXIT

# 1. Manifest -> source: verify each record's type, mode, and digest.
while read -r mode type sha path; do
  if [ -z "$mode" ] || [ -z "$path" ]; then
    echo "MALFORMED: ${mode:-<empty>} ${type:-} ${sha:-} ${path:-}"
    malformed=$((malformed + 1))
    continue
  fi
  checked=$((checked + 1))
  echo "$path" >> "$manifest_paths_file"

  target="$ROOT/$path"
  if [ ! -e "$target" ] && [ ! -L "$target" ]; then
    echo "MISSING: $path"
    missing=$((missing + 1))
    continue
  fi

  case "$mode" in
    120000)
      if [ ! -L "$target" ]; then
        echo "TYPE MISMATCH: $path (expected symlink, found $( [ -d "$target" ] && echo directory || echo regular))"
        mismatched=$((mismatched + 1))
        continue
      fi
      actual="$(printf '%s' "$(readlink "$target")" | shasum -a 256 | cut -d ' ' -f 1)"
      ;;
    100644|100755)
      if [ -L "$target" ] || [ ! -f "$target" ]; then
        echo "TYPE MISMATCH: $path (expected regular file)"
        mismatched=$((mismatched + 1))
        continue
      fi
      if [ "$mode" = "100755" ] && [ ! -x "$target" ]; then
        echo "MODE MISMATCH: $path (expected executable)"
        mismatched=$((mismatched + 1))
        continue
      fi
      if [ "$mode" = "100644" ] && [ -x "$target" ]; then
        echo "MODE MISMATCH: $path (unexpected executable bit)"
        mismatched=$((mismatched + 1))
        continue
      fi
      actual="$(shasum -a 256 "$target" | cut -d ' ' -f 1)"
      ;;
    *)
      echo "UNKNOWN MODE: $path (mode=$mode)"
      mismatched=$((mismatched + 1))
      continue
      ;;
  esac

  if [ "$actual" != "$sha" ]; then
    echo "MISMATCH: $path (expected=$sha actual=$actual)"
    mismatched=$((mismatched + 1))
  fi
done < "$MANIFEST"

# 2. Source -> manifest: detect packaged entries not in the manifest.
source_paths_file="$(mktemp)"
trap 'rm -f "$manifest_paths_file" "$source_paths_file"' EXIT

if [ "$(git -C "$ROOT" rev-parse --show-toplevel 2>/dev/null || true)" = "$(cd "$ROOT" && pwd -P)" ]; then
  # The packaged set is the Git HEAD tree, exactly as the generator derived it.
  git -C "$ROOT" ls-tree -r -z HEAD | while IFS= read -r -d '' record; do
    printf '%s\n' "${record#*$'\t'}"
  done | LC_ALL=C sort > "$source_paths_file"
else
  (
    cd "$ROOT"
    find . \( -type f -o -type l \) | sed 's|^\./||' | LC_ALL=C sort
  ) > "$source_paths_file"
fi

while IFS= read -r src_file; do
  [ -z "$src_file" ] && continue
  if ! grep -qxF "$src_file" "$manifest_paths_file"; then
    echo "UNEXPECTED: $src_file (in source tree but not in manifest)"
    unexpected=$((unexpected + 1))
  fi
done < "$source_paths_file"

echo ""
echo "files_manifested=$checked"
echo "files_actual=$(wc -l < "$source_paths_file" | tr -d ' ')"
echo "missing=$missing"
echo "mismatched=$mismatched"
echo "unexpected=$unexpected"
echo "malformed=$malformed"

if [ "$missing" -eq 0 ] && [ "$mismatched" -eq 0 ] && [ "$unexpected" -eq 0 ] && [ "$malformed" -eq 0 ]; then
  echo "status=PASS"
  exit 0
else
  echo "status=FAIL"
  exit 1
fi
