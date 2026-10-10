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
# shellcheck source=lib/release-paths.sh
. "$REPO_ROOT/scripts/lib/release-paths.sh"
MANIFEST="${1:-$REPO_ROOT/release-evidence/source-tree-sha256.txt}"
ROOT="${2:-$REPO_ROOT}"

if [ ! -f "$MANIFEST" ]; then
  echo "ERROR: source manifest not found: $MANIFEST" >&2
  exit 1
fi

# When the manifest file itself lives inside the tree under test — the
# packager embeds it at release-evidence/source-tree-sha256.txt so the
# archive is self-verifying — it is exempt from the inverse check: a
# manifest cannot list itself. The exemption covers exactly the passed
# manifest path, nothing else.
MANIFEST_ABS="$(cd "$(dirname "$MANIFEST")" && pwd -P)/$(basename "$MANIFEST")"
ROOT_ABS="$(cd "$ROOT" && pwd -P)"
MANIFEST_REL=""
case "$MANIFEST_ABS" in
  "$ROOT_ABS"/*) MANIFEST_REL="${MANIFEST_ABS#$ROOT_ABS/}" ;;
esac
# An extracted archive also carries the embedded manifest copy at
# release-evidence/source-tree-sha256.txt. When the passed manifest lives
# outside the tree — the published qualification manifest the clean-room
# lane verifies against — the embedded copy gets the same exemption only
# while it is byte-identical to it. A self-identity that differs from the
# record under verification is a defect, not an extra to tolerate.
if [ -z "$MANIFEST_REL" ] && [ -f "$ROOT/release-evidence/source-tree-sha256.txt" ]; then
  if cmp -s "$ROOT/release-evidence/source-tree-sha256.txt" "$MANIFEST"; then
    MANIFEST_REL="release-evidence/source-tree-sha256.txt"
  fi
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
  if ! release_path_check "$path"; then
    printf 'POLICY: %s is not a release-path-legal name\n' "$path"
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

# All three enumerations emit NUL records and validate each name against
# the release-path policy: a tree holding a name the toolchain cannot
# carry byte-for-byte fails here rather than passing a mangled record.
collect_source_paths() {
  local f
  while IFS= read -r -d '' f; do
    f="${f#./}"
    if ! release_path_check "$f"; then
      printf 'POLICY: %s is not a release-path-legal name\n' "$f" >&2
      return 1
    fi
    printf '%s\n' "$f"
  done | LC_ALL=C sort
}

GIT_TOP="$(git -C "$ROOT" rev-parse --show-toplevel 2>/dev/null || true)"
if [ "$GIT_TOP" = "$(cd "$ROOT" && pwd -P)" ]; then
  # The packaged set is the Git HEAD tree, exactly as the generator derived it.
  git -C "$ROOT" ls-tree -r -z HEAD | while IFS= read -r -d '' record; do
    printf '%s\0' "${record#*$'\t'}"
  done | collect_source_paths > "$source_paths_file"
elif [ -n "$GIT_TOP" ]; then
  # ROOT sits inside a repository (nested checkout). The manifest derives
  # from tracked source, so enumerate the tracked set under ROOT through
  # the index rather than walking generated or untracked content; the
  # caller's clean-tree gate keeps index == HEAD.
  (
    cd "$ROOT"
    git ls-files -z -- .
  ) | collect_source_paths > "$source_paths_file"
else
  (
    cd "$ROOT"
    find . \( -type f -o -type l \) -print0
  ) | collect_source_paths > "$source_paths_file"
fi

while IFS= read -r src_file; do
  [ -z "$src_file" ] && continue
  if [ -n "$MANIFEST_REL" ] && [ "$src_file" = "$MANIFEST_REL" ]; then
    continue
  fi
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
