#!/usr/bin/env bash
# Generate the canonical release source manifest for qualification.
#
# The manifest is the release source INVENTORY: it is derived from the Git
# HEAD tree — the same tree `git archive HEAD` packages — so it can never
# diverge from the released archive. Records carry the Git mode, the
# object type, the SHA-256 of the exact bytes, and the path:
#
#   100644 file    <sha256>  README.md
#   100755 file    <sha256>  scripts/verify-release-artifact.sh
#   120000 symlink <sha256>  CLAUDE.md
#
# A symlink's digest is SHA-256 of its TARGET BYTES (the blob Git stores),
# never the contents of the file it points to. Verification therefore
# checks the link itself rather than dereferencing it.
#
# Deriving from Git rather than `find` removes the hand-maintained
# exclusion lists that had to be kept in sync with `git archive` by hand.
# Those lists silently admitted ignored files (a manifest that could never
# match the archive) and would have silently dropped any tracked file
# living beneath an excluded directory name.
#
# Output is sorted by path with LC_ALL=C for determinism.
#
# Usage: ./scripts/generate-source-manifest.sh [output-file] [source-dir]
#   output-file: default: dist/release-evidence/source-tree-sha256.txt
#   source-dir:  default: repository root
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT="${1:-$REPO_ROOT/dist/release-evidence/source-tree-sha256.txt}"
SOURCE_DIR="${2:-$REPO_ROOT}"

if [ ! -d "$SOURCE_DIR" ]; then
  echo "ERROR: source directory not found: $SOURCE_DIR" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"
cd "$SOURCE_DIR"

if ! git -C "$SOURCE_DIR" rev-parse --verify HEAD >/dev/null 2>&1; then
  echo "ERROR: the source manifest requires a Git work tree with a HEAD commit" >&2
  exit 1
fi

# Skip the output file itself if it lands inside the tracked tree.
OUTPUT_RELPATH=""
if [ "$(cd "$(dirname "$OUTPUT")" && pwd)" = "$(pwd -P)" ]; then
  OUTPUT_RELPATH="$(basename "$OUTPUT")"
fi

# git ls-tree -z emits "<mode> <type> <object>\t<path>\0" per entry, so
# paths containing spaces or non-ASCII characters survive intact.
git -C "$SOURCE_DIR" ls-tree -r -z HEAD | while IFS= read -r -d '' record; do
  meta="${record%%$'\t'*}"
  path="${record#*$'\t'}"
  [ -z "$path" ] && continue
  if [ -n "$OUTPUT_RELPATH" ] && [ "$path" = "$OUTPUT_RELPATH" ]; then
    continue
  fi

  mode="${meta%% *}"
  rest="${meta#* }"
  type="${rest%% *}"

  case "$mode" in
    100644|100755)
      if [ "$type" != "blob" ]; then
        echo "ERROR: $path has mode $mode but object type $type" >&2
        exit 1
      fi
      if [ ! -f "$path" ] || [ -L "$path" ]; then
        echo "ERROR: $path is a regular file in Git but not in the work tree" >&2
        exit 1
      fi
      kind="file"
      sha="$(shasum -a 256 "$path" | cut -d ' ' -f 1)"
      ;;
    120000)
      if [ "$type" != "blob" ]; then
        echo "ERROR: $path has mode $mode but object type $type" >&2
        exit 1
      fi
      if [ ! -L "$path" ]; then
        echo "ERROR: $path is a symlink in Git but not in the work tree" >&2
        exit 1
      fi
      kind="symlink"
      # Digest the target BYTES exactly as Git stores them — no added
      # newline, and never the contents of the linked file.
      sha="$(printf '%s' "$(readlink "$path")" | shasum -a 256 | cut -d ' ' -f 1)"
      ;;
    *)
      echo "ERROR: unsupported Git mode $mode for $path" >&2
      exit 1
      ;;
  esac

  printf '%s %s %s  %s\n' "$mode" "$kind" "$sha" "$path"
done | LC_ALL=C sort -k4 > "$OUTPUT"

COUNT="$(wc -l < "$OUTPUT" | tr -d ' ')"
echo "Source manifest generated: $OUTPUT ($COUNT entries)" >&2
