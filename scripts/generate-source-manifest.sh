#!/usr/bin/env bash
# Generate a canonical source manifest for release qualification.
#
# Enumerates exactly the source files that will be packaged, computes
# SHA-256 for each, and writes a deterministic manifest.
#
# Output format (sorted with LC_ALL=C):
#   <sha256>  <relative/path>
#
# Exclusions are explicit and documented. Everything else is qualified.
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

# ─── Exclusions ────────────────────────────────────────────────────────
# These are NOT source files and must not appear in the manifest.
# Everything else in the source tree is qualified source.
#
# We use shell case matching (not regex) to avoid pattern-matching bugs.
# Paths are relative (e.g. ".git/objects/..." not "/.git/objects/...").

cd "$SOURCE_DIR"

# Enumerate all files, filter exclusions, compute SHA-256.
# Sort with LC_ALL=C for determinism.
find . -type f | while IFS= read -r filepath; do
  relpath="${filepath#./}"

  # Skip excluded top-level and nested directories using case matching.
  # This correctly handles both top-level (.git/...) and nested (foo/.git/...).
  case "$relpath" in
    .git/*|*/.git/*) continue ;;
    node_modules/*|*/node_modules/*) continue ;;
    dist/*|*/dist/*) continue ;;
    coverage/*|*/coverage/*) continue ;;
    tmp/*|*/tmp/*) continue ;;
    .build/*|*/.build/*) continue ;;
    bin/*|*/bin/*) continue ;;
    __pycache__/*|*/__pycache__/*) continue ;;
  esac

  # Skip release-evidence/ (only schemas/README.md are tracked, not generated evidence)
  case "$relpath" in
    release-evidence/schemas/*|release-evidence/README.md) ;;
    release-evidence/*) continue ;;
  esac

  # Skip excluded files by basename
  case "$(basename "$filepath")" in
    .DS_Store) continue ;;
  esac

  # Skip excluded file patterns
  case "$relpath" in
    *.pyc|*.pyo|*.swp|*.swo|*~|.#*) continue ;;
  esac

  # Skip the output file itself (if it's inside the source tree)
  OUTPUT_RELPATH=""
  if [ "$(cd "$(dirname "$OUTPUT")" && pwd)" = "$(pwd)" ]; then
    OUTPUT_RELPATH="$(basename "$OUTPUT")"
  fi
  if [ -n "$OUTPUT_RELPATH" ] && [ "$relpath" = "$OUTPUT_RELPATH" ]; then
    continue
  fi

  # Compute SHA-256
  sha="$(shasum -a 256 "$filepath" | cut -d ' ' -f 1)"
  echo "${sha}  ${relpath}"
done | LC_ALL=C sort > "$OUTPUT"

# Count
COUNT="$(wc -l < "$OUTPUT" | tr -d ' ')"
echo "Source manifest generated: $OUTPUT ($COUNT files)" >&2
