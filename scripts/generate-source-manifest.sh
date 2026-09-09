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

# Directories to exclude (match anywhere in path)
EXCLUDE_DIRS="node_modules\|/\.git/\|/dist/\|/coverage/\|/tmp/\|/\.build/\|/bin/\|__pycache__"

# Files to exclude by basename
EXCLUDE_FILES=".DS_Store"

# File patterns to exclude
EXCLUDE_PATTERNS="\.pyc$\|\.pyo$\|\.swp$\|\.swo$\|~$\|^\.#"

# ─── Generate manifest ────────────────────────────────────────────────
cd "$SOURCE_DIR"

# Enumerate all files, filter exclusions, compute SHA-256.
# Use find + grep for exclusions, then shasum each file.
# Sort with LC_ALL=C for determinism.
find . -type f | while IFS= read -r filepath; do
  relpath="${filepath#./}"

  # Skip excluded directories (anywhere in path)
  echo "$relpath" | grep -q "$EXCLUDE_DIRS" && continue

  # Skip release-evidence/ (only schemas/README.md are tracked)
  case "$relpath" in
    release-evidence/schemas/*|release-evidence/README.md) ;;
    release-evidence/*) continue ;;
  esac

  # Skip excluded files by basename
  [ "$(basename "$filepath")" = "$EXCLUDE_FILES" ] && continue

  # Skip excluded patterns
  echo "$relpath" | grep -q "\($EXCLUDE_PATTERNS\)" && continue

  # Compute SHA-256
  sha="$(shasum -a 256 "$filepath" | cut -d ' ' -f 1)"
  echo "${sha}  ${relpath}"
done | LC_ALL=C sort > "$OUTPUT"

# Count
COUNT="$(wc -l < "$OUTPUT" | tr -d ' ')"
echo "Source manifest generated: $OUTPUT ($COUNT files)" >&2
