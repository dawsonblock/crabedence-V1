#!/usr/bin/env bash
# Verify the source-tree SHA-256 manifest against actual file contents.
# Bidirectional check:
#   1. Every manifest entry must exist and match (manifest → source)
#   2. Every source file must appear in the manifest (source → manifest)
# Returns 0 if all files match and no unexpected files exist, 1 otherwise.
# Usage: ./scripts/verify-source-manifest.sh [manifest] [repo-root]
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

# Build a set of manifest paths for the inverse check
manifest_paths_file="$(mktemp)"
trap 'rm -f "$manifest_paths_file"' EXIT

# 1. Manifest → source: verify each manifest entry exists and matches
while IFS= read -r line; do
  [ -z "$line" ] && continue
  expected_sha="$(echo "$line" | cut -d ' ' -f 1)"
  file="$(echo "$line" | cut -d ' ' -f 3-)"
  checked=$((checked + 1))
  echo "$file" >> "$manifest_paths_file"
  if [ ! -f "$ROOT/$file" ]; then
    echo "MISSING: $file"
    missing=$((missing + 1))
    continue
  fi
  actual_sha="$(shasum -a 256 "$ROOT/$file" | cut -d ' ' -f 1)"
  if [ "$actual_sha" != "$expected_sha" ]; then
    echo "MISMATCH: $file (expected=$expected_sha actual=$actual_sha)"
    mismatched=$((mismatched + 1))
  fi
done < "$MANIFEST"

# 2. Source → manifest: detect unexpected files not in the manifest
# Walk the actual source tree and compare against manifest paths.
# Excludes match generate-source-manifest.sh exclusions.
source_paths_file="$(mktemp)"
trap 'rm -f "$manifest_paths_file" "$source_paths_file"' EXIT

(
  cd "$ROOT"
  find . -type f \
    ! -path './.git/*' \
    ! -path './dist/*' \
    ! -path './bin/*' \
    ! -path './node_modules/*' \
    ! -path './worker/node_modules/*' \
    ! -path './worker/dist/*' \
    ! -path './nemo/node_modules/*' \
    ! -path './release-evidence/*' \
    ! -path './.github/release-allowed-signers' \
    ! -path './source-tree-sha256.txt' \
    ! -path './source-tree-git-blobs.txt' \
    | sed 's|^\./||' \
    | sort \
) > "$source_paths_file"

# Find files in source but not in manifest
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

if [ "$missing" -eq 0 ] && [ "$mismatched" -eq 0 ] && [ "$unexpected" -eq 0 ]; then
  echo "status=PASS"
  exit 0
else
  echo "status=FAIL"
  exit 1
fi
