#!/usr/bin/env bash
# Verify the source-tree SHA-256 manifest against actual file contents.
# Returns 0 if all files match, 1 if any are missing or mismatched.
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

while IFS= read -r line; do
  [ -z "$line" ] && continue
  expected_sha="$(echo "$line" | cut -d ' ' -f 1)"
  file="$(echo "$line" | cut -d ' ' -f 3-)"
  checked=$((checked + 1))
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

echo ""
echo "files_checked=$checked"
echo "missing=$missing"
echo "mismatched=$mismatched"

if [ "$missing" -eq 0 ] && [ "$mismatched" -eq 0 ]; then
  echo "status=PASS"
  exit 0
else
  echo "status=FAIL"
  exit 1
fi
