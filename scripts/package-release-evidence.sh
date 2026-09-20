#!/usr/bin/env bash
# Package the FINALIZED evidence directory into one immutable archive.
#
# The public evidence bundle is the complete finalized tree, not a
# hand-maintained allow-list. SHA256SUMS covers every evidence file, so
# publishing a subset leaves the published set unable to verify itself —
# a consumer would hold a checksum manifest referencing files that were
# never uploaded.
#
# This runs AFTER finalization and never mutates the evidence directory:
# it only reads the finalized tree and writes the archive next to it.
#
# Usage: ./scripts/package-release-evidence.sh <evidence-dir> <output.tar.gz>
set -euo pipefail

EVIDENCE_DIR="${1:?usage: package-release-evidence.sh <evidence-dir> <output.tar.gz>}"
OUTPUT="${2:?usage: package-release-evidence.sh <evidence-dir> <output.tar.gz>}"

if [ ! -d "$EVIDENCE_DIR" ]; then
  echo "ERROR: evidence directory not found: $EVIDENCE_DIR" >&2
  exit 1
fi
if [ ! -f "$EVIDENCE_DIR/SHA256SUMS" ]; then
  echo "ERROR: evidence is not finalized: SHA256SUMS missing (run finalize-release-evidence.sh)" >&2
  exit 1
fi
if [ ! -f "$EVIDENCE_DIR/evidence-manifest.json" ]; then
  echo "ERROR: evidence is not finalized: evidence-manifest.json missing" >&2
  exit 1
fi

# The bundle must be the complete finalized set: every path the checksum
# manifest references has to be present before packaging.
missing=0
while IFS= read -r line; do
  [ -z "$line" ] && continue
  entry="${line#*  }"
  entry="${entry#\*}"; entry="${entry# }"
  case "$entry" in ./*) entry="${entry#./}" ;; esac
  [ -z "$entry" ] && continue
  if [ ! -e "$EVIDENCE_DIR/$entry" ]; then
    echo "ERROR: SHA256SUMS references a missing evidence file: $entry" >&2
    missing=$((missing + 1))
  fi
done < "$EVIDENCE_DIR/SHA256SUMS"
if [ "$missing" -ne 0 ]; then
  echo "ERROR: the evidence tree is incomplete ($missing missing); refusing to package" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"
PARENT="$(cd "$(dirname "$EVIDENCE_DIR")" && pwd)"
NAME="$(basename "$EVIDENCE_DIR")"

# Deterministic where the platform allows it, so the same finalized tree
# packages to the same bytes. The digest is computed after packaging and
# carried through the workflow either way.
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
  tar --sort=name --mtime='UTC 2020-01-01' --owner=0 --group=0 --numeric-owner \
    -czf "$OUTPUT" -C "$PARENT" "$NAME"
else
  COPYFILE_DISABLE=1 tar -czf "$OUTPUT" -C "$PARENT" "$NAME"
fi

shasum -a 256 "$OUTPUT" | cut -d ' ' -f1 > "$OUTPUT.sha256"
echo "Evidence bundle packaged: $OUTPUT ($(wc -c < "$OUTPUT" | tr -d ' ') bytes)" >&2
cat "$OUTPUT.sha256"
