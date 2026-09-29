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
# manifest references has to be present before packaging. Each line is
# "<64-hex><whitespace>[*]<path>": read splits the hash off and leaves the
# path (binary-mode "*" marker and "./" prefix stripped, internal
# whitespace preserved).
missing=0
while read -r _sha entry || [ -n "$_sha" ]; do
  entry="${entry#\*}"
  entry="${entry#./}"
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

# Coverage by name is not enough: a covered file modified after finalization
# must not package. Recompute every digest before going further.
if ! (cd "$EVIDENCE_DIR" && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1); then
  echo "ERROR: SHA256SUMS does not verify against the evidence tree (a covered file changed after finalization)" >&2
  (cd "$EVIDENCE_DIR" && shasum -a 256 -c SHA256SUMS 2>&1 | grep -v ': OK$') >&2 || true
  exit 1
fi

# The reverse direction too: every regular file being packaged must be listed
# in SHA256SUMS. A file added after finalization — or a non-regular member the
# checksum walk skipped — would otherwise ship inside the bundle without a
# checksum, breaking the "complete finalized set" guarantee. SHA256SUMS and
# evidence-manifest.json are legitimately uncovered (self-reference), and the
# checksum walk only covers regular files, so both are excluded here as well.
covered_list="$(mktemp)"
ondisk_list="$(mktemp)"
uncovered_list="$(mktemp)"
trap 'rm -f "$covered_list" "$ondisk_list" "$uncovered_list"' EXIT
while read -r _sha entry || [ -n "$_sha" ]; do
  entry="${entry#\*}"
  entry="${entry#./}"
  [ -n "$entry" ] && printf '%s\n' "$entry"
done < "$EVIDENCE_DIR/SHA256SUMS" | LC_ALL=C sort > "$covered_list"
(cd "$EVIDENCE_DIR" \
  && find . -type f ! -name SHA256SUMS ! -name evidence-manifest.json -print \
  | sed 's|^\./||' | LC_ALL=C sort) > "$ondisk_list"
# Materialize the set difference, then test the FILE. Piping comm into a
# short-circuiting consumer (grep -q, head) lets the consumer exit after the
# first line, comm dies with SIGPIPE, and pipefail inverts the branch — so a
# very large uncovered set could pass as "fully covered". No pipeline may
# carry this decision.
comm -23 "$ondisk_list" "$covered_list" > "$uncovered_list"
if [ -s "$uncovered_list" ]; then
  uncovered_count="$(wc -l < "$uncovered_list" | tr -d ' ')"
  echo "ERROR: $uncovered_count evidence file(s) not covered by SHA256SUMS would ship uncovered:" >&2
  # A bounded sample: the full list can be tens of thousands of paths.
  head -100 "$uncovered_list" >&2
  if [ "$uncovered_count" -gt 100 ]; then
    echo "  ... and $((uncovered_count - 100)) more" >&2
  fi
  exit 1
fi
# A non-regular member (symlink, fifo, ...) is never in SHA256SUMS and never
# reaches a consumer as a verified file — refuse to package one silently.
nonregular="$(cd "$EVIDENCE_DIR" && find . ! -type f ! -type d -print)"
if [ -n "$nonregular" ]; then
  echo "ERROR: evidence tree contains a non-regular file that SHA256SUMS cannot cover:" >&2
  printf '%s\n' "$nonregular" >&2
  exit 1
fi
rm -f "$covered_list" "$ondisk_list" "$uncovered_list"
trap - EXIT

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
  # BSD tar has no --sort/--mtime; feed it an explicitly sorted file list so
  # the archive is byte-deterministic on this platform too. --no-recursion is
  # required: the list already names every member, and without it bsdtar would
  # also recurse into the directory entries and emit duplicate members.
  # COPYFILE_DISABLE stops macOS from adding AppleDouble resource-fork members.
  bundle_list="$(mktemp)"
  (cd "$PARENT" && find "$NAME" -print | LC_ALL=C sort) > "$bundle_list"
  COPYFILE_DISABLE=1 tar --no-recursion -czf "$OUTPUT" -C "$PARENT" -T "$bundle_list"
  rm -f "$bundle_list"
fi

# The .sha256 sidecar uses the standard "<hash>  <basename>" format so a
# consumer can verify the published bundle with `shasum -c` — the same as the
# source tar/zip checksum files. Only the bare digest goes to stdout so the
# workflow captures it as the carried-through bundle identity.
bundle_sha="$(shasum -a 256 "$OUTPUT" | cut -d ' ' -f1)"
printf '%s  %s\n' "$bundle_sha" "$(basename "$OUTPUT")" > "$OUTPUT.sha256"
echo "Evidence bundle packaged: $OUTPUT ($(wc -c < "$OUTPUT" | tr -d ' ') bytes)" >&2
printf '%s\n' "$bundle_sha"
