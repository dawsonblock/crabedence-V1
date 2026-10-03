#!/usr/bin/env bash
# Produce and qualify a distributable source archive.
#
# The release-integrity rule this enforces: the bytes that get
# distributed are the bytes that passed qualification — and
# qualification digests are computed over the CHECKOUT, not the raw
# Git objects. `git archive` emits blob bytes, which differ wherever a
# text/eol attribute smudges the checkout (this tree has one such file:
# runtimes/nemo-relay's mock-codex.cmd, i/lf w/crlf). So the archive is
# built from the HEAD path list but reads WORKTREE bytes, matching the
# provenance model exactly.
#
# The archive is then extracted into a clean directory and the
# verifiers run against the EXTRACTED bytes:
#
#   1. scripts/verify-source-manifest.sh — the source manifest
#      recomputes every record (file bytes, symlink target bytes,
#      modes) against the extraction. A dropped symlink or mode bit
#      fails here.
#   2. scripts/verify-nemo-transfer.py — the transfer manifest's
#      shipped-tree identity (file + symlink inventory digest). When
#      the frozen baseline is present beside the repository it is
#      linked beside the extraction and --require-source runs; when it
#      is not, shipping-tree mode still catches a missing symlink in
#      the runtime tree.
#
# Usage: package-source-archive.sh [--format zip|tar.gz] [-o output]
#                                  [--prefix name] [--allow-dirty]
#   --format       archive format; default tar.gz
#   -o, --output   output path; default dist/source-<describe>.<ext>
#   --prefix       top-level directory name inside the archive;
#                  default nemo-control-<describe>
#   --allow-dirty  package a modified tracked worktree (for gate
#                  development); release use should be clean.
#   Exit 0 only when the extracted bytes verify.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

FORMAT="tar.gz"
OUTPUT=""
PREFIX=""
ALLOW_DIRTY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --format) FORMAT="$2"; shift 2 ;;
    --format=*) FORMAT="${1#*=}"; shift ;;
    -o|--output) OUTPUT="$2"; shift 2 ;;
    --output=*) OUTPUT="${1#*=}"; shift ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --prefix=*) PREFIX="${1#*=}"; shift ;;
    --allow-dirty) ALLOW_DIRTY=1; shift ;;
    *) echo "package-source-archive: unknown argument $1" >&2; exit 2 ;;
  esac
done
case "$FORMAT" in
  zip|tar.gz) ;;
  *) echo "package-source-archive: unknown format $FORMAT (want zip or tar.gz)" >&2; exit 2 ;;
esac

# Tracked-file modifications change the packaged bytes without changing
# the path list — refuse by default so a release cannot quietly ship a
# tree that differs from HEAD. Untracked files are never packaged.
if [ -n "$(git diff --name-only HEAD)" ] && [ "$ALLOW_DIRTY" -eq 0 ]; then
  echo "package-source-archive: tracked files differ from HEAD — commit first (or pass --allow-dirty for gate development)" >&2
  git diff --name-only HEAD | sed 's/^/  modified: /' >&2
  exit 1
fi

prefix="${PREFIX:-nemo-control-$(git describe --tags --always 2>/dev/null || git rev-parse --short HEAD)}"
# The archive root is a single directory name — a slash or traversal
# would silently relocate packaged entries outside the extraction dir.
case "$prefix" in
  ""|.|..|*/*|*\\*) printf "package-source-archive: --prefix must be a single directory name, got '%s'\n" "$prefix" >&2; exit 2 ;;
esac
OUTPUT="${OUTPUT:-dist/source-${prefix}.${FORMAT}}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The packaged path set is the HEAD tree — nothing else. The
# provenance invariant this enforces:
#
#   provenance-covered ⇒ tracked ⇒ source-manifested ⇒ packaged
#
# The digest covers worktree paths the policy does not exclude —
# including files Git may ignore (the .claude/skills link was exactly
# that: provenance-covered but untracked, so every Git-derived packager
# dropped it, and the later union fix silently packaged bytes the
# release commit never represented). Unioning filesystem paths with
# the commit tree broke the chain in the other direction, so the rule
# is now one-directional: every provenance-covered object MUST be
# represented by the release commit, and packaging fails before an
# archive is created when even one is not. The uncovered path is
# reported, never silently added.
list="$work/files.txt"
git ls-tree -r --name-only HEAD | LC_ALL=C sort -u > "$list"
if [ -d runtimes/nemo-relay ] && [ -f runtimes/nemo-provenance-policy.json ]; then
  prov="$work/provenance.txt"
  go run ./cmd/nemo-runtime-digest -root runtimes/nemo-relay \
    -policy runtimes/nemo-provenance-policy.json -list \
    | sed 's#^#runtimes/nemo-relay/#' | LC_ALL=C sort -u > "$prov"
  untracked="$(comm -13 "$list" "$prov")"
  if [ -n "$untracked" ]; then
    printf '%s\n' "$untracked" \
      | sed 's/^/package-source-archive: provenance-covered path is not tracked by release commit: /' >&2
    exit 1
  fi
fi

stage="$work/stage"
mkdir -p "$stage/$prefix"
tar -cf - -T "$list" | tar -xf - -C "$stage/$prefix"

case "$FORMAT" in
  tar.gz) tar -czf "$work/archive.tar.gz" -C "$stage" "$prefix" ;;
  # -y keeps symlink entries instead of dereferencing them — a plain
  # `zip -r` silently stores the target's contents or drops the entry,
  # which is how the .claude/skills link went missing previously.
  zip)    (cd "$stage" && zip -qry "$work/archive.zip" "$prefix") ;;
esac

mkdir -p "$work/extract"
case "$FORMAT" in
  tar.gz) tar -xzf "$work/archive.tar.gz" -C "$work/extract" ;;
  zip)    unzip -q "$work/archive.zip" -d "$work/extract" ;;
esac

extracted="$work/extract/$prefix"
if [ ! -d "$extracted" ]; then
  echo "package-source-archive: extraction produced no $prefix tree" >&2
  exit 1
fi

# Gate 1 — the whole-tree manifest: every file's bytes, every symlink's
# target bytes, every mode, checked bidirectionally against the
# extraction (the verifier's find-walk also catches any extra entries
# the packager added).
manifest="$work/source-tree-sha256.txt"
"$ROOT/scripts/generate-source-manifest.sh" "$manifest" "$ROOT" >/dev/null
"$ROOT/scripts/verify-source-manifest.sh" "$manifest" "$extracted" >/dev/null
echo "ok: source manifest verified on extracted archive ($(wc -l < "$manifest" | tr -d ' ') entries)"

# Gate 2 — transfer provenance on the extracted tree. Run the Python
# verifier directly (it resolves the repo root from the manifest path)
# so no build toolchain is needed inside the extraction.
transfer_manifest="$extracted/runtimes/nemo-transfer-manifest.json"
if [ -f "$transfer_manifest" ]; then
  frozen="$(cd "$ROOT/.." && pwd)/NEMO-feat-native-plugin-isolation"
  if [ -d "$frozen" ]; then
    # The manifest declares the baseline beside the repo root — put it
    # beside the extraction so --require-source sees the same layout.
    ln -sfn "$frozen" "$work/extract/NEMO-feat-native-plugin-isolation"
    python3 "$extracted/scripts/verify-nemo-transfer.py" --require-source "$transfer_manifest"
  else
    python3 "$extracted/scripts/verify-nemo-transfer.py" "$transfer_manifest"
  fi
fi

mkdir -p "$(dirname "$OUTPUT")"
mv "$work/archive.$FORMAT" "$OUTPUT"
digest="$(shasum -a 256 "$OUTPUT" | cut -d ' ' -f 1)"
printf '%s  %s\n' "$digest" "$(basename "$OUTPUT")" > "$OUTPUT.sha256"
echo "ok: source archive verified after extraction: $OUTPUT (sha256 $digest)"
