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
#   1. scripts/verify-source-manifest.sh — the source manifest, which
#      the packager embeds at release-evidence/source-tree-sha256.txt
#      so the archive carries its own source identity, recomputes
#      every record (file bytes, symlink target bytes, modes) against
#      the extraction. A dropped symlink or mode bit fails here.
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
# shellcheck source=lib/release-paths.sh
. "$ROOT/scripts/lib/release-paths.sh"
cd "$ROOT"

FORMAT="tar.gz"
OUTPUT=""
PREFIX=""
PREFIX_SET=0
ALLOW_DIRTY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --format) FORMAT="$2"; shift 2 ;;
    --format=*) FORMAT="${1#*=}"; shift ;;
    -o|--output) OUTPUT="$2"; shift 2 ;;
    --output=*) OUTPUT="${1#*=}"; shift ;;
    --prefix) PREFIX="$2"; PREFIX_SET=1; shift 2 ;;
    --prefix=*) PREFIX="${1#*=}"; PREFIX_SET=1; shift ;;
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
if [ "$ALLOW_DIRTY" -eq 0 ] && ! git diff --quiet HEAD; then
  echo "package-source-archive: tracked files differ from HEAD — commit first (or pass --allow-dirty for gate development)" >&2
  git diff --name-only HEAD | sed 's/^/  modified: /' >&2
  exit 1
fi

if [ "$PREFIX_SET" -eq 1 ]; then
  prefix="$PREFIX"
else
  prefix="nemo-control-$(git describe --tags --always 2>/dev/null || git rev-parse --short HEAD)"
fi
# The archive root is a single directory name AND an operand to tar,
# zip, mkdir, and extraction commands. The grammar is deliberately
# restrictive — [A-Za-z0-9][A-Za-z0-9._+-]* — so the prefix can never
# become an option (-Itrue, --checkpoint=1), a traversal (../escape),
# a path (foo/bar, foo\bar), or a control/whitespace payload. Anything
# else fails here, before any archive command runs.
if ! [[ "$prefix" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ ]]; then
  printf "package-source-archive: --prefix must match [A-Za-z0-9][A-Za-z0-9._+-]*, got %q\n" "$prefix" >&2
  exit 2
fi
OUTPUT="${OUTPUT:-dist/source-${prefix}.${FORMAT}}"
# Absolute output paths keep the value an operand, never an option, no
# matter what name the caller chose.
case "$OUTPUT" in
  /*) ;;
  *) OUTPUT="$PWD/$OUTPUT" ;;
esac

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

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
# Path enumeration is NUL-delimited end to end: Git's -z forms carry
# filenames verbatim, so no path can be split, option-parsed, or dropped
# by a line-oriented step. The release-path policy (scripts/lib/
# release-paths.sh) additionally rejects names that could not survive
# the archive/manifest toolchain byte-for-byte — control characters,
# backslashes, "-"-leading and whitespace-edged components — before
# anything is packaged.
list="$work/files.bin"
git ls-tree -r -z HEAD | while IFS= read -r -d '' record; do
  p="${record#*$'\t'}"
  if ! release_path_check "$p"; then
    printf 'package-source-archive: release path policy violation: %q\n' "$p" >&2
    exit 1
  fi
  printf '%s\0' "$p"
done > "$list"
if [ -d runtimes/nemo-relay ] && [ -f runtimes/nemo-provenance-policy.json ]; then
  prov="$work/provenance.bin"
  # NEMO_RUNTIME_DIGEST_BIN may name a prebuilt digest binary (CI and
  # the packaging tests use it to run the real enumerator without a
  # `go run` rebuild); the default builds the tool from this tree.
  digest_list() {
    if [ -n "${NEMO_RUNTIME_DIGEST_BIN:-}" ]; then
      "$NEMO_RUNTIME_DIGEST_BIN" -root runtimes/nemo-relay \
        -policy runtimes/nemo-provenance-policy.json -list -z
    else
      go run ./cmd/nemo-runtime-digest -root runtimes/nemo-relay \
        -policy runtimes/nemo-provenance-policy.json -list -z
    fi
  }
  digest_list | while IFS= read -r -d '' p; do
    full="runtimes/nemo-relay/$p"
    if ! release_path_check "$full"; then
      printf 'package-source-archive: release path policy violation in provenance enumeration: %q\n' "$full" >&2
      exit 1
    fi
    printf '%s\0' "$full"
  done > "$prov"
  # NUL-exact set membership: every provenance-covered object must be
  # represented by the release commit. A miss is reported byte-verbatim
  # and fails packaging; it is never silently added to the archive.
  if ! python3 - "$list" "$prov" >&2 <<'PYEOF'
import sys
with open(sys.argv[1], "rb") as fh:
    tracked = set(fh.read().split(b"\0"))
missing = False
with open(sys.argv[2], "rb") as fh:
    for p in fh.read().split(b"\0"):
        if p and p not in tracked:
            sys.stderr.buffer.write(
                b"package-source-archive: provenance-covered path is not"
                b" tracked by release commit: " + p + b"\n")
            missing = True
sys.exit(1 if missing else 0)
PYEOF
  then
    exit 1
  fi
fi

# tar writes GNU-format members, never the default pax: libarchive pax
# writers normalize non-ASCII names (NFC -> NFD), which would make the
# archived path differ from the tracked name and fail manifest
# verification. The GNU format stores the name bytes verbatim and has no
# practical length limit. The flag is spelled differently per
# implementation — GNU tar calls it `gnu`, libarchive `gnutar` — and
# neither accepts the other's name, so the name follows the binary
# rather than being hard-coded.
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
  tar_format=gnu
else
  tar_format=gnutar
fi
stage="$work/stage"
mkdir -p -- "$stage/$prefix"
tar --format="$tar_format" --null -cf - -T "$list" | tar -xf - -C "$stage/$prefix"

# The generated source manifest ships inside the archive at
# release-evidence/source-tree-sha256.txt so the extracted artifact
# carries its own identity — a clean room can run the distribution
# suite from the archive alone. The manifest enumerates the tree it is
# embedded into and cannot list itself, so the verifier exempts exactly
# its own path from the inverse check.
manifest="$work/source-tree-sha256.txt"
"$ROOT/scripts/generate-source-manifest.sh" "$manifest" "$ROOT" >/dev/null
mkdir -p -- "$stage/$prefix/release-evidence"
cp "$manifest" "$stage/$prefix/release-evidence/source-tree-sha256.txt"

# Deterministic archives: the member list is sorted byte-wise and member
# mtimes are normalized before the archive is built, so the same staged
# tree archives to the same member order and timestamps on any host.
# Ownership is normalized inside the tar stream per implementation
# (zip has no such field to normalize).
find "$stage/$prefix" -exec touch -h -t 202001010000.00 {} +
member_list="$work/members.txt"
( cd "$stage" && find "$prefix" -print | LC_ALL=C sort ) > "$member_list"

case "$FORMAT" in
  tar.gz)
    if [ "$tar_format" = "gnu" ]; then
      tar --format=gnu --no-recursion --owner=0 --group=0 --numeric-owner \
        -cf - -C "$stage" -T "$member_list"
    else
      tar --format=gnutar --no-recursion --uid=0 --gid=0 --uname=root --gname=root \
        -cf - -C "$stage" -T "$member_list"
    fi | gzip -n > "$work/archive.tar.gz"
    ;;
  # -y keeps symlink entries instead of dereferencing them — a plain
  # `zip -r` silently stores the target's contents or drops the entry,
  # which is how the .claude/skills link went missing previously. The
  # member list comes from -@ so the archive members are the sorted
  # canonical set, not a filesystem walk order.
  zip)    (cd "$stage" && zip -qry -@ "$work/archive.zip" < "$member_list") ;;
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

# Gate 1 — the whole-tree manifest, verified exactly as the distribution
# lane will run it: the EMBEDDED manifest against the extraction. Every
# file's bytes, every symlink's target bytes, every mode, checked
# bidirectionally (the verifier's find-walk also catches any extra
# entries the packager added beyond the manifest file itself).
"$ROOT/scripts/verify-source-manifest.sh" \
  "$extracted/release-evidence/source-tree-sha256.txt" "$extracted" >/dev/null
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

mkdir -p -- "$(dirname "$OUTPUT")"
mv "$work/archive.$FORMAT" "$OUTPUT"
digest="$(shasum -a 256 "$OUTPUT" | cut -d ' ' -f 1)"
printf '%s  %s\n' "$digest" "$(basename "$OUTPUT")" > "$OUTPUT.sha256"
echo "ok: source archive verified after extraction: $OUTPUT (sha256 $digest)"
