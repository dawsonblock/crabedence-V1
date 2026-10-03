#!/usr/bin/env bash
# Distribution qualification: prove an EXTRACTED source archive is the
# qualified source, using only what the archive carries.
#
# This is the distribution lane of the repository/distribution split:
#
#   repository qualification  (scripts/qualify-repository.sh) may
#     inspect Git history, attributes, tags, and tracked files.
#   distribution qualification (this script) runs against a clean
#     extraction with no .git and no parent repository visible. It
#     verifies the already-generated material the archive ships: the
#     embedded source manifest (file bytes, symlink target bytes,
#     modes, complete inventory), the NEMO transfer manifest, the
#     release-path policy, symlink resolution, component metadata, and
#     declared build inputs.
#
# A tree containing .git is not a distribution extraction and is
# refused: the lane exists to prove the artifact stands alone, so any
# Git state would invalidate the result.
#
# Usage:
#   qualify-source-distribution.sh <extracted-source-root> \
#       [--manifest PATH] [--require-source PATH]
#
#   --manifest PATH     source manifest to verify; default
#                       <root>/release-evidence/source-tree-sha256.txt
#   --require-source P  frozen NEMO baseline for the transfer
#                       manifest's strict source check; without it the
#                       shipping-tree check runs instead
#
# Exit 0 only when every gate passes.
set -euo pipefail

ROOT_ARG="${1:-}"
if [ -z "$ROOT_ARG" ]; then
  echo "usage: qualify-source-distribution.sh <extracted-source-root> [--manifest PATH] [--require-source PATH]" >&2
  exit 2
fi
if [ ! -d "$ROOT_ARG" ]; then
  echo "qualify-source-distribution: source root not found: $ROOT_ARG" >&2
  exit 2
fi
ROOT="$(cd "$ROOT_ARG" && pwd -P)"
shift

# The qualification tooling must come from the ARCHIVE UNDER TEST —
# never from the calling repository — so the result describes the
# shipped artifact, not whatever version the caller happened to run.
if [ ! -d "$ROOT/scripts" ] || [ ! -f "$ROOT/scripts/verify-source-manifest.sh" ]; then
  echo "qualify-source-distribution: $ROOT does not look like an extracted source archive (missing scripts/verify-source-manifest.sh)" >&2
  exit 2
fi

MANIFEST="$ROOT/release-evidence/source-tree-sha256.txt"
REQUIRE_SOURCE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --manifest) MANIFEST="$2"; shift 2 ;;
    --manifest=*) MANIFEST="${1#*=}"; shift ;;
    --require-source) REQUIRE_SOURCE="$2"; shift 2 ;;
    --require-source=*) REQUIRE_SOURCE="${1#*=}"; shift ;;
    *) echo "qualify-source-distribution: unknown argument $1" >&2; exit 2 ;;
  esac
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

failures=0
gate() {
  # gate <name> <command...>: run, report, count failures without
  # aborting — a qualification run reports EVERY gate's result.
  local name="$1"; shift
  echo "== gate: $name"
  if "$@"; then
    echo "ok: $name"
  else
    echo "FAIL: $name" >&2
    failures=$((failures + 1))
  fi
}

# Gate 0 — isolation contract. The distribution lane proves the
# artifact stands alone; a .git entry anywhere in the tree means this
# is not a clean extraction.
git_hit="$(find "$ROOT" -name .git -print -quit)"
if [ -n "$git_hit" ]; then
  printf 'qualify-source-distribution: .git entry in distribution tree: %s\n' "$git_hit" >&2
  echo "FAIL: no-git-in-extraction" >&2
  failures=$((failures + 1))
else
  echo "ok: no-git-in-extraction"
fi

# Gate 1 — source identity: the already-generated source manifest
# against the extracted tree, bidirectionally (bytes, modes, types,
# complete path inventory). Default is the manifest embedded in the
# archive; the verifier exempts exactly that path since a manifest
# cannot list itself.
if [ ! -f "$MANIFEST" ]; then
  echo "== gate: source-manifest"
  echo "FAIL: source-manifest (no manifest at $MANIFEST)" >&2
  failures=$((failures + 1))
else
  gate "source-manifest" bash "$ROOT/scripts/verify-source-manifest.sh" "$MANIFEST" "$ROOT"
fi

# Gate 2 — NEMO transfer provenance on the shipped tree.
if [ -f "$ROOT/runtimes/nemo-transfer-manifest.json" ]; then
  if [ -n "$REQUIRE_SOURCE" ]; then
    gate "nemo-transfer-manifest" \
      python3 "$ROOT/scripts/verify-nemo-transfer.py" \
        --require-source "$REQUIRE_SOURCE" "$ROOT/runtimes/nemo-transfer-manifest.json"
  else
    gate "nemo-transfer-manifest" \
      python3 "$ROOT/scripts/verify-nemo-transfer.py" "$ROOT/runtimes/nemo-transfer-manifest.json"
  fi
else
  echo "== gate: nemo-transfer-manifest (absent, skipped)"
fi

# Gate 3 — every shipped name is release-path legal (the same policy
# the packager enforces), enumerated NUL-safe so no name can hide.
gate "release-path-policy" bash -c '
  set -euo pipefail
  root="$1"
  . "$root/scripts/lib/release-paths.sh"
  ok=0
  while IFS= read -r -d "" f; do
    f="${f#$root/}"
    if ! release_path_check "$f"; then
      printf "qualify-source-distribution: release path policy violation: %q\n" "$f" >&2
      ok=1
    fi
  done < <(find "$root" \( -type f -o -type l \) -print0)
  exit "$ok"
' _ "$ROOT"

# Gate 4 — no dangling symlinks: the manifest checks target BYTES but a
# distribution must also carry targets that resolve inside or beside
# the tree it ships (absolute paths into the packager's machine are a
# packaging bug).
gate "symlink-resolution" bash -c '
  set -euo pipefail
  bad=0
  while IFS= read -r -d "" link; do
    if [ ! -e "$link" ]; then
      printf "qualify-source-distribution: dangling symlink: %s -> %s\n" \
        "$link" "$(readlink "$link")" >&2
      bad=1
    fi
  done < <(find "$1" -type l -print0)
  exit "$bad"
' _ "$ROOT"

# Gate 5 — no generated content leaked into the source artifact: build
# outputs and dependency caches are produced, not source. The release
# commit tracks none of these, so a packaged copy is a packaging bug.
gate "no-generated-content" bash -c '
  set -euo pipefail
  bad=0
  while IFS= read -r -d "" d; do
    printf "qualify-source-distribution: generated directory in source artifact: %s\n" "$d" >&2
    bad=1
  done < <(find "$1" \( -type d \( -name node_modules -o -name dist \
      -o -name target -o -name __pycache__ -o -name .venv \
      -o -name build -o -name .test-dist \) \) -print0)
  exit "$bad"
' _ "$ROOT"

# Gate 6 — declared build inputs and component metadata are present
# and parse: the distribution must carry everything its documented
# build consumes.
gate "build-inputs" bash -c '
  set -euo pipefail
  root="$1"; bad=0
  # Every declared build input must exist; VERSION and go.mod must also
  # be non-empty (an empty go.sum is legitimate for a no-dependency
  # module, so existence is all that file can promise).
  for f in VERSION go.mod go.sum worker/package.json \
           worker/package-lock.json nemo/package.json; do
    if [ ! -f "$root/$f" ]; then
      printf "qualify-source-distribution: missing build input: %s\n" "$f" >&2
      bad=1
    fi
  done
  for f in VERSION go.mod; do
    if [ -f "$root/$f" ] && [ ! -s "$root/$f" ]; then
      printf "qualify-source-distribution: empty build input: %s\n" "$f" >&2
      bad=1
    fi
  done
  for j in worker/package.json nemo/package.json \
           runtimes/nemo-transfer-manifest.json \
           runtimes/nemo-provenance-policy.json; do
    if [ -f "$root/$j" ] && ! python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$root/$j"; then
      printf "qualify-source-distribution: malformed JSON: %s\n" "$j" >&2
      bad=1
    fi
  done
  exit "$bad"
' _ "$ROOT"

echo
if [ "$failures" -eq 0 ]; then
  echo "qualify-source-distribution: PASS"
  exit 0
fi
echo "qualify-source-distribution: FAIL ($failures gate(s) failed)" >&2
exit 1
