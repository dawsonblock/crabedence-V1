#!/usr/bin/env bash
# Repository qualification: the Git-dependent half of the
# repository/distribution split. Everything here requires the Git
# object database — history, attributes, tags, and the tracked-file
# set — and never runs against an extracted archive.
#
#   distribution qualification (scripts/qualify-source-distribution.sh)
#     is the other lane: it runs on the clean extraction with no .git.
#
# Usage: qualify-repository.sh [repo-root]
# Exit 0 only when every gate passes.
set -euo pipefail

ROOT_ARG="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
ROOT="$(cd "$ROOT_ARG" && pwd -P)"

if ! git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "qualify-repository: $ROOT is not a Git work tree — run the distribution lane instead" >&2
  exit 2
fi
# shellcheck source=lib/release-paths.sh
. "$ROOT/scripts/lib/release-paths.sh"

failures=0
gate() {
  local name="$1"; shift
  echo "== gate: $name"
  if "$@"; then
    echo "ok: $name"
  else
    echo "FAIL: $name" >&2
    failures=$((failures + 1))
  fi
}

# Gate 1 — HEAD resolves. Nothing else can be qualified without it.
gate "git-head-resolves" git -C "$ROOT" rev-parse --verify HEAD

# Gate 2 — every tracked path is release-path legal, NUL-safe so no
# name can hide behind line-oriented handling.
gate "tracked-path-policy" bash -c '
  set -euo pipefail
  root="$1"
  . "$root/scripts/lib/release-paths.sh"
  ok=0
  while IFS= read -r -d "" f; do
    if ! release_path_check "$f"; then
      printf "qualify-repository: release path policy violation: %q\n" "$f" >&2
      ok=1
    fi
  done < <(git -C "$root" ls-files -z)
  exit "$ok"
' _ "$ROOT"

# Gate 3 — .gitattributes coverage. The source archive packages
# WORKTREE bytes, which differ from blob bytes wherever an attribute
# smudges the checkout; every attribute that alters checkout bytes must
# be reported, and the tracked CRLF fixture must keep its eol=crlf
# attribute or the packaged bytes no longer match what qualification
# hashed.
gate "gitattributes-covered" bash -c '
  set -euo pipefail
  root="$1"
  bad=0
  # Report every tracked path carrying text/eol/crlf attributes — one
  # check-attr call emitting path/attr/value NUL triples, so the smudge
  # surface is visible.
  while IFS= read -r -d "" p && IFS= read -r -d "" a && IFS= read -r -d "" v; do
    case "$v" in
      unspecified|unset) ;;
      *) printf "qualify-repository: attribute applies: %s %s=%s\n" "$p" "$a" "$v" ;;
    esac
  done < <(git -C "$root" ls-files -z | git -C "$root" check-attr --stdin -z text eol crlf)
  # The fixture whose checkout bytes differ from its blob must keep
  # the attribute that produces them.
  git -C "$root" check-attr text eol -- runtimes/nemo-relay/tests/fixtures/cli/mock-codex.cmd \
    | grep -q "eol: crlf" || {
      echo "qualify-repository: mock-codex.cmd lost eol=crlf — packaged bytes would change" >&2
      bad=1
    }
  exit "$bad"
' _ "$ROOT"

# Gate 4 — tracked set matches HEAD index (no staged-but-uncommitted
# or modified tracked content): the packaged tree is HEAD, so anything
# diverging would make qualification describe different bytes.
gate "worktree-matches-head" bash -c '
  set -euo pipefail
  if ! git -C "$1" diff --quiet HEAD; then
    echo "qualify-repository: tracked worktree differs from HEAD" >&2
    git -C "$1" diff --name-only HEAD >&2
    exit 1
  fi
' _ "$ROOT"

echo
if [ "$failures" -eq 0 ]; then
  echo "qualify-repository: PASS"
  exit 0
fi
echo "qualify-repository: FAIL ($failures gate(s) failed)" >&2
exit 1
