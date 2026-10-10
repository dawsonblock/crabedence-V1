#!/usr/bin/env bash
# The canonical evidence-bundle inventory — the ONE membership rule that
# generation, finalization, verification and packaging share, so no stage
# can produce a tree another stage later rejects.
#
#   checksum members: every regular file except those under a `.*` name
#     or an `attestation` name at any level, and except SHA256SUMS and
#     evidence-manifest.json themselves (the manifest's digest is computed
#     FROM SHA256SUMS — covering either would be a self-invalidating
#     cycle).
#   tolerated members: SHA256SUMS, evidence-manifest.json, every entry
#     under an `attestation` name (the external seal applied after
#     finalization; consumers verify it with `gh attestation verify`,
#     not with the checksum manifest), and directories.
#   strays — never evidence, never shipped, refused at every stage:
#       * hidden entries (`.*`) at any level — scratch state left inside
#         the bundle;
#       * non-regular members (symlink, fifo, socket, device) — nothing
#         SHA256SUMS can cover may ship as a verified file.
#
# A stage that discovers a stray REFUSES: silently pruning it into the
# checksum rule produced trees the packager then rejected, and silently
# shipping it would put unverifiable content in the published bundle.

# Emit the checksum-member set, NUL-separated and sorted byte-wise, each
# path relative to DIR with a leading ./ — the form `shasum` records and
# verifies. Optional extra arguments name additional basenames to exclude
# (the generator's artifact.json, which does not exist when it runs).
evidence_checksum_members() {
  local dir="$1"
  shift
  local -a extra_exclusions=()
  local name
  for name in "$@"; do
    extra_exclusions+=( ! -name "$name" )
  done
  ( cd "$dir" && find . -mindepth 1 \( -name '.*' -o -name attestation \) -prune -o \
      -type f ! -name SHA256SUMS ! -name evidence-manifest.json \
      ${extra_exclusions[@]+"${extra_exclusions[@]}"} -print0 \
      | LC_ALL=C sort -z )
}

# Emit every hidden entry — scratch state (`.*`) at any level — relative
# to DIR, sorted byte-wise. An empty result is the pass.
evidence_hidden_entries() {
  ( cd "$1" && find . -mindepth 1 -name '.*' -print | LC_ALL=C sort )
}

# Emit every non-regular member — anything that is neither a regular file
# nor a directory — relative to DIR, sorted byte-wise. An empty result is
# the pass.
evidence_nonregular_members() {
  ( cd "$1" && find . -mindepth 1 ! -type f ! -type d -print | LC_ALL=C sort )
}

# Fail-closed stray check shared by every stage: refuses (returns 1,
# naming the entries) when the tree contains members outside the canonical
# set. "$2" is the stage name used in the message.
evidence_refuse_strays() {
  local dir="$1" stage="$2" entries
  entries="$(evidence_hidden_entries "$dir")"
  if [ -n "$entries" ]; then
    echo "ERROR: hidden entries in the evidence tree are not evidence and cannot ship:" >&2
    printf '%s\n' "$entries" >&2
    echo "       ($stage refuses: remove the scratch state deliberately)" >&2
    return 1
  fi
  entries="$(evidence_nonregular_members "$dir")"
  if [ -n "$entries" ]; then
    echo "ERROR: evidence tree contains non-regular members SHA256SUMS cannot cover:" >&2
    printf '%s\n' "$entries" >&2
    echo "       ($stage refuses: a non-regular file can never ship as a verified file)" >&2
    return 1
  fi
  return 0
}
