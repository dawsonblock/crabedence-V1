#!/usr/bin/env bash
# The canonical evidence-bundle inventory — the ONE membership rule that
# generation, finalization, verification and packaging share, so no stage
# can produce a tree another stage later rejects.
#
#   checksum members: every regular file except those under a `.*` name,
#     except the contents of the single root `attestation/` seal
#     directory, and except SHA256SUMS and evidence-manifest.json
#     themselves (the manifest's digest is computed FROM SHA256SUMS —
#     covering either would be a self-invalidating cycle).
#   tolerated members: SHA256SUMS, evidence-manifest.json, the root
#     `attestation/` seal directory and its declared seal members (the
#     external seal applied after finalization; consumers verify it
#     through the attestation reference binding and `gh attestation
#     verify`, not with the checksum manifest), and directories.
#   strays — never evidence, never shipped, refused at every stage:
#       * hidden entries (`.*`) at any level — scratch state left inside
#         the bundle;
#       * non-regular members (symlink, fifo, socket, device) — nothing
#         SHA256SUMS can cover may ship as a verified file;
#       * ANY entry named `attestation` other than the single root
#         directory — a regular file by that name would otherwise slip
#         past both the stray checks (it is neither hidden nor
#         non-regular) and the checksum walk (its name was pruned), so
#         it would ship inside the bundle with no integrity coverage.
#
# The seal namespace is `./attestation/` — exactly one, at the evidence
# root only, a real directory (never a symlink), holding only the
# declared seal members the release workflow's attestation step emits:
#   attestation.json, attestation-id.txt, attestation-url.txt
# Each seal member is a regular file bounded at 64 KiB — the seal is a
# signed reference, not a payload channel. Anything else in the
# directory, the name used at any other depth, or the name on a
# non-directory member is refused.
#
# A stage that discovers a stray REFUSES: silently pruning it into the
# checksum rule produced trees the packager then rejected, and silently
# shipping it would put unverifiable content in the published bundle.

# The declared seal contents — the files the release workflow's
# attestation step produces. The list is the whole namespace: any other
# member under ./attestation is a violation.
EVIDENCE_SEAL_MEMBERS="attestation.json attestation-id.txt attestation-url.txt"
# The seal is a reference, not a payload channel: no member may exceed
# this size.
EVIDENCE_SEAL_MAX_MEMBER_BYTES=65536

# Emit the checksum-member set, NUL-separated and sorted byte-wise, each
# path relative to DIR with a leading ./ — the form `shasum` records and
# verifies. Optional extra arguments name additional basenames to exclude
# (the generator's artifact.json, which does not exist when it runs).
#
# Only the ROOT attestation directory is pruned: any other entry named
# `attestation` — including a root regular file — is enumerated like
# everything else, so the checksum rule can never silently exempt it.
# (Every stage still refuses it as a stray before shipping.)
evidence_checksum_members() {
  local dir="$1"
  shift
  local -a extra_exclusions=()
  local name
  for name in "$@"; do
    extra_exclusions+=( ! -name "$name" )
  done
  ( cd "$dir" && find . -mindepth 1 \( -name '.*' -o -path './attestation' -type d \) -prune -o \
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

# Emit every `attestation` member that is not the single root seal
# directory: entries named attestation at depth 2+ (nested under an
# arbitrary subdirectory is never the namespace) and a root `attestation`
# that is anything but a real directory (a regular file — the F-012
# bypass — or a symlink). An empty result is the pass.
evidence_attestation_strays() {
  ( cd "$1" &&
    find . -mindepth 2 -name attestation -print
    if [ -L ./attestation ] || { [ -e ./attestation ] && [ ! -d ./attestation ]; }; then
      printf '%s\n' './attestation'
    fi
  ) | LC_ALL=C sort
}

# Emit every member of the root seal directory that is not a declared
# seal member: undeclared names, nested directories (whose contents can
# never be a declared member), non-regular files, hidden entries, and
# members over the size bound — reported as attestation/<member>. An
# empty result is the pass; anything but a real directory at the root
# attestation name is reported by evidence_attestation_strays instead.
evidence_seal_violations() {
  local dir="$1"
  [ -d "$dir/attestation" ] || return 0
  ( cd "$dir/attestation" &&
    find . -mindepth 1 \( \
      ! -type f -o \
      ! \( -name attestation.json -o -name attestation-id.txt -o -name attestation-url.txt \) -o \
      -size +"${EVIDENCE_SEAL_MAX_MEMBER_BYTES}c" \
    \) -print | LC_ALL=C sort | sed 's|^\./|attestation/|'
  )
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
  entries="$(evidence_attestation_strays "$dir")"
  if [ -n "$entries" ]; then
    echo "ERROR: 'attestation' may exist only as the single root seal directory:" >&2
    printf '%s\n' "$entries" >&2
    echo "       ($stage refuses: the name on any other member — a regular file, a symlink, or" >&2
    echo "        a nested entry — ships outside every integrity check)" >&2
    return 1
  fi
  entries="$(evidence_seal_violations "$dir")"
  if [ -n "$entries" ]; then
    echo "ERROR: the attestation seal holds only the declared reference members" >&2
    echo "       ($EVIDENCE_SEAL_MEMBERS, regular files <= ${EVIDENCE_SEAL_MAX_MEMBER_BYTES} bytes):" >&2
    printf '%s\n' "$entries" >&2
    echo "       ($stage refuses: undeclared seal content cannot be independently verified)" >&2
    return 1
  fi
  return 0
}
