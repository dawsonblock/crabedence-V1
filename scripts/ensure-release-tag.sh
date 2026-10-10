#!/usr/bin/env bash
# Admit the release tag for a qualified source commit.
#
# Tag creation is idempotent but never moving:
#   - an existing tag pointing at the qualified commit is reused;
#   - an existing tag pointing at ANY other commit is a hard failure —
#     a published release tag is never moved, cut a new RC instead;
#   - an absent tag is created annotated and pushed.
#
# Usage: ensure-release-tag.sh <tag> <qualified-commit>
#   RELEASE_REMOTE  remote to query/push (default origin; may be a path)
#   ENSURE_DRY_RUN  when 1, only check — never create or push
set -euo pipefail

TAG="${1:-}"
COMMIT="${2:-}"
REMOTE="${RELEASE_REMOTE:-origin}"

if [ -z "$TAG" ] || [ -z "$COMMIT" ]; then
  echo "usage: ensure-release-tag.sh <tag> <qualified-commit>" >&2
  exit 2
fi
if [[ ! "$COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  echo "ensure-release-tag: qualified commit must be a full lowercase SHA-1: $COMMIT" >&2
  exit 2
fi

# Peel annotated tags first: refs/tags/T^{} resolves a tag object to the
# commit it annotates, so the comparison is always against the commit.
existing="$(git ls-remote "$REMOTE" "refs/tags/${TAG}^{}" 2>/dev/null | cut -f1 || true)"
if [ -z "$existing" ]; then
  existing="$(git ls-remote "$REMOTE" "refs/tags/${TAG}" 2>/dev/null | cut -f1 || true)"
fi

if [ -n "$existing" ]; then
  if [ "$existing" != "$COMMIT" ]; then
    echo "ERROR: tag $TAG already exists at $existing, which is not the qualified commit $COMMIT" >&2
    echo "A published release tag is never moved; cut a new RC instead." >&2
    exit 1
  fi
  echo "tag $TAG already points at the qualified commit; reusing it"
  exit 0
fi

if [ "${ENSURE_DRY_RUN:-0}" = "1" ]; then
  echo "tag $TAG does not exist on $REMOTE (dry run — not created)"
  exit 0
fi

# The annotation is exactly the bare tag name — the release verifier
# requires %(contents:subject) == ref name. When the local Git config has
# a signing key the tag is signed (maintainer flow); the CI publish lane
# has no key and produces an annotated tag.
if [ -n "$(git config --get user.signingkey 2>/dev/null || true)" ]; then
  git tag -s "$TAG" -m "$TAG" "$COMMIT"
else
  git tag -a "$TAG" -m "$TAG" "$COMMIT"
fi
git push "$REMOTE" "$TAG"
echo "tag $TAG created and pushed at $COMMIT"
