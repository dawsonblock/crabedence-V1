#!/usr/bin/env bash
# Scan the evidence directory for leaked secrets before finalization.
#
# The gate runner redacts credential-bearing argv, but a test or provider
# can still PRINT a secret to stdout/stderr, and that output lands in the
# gate log. This is the backstop: scan the evidence tree for the exact
# secret VALUES the qualification environment knows about and stop the
# release if any appears.
#
# Deliberately narrow: it matches known values only. It never guesses at
# entropy, and it never rewrites process output, so legitimate diagnostic
# evidence is preserved intact — a leak fails the release instead of being
# silently scrubbed.
#
# Usage: ./scripts/scan-evidence-secrets.sh <evidence-dir> [secret...]
set -euo pipefail

EVIDENCE_DIR="${1:?usage: scan-evidence-secrets.sh <evidence-dir> [secret...]}"
shift || true

if [ ! -d "$EVIDENCE_DIR" ]; then
  echo "ERROR: evidence directory not found: $EVIDENCE_DIR" >&2
  exit 1
fi

SECRETS=("$@")

# Credentials the qualification environment may carry. An unset variable
# contributes nothing, so it can never become a match-everything pattern.
for var in \
  CRABBOX_TEST_DATABASE_URL \
  CRABBOX_GITHUB_TEST_TOKEN \
  GITHUB_TOKEN \
  CRABBOX_OPENCOMPUTER_API_KEY \
  OPENCOMPUTER_API_KEY; do
  eval "value=\${$var:-}"
  if [ -n "$value" ]; then
    SECRETS+=("$value")
  fi
done

if [ "${#SECRETS[@]}" -eq 0 ]; then
  echo "Evidence secret scan: no known secret values in the environment to scan for" >&2
  exit 0
fi

found=0
for secret in "${SECRETS[@]}"; do
  [ -z "$secret" ] && continue
  matches="$(grep -rIlF -- "$secret" "$EVIDENCE_DIR" 2>/dev/null || true)"
  while IFS= read -r file; do
    [ -z "$file" ] && continue
    echo "LEAK: a known secret value appears in $file" >&2
    found=$((found + 1))
  done <<< "$matches"
done

if [ "$found" -ne 0 ]; then
  echo "ERROR: $found evidence file(s) contain a known secret value; stopping the release" >&2
  exit 1
fi

echo "Evidence secret scan: no known secret value present ($(find "$EVIDENCE_DIR" -type f | wc -l | tr -d ' ') files scanned)" >&2
