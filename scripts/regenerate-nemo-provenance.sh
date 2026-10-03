#!/usr/bin/env bash
# Regenerate the NEMO transfer-provenance declaration mechanically.
#
# One canonical operation: recompute the policy binding, both tree
# identities, and the exhaustive typed delta from the trees on disk, rewrite
# runtimes/nemo-transfer-manifest.json, and re-render the generated blocks
# in runtimes/nemo-relay/TRANSFER-PROVENANCE.md. Nothing in the declaration
# is hand-maintained — every derived value comes from this run.
#
# Regeneration is deliberately separate from verification:
# scripts/verify-nemo-provenance.sh is read-only and fails on drift; running
# this twice produces a zero-diff second run.
set -euo pipefail

cd "$(dirname "$0")/.."
exec go run ./cmd/nemo-runtime-digest -manifest runtimes/nemo-transfer-manifest.json -update
