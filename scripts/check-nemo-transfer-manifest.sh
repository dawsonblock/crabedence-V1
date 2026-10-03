#!/usr/bin/env bash
# The transfer-integrity gate.
#
# The vendored NeMo Relay runtime is a copy, not a submodule, so the
# distribution's claim about which runtime it ships is a digest. The declared
# identity lives in runtimes/nemo-transfer-manifest.json — outside the tree it
# covers, because a declaration inside the tree would be part of the digest it
# declares and could never be self-consistent.
#
# This gate compares the declaration against the tree: the shipped-tree
# digest, file count, runtime version, and exclusion set; the declared source
# identity when the source copy is present (a standalone checkout does not
# carry it, and that is reported rather than silently skipped); and the
# inventory claims — that the added workspace members are members, that the
# declared paths exist, and, when the source copy is present, that the
# declared delta is the complete one: no modification, addition, or removal
# may be missing from the declaration, and none declared may be stale.
#
# A failure means the tree changed without its declaration being regenerated.
# Regenerate deliberately, in the same commit as the change:
#
#   go run ./cmd/nemo-runtime-digest -manifest runtimes/nemo-transfer-manifest.json -update
#
# The transfer record itself is runtimes/nemo-relay/TRANSFER-PROVENANCE.md.
set -euo pipefail

cd "$(dirname "$0")/.."

go run ./cmd/nemo-runtime-digest -manifest runtimes/nemo-transfer-manifest.json

# Documentation that restates provenance statistics is a dependent of the
# manifest, not a second source of truth: drift between them fails the gate.
scripts/check-provenance-docs.sh
