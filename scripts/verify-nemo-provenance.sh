#!/usr/bin/env bash
# Verify the NEMO transfer-provenance declaration — read-only.
#
# Shipping-tree mode (default): the runtime must equal its own declared
# canonical identity; a missing frozen source is reported, not failed.
#
# Transfer-qualification mode (--require-source): the frozen reference must
# be present, recompute to its declared identity, and the typed delta must
# equal the computed one exhaustively. Official release admission runs this
# mode; absence of the source is a hard failure, never a note.
set -euo pipefail

cd "$(dirname "$0")/.."
go_flag=""
py_flag=""
for arg in "$@"; do
  case "$arg" in
    --require-source) go_flag="-require-source"; py_flag="--require-source" ;;
    *) echo "verify-nemo-provenance: unknown argument $arg" >&2; exit 2 ;;
  esac
done
go run ./cmd/nemo-runtime-digest -manifest runtimes/nemo-transfer-manifest.json $go_flag
python3 scripts/verify-nemo-transfer.py $py_flag
scripts/check-provenance-docs.sh
