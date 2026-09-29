#!/usr/bin/env bash
set -euo pipefail

# Coverage gates. The first argument remains the legacy-cli floor
# (historical "Go core coverage" gate). The Effect Fabric trust core
# has its own named gates — a single CLI-only percentage must never be
# reported as coverage of the execution substrate.
#
# Floors are set just below the coverage each package's own test suite
# actually produces under `go test ./...` (no live database). Packages
# whose deepest tests are gated on CRABBOX_TEST_DATABASE_URL
# (idempotency, authority) carry lower floors; the live suite measures
# them separately via scripts/test-live-postgres.sh.
cli_threshold="${1:-90.0}"
if [[ ! "$cli_threshold" =~ ^([0-9]+([.][0-9]+)?|[.][0-9]+)$ ]]; then
  echo "invalid coverage threshold: $cli_threshold (must be a number from 0 to 100)" >&2
  exit 2
fi
if ! awk -v threshold="$cli_threshold" 'BEGIN { exit !(threshold >= 0 && threshold <= 100) }'; then
  echo "invalid coverage threshold: $cli_threshold (must be a number from 0 to 100)" >&2
  exit 2
fi

# name#file-path regex#floor — evaluated against the full ./... profile.
gates=(
  "legacy-cli#internal/cli/(bootstrap|claim|config|errors|flags|fmt|init|provider_labels|runlog|slug)\\.go:#${cli_threshold}"
  "capability-registry#internal/capability/#75.0"
  "execution-kernel#internal/execution/#70.0"
  "effect-store#internal/idempotency/#40.0"
  "authority#internal/authority/#38.0"
  "reconciliation#internal/reconcile/#70.0"
  "evidence#internal/evidence/#68.0"
)

if ! work_dir="$(mktemp -d "${TMPDIR:-/tmp}/crabbox-go-coverage.XXXXXX")"; then
  echo "could not create temporary coverage directory" >&2
  exit 1
fi
cleanup() {
  rm -rf "$work_dir"
}
trap cleanup EXIT
profile="$work_dir/coverage.out"

go test -timeout=15m ./... -covermode=atomic -coverprofile="$profile"

failures=0
for gate in "${gates[@]}"; do
  IFS='#' read -r name pattern floor <<<"$gate"
  gate_profile="$work_dir/${name}.out"
  awk -v pattern="$pattern" '
    NR == 1 { print; next }
    $1 ~ pattern { print }
  ' "$profile" >"$gate_profile"

  if [[ "$(wc -l <"$gate_profile" | tr -d ' ')" -le 1 ]]; then
    echo "coverage gate ${name}: no matching profile entries (pattern ${pattern})" >&2
    failures=$((failures + 1))
    continue
  fi

  coverage="$(go tool cover -func="$gate_profile" | awk '/^total:/ { sub(/%/, "", $3); print $3 }')"
  if awk -v coverage="$coverage" -v floor="$floor" 'BEGIN { exit !(coverage + 0 < floor + 0) }'; then
    printf "coverage gate %-20s %.1f%% < %.1f%%\n" "$name" "$coverage" "$floor" >&2
    failures=$((failures + 1))
  else
    printf "coverage gate %-20s %.1f%% >= %.1f%%\n" "$name" "$coverage" "$floor"
  fi
done

if [[ "$failures" -gt 0 ]]; then
  echo "$failures coverage gate(s) below floor" >&2
  exit 1
fi
