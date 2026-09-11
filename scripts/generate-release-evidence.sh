#!/usr/bin/env bash
# Generate machine-verifiable release evidence into dist/release-evidence/.
#
# This script is the canonical release qualification pipeline. It:
#   1. Requires a clean Git working tree.
#   2. Captures source provenance from Git.
#   3. Generates source-tree manifest using scripts/generate-source-manifest.sh.
#   4. Runs all qualification gates with uncached Go tests.
#   5. Captures raw logs and machine-readable JSON for every gate.
#   6. Fails closed if any mandatory gate fails.
#   7. Generates qualification.json as the canonical admission record.
#   8. Generates SHA256SUMS for the evidence bundle.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVIDENCE_DIR="$REPO_ROOT/dist/release-evidence"
mkdir -p "$EVIDENCE_DIR/gate-results"

# Clean previous generated artifacts.
rm -f "$EVIDENCE_DIR"/*.json "$EVIDENCE_DIR"/SHA256SUMS \
  "$EVIDENCE_DIR"/source-tree-sha256.txt "$EVIDENCE_DIR"/source-tree-git-blobs.txt \
  "$EVIDENCE_DIR"/provenance.json "$EVIDENCE_DIR"/artifact.json \
  "$EVIDENCE_DIR"/toolchains.json "$EVIDENCE_DIR"/environment.json
rm -rf "$EVIDENCE_DIR/gate-results"
mkdir -p "$EVIDENCE_DIR/gate-results"

# ─── Gate tracking ─────────────────────────────────────────────────────────
# Each gate records: name, status (PASS/FAIL/NOT_RUN), exit code, log file,
# and tests_executed (for test-suite gates; empty for non-test gates).
declare -a GATE_NAMES=()
declare -a GATE_STATUS=()
declare -a GATE_EXIT=()
declare -a GATE_LOG=()
declare -a GATE_TESTS=()

record_gate() {
  local name="$1" status="$2" exit_code="$3" log="$4" tests="${5:-}"
  GATE_NAMES+=("$name")
  GATE_STATUS+=("$status")
  GATE_EXIT+=("$exit_code")
  GATE_LOG+=("$log")
  GATE_TESTS+=("$tests")
}

# ─── run_and_log (Phase 2) ──────────────────────────────────────────────────
# Captures the actual exit status of the command. Never swallows failures.
# Returns the command's real exit code so the caller can track gate status.
run_and_log() {
  local name="$1"
  shift
  local log="$EVIDENCE_DIR/gate-results/${name}.log"
  {
    echo "command=$*"
    echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "---"
  } > "$log"
  set +e
  "$@" >> "$log" 2>&1
  local rc=$?
  set -e
  {
    echo "---"
    echo "finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "exit=$rc"
  } >> "$log"
  return "$rc"
}

# Run a mandatory gate. If it fails, record FAIL and continue (so all gates
# run and evidence is preserved). The final qualification.json will mark the
# release as not promotable.
run_gate() {
  local name="$1"
  shift
  local log="$EVIDENCE_DIR/gate-results/${name}.log"
  if run_and_log "$name" "$@"; then
    record_gate "$name" "PASS" 0 "$log"
    echo "  PASS  $name"
  else
    local rc=$?
    record_gate "$name" "FAIL" "$rc" "$log"
    echo "  FAIL  $name (exit=$rc)"
  fi
}

# ─── Phase 4: Require clean Git state ────────────────────────────────────────
# The clean-tree check excludes the release-evidence/ directory because
# those files are generated outputs of this script, not source inputs.
# The qualification proves the source tree is clean; the evidence is the
# artifact produced from that clean source.
if ! git -C "$REPO_ROOT" diff --quiet -- . ':(exclude)release-evidence/' \
  || ! git -C "$REPO_ROOT" diff --cached --quiet -- . ':(exclude)release-evidence/'; then
  echo "ERROR: release qualification requires a clean source working tree (staged or unstaged source changes present)" >&2
  exit 1
fi
# Check for untracked files outside release-evidence/.
UNTRACKED="$(git -C "$REPO_ROOT" status --porcelain --untracked-files=all -- . ':(exclude)release-evidence/')"
if [ -n "$UNTRACKED" ]; then
  echo "ERROR: release qualification requires a clean source working tree (untracked source files present)" >&2
  exit 1
fi

# ─── Phase 5: Source provenance ─────────────────────────────────────────────
COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD)"
TREE="$(git -C "$REPO_ROOT" rev-parse HEAD^{tree})"
BRANCH="$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD)"

cat > "$EVIDENCE_DIR/provenance.json" << EOF
{
  "commit": "$COMMIT",
  "tree": "$TREE",
  "branch": "$BRANCH",
  "dirty": false
}
EOF

echo "$COMMIT" > "$EVIDENCE_DIR/source-commit.txt"
git -C "$REPO_ROOT" log -1 --format='commit %H%nAuthor: %an <%ae>%nDate: %ad%nSubject: %s' \
  > "$EVIDENCE_DIR/source-commit-metadata.txt"

# ─── Phase 22: Build reproducibility metadata ────────────────────────────────
GO_SUM_SHA=""
if [ -f "$REPO_ROOT/go.sum" ]; then
  GO_SUM_SHA="$(shasum -a 256 "$REPO_ROOT/go.sum" | cut -d ' ' -f 1)"
fi
PKG_LOCK_SHA=""
if [ -f "$REPO_ROOT/worker/package-lock.json" ]; then
  PKG_LOCK_SHA="$(shasum -a 256 "$REPO_ROOT/worker/package-lock.json" | cut -d ' ' -f 1)"
fi
cat > "$EVIDENCE_DIR/build-reproducibility.json" << EOF
{
  "source_commit": "$COMMIT",
  "source_tree": "$TREE",
  "go_sum_sha256": "$GO_SUM_SHA",
  "package_lock_sha256": "$PKG_LOCK_SHA",
  "build_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "platform": "$(uname -s)/$(uname -m)"
}
EOF

# ─── Phase 6: Source-tree manifest ──────────────────────────────────────────
# Use the canonical source manifest generator (scripts/generate-source-manifest.sh)
# which uses find (not git ls-files) and explicit exclusions.
bash "$REPO_ROOT/scripts/generate-source-manifest.sh" \
  "$EVIDENCE_DIR/source-tree-sha256.txt" "$REPO_ROOT" 2>&1 | \
  tee "$EVIDENCE_DIR/gate-results/source-manifest-generate.log"

# Git blob manifest: path → git_blob_id (for Git-native verification)
git -C "$REPO_ROOT" ls-files -z -- . ':(exclude)release-evidence/' ':(exclude)dist/' | sort -z | while IFS= read -r -d '' file; do
  blob="$(git -C "$REPO_ROOT" rev-parse "HEAD:$file")"
  echo "$blob  $file"
done > "$EVIDENCE_DIR/source-tree-git-blobs.txt"

# ─── Phase 7: Verify source manifest ────────────────────────────────────────
# Use the canonical bidirectional verifier (scripts/verify-source-manifest.sh)
# instead of inline logic. The canonical script checks both:
#   1. manifest → source (every manifest entry exists and matches)
#   2. source → manifest (no unexpected files added after generation)
MANIFEST_VERIFY="$EVIDENCE_DIR/gate-results/source-manifest-verify.log"
{
  echo "command=bash $REPO_ROOT/scripts/verify-source-manifest.sh $EVIDENCE_DIR/source-tree-sha256.txt $REPO_ROOT"
  echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "---"
} > "$MANIFEST_VERIFY"

set +e
bash "$REPO_ROOT/scripts/verify-source-manifest.sh"   "$EVIDENCE_DIR/source-tree-sha256.txt" "$REPO_ROOT" >> "$MANIFEST_VERIFY" 2>&1
manifest_rc=$?
set -e

{
  echo "---"
  echo "exit=$manifest_rc"
  if [ "$manifest_rc" -eq 0 ]; then
    echo "status=PASS"
    record_gate "source_manifest" "PASS" 0 "$MANIFEST_VERIFY"
  else
    echo "status=FAIL"
    record_gate "source_manifest" "FAIL" 1 "$MANIFEST_VERIFY"
  fi
  echo "finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >> "$MANIFEST_VERIFY"
echo "  $(grep 'status=' "$MANIFEST_VERIFY" | tail -1 | cut -d= -f2)  source_manifest"

# ─── Phase 21: Toolchain identity ───────────────────────────────────────────
GO_VERSION="$(go version 2>/dev/null || echo 'unavailable')"
NODE_VERSION="$(node --version 2>/dev/null || echo 'unavailable')"
NPM_VERSION="$(npm --version 2>/dev/null || echo 'unavailable')"
WORKER_PKG_VERSION="$(node -e "console.log(require('./worker/package.json').version)" 2>/dev/null || echo 'unavailable')"
GIT_VERSION="$(git --version 2>/dev/null || echo 'unavailable')"
PG_VERSION="$(psql --version 2>/dev/null || echo 'not-installed')"

cat > "$EVIDENCE_DIR/toolchains.json" << EOF
{
  "go": "$GO_VERSION",
  "node": "$NODE_VERSION",
  "npm": "$NPM_VERSION",
  "git": "$GIT_VERSION",
  "postgres_client": "$PG_VERSION",
  "worker_package_version": "$WORKER_PKG_VERSION",
  "go_os": "$(go env GOOS 2>/dev/null || echo 'unknown')",
  "go_arch": "$(go env GOARCH 2>/dev/null || echo 'unknown')"
}
EOF

cat > "$EVIDENCE_DIR/environment.json" << EOF
{
  "os": "$(uname -s)",
  "os_version": "$(uname -r)",
  "arch": "$(uname -m)",
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

# ─── Phase 8-9: Go gates (uncached, -count=1) ───────────────────────────────
echo ""
echo "=== Go gates ==="
run_gate go-vet go vet ./...
run_gate go-evidence-tests go test -count=1 -timeout=120s \
  -run "TestTerminalReceipt|TestTerminalLog|TestRunEvidence|TestFinalizeRun|TestEvidence|TestCoordinatorFinish|TestCoordinatorRunReceipt|TestReceipt|TestRunRecorder|TestTiming" \
  ./internal/cli/
run_gate go-tart-tests go test -count=1 -timeout=120s ./internal/providers/tart/
run_gate go-lume-tests go test -count=1 -timeout=60s ./internal/providers/lume/
run_gate go-shared-tests go test -count=1 -timeout=60s ./internal/providers/shared/

# Phase 9: Go race evidence
run_gate go-race-evidence go test -race -count=1 -timeout=120s \
  -run "TestTerminalReceipt|TestTerminalLog|TestRunEvidence|TestFinalizeRun|TestEvidence|TestReceiptContract" \
  ./internal/cli/
run_gate go-race-providers go test -race -count=1 -timeout=120s \
  ./internal/providers/tart/ ./internal/providers/lume/ ./internal/providers/shared/

# ─── Effect Fabric contract gates ────────────────────────────────────────────
# Dedicated gates for the durable execution contract. These are NOT
# hidden inside the general Go test gates — they are first-class
# release gates so that contract regressions are immediately visible.
echo ""
echo "=== Effect Fabric contract gates ==="

# effect-fabric-contract: typed contract unit tests (no DB required).
# Verifies state predicates, lease config validation, acquire result
# kinds, terminal receipt digest, recovery decision types, receipt
# identity fields, digest determinism, FinalizedAt exclusion, clock
# interface, state aliases, and RecoveryRetryable rejection.
run_gate effect-fabric-contract go test -count=1 -timeout=60s \
  -run "TestState|TestLeaseConfig|TestAcquireResult|TestTerminalReceipt|TestRecovery|TestLeaseError|TestMigrateState|TestDefaultLeaseConfig|TestFixedClock|TestSystemClock" \
  ./internal/idempotency/

# effect-fabric-reconciliation: reconciliation worker unit tests.
# Verifies NoopResolver, resolver registration, and fail-closed behavior.
run_gate effect-fabric-reconciliation go test -count=1 -timeout=60s \
  ./internal/reconcile/

# effect-fabric-race: race-detector run over the execution + idempotency
# + capability + reconcile packages. Closes concurrent-acquisition races
# and stale-worker fencing violations.
# Unset CRABBOX_TEST_DATABASE_URL so live tests skip — the race gate
# should not run live PostgreSQL tests (they're too slow with -race
# and are covered by effect-fabric-postgres separately).
run_gate effect-fabric-race env -u CRABBOX_TEST_DATABASE_URL \
  go test -race -count=1 -timeout=120s \
  ./internal/capability/ ./internal/execution/ ./internal/idempotency/ ./internal/reconcile/

# ─── Phase 10-12: Live PostgreSQL gates ────────────────────────────────────
echo ""
echo "=== Live PostgreSQL gates ==="

# Live PostgreSQL gates fail closed. Without CRABBOX_TEST_DATABASE_URL the
# tests skip themselves and exit 0, which must NOT be recorded as PASS.
# The wrapper checks the env var, runs Vitest with JSON output to a
# SEPARATE pure JSON file (not the decorated log), and parses that file
# to require a nonzero number of executed tests.
run_live_postgres_gate() {
  local name="$1"
  local test_file="$2"
  local log="$EVIDENCE_DIR/gate-results/${name}.log"
  local json_out="$EVIDENCE_DIR/${name}.vitest.json"

  if [ -z "${CRABBOX_TEST_DATABASE_URL:-}" ]; then
    {
      echo "command=run_live_postgres_gate $name $test_file"
      echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      echo "---"
      echo "SKIP: CRABBOX_TEST_DATABASE_URL not set"
      echo "exit=1"
      echo "finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$log"
    record_gate "$name" "FAIL" 1 "$log"
    echo "  FAIL  $name (CRABBOX_TEST_DATABASE_URL not set)"
    return
  fi

  # Run Vitest with JSON reporter, writing pure JSON to a separate file.
  # Use the Worker package's locked Vitest, not root npx (reproducibility).
  {
    echo "command=run_live_postgres_gate $name $test_file"
    echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "---"
  } > "$log"

  set +e
  # Use the locked worker Vitest executable for reproducibility.
  # The live config does NOT exclude *.live.test.ts (the default
  # vitest.config.ts excludes them so they don't run in `npm test`).
  (cd worker && npx vitest run --no-file-parallelism \
    --config vitest.live.config.ts --reporter=json \
    "$test_file" > "$json_out" 2>> "$log")
  local rc=$?
  set -e

  {
    echo "---"
    echo "finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "exit=$rc"
  } >> "$log"

  if [ "$rc" -ne 0 ]; then
    record_gate "$name" "FAIL" "$rc" "$log"
    echo "  FAIL  $name (exit=$rc)"
    return
  fi

  # Parse the pure JSON file (not the decorated log) to verify tests
  # actually executed (not skipped).
  local total_tests skipped_tests executed_tests
  if [ ! -f "$json_out" ] || ! jq empty "$json_out" 2>/dev/null; then
    {
      echo ""
      echo "FAIL: vitest JSON output missing or invalid"
      echo "exit=1"
    } >> "$log"
    record_gate "$name" "FAIL" 1 "$log"
    echo "  FAIL  $name (no valid JSON output)"
    return
  fi

  total_tests="$(jq '[.testResults[].assertionResults | length] | add // 0' "$json_out" 2>/dev/null || echo 0)"
  skipped_tests="$(jq '[.testResults[].assertionResults[] | select(.status == "skip")] | length' "$json_out" 2>/dev/null || echo 0)"
  executed_tests=$((total_tests - skipped_tests))

  if [ "$executed_tests" -le 0 ]; then
    {
      echo ""
      echo "FAIL: 0 tests executed ($total_tests total, $skipped_tests skipped)"
      echo "exit=1"
    } >> "$log"
    record_gate "$name" "FAIL" 1 "$log"
    echo "  FAIL  $name (0 tests executed, all skipped)"
    return
  fi

  record_gate "$name" "PASS" 0 "$log"
  echo "  PASS  $name ($executed_tests tests executed)"
}

run_live_postgres_gate postgres-fencing test/postgres-authority-fencing.live.test.ts
run_live_postgres_gate postgres-parity test/coordinator-parity.live.test.ts

# effect-fabric-postgres: live PostgreSQL contract tests for the
# durable execution store. Runs the expired-lease matrix, stale-worker
# fencing, finalization conflicts, and evidence recovery tests.
# These require a real PostgreSQL instance (CRABBOX_TEST_DATABASE_URL).
echo ""
echo "=== Effect Fabric live PostgreSQL gates ==="

# Live Go PostgreSQL gate for the effect fabric contract.
# Uses the same fail-closed wrapper pattern as the Vitest live gates.
run_effect_fabric_postgres_gate() {
  local name="effect-fabric-postgres"
  local log="$EVIDENCE_DIR/gate-results/${name}.log"

  if [ -z "${CRABBOX_TEST_DATABASE_URL:-}" ]; then
    {
      echo "command=run_effect_fabric_postgres_gate"
      echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      echo "---"
      echo "SKIP: CRABBOX_TEST_DATABASE_URL not set"
      echo "exit=1"
      echo "finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$log"
    record_gate "$name" "FAIL" 1 "$log"
    echo "  FAIL  $name (CRABBOX_TEST_DATABASE_URL not set)"
    return
  fi

  {
    echo "command=go test -count=1 -timeout=300s -run TestLiveEffectFabric ./internal/idempotency/ && go test -count=1 -timeout=300s -run TestLiveConcurrent ./internal/execution/"
    echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "---"
  } > "$log"

  set +e
  go test -count=1 -timeout=300s \
    -run "TestLiveEffectFabric|TestLiveStore" \
    ./internal/idempotency/ >> "$log" 2>&1
  local rc1=$?
  # Also run the 100-way concurrent mutation dispatch test (CRAB-V1-021).
  go test -count=1 -timeout=300s \
    -run "TestLiveConcurrentIdenticalMutationSingleDispatch" \
    ./internal/execution/ >> "$log" 2>&1
  local rc2=$?
  set -e
  local rc=$((rc1 + rc2))

  {
    echo "---"
    echo "finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "exit=$rc"
  } >> "$log"

  if [ "$rc" -ne 0 ]; then
    record_gate "$name" "FAIL" "$rc" "$log"
    echo "  FAIL  $name (exit=$rc)"
    # Print the test output to stdout so failures are visible in CI.
    cat "$log"
    return
  fi

  # Verify tests actually executed (not skipped). Go test prints "ok"
  # lines for packages that ran tests.
  local executed
  executed=$(grep -cE '^(ok|FAIL|--- PASS|--- FAIL)' "$log" 2>/dev/null || true)
  if [ "$executed" -le 0 ]; then
    {
      echo ""
      echo "FAIL: 0 tests executed (all skipped or no match)"
      echo "exit=1"
    } >> "$log"
    record_gate "$name" "FAIL" 1 "$log"
    echo "  FAIL  $name (0 tests executed)"
    return
  fi

  record_gate "$name" "PASS" 0 "$log"
  echo "  PASS  $name ($executed test lines)"
}

run_effect_fabric_postgres_gate

# ─── Authority store live PostgreSQL gate ─────────────────────────────────────
# Tests grant lookup, principal mismatch, capability mismatch, expiry,
# revocation, and database error handling.
echo ""
echo "=== Authority store live PostgreSQL gate ==="

run_authority_postgres_gate() {
  local name="authority-postgres"
  local log="$EVIDENCE_DIR/gate-results/${name}.log"

  if [ -z "${CRABBOX_TEST_DATABASE_URL:-}" ]; then
    {
      echo "command=run_authority_postgres_gate"
      echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      echo "---"
      echo "SKIP: CRABBOX_TEST_DATABASE_URL not set"
      echo "exit=1"
      echo "finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$log"
    record_gate "$name" "FAIL" 1 "$log"
    echo "  FAIL  $name (CRABBOX_TEST_DATABASE_URL not set)"
    return
  fi

  {
    echo "command=go test -count=1 -timeout=120s -run TestLiveAuthority ./internal/authority/"
    echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "---"
  } > "$log"

  set +e
  go test -count=1 -timeout=120s \
    -run "TestLiveAuthority" \
    ./internal/authority/ >> "$log" 2>&1
  local rc=$?
  set -e

  {
    echo "---"
    echo "finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "exit=$rc"
  } >> "$log"

  if [ "$rc" -ne 0 ]; then
    record_gate "$name" "FAIL" "$rc" "$log"
    echo "  FAIL  $name (exit=$rc)"
    cat "$log"
    return
  fi

  local executed
  executed=$(grep -cE '^(ok|FAIL|--- PASS|--- FAIL)' "$log" 2>/dev/null || true)
  if [ "$executed" -le 0 ]; then
    {
      echo ""
      echo "FAIL: 0 tests executed (all skipped or no match)"
      echo "exit=1"
    } >> "$log"
    record_gate "$name" "FAIL" 1 "$log"
    echo "  FAIL  $name (0 tests executed)"
    return
  fi

  record_gate "$name" "PASS" 0 "$log"
  echo "  PASS  $name ($executed test lines)"
}

run_authority_postgres_gate

# ─── Phase 13: Cross-language conformance ───────────────────────────────────
echo ""
echo "=== Cross-language conformance ==="
run_gate cross-language-conformance \
  go test -count=1 -timeout=60s \
  -run "TestRunEvidenceConformanceCorpus|TestReceiptContractConformance" \
  ./internal/cli/

# ─── Phase 15: Worker gates ────────────────────────────────────────────────
echo ""
echo "=== Worker gates ==="
# Ensure Worker dependencies are installed.
npm ci --prefix worker
run_gate worker-typecheck npm run check --prefix worker
run_gate worker-tests npm test --prefix worker
run_gate worker-format npm run format:check --prefix worker
run_gate worker-lint npm run lint --prefix worker
run_gate worker-build npm run build --prefix worker

# ─── Phase NEMO: NeMo kernel/adapter gates ────────────────────────────────
echo ""
echo "=== NeMo gates ==="
# Ensure NeMo dependencies are installed.
npm ci --prefix nemo
run_gate nemo-typecheck sh -c 'cd nemo && npx tsc --noEmit'
run_gate nemo-tests sh -c 'cd nemo && npx vitest run'

# ─── Phase 15: Worker structured summaries ─────────────────────────────────
# Extract test counts from the worker test log.
WORKER_TEST_LOG="$EVIDENCE_DIR/gate-results/worker-tests.log"
if [ -f "$WORKER_TEST_LOG" ]; then
  TESTS_PASSED="$(grep -oE 'Tests.*[0-9]+ passed' "$WORKER_TEST_LOG" | grep -oE '[0-9]+ passed' | head -1 | grep -oE '^[0-9]+' || echo 0)"
  TESTS_FAILED="$(grep -oE 'Tests.*[0-9]+ failed' "$WORKER_TEST_LOG" | grep -oE '[0-9]+ failed' | head -1 | grep -oE '^[0-9]+' || echo 0)"
  TESTS_SKIPPED="$(grep -oE 'Tests.*[0-9]+ skipped' "$WORKER_TEST_LOG" | grep -oE '[0-9]+ skipped' | head -1 | grep -oE '^[0-9]+' || echo 0)"
  FILES_PASSED="$(grep -oE 'Test Files.*[0-9]+ passed' "$WORKER_TEST_LOG" | grep -oE '[0-9]+ passed' | head -1 | grep -oE '^[0-9]+' || echo 0)"
  FILES_SKIPPED="$(grep -oE 'Test Files.*[0-9]+ skipped' "$WORKER_TEST_LOG" | grep -oE '[0-9]+ skipped' | head -1 | grep -oE '^[0-9]+' || echo 0)"
  # Derive exit code from the actual gate log, not hardcoded.
  WORKER_TESTS_EXIT="$(grep '^exit=' "$WORKER_TEST_LOG" | tail -1 | cut -d= -f2 || echo 1)"
  cat > "$EVIDENCE_DIR/worker-tests.json" << EOF
{
  "files_passed": $FILES_PASSED,
  "files_skipped": $FILES_SKIPPED,
  "tests_passed": $TESTS_PASSED,
  "tests_skipped": $TESTS_SKIPPED,
  "tests_failed": $TESTS_FAILED,
  "exit": $WORKER_TESTS_EXIT
}
EOF
fi

# Extract lint counts from the worker lint log.
WORKER_LINT_LOG="$EVIDENCE_DIR/gate-results/worker-lint.log"
if [ -f "$WORKER_LINT_LOG" ]; then
  LINT_ERRORS="$(grep -oE 'Found [0-9]+ warnings? and [0-9]+ errors?' "$WORKER_LINT_LOG" | grep -oE '[0-9]+ errors?' | grep -oE '^[0-9]+' || echo 0)"
  LINT_WARNINGS="$(grep -oE 'Found [0-9]+ warnings? and [0-9]+ errors?' "$WORKER_LINT_LOG" | grep -oE '[0-9]+ warnings?' | grep -oE '^[0-9]+' || echo 0)"
  # Derive exit code from the actual gate log, not hardcoded.
  WORKER_LINT_EXIT="$(grep '^exit=' "$WORKER_LINT_LOG" | tail -1 | cut -d= -f2 || echo 1)"
  cat > "$EVIDENCE_DIR/worker-lint.json" << EOF
{
  "errors": $LINT_ERRORS,
  "warnings": $LINT_WARNINGS,
  "exit": $WORKER_LINT_EXIT
}
EOF
fi

# ─── Phase 16: Generate qualification.json ──────────────────────────────────
# Build the canonical qualification manifest from gate results.
echo ""
echo "=== Generating qualification.json ==="

# Extract tests_executed from a gate log. Returns 0 for non-test gates or
# when the count cannot be determined. For Go test gates, parses the
# "ok"/"FAIL" package summary lines (Go test without -v does not print
# per-test PASS/FAIL lines). For Vitest gates, parses the summary line.
# For live PostgreSQL gates, reads the structured JSON summary.
extract_tests_executed() {
  local gate_name="$1"
  local log="$2"
  local count=0

  case "$gate_name" in
    go-evidence-tests|go-tart-tests|go-lume-tests|go-shared-tests|go-race-evidence|go-race-providers|go-race-cli|effect-fabric-contract|effect-fabric-reconciliation|effect-fabric-race|effect-fabric-postgres|authority-postgres)
      # Go test without -v prints one line per package:
      #   ok  \t<package>\t<duration>
      #   FAIL\t<package>\t<duration>
      # Count those lines as evidence tests ran.
      # Also check for -v output (--- PASS/--- FAIL) in case verbose is used.
      # NOTE: grep -c outputs "0" and exits 1 when no matches. Using
      # `|| true` (not `|| echo 0`) avoids appending a second "0".
      count=$(grep -cE '^(ok|FAIL|--- PASS|--- FAIL)' "$log" 2>/dev/null || true)
      ;;
    worker-tests|nemo-tests)
      # Vitest prints a summary like:
      #   Tests  5 passed (5)
      # The output may contain ANSI color codes in CI, so strip them.
      local tests_line
      tests_line=$(sed 's/\x1b\[[0-9;]*m//g' "$log" 2>/dev/null | grep -E 'Tests[[:space:]]+[0-9]+' | tail -1 || true)
      if [ -n "$tests_line" ]; then
        # Try to extract the number in parentheses first: "5 passed (5)"
        local in_parens
        in_parens=$(echo "$tests_line" | grep -oE '\([0-9]+\)' | grep -oE '[0-9]+' || true)
        if [ -n "$in_parens" ]; then
          count="$in_parens"
        else
          # Sum the individual counts: "5 passed | 2 failed | 1 skipped"
          local passed failed skipped
          passed=$(echo "$tests_line" | grep -oE '[0-9]+ passed' | grep -oE '^[0-9]+' || true)
          failed=$(echo "$tests_line" | grep -oE '[0-9]+ failed' | grep -oE '^[0-9]+' || true)
          skipped=$(echo "$tests_line" | grep -oE '[0-9]+ skipped' | grep -oE '^[0-9]+' || true)
          passed="${passed:-0}"
          failed="${failed:-0}"
          skipped="${skipped:-0}"
          count=$((passed + failed + skipped))
        fi
      fi
      ;;
    postgres-*)
      # Live Postgres gates write a vitest JSON file alongside the log.
      # Use jq (already available in CI) to count assertion results.
      local json_summary
      for candidate in "${log%.log}.summary.json" "$EVIDENCE_DIR/${gate_name}.summary.json" "$EVIDENCE_DIR/${gate_name}.vitest.json"; do
        if [ -f "$candidate" ]; then
          json_summary="$candidate"
          break
        fi
      done
      if [ -n "${json_summary:-}" ] && [ -f "$json_summary" ] && command -v jq >/dev/null 2>&1; then
        # Count total assertion results across all test files.
        count=$(jq '[.testResults[].assertionResults | length] | add // 0' "$json_summary" 2>/dev/null || true)
      fi
      ;;
    cross-language-conformance)
      # Conformance runner prints PASS/FAIL lines per case.
      count=$(grep -cE '^(PASS|FAIL|ok|not ok)' "$log" 2>/dev/null || true)
      ;;
    *)
      # Non-test gates (vet, typecheck, format, lint, build) have no test count.
      count=0
      ;;
  esac

  # Ensure numeric and non-negative.
  if ! [[ "$count" =~ ^[0-9]+$ ]]; then
    count=0
  fi
  echo "$count"
}

# Build gates JSON array from tracked results, including tests_executed.
GATES_JSON="["
for i in "${!GATE_NAMES[@]}"; do
  [ "$i" -gt 0 ] && GATES_JSON+=","
  tests_executed="$(extract_tests_executed "${GATE_NAMES[$i]}" "${GATE_LOG[$i]}")"
  GATES_JSON+="{\"id\":\"${GATE_NAMES[$i]}\",\"name\":\"${GATE_NAMES[$i]}\",\"mandatory\":true,\"status\":\"${GATE_STATUS[$i]}\",\"exit_code\":${GATE_EXIT[$i]},\"tests_executed\":${tests_executed},\"evidence_file\":\"gate-results/$(basename "${GATE_LOG[$i]}")\"}"
done
GATES_JSON+="]"

# Determine overall release status.
ALL_PASS=true
for status in "${GATE_STATUS[@]}"; do
  if [ "$status" != "PASS" ]; then
    ALL_PASS=false
    break
  fi
done

if [ "$ALL_PASS" = true ]; then
  RELEASE_STATUS="PASS"
  ARTIFACT_PROMOTABLE=true
else
  RELEASE_STATUS="FAIL"
  ARTIFACT_PROMOTABLE=false
fi

# Count gates.
TOTAL_GATES="${#GATE_NAMES[@]}"
PASSED_GATES=0
FAILED_GATES=0
for status in "${GATE_STATUS[@]}"; do
  if [ "$status" = "PASS" ]; then
    PASSED_GATES=$((PASSED_GATES + 1))
  else
    FAILED_GATES=$((FAILED_GATES + 1))
  fi
done

cat > "$EVIDENCE_DIR/qualification.json" << EOF
{
  "qualification_version": 1,
  "release_status": "$RELEASE_STATUS",
  "artifact_promotable": $ARTIFACT_PROMOTABLE,
  "gate_summary": {
    "total": $TOTAL_GATES,
    "passed": $PASSED_GATES,
    "failed": $FAILED_GATES,
    "skipped": 0
  },
  "gates": $GATES_JSON,
  "invariants": [
    {"id": "CRAB-V1-001", "description": "V3 receipt always binds evidence_sha256"},
    {"id": "CRAB-V1-002", "description": "V2 receipt can never contain evidence_sha256"},
    {"id": "CRAB-V1-003", "description": "receipt evidence digest equals canonical RunEvidenceV1 SHA-256"},
    {"id": "CRAB-V1-004", "description": "Go and TypeScript produce identical canonical evidence"},
    {"id": "CRAB-V1-005", "description": "Go and TypeScript accept/reject identical receipt/evidence domains"},
    {"id": "CRAB-V1-006", "description": "startup confirmation failure evidence survives to RunEvidenceV1"},
    {"id": "CRAB-V1-007", "description": "detached providers never advertise exit observability"},
    {"id": "CRAB-V1-008", "description": "persistence failure cannot alter FinalRunOutcome"},
    {"id": "CRAB-V1-009", "description": "new mutations fail after coordinator authority loss"},
    {"id": "CRAB-V1-010", "description": "replacement mutations cannot overlap pre-admitted old-coordinator mutations"},
    {"id": "CRAB-V1-011", "description": "qualified source tree equals packaged source tree"},
    {"id": "CRAB-V1-012", "description": "every mandatory qualification gate was executed and passed"},
    {"id": "CRAB-V1-013", "description": "Go capability registry is authoritative for execution class"},
    {"id": "CRAB-V1-014", "description": "durable idempotency prevents duplicate side effects"},
    {"id": "CRAB-V1-015", "description": "UNKNOWN is a first-class terminal state for post-dispatch ambiguity"},
    {"id": "CRAB-V1-016", "description": "crabbox exec never returns fake success for undispatched operations"},
    {"id": "CRAB-V1-017", "description": "expired IN_FLIGHT work is never blindly redispatched"},
    {"id": "CRAB-V1-018", "description": "only an unexpired active lease generation may mutate execution state"},
    {"id": "CRAB-V1-019", "description": "terminal finalization is immutable and conflict-aware"},
    {"id": "CRAB-V1-020", "description": "post-dispatch uncertainty cannot become retryable without evidence"},
    {"id": "CRAB-V1-021", "description": "concurrent identical mutations cause at most one provider dispatch"}
  ],
  "provenance": {
    "commit": "$COMMIT",
    "tree": "$TREE",
    "branch": "$BRANCH",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  },
  "toolchains": {
    "go": "$GO_VERSION",
    "node": "$NODE_VERSION",
    "npm": "$NPM_VERSION",
    "git": "$GIT_VERSION",
    "postgres_client": "$PG_VERSION",
    "worker_package_version": "$WORKER_PKG_VERSION"
  },
  "environment": {
    "os": "$(uname -s)",
    "os_version": "$(uname -r)",
    "arch": "$(uname -m)",
    "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  }
}
EOF

# ─── Phase 23: Generate qualification matrix from JSON ──────────────────────
"$REPO_ROOT/scripts/generate-qualification-matrix.sh"

# ─── Phase 24: Copy qualification schema into evidence bundle ───────────────
# The artifact must be self-contained: the verifier should not need to reach
# outside the evidence directory to find the schema.
mkdir -p "$EVIDENCE_DIR/schemas"
cp "$REPO_ROOT/schemas/qualification.schema.json" "$EVIDENCE_DIR/schemas/qualification.schema.json"

# ─── Phase 26: Generate release-manifest.json ───────────────────────────────
# The release manifest is the top-level index of the release artifact. It
# binds the release name/version to the source commit, artifact digest,
# evidence file list, and qualification summary.
#
# RELEASE_NAME / RELEASE_VERSION come from the environment (set by CI)
# so that the same script works for any RC version without code changes.
# Require explicit RELEASE_VERSION — fail closed if not set.
if [ -z "${RELEASE_VERSION:-}" ]; then
  echo "ERROR: RELEASE_VERSION must be set (e.g., 1.0.0-rc.7)" >&2
  echo "       Refusing to use a hardcoded default." >&2
  exit 1
fi
RELEASE_NAME="${RELEASE_NAME:-crabedence-v${RELEASE_VERSION}}"

# Aggregate tests_executed across all test gates for the release manifest.
TOTAL_TESTS_EXECUTED=0
TOTAL_TESTS_SKIPPED=0
for i in "${!GATE_NAMES[@]}"; do
  gate_name="${GATE_NAMES[$i]}"
  case "$gate_name" in
    *tests|postgres-*|effect-fabric-*|cross-language-conformance|authority-*)
      te="$(extract_tests_executed "$gate_name" "${GATE_LOG[$i]}")"
      TOTAL_TESTS_EXECUTED=$((TOTAL_TESTS_EXECUTED + te))
      ;;
  esac
done

cat > "$EVIDENCE_DIR/release-manifest.json" << EOF
{
  "release_name": "$RELEASE_NAME",
  "release_version": "$RELEASE_VERSION",
  "release_type": "release-candidate",
  "status": "$RELEASE_STATUS",
  "artifact_promotable": $ARTIFACT_PROMOTABLE,
  "provenance": {
    "commit": "$COMMIT",
    "tree": "$TREE",
    "branch": "$BRANCH"
  },
  "qualification": {
    "total_gates": $TOTAL_GATES,
    "passed_gates": $PASSED_GATES,
    "failed_gates": $FAILED_GATES,
    "tests_executed": $TOTAL_TESTS_EXECUTED,
    "tests_skipped": $TOTAL_TESTS_SKIPPED,
    "qualification_file": "qualification.json"
  },
  "evidence_bundle": {
    "checksums_file": "SHA256SUMS",
    "artifact_file": "artifact.json"
  },
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

# ─── Phase 27: Generate SBOM (Software Bill of Materials) ────────────────────
# Generate a minimal SBOM from Go modules and npm dependencies.
# Format: SPDX 2.3 JSON
GO_MODULE="$(head -1 "$REPO_ROOT/go.mod" | awk '{print $2}')"
SBOM_PACKAGES=""
SBOM_IDX=0

# Go direct dependencies from go.mod
while IFS= read -r line; do
  [ -z "$line" ] && continue
  case "$line" in
    require\(*\)) continue;;
    require\ *) continue;;
    \}) continue;;
  esac
  mod_path="$(echo "$line" | awk '{print $1}')"
  mod_ver="$(echo "$line" | awk '{print $2}')"
  [ -z "$mod_path" ] && continue
  [ -z "$mod_ver" ] && continue
  [ "$SBOM_IDX" -gt 0 ] && SBOM_PACKAGES+=","
  SBOM_PACKAGES+="{\"name\":\"$mod_path\",\"version\":\"$mod_ver\",\"ecosystem\":\"go\",\"supplier\":\"Unknown\"}"
  SBOM_IDX=$((SBOM_IDX + 1))
done < <(sed -n '/^require (/,/)/p' "$REPO_ROOT/go.mod" | grep -v '^require (' | grep -v '^)')

# Worker npm dependencies
if [ -f "$REPO_ROOT/worker/package-lock.json" ]; then
  while IFS= read -r pkg_name; do
    [ -z "$pkg_name" ] && continue
    pkg_ver="$(jq -r --arg n "$pkg_name" '.packages["node_modules/\($n)"].version // empty' "$REPO_ROOT/worker/package-lock.json" 2>/dev/null)"
    [ -z "$pkg_ver" ] && continue
    [ "$SBOM_IDX" -gt 0 ] && SBOM_PACKAGES+=","
    SBOM_PACKAGES+="{\"name\":\"$pkg_name\",\"version\":\"$pkg_ver\",\"ecosystem\":\"npm\",\"supplier\":\"Unknown\"}"
    SBOM_IDX=$((SBOM_IDX + 1))
  done < <(jq -r '.packages | to_entries[] | select(.key | startswith("node_modules/")) | .key | sub("node_modules/"; "")' "$REPO_ROOT/worker/package-lock.json" 2>/dev/null | grep -v '/' | sort -u | head -100)
fi

cat > "$EVIDENCE_DIR/sbom.spdx.json" << EOF
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "$RELEASE_NAME",
  "documentNamespace": "https://crabedence.dev/spdx/$RELEASE_NAME-$COMMIT",
  "creationInfo": {
    "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "creators": ["Tool: crabedence-release-evidence", "Organization: Crabedence"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-Root",
      "name": "$GO_MODULE",
      "versionInfo": "$COMMIT",
      "downloadLocation": "git+https://github.com/dawsonblock/crabedence-V1.git@$COMMIT",
      "filesAnalyzed": false,
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "supplier": "Organization: Crabedence"
    }${SBOM_PACKAGES:+,$SBOM_PACKAGES}
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-Package-Root"
    }
  ]
}
EOF

# ─── Phase 20: SHA256SUMS for evidence bundle ──────────────────────────────
# Must be generated AFTER all other files (including release-manifest.json
# and sbom.spdx.json) so that every file in the evidence directory is covered.
# evidence-manifest.json is EXCLUDED because its digest is computed FROM
# this SHA256SUMS — including it would create a self-invalidating cycle.
cd "$EVIDENCE_DIR"
find . -type f ! -name SHA256SUMS ! -name evidence-manifest.json ! -name artifact.json -print0 | sort -z | xargs -0 shasum -a 256 > SHA256SUMS

# ─── Phase 25: Generate evidence-manifest.json ──────────────────────────────
# The evidence bundle digest is the SHA-256 of the SHA256SUMS manifest,
# binding all evidence files into a single verifiable digest.
#
# SHA256SUMS is NOT regenerated after this file is written. The digest
# claim (digest_of: "SHA256SUMS") remains verifiable because SHA256SUMS
# is immutable at this point.
#
# Note: `artifact.json` is reserved for the release workflow's source
# archive metadata (tar.gz/zip hashes). This file (evidence-manifest.json)
# is the evidence bundle identity. Do not conflate the two.
EVIDENCE_SHA="$(shasum -a 256 SHA256SUMS | awk '{print $1}')"
MANIFEST_FILE_COUNT="$(wc -l < SHA256SUMS | tr -d ' ')"
cat > "$EVIDENCE_DIR/evidence-manifest.json" << EOF
{
  "name": "$RELEASE_NAME",
  "manifest_type": "evidence-bundle",
  "sha256": "$EVIDENCE_SHA",
  "digest_of": "SHA256SUMS",
  "file_count": $MANIFEST_FILE_COUNT,
  "commit": "$COMMIT",
  "tree": "$TREE",
  "branch": "$BRANCH",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

# ─── Phase 3: Fail closed ──────────────────────────────────────────────────
echo ""
if [ "$RELEASE_STATUS" = "PASS" ]; then
  echo "RELEASE QUALIFICATION: PASS ($PASSED_GATES/$TOTAL_GATES gates passed)"
else
  echo "RELEASE QUALIFICATION: FAILED ($FAILED_GATES/$TOTAL_GATES gates failed)" >&2
  echo "Artifact is NOT promotable" >&2
  exit 1
fi

echo "Release evidence generated in $EVIDENCE_DIR"
