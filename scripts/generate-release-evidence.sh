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
# Each gate records: name, status (PASS/FAIL/NOT_RUN), exit code, log file.
declare -a GATE_NAMES=()
declare -a GATE_STATUS=()
declare -a GATE_EXIT=()
declare -a GATE_LOG=()

record_gate() {
  local name="$1" status="$2" exit_code="$3" log="$4"
  GATE_NAMES+=("$name")
  GATE_STATUS+=("$status")
  GATE_EXIT+=("$exit_code")
  GATE_LOG+=("$log")
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
MANIFEST_VERIFY="$EVIDENCE_DIR/gate-results/source-manifest-verify.log"
{
  echo "command=verify source-tree-sha256.txt"
  echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "---"
  missing=0
  mismatched=0
  checked=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    expected_sha="$(echo "$line" | cut -d ' ' -f 1)"
    file="$(echo "$line" | cut -d ' ' -f 3-)"
    checked=$((checked + 1))
    if [ ! -f "$REPO_ROOT/$file" ]; then
      echo "MISSING: $file"
      missing=$((missing + 1))
      continue
    fi
    actual_sha="$(shasum -a 256 "$REPO_ROOT/$file" | cut -d ' ' -f 1)"
    if [ "$actual_sha" != "$expected_sha" ]; then
      echo "MISMATCH: $file (expected=$expected_sha actual=$actual_sha)"
      mismatched=$((mismatched + 1))
    fi
  done < "$EVIDENCE_DIR/source-tree-sha256.txt"
  echo "---"
  echo "files_checked=$checked"
  echo "missing=$missing"
  echo "mismatched=$mismatched"
  if [ "$missing" -eq 0 ] && [ "$mismatched" -eq 0 ]; then
    echo "status=PASS"
    record_gate "source_manifest" "PASS" 0 "$MANIFEST_VERIFY"
  else
    echo "status=FAIL"
    record_gate "source_manifest" "FAIL" 1 "$MANIFEST_VERIFY"
  fi
  echo "finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$MANIFEST_VERIFY"
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
npm ci --prefix worker 2>/dev/null || true
run_gate worker-typecheck npm run check --prefix worker
run_gate worker-tests npm test --prefix worker
run_gate worker-format npm run format:check --prefix worker
run_gate worker-lint npm run lint --prefix worker
run_gate worker-build npm run build --prefix worker

# ─── Phase NEMO: NeMo kernel/adapter gates ────────────────────────────────
echo ""
echo "=== NeMo gates ==="
# Ensure NeMo dependencies are installed.
npm ci --prefix nemo 2>/dev/null || npm install --prefix nemo 2>/dev/null || true
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

# Build gates JSON array from tracked results.
GATES_JSON="["
for i in "${!GATE_NAMES[@]}"; do
  [ "$i" -gt 0 ] && GATES_JSON+=","
  GATES_JSON+="{\"id\":\"${GATE_NAMES[$i]}\",\"name\":\"${GATE_NAMES[$i]}\",\"mandatory\":true,\"status\":\"${GATE_STATUS[$i]}\",\"exit_code\":${GATE_EXIT[$i]},\"evidence_file\":\"gate-results/$(basename "${GATE_LOG[$i]}")\"}"
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
    {"id": "CRAB-V1-016", "description": "crabbox exec never returns fake success for undispatched operations"}
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

# ─── Phase 20: SHA256SUMS for evidence bundle ──────────────────────────────
# Must be generated AFTER all other files (including qualification-matrix.md)
# so that every file in the evidence directory is covered.
cd "$EVIDENCE_DIR"
find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 shasum -a 256 > SHA256SUMS

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
