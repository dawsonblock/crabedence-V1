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

# Gate semantics live in exactly one validator, shared with release
# admission and the standalone artifact verifier.
source "$REPO_ROOT/scripts/lib/qualification-gates.sh"
# Live-database gates fail closed on their own: a gate that needs
# PostgreSQL records FAIL when none is configured, rather than letting the
# suite skip and be recorded as a zero-test PASS.
source "$REPO_ROOT/scripts/lib/live-gate.sh"
# Gate logs record the command line; credential-bearing KEY=value tokens
# are redacted so a secret never lands in the evidence bundle.
source "$REPO_ROOT/scripts/lib/redact.sh"
source "$REPO_ROOT/scripts/lib/evidence-inventory.sh"

# ─── Release identity (Phase 02) ────────────────────────────────────────
# The canonical release identity is declared once, up front: the record's
# embedded version is the VERSION file's, and only that value may label
# the manifest. A mismatch is a provenance defect — fail before any gate
# runs rather than producing an inconsistently-named bundle.
if [ -z "${RELEASE_VERSION:-}" ]; then
  echo "ERROR: RELEASE_VERSION must be set (e.g., 1.0.0-rc.7)" >&2
  echo "       Refusing to use a hardcoded default." >&2
  exit 1
fi
VERSION_FILE="$(tr -d '[:space:]' < "$REPO_ROOT/VERSION")"
if [ "$RELEASE_VERSION" != "$VERSION_FILE" ]; then
  echo "ERROR: RELEASE_VERSION=$RELEASE_VERSION does not equal VERSION ($VERSION_FILE)" >&2
  echo "       The embedded release version must equal the canonical version source." >&2
  exit 1
fi
RELEASE_NAME="${RELEASE_NAME:-crabedence-v${RELEASE_VERSION}}"

# Clean previous generated artifacts.
rm -f "$EVIDENCE_DIR"/*.json "$EVIDENCE_DIR"/SHA256SUMS \
  "$EVIDENCE_DIR"/source-tree-sha256.txt "$EVIDENCE_DIR"/source-tree-git-blobs.txt \
  "$EVIDENCE_DIR"/provenance.json "$EVIDENCE_DIR"/artifact.json \
  "$EVIDENCE_DIR"/toolchains.json "$EVIDENCE_DIR"/environment.json \
  "$EVIDENCE_DIR"/FINAL_QUALIFICATION_REPORT.md
rm -rf "$EVIDENCE_DIR/gate-results" "$EVIDENCE_DIR/gates"
mkdir -p "$EVIDENCE_DIR/gate-results"

# ─── Gate tracking ─────────────────────────────────────────────────────────
# Each gate records: name, status (PASS/FAIL/NOT_RUN), exit code, log file,
# and tests_executed (for test-suite gates; empty for non-test gates).
declare -a GATE_NAMES=()
declare -a GATE_TYPES=()
declare -a GATE_STATUS=()
declare -a GATE_EXIT=()
declare -a GATE_LOG=()
declare -a GATE_TESTS=()
declare -a GATE_DURATION=()
# Per-gate test_suite evidence binding (JSON object, empty when the gate
# carries none). Live virtualization lanes bind their per-test results
# here so the shared validator can check the required-test inventory.
declare -a GATE_SUITE=()

# now_ms prints the current epoch time in milliseconds. perl is already a
# release dependency (shasum is perl); the date fallback is
# second-granularity.
now_ms() {
  perl -MTime::HiRes=time -e 'printf "%d\n", time * 1000' 2>/dev/null \
    || echo "$(( $(date +%s) * 1000 ))"
}

# GATE_START_MS marks the start of the gate currently running;
# record_gate consumes it into duration_ms.
GATE_START_MS=""

record_gate() {
  local name="$1" type="$2" status="$3" exit_code="$4" log="$5" tests="${6:-}" suite_json="${7:-}"
  local duration=0
  if [ -n "${GATE_START_MS:-}" ]; then
    duration=$(( $(now_ms) - GATE_START_MS ))
    GATE_START_MS=""
  fi
  GATE_NAMES+=("$name")
  GATE_TYPES+=("$type")
  GATE_STATUS+=("$status")
  GATE_EXIT+=("$exit_code")
  GATE_LOG+=("$log")
  GATE_TESTS+=("$tests")
  GATE_DURATION+=("$duration")
  GATE_SUITE+=("$suite_json")
}

# ─── run_and_log (Phase 2) ──────────────────────────────────────────────────
# Captures the actual exit status of the command. Never swallows failures.
# Returns the command's real exit code so the caller can track gate status.
run_and_log() {
  local name="$1"
  shift
  local log="$EVIDENCE_DIR/gate-results/${name}.log"
  GATE_START_MS="$(now_ms)"
  {
    echo "command=$(redact_command "$@")"
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

# Run a mandatory gate of the given type. If it fails, record FAIL and
# continue (so all gates run and evidence is preserved). The final
# qualification.json will mark the release as not promotable.
run_gate() {
  local name="$1"
  local type="$2"
  shift 2
  local log="$EVIDENCE_DIR/gate-results/${name}.log"
  if run_and_log "$name" "$@"; then
    record_gate "$name" "$type" "PASS" 0 "$log"
    echo "  PASS  $name"
  else
    local rc=$?
    record_gate "$name" "$type" "FAIL" "$rc" "$log"
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

# One timestamp for the whole qualification run. Every derived artifact
# (qualification provenance, evidence manifest, evidence root, report)
# binds THIS value — downstream regeneration reads it back from the
# records instead of sampling the clock again, which is what makes
# re-finalization byte-identical.
EVIDENCE_TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

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
# The canonical source manifest generator (scripts/generate-source-manifest.sh)
# treats the Git HEAD tree as authoritative — the same tree `git archive
# HEAD` packages — and records regular/executable/symlink identity, so the
# manifest cannot diverge from the released archive and needs no
# hand-maintained exclusion list.
bash "$REPO_ROOT/scripts/generate-source-manifest.sh" \
  "$EVIDENCE_DIR/source-tree-sha256.txt" "$REPO_ROOT" 2>&1 | \
  tee "$EVIDENCE_DIR/gate-results/source-manifest-generate.log"

# Git blob manifest: path → git_blob_id (for Git-native verification).
# ls-files reports paths relative to REPO_ROOT, while "HEAD:$file"
# resolves against the repository root; the "./" form keeps the lookup
# anchored at REPO_ROOT in both standalone and nested checkouts.
git -C "$REPO_ROOT" ls-files -z -- . ':(exclude)release-evidence/' ':(exclude)dist/' | sort -z | while IFS= read -r -d '' file; do
  blob="$(git -C "$REPO_ROOT" rev-parse "HEAD:./$file")"
  echo "$blob  $file"
done > "$EVIDENCE_DIR/source-tree-git-blobs.txt"

# ─── Phase 7: Verify source manifest ────────────────────────────────────────
# Use the canonical bidirectional verifier (scripts/verify-source-manifest.sh)
# instead of inline logic. The canonical script checks both:
#   1. manifest → source (every manifest entry exists and matches)
#   2. source → manifest (no unexpected files added after generation)
MANIFEST_VERIFY="$EVIDENCE_DIR/gate-results/source-manifest-verify.log"
GATE_START_MS="$(now_ms)"
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
    record_gate "source_manifest" "PROVENANCE" "PASS" 0 "$MANIFEST_VERIFY"
  else
    echo "status=FAIL"
    record_gate "source_manifest" "PROVENANCE" "FAIL" 1 "$MANIFEST_VERIFY"
  fi
  echo "finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >> "$MANIFEST_VERIFY"
echo "  $(grep 'status=' "$MANIFEST_VERIFY" | tail -1 | cut -d= -f2)  source_manifest"

# ─── Phase 21: Toolchain identity ───────────────────────────────────────────
GO_VERSION="$(go version 2>/dev/null || echo 'unavailable')"
GO_ENV_GOVERSION="$(go env GOVERSION 2>/dev/null || echo 'unavailable')"
GO_ENV_GOTOOLCHAIN="$(go env GOTOOLCHAIN 2>/dev/null || echo 'unavailable')"
GO_MOD_TOOLCHAIN="$(sed -n 's/^toolchain \(go[0-9][0-9.]*\).*/\1/p' "$REPO_ROOT/go.mod")"
GO_MOD_TOOLCHAIN="${GO_MOD_TOOLCHAIN%%$'\n'*}"
NODE_VERSION="$(node --version 2>/dev/null || echo 'unavailable')"
NPM_VERSION="$(npm --version 2>/dev/null || echo 'unavailable')"
WORKER_PKG_VERSION="$(node -e "console.log(require('./worker/package.json').version)" 2>/dev/null || echo 'unavailable')"
GIT_VERSION="$(git --version 2>/dev/null || echo 'unavailable')"
PG_VERSION="$(psql --version 2>/dev/null || echo 'not-installed')"

# Live-database qualification environment: capture the PostgreSQL
# SERVER version and the Effect Fabric schema migration version so the
# evidence records exactly what the live gates ran against.
PG_SERVER_VERSION="unavailable"
SCHEMA_VERSION="unavailable"
if [ -n "${CRABBOX_TEST_DATABASE_URL:-}" ]; then
  PG_SERVER_VERSION="$(psql "$CRABBOX_TEST_DATABASE_URL" -tAc 'SHOW server_version' 2>/dev/null | tr -d '[:space:]' || true)"
  PG_SERVER_VERSION="${PG_SERVER_VERSION:-unavailable}"
  SCHEMA_VERSION="$(psql "$CRABBOX_TEST_DATABASE_URL" -tAc 'SELECT COALESCE(MAX(version),0) FROM schema_migrations' 2>/dev/null | tr -d '[:space:]' || true)"
  SCHEMA_VERSION="${SCHEMA_VERSION:-unavailable}"
fi

cat > "$EVIDENCE_DIR/toolchains.json" << EOF
{
  "go": "$GO_VERSION",
  "goversion": "$GO_ENV_GOVERSION",
  "gotoolchain": "$GO_ENV_GOTOOLCHAIN",
  "go_toolchain_directive": "$GO_MOD_TOOLCHAIN",
  "node": "$NODE_VERSION",
  "npm": "$NPM_VERSION",
  "git": "$GIT_VERSION",
  "postgres_client": "$PG_VERSION",
  "postgres_server": "$PG_SERVER_VERSION",
  "effect_fabric_schema_version": "$SCHEMA_VERSION",
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

# exact-toolchain: the release must execute on EXACTLY the toolchain go.mod
# declares — not merely some Go 1.26.x — with GOTOOLCHAIN=local so the go
# command cannot substitute another toolchain mid-qualification. The gate's
# own log carries go version / go env GOVERSION / go env GOTOOLCHAIN.
run_gate exact-toolchain BUILD bash "$REPO_ROOT/scripts/verify-go-toolchain.sh" "$REPO_ROOT"

# ─── Phase 8-9: Go gates (uncached, -count=1) ───────────────────────────────
echo ""
echo "=== Go gates ==="
run_gate go-vet STATIC_ANALYSIS go vet ./...
run_gate go-evidence-tests TEST go test -v -count=1 -timeout=120s \
  -run "TestTerminalReceipt|TestTerminalLog|TestRunEvidence|TestFinalizeRun|TestEvidence|TestCoordinatorFinish|TestCoordinatorRunReceipt|TestReceipt|TestRunRecorder|TestTiming" \
  ./internal/cli/
run_gate go-tart-tests TEST go test -v -count=1 -timeout=120s ./internal/providers/tart/
run_gate go-lume-tests TEST go test -v -count=1 -timeout=60s ./internal/providers/lume/
run_gate go-shared-tests TEST go test -v -count=1 -timeout=60s ./internal/providers/shared/

# Phase 9: Go race evidence
run_gate go-race-evidence TEST go test -v -race -count=1 -timeout=120s \
  -run "TestTerminalReceipt|TestTerminalLog|TestRunEvidence|TestFinalizeRun|TestEvidence|TestReceiptContract" \
  ./internal/cli/
run_gate go-race-providers TEST go test -v -race -count=1 -timeout=120s \
  ./internal/providers/tart/ ./internal/providers/lume/ ./internal/providers/shared/

# The sandbox executor is its own lane. It is the component that boots
# untrusted code, and its race suite is the only thing that exercises the
# policy, dispatch and recovery paths under concurrency — including the
# hard-crash qualification that SIGKILLs the daemon mid-job. Folding it
# into a general Go gate would hide a regression in the one package whose
# failure mode is executing something nobody authorized.
run_gate go-race-sandboxexecutor TEST go test -v -race -count=1 -timeout=1200s \
  ./internal/sandboxexecutor/

# ─── Live microVM lanes ──────────────────────────────────────────────────────
# The real-microVM qualification, per virtualization lane. A lane gate
# proves what no source-level fake can: a real VM booting under the
# authorized policy, refusing a substituted instance, unable to reach the
# network or host credentials, producing an artifact whose digest
# survives independent verification — on exactly one backend.
#
# Lane separation is load-bearing: Apple Hypervisor Framework evidence
# never qualifies Linux KVM and vice versa. Gate ids come from the
# authoritative inventory (qualification/required-tests.json), which is
# copied into the bundle and digest-bound to each lane gate so the
# required-case set cannot be forged or swapped.
#
# A lane gate is registered when:
#   (a) the release claims it via CRABBOX_QUALIFY_LANES, or
#   (b) this host provides it with a usable pinned runtime.
# A claimed lane that cannot produce passing per-test evidence records
# FAIL — a claim never skips. Imported lane evidence (a sibling run's
# raw stream + case results under CRABBOX_LANE_EVIDENCE_DIR/<lane>/)
# is accepted only when it passes the same inventory check and binds to
# this exact source commit — borrowed evidence from another build fails.

REQUIRED_TESTS_REL="required-tests.json"
REQUIRED_TESTS_SRC="$REPO_ROOT/qualification/$REQUIRED_TESTS_REL"
REQUIRED_TESTS_SHA=""
if [ -f "$REQUIRED_TESTS_SRC" ]; then
  cp "$REQUIRED_TESTS_SRC" "$EVIDENCE_DIR/$REQUIRED_TESTS_REL"
  REQUIRED_TESTS_SHA="$(shasum -a 256 "$EVIDENCE_DIR/$REQUIRED_TESTS_REL" | awk '{print $1}')"
fi

# The trusted runtime pins in force for this qualification ride in the
# bundle too — a verifier can check which digests the live lane was
# required to match, not just what the lane claims ran.
MSB_PINS_SRC="$REPO_ROOT/qualification/msb-runtime-pins.json"
if [ -f "$MSB_PINS_SRC" ]; then
  cp "$MSB_PINS_SRC" "$EVIDENCE_DIR/msb-runtime-pins.json"
fi

# Normalize claimed lane names: accept the short aliases "apple" and
# "kvm" as well as the canonical inventory lane ids.
normalize_claimed_lanes() {
  local out="" l
  for l in $1; do
    case "$l" in
      apple|apple-hypervisor|apple-hypervisor-framework) out="$out apple-hypervisor-framework" ;;
      kvm|linux|linux-kvm) out="$out linux-kvm" ;;
      *) out="$out $l" ;;
    esac
  done
  echo "${out# }"
}
CLAIMED_LANES="$(normalize_claimed_lanes "${CRABBOX_QUALIFY_LANES:-}")"
LANE_IMPORT_DIR="${CRABBOX_LANE_EVIDENCE_DIR:-}"

# The lane this host can provide.
HOST_LANE=""
case "$(uname -s)" in
  Darwin) [ "$(sysctl -n kern.hv_support 2>/dev/null)" = "1" ] && HOST_LANE="apple-hypervisor-framework" ;;
  Linux)  [ -c /dev/kvm ] && HOST_LANE="linux-kvm" ;;
esac

MSB_BIN="${CRABBOX_MSB_BIN:-$HOME/.microsandbox/bin/msb}"
if [ ! -x "$MSB_BIN" ]; then
  MSB_BIN="$(command -v msb 2>/dev/null || true)"
fi
MSB_USABLE=false
MSB_UNUSABLE_REASON="msb missing or doctor failed"
if [ -n "$MSB_BIN" ] && [ -x "$MSB_BIN" ] && "$MSB_BIN" doctor >/dev/null 2>&1; then
  # A healthy msb is necessary but not sufficient: a qualification lane
  # must run on byte-identical trusted runtime + firmware, so whatever
  # is installed is verified against qualification/msb-runtime-pins.json
  # before a live lane may run on it.
  if pin_err="$(bash "$REPO_ROOT/scripts/verify-msb-runtime-pins.sh" "$MSB_BIN" 2>&1)"; then
    MSB_USABLE=true
  else
    MSB_UNUSABLE_REASON="$(printf '%s\n' "$pin_err" | sed 's/^ERROR: //' | tr '\n' ' ')"
  fi
fi

# build_test_suite_json <lane> <cases-file> <raw-file>
# Emits the test_suite binding object for a lane gate whose evidence
# files exist in the bundle.
build_test_suite_json() {
  local lane="$1" cases="$2" raw="$3"
  jq -cn --arg lane "$lane" \
    --arg inv_file "$REQUIRED_TESTS_REL" --arg inv_sha "$REQUIRED_TESTS_SHA" \
    --arg res_file "gate-results/$(basename "$cases")" \
    --arg res_sha "$(shasum -a 256 "$cases" | awk '{print $1}')" \
    --arg raw_file "gate-results/$(basename "$raw")" \
    --arg raw_sha "$(shasum -a 256 "$raw" | awk '{print $1}')" \
    '{suite:"live-microvm", lane:$lane,
      inventory:{file:$inv_file, sha256:$inv_sha},
      results:{file:$res_file, sha256:$res_sha},
      raw:{file:$raw_file, sha256:$raw_sha}}'
}

# register_lane_fail <gate-id> <reason>
# A claimed lane that cannot produce passing per-test evidence records
# an honest FAIL — never an absent gate on a claimed lane.
register_lane_fail() {
  local gid="$1" reason="$2"
  local log="$EVIDENCE_DIR/gate-results/${gid}.log"
  GATE_START_MS="$(now_ms)"
  {
    echo "command=live microVM qualification lane $gid"
    echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "---"
    echo "FAIL: $reason"
    echo "tests_discovered=0"
    echo "tests_passed=0"
    echo "tests_failed=1"
    echo "tests_skipped=0"
    echo "---"
    echo "finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "exit=1"
  } > "$log"
  record_gate "$gid" TEST FAIL 1 "$log"
  echo "  FAIL  $gid ($reason)"
}

# register_lane_import <lane> <gate-id>
# Accept per-test evidence produced for this lane on another host —
# only when the case results satisfy the inventory AND are bound to
# this exact source commit. Evidence for a different build is refused.
# lane_import_source <lane>
# Finds imported evidence for a lane under CRABBOX_LANE_EVIDENCE_DIR.
# Each import directory holds cases.json + test.json; the lane is read
# from the cases record itself (a directory named for a lane proves
# nothing — the record's own lane field is authoritative).
lane_import_source() {
  local lane="$1" d
  [ -d "$LANE_IMPORT_DIR" ] || return 1
  for d in "$LANE_IMPORT_DIR"/*/; do
    [ -f "$d/cases.json" ] && [ -f "$d/test.json" ] || continue
    if [ "$(jq -r '.lane // empty' "$d/cases.json" 2>/dev/null)" = "$lane" ]; then
      echo "$d"
      return 0
    fi
  done
  return 1
}

register_lane_import() {
  local lane="$1" gid="$2"
  local srcdir="$3"
  local log="$EVIDENCE_DIR/gate-results/${gid}.log"
  local cases="$EVIDENCE_DIR/gate-results/${gid}.cases.json"
  local raw="$EVIDENCE_DIR/gate-results/${gid}.test.json"
  GATE_START_MS="$(now_ms)"
  cp "$srcdir/cases.json" "$cases"
  cp "$srcdir/test.json" "$raw"
  {
    echo "command=imported live microVM lane evidence ($lane) from $srcdir"
    echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "---"
  } > "$log"
  local imported_commit findings=""
  imported_commit="$(jq -r '.source_commit // empty' "$cases" 2>/dev/null)"
  if [ "$imported_commit" != "$COMMIT" ]; then
    findings="imported results commit ${imported_commit:-<missing>} does not match the qualified commit $COMMIT"
  else
    findings="$(required_tests_case_findings "$cases" "$EVIDENCE_DIR/$REQUIRED_TESTS_REL" "$lane" || true)"
  fi
  local passed failed
  passed="$(jq '.counts.passed // 0' "$cases" 2>/dev/null || echo 0)"
  failed="$(jq '.counts.failed // 0' "$cases" 2>/dev/null || echo 0)"
  {
    echo "imported_from=$srcdir"
    echo "imported_commit=$imported_commit"
    [ -n "$findings" ] && echo "$findings"
    echo "tests_passed=$passed"
    echo "tests_failed=$failed"
    echo "---"
    echo "finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >> "$log"
  if [ -n "$findings" ] || [ "$failed" -gt 0 ] || [ "$passed" -le 0 ]; then
    echo "exit=1" >> "$log"
    record_gate "$gid" TEST FAIL 1 "$log"
    echo "  FAIL  $gid (imported $lane evidence does not satisfy the required-test inventory)"
    return
  fi
  echo "exit=0" >> "$log"
  record_gate "$gid" TEST PASS 0 "$log" "" \
    "$(build_test_suite_json "$lane" "$cases" "$raw")"
  echo "  PASS  $gid ($passed cases, imported $lane evidence)"
}

# register_lane_live <lane> <gate-id>
# Run the live suite on this host under `go test -json`, then normalize
# the stream into per-case evidence bound to this commit and toolchain.
# The shared validator re-checks it against the bundled inventory, so a
# "passing" run that skipped an isolation case cannot produce an
# admissible record.
register_lane_live() {
  local lane="$1" gid="$2"
  local log="$EVIDENCE_DIR/gate-results/${gid}.log"
  local raw="$EVIDENCE_DIR/gate-results/${gid}.test.json"
  local cases="$EVIDENCE_DIR/gate-results/${gid}.cases.json"
  GATE_START_MS="$(now_ms)"
  {
    echo "command=env CRABBOX_MSB_LIVE=1 CRABBOX_MSB_QUALIFY=1 go test -json -race -count=1 -timeout=1200s -run '^TestMSBLive' ./internal/sandboxexecutor/"
    echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "---"
  } > "$log"
  set +e
  env CRABBOX_MSB_LIVE=1 CRABBOX_MSB_QUALIFY=1 \
    go test -json -race -count=1 -timeout=1200s -run '^TestMSBLive' \
    ./internal/sandboxexecutor/ > "$raw" 2>>"$log"
  local rc=$?
  set -e
  {
    echo "---"
    echo "go_test_exit=$rc"
    echo "finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >> "$log"
  # Normalize the raw stream into per-case evidence; also verify the
  # inventory still covers every suite test in source.
  set +e
  python3 "$REPO_ROOT/scripts/go-test-case-evidence.py" \
    --stream "$raw" --out "$cases" \
    --suite live-microvm --lane "$lane" \
    --commit "$COMMIT" --toolchain-go "$GO_VERSION" \
    --inventory "$EVIDENCE_DIR/$REQUIRED_TESTS_REL" \
    --source-root "$REPO_ROOT" >>"$log" 2>&1
  local norm_rc=$?
  set -e
  local passed failed skipped findings=""
  passed="$(jq '.counts.passed // 0' "$cases" 2>/dev/null || echo 0)"
  failed="$(jq '.counts.failed // 0' "$cases" 2>/dev/null || echo 0)"
  skipped="$(jq '.counts.skipped // 0' "$cases" 2>/dev/null || echo 0)"
  {
    echo "tests_passed=$passed"
    echo "tests_failed=$failed"
    echo "tests_skipped=$skipped"
  } >> "$log"
  if [ "$norm_rc" -eq 0 ]; then
    findings="$(required_tests_case_findings "$cases" "$EVIDENCE_DIR/$REQUIRED_TESTS_REL" "$lane" || true)"
    [ -n "$findings" ] && echo "$findings" >> "$log"
  fi
  # A skip of a lane-foreign case (the other lane's platform-specific
  # test) is honest evidence — required-case skips are already findings
  # from the inventory check above, so a blanket skipped>0 check would
  # fail a correct lane for its foreign cases.
  if [ "$rc" -ne 0 ] || [ "$norm_rc" -ne 0 ] || [ -n "$findings" ] \
    || [ "$failed" -gt 0 ] || [ "$passed" -le 0 ]; then
    echo "exit=1" >> "$log"
    record_gate "$gid" TEST FAIL 1 "$log"
    echo "  FAIL  $gid (rc=$rc normalize=$norm_rc passed=$passed failed=$failed skipped=$skipped)"
    return
  fi
  echo "exit=0" >> "$log"
  record_gate "$gid" TEST PASS 0 "$log" "" \
    "$(build_test_suite_json "$lane" "$cases" "$raw")"
  echo "  PASS  $gid ($passed cases, lane $lane)"
}

lane_is_claimed() {
  case " $CLAIMED_LANES " in
    *" $1 "*) return 0 ;;
    *) return 1 ;;
  esac
}

if [ -n "$CLAIMED_LANES" ] && [ -z "$REQUIRED_TESTS_SHA" ]; then
  echo "  ERROR  claimed lanes ($CLAIMED_LANES) require qualification/required-tests.json — refusing to qualify lane claims without the authoritative inventory" >&2
  register_lane_fail "live-microvm-uninventoried" "claimed lanes without required-tests.json"
elif [ -n "$REQUIRED_TESTS_SHA" ]; then
  for LANE in $(jq -r '.lanes | keys[]' "$EVIDENCE_DIR/$REQUIRED_TESTS_REL"); do
    GATE_ID="$(jq -r --arg l "$LANE" '.lanes[$l].gate_id' "$EVIDENCE_DIR/$REQUIRED_TESTS_REL")"
    if [ "$LANE" = "$HOST_LANE" ] && [ "$MSB_USABLE" = true ]; then
      register_lane_live "$LANE" "$GATE_ID"
    elif lane_is_claimed "$LANE"; then
      IMPORT_SRC="$(lane_import_source "$LANE" || true)"
      if [ -n "$IMPORT_SRC" ]; then
        register_lane_import "$LANE" "$GATE_ID" "$IMPORT_SRC"
      elif [ "$LANE" = "$HOST_LANE" ]; then
        register_lane_fail "$GATE_ID" "claimed lane $LANE but the pinned runtime is unusable on this host ($MSB_UNUSABLE_REASON)"
      else
        register_lane_fail "$GATE_ID" "claimed lane $LANE on a host that provides ${HOST_LANE:-no lane}, and no imported evidence under CRABBOX_LANE_EVIDENCE_DIR"
      fi
    else
      echo "  --    $GATE_ID (lane not claimed and this host provides ${HOST_LANE:-no lane} — no evidence recorded)"
    fi
  done
else
  echo "  --    live-microvm (no required-test inventory — lane gates not registered)"
fi

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
run_gate effect-fabric-contract TEST go test -v -count=1 -timeout=60s \
  -run "TestState|TestLeaseConfig|TestAcquireResult|TestTerminalReceipt|TestRecovery|TestLeaseError|TestMigrateState|TestDefaultLeaseConfig|TestFixedClock|TestSystemClock" \
  ./internal/idempotency/

# effect-fabric-reconciliation: reconciliation worker unit tests.
# Verifies NoopResolver, resolver registration, and fail-closed behavior.
run_gate effect-fabric-reconciliation TEST go test -v -count=1 -timeout=60s \
  ./internal/reconcile/

# effect-fabric-evidence: the signed-receipt trust boundary that gates
# every CRITICAL terminal transition. Signature verification, trusted-
# signer enforcement, binding checks, tamper rejection, and signer
# persistence are mandatory release evidence — vet compiles the
# package but does not execute its adversarial tests.
run_gate effect-fabric-evidence TEST go test -v -race -count=1 -timeout=60s \
  ./internal/evidence/

# effect-fabric-post-dispatch-timeout: the >30-second qualification for
# the client dispatch boundary. A mutation that outlives the production
# client wait must come back as an ambiguous failure (the client's
# POST_DISPATCH classification) while the service — which never learned
# the client left — still reaches its durable terminal outcome; and a
# response that arrives after the service's 60-second connection
# lifetime must still be delivered, so a longer client wait is
# meaningful. Both properties are wall-clock properties of the
# production defaults, so they cannot be shortened: ~100 seconds total.
run_gate effect-fabric-post-dispatch-timeout TEST env CRABBOX_QUALIFICATION_POST_DISPATCH=1 \
  go test -v -count=1 -timeout=240s \
  -run 'TestPostDispatchTimeoutQualification|TestLateResponseAfterConnectionLifetime' ./internal/execution/

# effect-fabric-race: race-detector run over the execution + idempotency
# + capability + reconcile packages. Closes concurrent-acquisition races
# and stale-worker fencing violations.
# Unset CRABBOX_TEST_DATABASE_URL so live tests skip — the race gate
# should not run live PostgreSQL tests (they're too slow with -race
# and are covered by effect-fabric-postgres separately).
run_gate effect-fabric-race TEST env -u CRABBOX_TEST_DATABASE_URL \
  go test -v -race -count=1 -timeout=120s \
  ./internal/capability/ ./internal/execution/ ./internal/evidence/ ./internal/idempotency/ ./internal/reconcile/

# ─── Registry policy identity ───────────────────────────────────────────────
# The qualified policy identity: the digest of the exact built-in
# capability registry this source ships, plus the verifiable envelope
# (digest + the canonical descriptor bytes it covers) so any consumer —
# the standalone verifier included — recomputes SHA-256 over the bytes it
# was given without a Go toolchain. The release artifact binds this
# value and the runtime serves it: qualified policy = released policy =
# runtime policy.
run_gate registry-digest PROVENANCE go run ./cmd/registry-digest

# NeMo transfer provenance: the format-2 manifest must verify against the
# frozen reference source — file content, executable bits, symlink targets,
# typed delta. -require-source makes a missing reference a hard failure,
# which is what release admission means here.
run_gate nemo-transfer-provenance PROVENANCE \
  bash "$REPO_ROOT/scripts/verify-nemo-provenance.sh" --require-source

REGISTRY_SHA256="$(sed -n 's/^\([0-9a-f]\{64\}\)$/\1/p' "$EVIDENCE_DIR/gate-results/registry-digest.log" | tail -1)"
if [ -z "$REGISTRY_SHA256" ]; then
  echo "ERROR: registry-digest gate produced no digest — the release cannot bind its policy identity" >&2
  tail -5 "$EVIDENCE_DIR/gate-results/registry-digest.log" >&2 || true
  exit 1
fi
echo "$REGISTRY_SHA256" > "$EVIDENCE_DIR/registry.sha256"
go run ./cmd/registry-digest -envelope > "$EVIDENCE_DIR/registry.json"
if ! grep -q "$REGISTRY_SHA256" "$EVIDENCE_DIR/registry.json"; then
  echo "ERROR: registry envelope does not carry the qualified digest" >&2
  exit 1
fi

# Qualification registry identity: the release registry plus the explicit
# qualification extensions. The extension record binds both identities,
# so the evidence shows exactly which descriptors separate the qualified
# policy from the shipped policy — and that no release descriptor was
# replaced or modified.
go run ./cmd/registry-digest -qualification -envelope > "$EVIDENCE_DIR/qualification-registry.json"
go run ./cmd/registry-digest -extensions > "$EVIDENCE_DIR/qualification-registry-extensions.json"
QUALIFICATION_REGISTRY_SHA256="$(jq -r '.registry_sha256' "$EVIDENCE_DIR/qualification-registry.json")"
if [ -z "$QUALIFICATION_REGISTRY_SHA256" ] || [ "$QUALIFICATION_REGISTRY_SHA256" = "null" ]; then
  echo "ERROR: qualification registry envelope carries no digest" >&2
  exit 1
fi
echo "$QUALIFICATION_REGISTRY_SHA256" > "$EVIDENCE_DIR/qualification-registry.sha256"
if [ "$(jq -r '.base_registry_sha256' "$EVIDENCE_DIR/qualification-registry-extensions.json")" != "$REGISTRY_SHA256" ]; then
  echo "ERROR: qualification extension record does not bind the release registry digest" >&2
  exit 1
fi
if [ "$(jq -r '.qualification_registry_sha256' "$EVIDENCE_DIR/qualification-registry-extensions.json")" != "$QUALIFICATION_REGISTRY_SHA256" ]; then
  echo "ERROR: qualification extension record does not bind the qualification registry digest" >&2
  exit 1
fi

# NeMo Relay runtime identity. A release ships two runtimes, and the source
# commit identifies only one of them: the registry digest binds the capability
# policy, and this binds the vendored NeMo Relay tree the distribution carries
# — including the local integration crates and the MCP credential patch. Both
# land in the evidence directory, so SHA256SUMS covers them and the manifest
# digest and attestation carry them.
go run ./cmd/nemo-runtime-digest -envelope > "$EVIDENCE_DIR/nemo-runtime.json"
NEMO_RUNTIME_SHA256="$(jq -r '.nemo_runtime_sha256' "$EVIDENCE_DIR/nemo-runtime.json")"
if [ -z "$NEMO_RUNTIME_SHA256" ] || [ "$NEMO_RUNTIME_SHA256" = "null" ]; then
  echo "ERROR: NeMo Relay runtime envelope carries no digest — the release cannot bind the runtime it ships" >&2
  exit 1
fi
echo "$NEMO_RUNTIME_SHA256" > "$EVIDENCE_DIR/nemo-runtime.sha256"

# ─── Phase 10-12: Live PostgreSQL gates ────────────────────────────────────
echo ""
echo "=== Live PostgreSQL gates ==="

# Live PostgreSQL gates fail closed. Without CRABBOX_TEST_DATABASE_URL the
# tests skip themselves and exit 0, which must NOT be recorded as PASS.
# The wrapper checks the env var, runs Vitest with JSON output to a
# SEPARATE pure JSON file (not the decorated log), and parses that file
# to require a nonzero number of executed tests.
run_live_postgres_gate() {
  GATE_START_MS="$(now_ms)"
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
    record_gate "$name" "INTEGRATION" "FAIL" 1 "$log"
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
    record_gate "$name" "INTEGRATION" "FAIL" "$rc" "$log"
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
    record_gate "$name" "INTEGRATION" "FAIL" 1 "$log"
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
    record_gate "$name" "INTEGRATION" "FAIL" 1 "$log"
    echo "  FAIL  $name (0 tests executed, all skipped)"
    return
  fi

  record_gate "$name" "INTEGRATION" "PASS" 0 "$log"
  echo "  PASS  $name ($executed_tests tests executed)"
}

# The Vitest live gates run the worker package's locked Vitest — install
# it before the first gate that can need it, not only before the worker
# section far below. CI installs worker deps before invoking this script;
# a standalone run must satisfy the same precondition itself.
npm ci --prefix worker

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
  GATE_START_MS="$(now_ms)"
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
    record_gate "$name" "INTEGRATION" "FAIL" 1 "$log"
    echo "  FAIL  $name (CRABBOX_TEST_DATABASE_URL not set)"
    return
  fi

  {
    echo "command=go test -json -count=1 -p 1 -timeout=300s -run 'TestLive|TestStoreConformance' ./internal/idempotency/ ./internal/reconcile/ ./internal/execution/"
    echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "---"
  } > "$log"

  local json_out="$EVIDENCE_DIR/effect-fabric-postgres.json"
  set +e
  # Run ALL live PostgreSQL tests in the effect-fabric packages — not a
  # curated name pattern. A pattern that silently excludes new live
  # tests (as "TestLiveEffectFabric|TestLiveStore" did) lets release
  # evidence claim coverage that was never exercised. -p 1 serializes
  # the packages: all three share one database, and the reconcile
  # worker's table-wide claim batch would otherwise race another
  # package's live assertions. -json produces structured per-test
  # pass/fail/skip accounting for the evidence bundle.
  # TestStoreConformance is included explicitly: the cross-engine
  # conformance suite runs its PostgreSQL leg whenever the database URL
  # is set (it is not TestLive-prefixed), so excluding it would drop
  # engine-parity coverage — epoch fencing, observation fidelity, and
  # lifecycle semantics — from the release evidence.
  go test -json -count=1 -p 1 -timeout=300s \
    -run "TestLive|TestStoreConformance" \
    ./internal/idempotency/ ./internal/reconcile/ ./internal/execution/ \
    > "$json_out" 2>&1
  local rc=$?
  set -e
  cat "$json_out" >> "$log"

  {
    echo "---"
    echo "finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "exit=$rc"
  } >> "$log"

  # Structured accounting: count per-test actions from the -json
  # stream (test events carry .Test; package events do not).
  local discovered passed failed skipped
  discovered=$(jq -r '[.[]? | select(.Test != null and (.Action == "pass" or .Action == "fail" or .Action == "skip"))] | length' \
    < <(jq -s '.' "$json_out" 2>/dev/null || echo '[]') 2>/dev/null || echo 0)
  passed=$(jq -r '[.[]? | select(.Test != null and .Action == "pass")] | length' \
    < <(jq -s '.' "$json_out" 2>/dev/null || echo '[]') 2>/dev/null || echo 0)
  failed=$(jq -r '[.[]? | select(.Test != null and .Action == "fail")] | length' \
    < <(jq -s '.' "$json_out" 2>/dev/null || echo '[]') 2>/dev/null || echo 0)
  skipped=$(jq -r '[.[]? | select(.Test != null and .Action == "skip")] | length' \
    < <(jq -s '.' "$json_out" 2>/dev/null || echo '[]') 2>/dev/null || echo 0)

  {
    echo "tests_discovered=$discovered"
    echo "tests_passed=$passed"
    echo "tests_failed=$failed"
    echo "tests_skipped=$skipped"
  } >> "$log"

  # Mandatory live gate: fail on any failure, on zero passes, and on
  # any skip — a SKIP is not evidence of execution.
  if [ "$rc" -ne 0 ] || [ "$failed" -gt 0 ] || [ "$passed" -le 0 ] || [ "$skipped" -gt 0 ]; then
    {
      echo ""
      echo "FAIL: discovered=$discovered passed=$passed failed=$failed skipped=$skipped exit=$rc (mandatory live gate requires >0 passes, 0 failures, 0 skips)"
      echo "exit=1"
    } >> "$log"
    record_gate "$name" "INTEGRATION" "FAIL" 1 "$log"
    echo "  FAIL  $name (discovered=$discovered passed=$passed failed=$failed skipped=$skipped)"
    cat "$log"
    return
  fi

  record_gate "$name" "INTEGRATION" "PASS" 0 "$log"
  echo "  PASS  $name (discovered=$discovered passed=$passed failed=$failed skipped=$skipped)"
}

run_effect_fabric_postgres_gate

# provider-github-faults: dedicated evidence for the real external
# provider qualification — github.issue.create fault injection at every
# dispatch boundary, proving at-most-once external effect across crashes.
# The tests also run inside effect-fabric-postgres; this gate emits their
# own structured evidence file for the bundle.
run_provider_github_faults_gate() {
  GATE_START_MS="$(now_ms)"
  local name="provider-github-faults"
  local log="$EVIDENCE_DIR/gate-results/${name}.log"

  if [ -z "${CRABBOX_TEST_DATABASE_URL:-}" ]; then
    {
      echo "command=run_provider_github_faults_gate"
      echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      echo "---"
      echo "SKIP: CRABBOX_TEST_DATABASE_URL not set"
      echo "exit=1"
      echo "finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$log"
    record_gate "$name" "FAULT_INJECTION" "FAIL" 1 "$log"
    echo "  FAIL  $name (CRABBOX_TEST_DATABASE_URL not set)"
    return
  fi

  {
    echo "command=go test -json -count=1 -timeout=120s -run TestLiveGitHub ./internal/execution/"
    echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "---"
  } > "$log"

  local json_out="$EVIDENCE_DIR/provider-github-faults.json"
  set +e
  go test -json -count=1 -timeout=120s \
    -run "TestLiveGitHub" \
    ./internal/execution/ \
    > "$json_out" 2>&1
  local rc=$?
  set -e
  cat "$json_out" >> "$log"

  {
    echo "---"
    echo "finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "exit=$rc"
  } >> "$log"

  local discovered passed failed skipped
  discovered=$(jq -r '[.[]? | select(.Test != null and (.Action == "pass" or .Action == "fail" or .Action == "skip"))] | length' \
    < <(jq -s '.' "$json_out" 2>/dev/null || echo '[]') 2>/dev/null || echo 0)
  passed=$(jq -r '[.[]? | select(.Test != null and .Action == "pass")] | length' \
    < <(jq -s '.' "$json_out" 2>/dev/null || echo '[]') 2>/dev/null || echo 0)
  failed=$(jq -r '[.[]? | select(.Test != null and .Action == "fail")] | length' \
    < <(jq -s '.' "$json_out" 2>/dev/null || echo '[]') 2>/dev/null || echo 0)
  skipped=$(jq -r '[.[]? | select(.Test != null and .Action == "skip")] | length' \
    < <(jq -s '.' "$json_out" 2>/dev/null || echo '[]') 2>/dev/null || echo 0)

  {
    echo "tests_discovered=$discovered"
    echo "tests_passed=$passed"
    echo "tests_failed=$failed"
    echo "tests_skipped=$skipped"
  } >> "$log"

  if [ "$rc" -ne 0 ] || [ "$failed" -gt 0 ] || [ "$passed" -le 0 ] || [ "$skipped" -gt 0 ]; then
    {
      echo ""
      echo "FAIL: discovered=$discovered passed=$passed failed=$failed skipped=$skipped exit=$rc (provider fault gate requires >0 passes, 0 failures, 0 skips)"
      echo "exit=1"
    } >> "$log"
    record_gate "$name" "FAULT_INJECTION" "FAIL" 1 "$log"
    echo "  FAIL  $name (discovered=$discovered passed=$passed failed=$failed skipped=$skipped)"
    cat "$log"
    return
  fi

  record_gate "$name" "FAULT_INJECTION" "PASS" 0 "$log"
  echo "  PASS  $name (discovered=$discovered passed=$passed failed=$failed skipped=$skipped)"
}

run_provider_github_faults_gate

# provider-github-real-api: OPTIONAL real-provider qualification. The
# httptest fault harness proves the adapter protocol deterministically;
# this gate proves it against GitHub itself. Registered ONLY when a
# test token and repo are configured — a missing gate is never recorded
# as PASS, and a configured gate cannot pass by skipping.
if [ -n "${CRABBOX_GITHUB_TEST_TOKEN:-}" ] && [ -n "${CRABBOX_GITHUB_TEST_REPO:-}" ]; then
  run_gate provider-github-real-api INTEGRATION env \
    GITHUB_TOKEN="$CRABBOX_GITHUB_TEST_TOKEN" \
    CRABBOX_GITHUB_TEST_REPO="$CRABBOX_GITHUB_TEST_REPO" \
    go test -v -count=1 -timeout=120s \
    -run "TestRealGitHubAPI" ./internal/execution/
else
  echo "  SKIP  provider-github-real-api (CRABBOX_GITHUB_TEST_TOKEN/CRABBOX_GITHUB_TEST_REPO not configured — gate not applicable)"
fi

# ─── Authority store live PostgreSQL gate ─────────────────────────────────────
# Tests grant lookup, principal mismatch, capability mismatch, expiry,
# revocation, and database error handling.
echo ""
echo "=== Authority store live PostgreSQL gate ==="

run_authority_postgres_gate() {
  GATE_START_MS="$(now_ms)"
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
    record_gate "$name" "INTEGRATION" "FAIL" 1 "$log"
    echo "  FAIL  $name (CRABBOX_TEST_DATABASE_URL not set)"
    return
  fi

  {
    echo "command=go test -v -count=1 -timeout=120s -run TestLiveAuthority ./internal/authority/"
    echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "---"
  } > "$log"

  set +e
  go test -v -count=1 -timeout=120s \
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
    record_gate "$name" "INTEGRATION" "FAIL" "$rc" "$log"
    echo "  FAIL  $name (exit=$rc)"
    cat "$log"
    return
  fi

  local executed
  executed=$(grep -cE '^\s*--- (PASS|FAIL):' "$log" 2>/dev/null || true)
  if [ "$executed" -le 0 ]; then
    {
      echo ""
      echo "FAIL: 0 tests executed (all skipped or no match)"
      echo "exit=1"
    } >> "$log"
    record_gate "$name" "INTEGRATION" "FAIL" 1 "$log"
    echo "  FAIL  $name (0 tests executed)"
    return
  fi

  record_gate "$name" "INTEGRATION" "PASS" 0 "$log"
  echo "  PASS  $name ($executed tests executed)"
}

run_authority_postgres_gate

# ─── Phase 13: Cross-language conformance ───────────────────────────────────
echo ""
echo "=== Cross-language conformance ==="
# ─── External CRITICAL qualification gates ──────────────────────────────
# The external qualification provider runs in its own process with a
# durable ledger. Both gates require a live PostgreSQL: with none
# configured they record FAIL directly (run_required_live_go_gate) rather
# than letting the suite skip and be stored as a zero-test PASS that only
# the canonical validator would later reject.
run_required_live_go_gate critical-external INTEGRATION \
  go test -v -count=1 -timeout=300s \
  -run "TestLiveCriticalQualification(Commit|AmbiguityThenReconcile|DefinitiveRejection|EvidenceIntegrity|AuthorityMatrix|ClosedAuthoritySemantics|TimeoutThenReconcile|LookupOutageThenRecovery|CorruptedArtifact|RegistryExtensionBinding|CrashThenRecover)$" \
  ./internal/execution/
run_required_live_go_gate critical-faults FAULT_INJECTION \
  go test -v -count=1 -timeout=300s \
  -run "TestLiveCriticalQualification(FailBeforeAccept|TokenPayloadCollision)$" \
  ./internal/execution/

run_gate cross-language-conformance TEST \
  go test -v -count=1 -timeout=60s \
  -run "TestRunEvidenceConformanceCorpus|TestReceiptContractConformance" \
  ./internal/cli/

# ─── Phase 15: Worker gates ────────────────────────────────────────────────
echo ""
echo "=== Worker gates ==="
# Worker dependencies were installed before the live postgres gates above.
run_gate worker-typecheck STATIC_ANALYSIS npm run check --prefix worker
run_gate worker-tests TEST npm test --prefix worker
run_gate worker-format STATIC_ANALYSIS npm run format:check --prefix worker
run_gate worker-lint STATIC_ANALYSIS npm run lint --prefix worker
run_gate worker-build BUILD npm run build --prefix worker

# ─── Phase NEMO: NeMo kernel/adapter gates ────────────────────────────────
echo ""
echo "=== NeMo gates ==="
# Ensure NeMo dependencies are installed.
npm ci --prefix nemo
run_gate nemo-typecheck STATIC_ANALYSIS sh -c 'cd nemo && npx tsc --noEmit'
run_gate nemo-tests TEST sh -c 'cd nemo && npx vitest run'

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

# ─── Evidence secret scan (before finalization) ─────────────────────────────
# The gate runner redacts credential-bearing argv, but a test or provider
# can still print a secret into its own log. Scan the whole evidence tree
# for the exact secret values the environment knows about; a hit stops the
# release rather than shipping the secret in the evidence bundle.
echo ""
echo "=== Evidence secret scan ==="
run_gate evidence-secret-scan PROVENANCE \
  bash "$REPO_ROOT/scripts/scan-evidence-secrets.sh" "$EVIDENCE_DIR"

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
    effect-fabric-postgres|provider-github-faults|live-microvm-*)
      # -json gates write structured accounting lines into the log:
      #   tests_discovered=N / tests_passed=N / tests_failed=N / tests_skipped=N
      # (the -json event stream has no "--- PASS:" lines to grep).
      local p f
      p=$(grep -oE '^tests_passed=[0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$' || true)
      f=$(grep -oE '^tests_failed=[0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$' || true)
      count=$((${p:-0} + ${f:-0}))
      ;;
    go-evidence-tests|go-tart-tests|go-lume-tests|go-shared-tests|go-race-evidence|go-race-providers|go-race-sandboxexecutor|go-race-cli|effect-fabric-contract|effect-fabric-reconciliation|effect-fabric-evidence|effect-fabric-race|authority-postgres|provider-github-real-api|critical-external|critical-faults|effect-fabric-post-dispatch-timeout)
      # Go test with -v prints one line per test:
      #   --- PASS: TestName (0.00s)
      #   --- FAIL: TestName (0.00s)
      #   --- SKIP: TestName (0.00s)
      # Count executed tests only — a SKIP is not evidence of execution.
      # Per-test result lines, not package-level ok/FAIL lines.
      # A go test -run expression matching zero tests produces "ok" but
      # no --- PASS lines — the count correctly returns 0.
      # NOTE: grep -c outputs "0" and exits 1 when no matches. Using
      # `|| true` (not `|| echo 0`) avoids appending a second "0".
      count=$(grep -cE '^\s*--- (PASS|FAIL):' "$log" 2>/dev/null || true)
      ;;
    worker-tests|nemo-tests)
      # Vitest prints a summary like:
      #   Tests  5 passed (5)
      # The output may contain ANSI color codes in CI, so strip them.
      local tests_line
      tests_line=$(sed 's/\x1b\[[0-9;]*m//g' "$log" 2>/dev/null | grep -E 'Tests[[:space:]]+[0-9]+' | tail -1 || true)
      if [ -n "$tests_line" ]; then
        # Executed = passed + failed — a skip is not evidence of
        # execution. The parenthesized total includes skips, so it is
        # only a fallback when the per-status counts are absent.
        local passed failed skipped
        passed=$(echo "$tests_line" | grep -oE '[0-9]+ passed' | grep -oE '^[0-9]+' || true)
        failed=$(echo "$tests_line" | grep -oE '[0-9]+ failed' | grep -oE '^[0-9]+' || true)
        skipped=$(echo "$tests_line" | grep -oE '[0-9]+ skipped' | grep -oE '^[0-9]+' || true)
        if [ -n "$passed" ] || [ -n "$failed" ]; then
          count=$((${passed:-0} + ${failed:-0}))
        else
          local in_parens
          in_parens=$(echo "$tests_line" | grep -oE '\([0-9]+\)' | grep -oE '[0-9]+' || true)
          count=$((${in_parens:-0} - ${skipped:-0}))
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
        # Count executed assertion results — skipped/pending/todo are
        # not evidence of execution.
        count=$(jq '[.testResults[].assertionResults[] | select(.status == "passed" or .status == "failed")] | length' "$json_summary" 2>/dev/null || true)
      fi
      ;;
    cross-language-conformance)
      # With -v, count executed per-test result lines (SKIP excluded).
      count=$(grep -cE '^\s*--- (PASS|FAIL):' "$log" 2>/dev/null || true)
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

# Extract tests_skipped from a gate log. Mirrors extract_tests_executed
# so the release manifest reports real skip accounting instead of a
# hardcoded 0.
extract_tests_skipped() {
  local gate_name="$1"
  local log="$2"
  local count=0

  case "$gate_name" in
    effect-fabric-postgres|provider-github-faults|live-microvm-*)
      # -json gates write structured accounting lines into the log.
      count=$(grep -oE '^tests_skipped=[0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$' || true)
      count=${count:-0}
      ;;
    go-evidence-tests|go-tart-tests|go-lume-tests|go-shared-tests|go-race-evidence|go-race-providers|go-race-sandboxexecutor|go-race-cli|effect-fabric-contract|effect-fabric-reconciliation|effect-fabric-evidence|effect-fabric-race|authority-postgres|provider-github-real-api|critical-external|critical-faults|cross-language-conformance|effect-fabric-post-dispatch-timeout)
      count=$(grep -cE '^\s*--- SKIP:' "$log" 2>/dev/null || true)
      ;;
    worker-tests|nemo-tests)
      local tests_line
      tests_line=$(sed 's/\x1b\[[0-9;]*m//g' "$log" 2>/dev/null | grep -E 'Tests[[:space:]]+[0-9]+' | tail -1 || true)
      if [ -n "$tests_line" ]; then
        local skipped
        skipped=$(echo "$tests_line" | grep -oE '[0-9]+ skipped' | grep -oE '^[0-9]+' || true)
        count=${skipped:-0}
      fi
      ;;
    postgres-*)
      local json_summary
      for candidate in "${log%.log}.summary.json" "$EVIDENCE_DIR/${gate_name}.summary.json" "$EVIDENCE_DIR/${gate_name}.vitest.json"; do
        if [ -f "$candidate" ]; then
          json_summary="$candidate"
          break
        fi
      done
      if [ -n "${json_summary:-}" ] && [ -f "$json_summary" ] && command -v jq >/dev/null 2>&1; then
        count=$(jq '[.testResults[].assertionResults[] | select(.status == "skipped" or .status == "pending" or .status == "todo")] | length' "$json_summary" 2>/dev/null || true)
      fi
      ;;
    *)
      count=0
      ;;
  esac

  if ! [[ "$count" =~ ^[0-9]+$ ]]; then
    count=0
  fi
  echo "$count"
}

# Extract tests_failed from a gate log. Log-format adapter, mirroring
# extract_tests_executed: this dispatches on the log FORMAT a runner
# produces, never on gate semantics — whether a gate must report counts
# is decided solely by its declared gate_type.
extract_tests_failed() {
  local gate_name="$1"
  local log="$2"
  local count=0

  case "$gate_name" in
    effect-fabric-postgres|provider-github-faults|live-microvm-*)
      # -json gates write structured accounting lines into the log.
      count=$(grep -oE '^tests_failed=[0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$' || true)
      count=${count:-0}
      ;;
    postgres-*)
      # Live Postgres gates write a vitest JSON file alongside the log.
      local json_summary
      for candidate in "${log%.log}.summary.json" "$EVIDENCE_DIR/${gate_name}.summary.json" "$EVIDENCE_DIR/${gate_name}.vitest.json"; do
        if [ -f "$candidate" ]; then
          json_summary="$candidate"
          break
        fi
      done
      if [ -n "${json_summary:-}" ] && [ -f "$json_summary" ] && command -v jq >/dev/null 2>&1; then
        count=$(jq '[.testResults[].assertionResults[] | select(.status == "failed")] | length' "$json_summary" 2>/dev/null || true)
      fi
      ;;
    go-evidence-tests|go-tart-tests|go-lume-tests|go-shared-tests|go-race-evidence|go-race-providers|go-race-sandboxexecutor|go-race-cli|effect-fabric-contract|effect-fabric-reconciliation|effect-fabric-evidence|effect-fabric-race|authority-postgres|provider-github-real-api|critical-external|critical-faults|cross-language-conformance|effect-fabric-post-dispatch-timeout)
      count=$(grep -cE '^\s*--- FAIL:' "$log" 2>/dev/null || true)
      ;;
    worker-tests|nemo-tests)
      local tests_line
      tests_line=$(sed 's/\x1b\[[0-9;]*m//g' "$log" 2>/dev/null | grep -E 'Tests[[:space:]]+[0-9]+' | tail -1 || true)
      if [ -n "$tests_line" ]; then
        count=$(echo "$tests_line" | grep -oE '[0-9]+ failed' | grep -oE '^[0-9]+' || true)
        count=${count:-0}
      fi
      ;;
    *)
      count=0
      ;;
  esac

  if ! [[ "$count" =~ ^[0-9]+$ ]]; then
    count=0
  fi
  echo "$count"
}

# Build the schema-v2 gates JSON array: canonical gate records with the
# declared type, timing, honest test accounting, and the evidence digest.
# The validator in scripts/lib/qualification-gates.sh consumes these
# records; no consumer re-derives gate semantics from names.
for i in "${!GATE_NAMES[@]}"; do
  if ! qualification_gate_type_valid "${GATE_TYPES[$i]}"; then
    echo "ERROR: gate ${GATE_NAMES[$i]} declares unknown type ${GATE_TYPES[$i]}" >&2
    exit 1
  fi
  if [ ! -f "${GATE_LOG[$i]}" ]; then
    echo "ERROR: gate ${GATE_NAMES[$i]} has no evidence log" >&2
    exit 1
  fi
done

GATES_JSON="["
for i in "${!GATE_NAMES[@]}"; do
  [ "$i" -gt 0 ] && GATES_JSON+=","
  gate_name="${GATE_NAMES[$i]}"
  gate_log="${GATE_LOG[$i]}"
  gate_rel="${gate_log#"$EVIDENCE_DIR"/}"
  tests_executed="$(extract_tests_executed "$gate_name" "$gate_log")"
  tests_failed="$(extract_tests_failed "$gate_name" "$gate_log")"
  evidence_sha="$(shasum -a 256 "$gate_log" | awk '{print $1}')"
  GATES_JSON+="{\"gate_id\":\"${gate_name}\",\"gate_type\":\"${GATE_TYPES[$i]}\",\"mandatory\":true,\"status\":\"${GATE_STATUS[$i]}\",\"exit_code\":${GATE_EXIT[$i]},\"tests_executed\":${tests_executed},\"tests_failed\":${tests_failed},\"duration_ms\":${GATE_DURATION[$i]},\"evidence\":{\"file\":\"${gate_rel}\",\"sha256\":\"${evidence_sha}\"}"
  if [ -n "${GATE_SUITE[$i]}" ]; then
    GATES_JSON+=",\"test_suite\":${GATE_SUITE[$i]}"
  fi
  GATES_JSON+="}"
done
GATES_JSON+="]"

# Derived lane identities: qualified lanes are those with a passing lane
# gate carrying test_suite evidence; claimed lanes were declared up front
# by the release (CRABBOX_QUALIFY_LANES).
QUALIFIED_LANES=""
for i in "${!GATE_NAMES[@]}"; do
  if [ "${GATE_STATUS[$i]}" = "PASS" ] && [ -n "${GATE_SUITE[$i]}" ]; then
    lane="$(jq -r '.lane' <<<"${GATE_SUITE[$i]}")"
    case " $QUALIFIED_LANES " in
      *" $lane "*) ;;
      *) QUALIFIED_LANES="${QUALIFIED_LANES:+$QUALIFIED_LANES }$lane" ;;
    esac
  fi
done
CLAIMED_LANES_JSON="[$(for l in $CLAIMED_LANES; do printf '"%s",' "$l"; done | sed 's/,$//')]"
QUALIFIED_LANES_JSON="[$(for l in $QUALIFIED_LANES; do printf '"%s",' "$l"; done | sed 's/,$//')]"

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
  "schema_version": 2,
  "release": "$RELEASE_VERSION",
  "release_status": "$RELEASE_STATUS",
  "artifact_promotable": $ARTIFACT_PROMOTABLE,
  "claimed_lanes": $CLAIMED_LANES_JSON,
  "qualified_lanes": $QUALIFIED_LANES_JSON,
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
    {"id": "CRAB-V1-021", "description": "concurrent identical mutations cause at most one provider dispatch"},
    {"id": "CRAB-V1-022", "description": "the release toolchain is exactly the declared toolchain (declared = installed = runtime GOVERSION, GOTOOLCHAIN=local)"}
  ],
  "provenance": {
    "commit": "$COMMIT",
    "tree": "$TREE",
    "branch": "$BRANCH",
    "timestamp": "$EVIDENCE_TIMESTAMP"
  },
  "toolchains": {
    "go": "$GO_VERSION",
    "goversion": "$GO_ENV_GOVERSION",
    "gotoolchain": "$GO_ENV_GOTOOLCHAIN",
    "go_toolchain_directive": "$GO_MOD_TOOLCHAIN",
    "node": "$NODE_VERSION",
    "npm": "$NPM_VERSION",
    "git": "$GIT_VERSION",
    "postgres_client": "$PG_VERSION",
    "postgres_server": "$PG_SERVER_VERSION",
    "effect_fabric_schema_version": "$SCHEMA_VERSION",
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

# ─── Producer self-check: the record must satisfy its own semantics ─────────
# The same validator release admission and the standalone verifier use. A
# producer that emits a PASS record violating the gate schema must not
# package it as evidence.
if ! GATE_FINDINGS="$(validate_qualification_gates "$EVIDENCE_DIR/qualification.json")"; then
  echo "WARNING: qualification record violates gate semantics:" >&2
  echo "$GATE_FINDINGS" >&2
  if [ "$RELEASE_STATUS" = "PASS" ]; then
    echo "ERROR: producer emitted a PASS record that violates the gate schema — refusing to package it" >&2
    exit 1
  fi
fi

# ─── Phase 16b: Per-gate records ────────────────────────────────────────────
# qualification.json is the canonical admission record; gates/<id>.json
# explodes each gate into a standalone record so a single gate's result
# and log binding can be examined and verified independently.
mkdir -p "$EVIDENCE_DIR/gates"
jq -r '.gates[].gate_id' "$EVIDENCE_DIR/qualification.json" | while IFS= read -r gid; do
  jq --arg gid "$gid" \
    '.gates[] | select(.gate_id == $gid) | {schema_version: 2, record_type: "gate"} + .' \
    "$EVIDENCE_DIR/qualification.json" > "$EVIDENCE_DIR/gates/$gid.json"
done

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
# RELEASE_NAME / RELEASE_VERSION are validated up front: the version must
# equal the VERSION file so the embedded identity can never diverge from
# the canonical source.

# Aggregate tests_executed and tests_skipped across the test-bearing
# gates for the release manifest. Test accounting follows the DECLARED
# gate type — never a name pattern.
TOTAL_TESTS_EXECUTED=0
TOTAL_TESTS_SKIPPED=0
for i in "${!GATE_NAMES[@]}"; do
  if qualification_gate_type_test_bearing "${GATE_TYPES[$i]}"; then
    te="$(extract_tests_executed "${GATE_NAMES[$i]}" "${GATE_LOG[$i]}")"
    ts="$(extract_tests_skipped "${GATE_NAMES[$i]}" "${GATE_LOG[$i]}")"
    TOTAL_TESTS_EXECUTED=$((TOTAL_TESTS_EXECUTED + te))
    TOTAL_TESTS_SKIPPED=$((TOTAL_TESTS_SKIPPED + ts))
  fi
done

cat > "$EVIDENCE_DIR/release-manifest.json" << EOF
{
  "release_name": "$RELEASE_NAME",
  "release_version": "$RELEASE_VERSION",
  "release_type": "release-candidate",
  "status": "$RELEASE_STATUS",
  "artifact_promotable": $ARTIFACT_PROMOTABLE,
  "claimed_lanes": $CLAIMED_LANES_JSON,
  "supported_lanes": $QUALIFIED_LANES_JSON,
  "components": {
    "authority_registry_sha256": "$REGISTRY_SHA256",
    "qualification_registry_sha256": "$QUALIFICATION_REGISTRY_SHA256",
    "nemo_runtime_sha256": "$NEMO_RUNTIME_SHA256"
  },
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
  # Every top-level npm dependency is listed: truncating this list would
  # ship an incomplete component inventory inside sealed evidence.
  done < <(jq -r '.packages | to_entries[] | select(.key | startswith("node_modules/")) | .key | sub("node_modules/"; "")' "$REPO_ROOT/worker/package-lock.json" 2>/dev/null | grep -v '/' | sort -u)
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

# ─── Phase 19: Manifest copy, evidence root, then the generated report ───
# The component manifest ships inside the bundle so the evidence root
# binds it without reaching back into the repository.
cp "$REPO_ROOT/runtimes/nemo-transfer-manifest.json" "$EVIDENCE_DIR/nemo-transfer-manifest.json"

# The semantic closure: binds every identity the run produced — commit,
# source manifest, runtime and component digests, every gate's log
# digest — reduced to a single signable root_sha256. The artifact
# binding lands at finalization.
python3 "$REPO_ROOT/scripts/generate-evidence-root.py" "$EVIDENCE_DIR" --repo-root "$REPO_ROOT"

# FINAL_QUALIFICATION_REPORT.md is generated from qualification.json /
# release-manifest.json / evidence-root.json — never written by hand,
# so a PASS cannot be asserted in prose the records do not support. It
# runs after the root so the report can display the signed digest.
"$REPO_ROOT/scripts/generate-qualification-report.sh" "$EVIDENCE_DIR"

# ─── Phase 20: SHA256SUMS for evidence bundle ──────────────────────────────
# Must be generated AFTER all other files (including release-manifest.json
# and sbom.spdx.json) so that every file in the evidence directory is covered.
# evidence-manifest.json is EXCLUDED because its digest is computed FROM
# this SHA256SUMS — including it would create a self-invalidating cycle.
cd "$EVIDENCE_DIR"
# Every stage agrees on membership (scripts/lib/evidence-inventory.sh):
# a hidden scratch entry or a non-regular member is never evidence and
# never ships, so finding one here refuses the bundle rather than
# producing a tree finalization or packaging would reject downstream.
evidence_refuse_strays "$EVIDENCE_DIR" "evidence generation"
# artifact.json is excluded: the release workflow writes it after the
# archive is built — it cannot exist yet. The sort is byte-wise so the
# manifest does not depend on the host locale.
evidence_checksum_members "$EVIDENCE_DIR" artifact.json \
  | xargs -0 shasum -a 256 > SHA256SUMS

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
  "generated_at": "$EVIDENCE_TIMESTAMP"
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
