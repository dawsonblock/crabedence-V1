#!/usr/bin/env bash
# Generate machine-verifiable release evidence into release-evidence/.
# Captures raw command output, toolchain versions, environment metadata,
# and per-file SHA-256 hashes so the bundle is independently auditable.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVIDENCE_DIR="$REPO_ROOT/release-evidence"
mkdir -p "$EVIDENCE_DIR"

# Clean previous generated artifacts (keep manually-edited matrix).
rm -f "$EVIDENCE_DIR"/*.log "$EVIDENCE_DIR"/*.json "$EVIDENCE_DIR"/SHA256SUMS

run_and_log() {
  local name="$1"
  shift
  local log="$EVIDENCE_DIR/$name.log"
  echo "+ $*" > "$log"
  echo "---" >> "$log"
  "$@" >> "$log" 2>&1 || echo "EXIT=$?" >> "$log"
  echo "---" >> "$log"
  echo "exit=$?" >> "$log"
}

# 1. Environment and toolchain metadata.
cat > "$EVIDENCE_DIR/environment.json" << EOF
{
  "os": "$(uname -s)",
  "os_version": "$(uname -r)",
  "arch": "$(uname -m)",
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

# Generate toolchains.json with actual versions.
{
  echo '{'
  echo "  \"go\": \"$(go version 2>/dev/null || echo 'unavailable')\","
  echo "  \"node\": \"$(node --version 2>/dev/null || echo 'unavailable')\","
  echo "  \"npm\": \"$(npm --version 2>/dev/null || echo 'unavailable')\","
  echo "  \"worker_package_version\": \"$(node -e "console.log(require('./worker/package.json').version)" 2>/dev/null || echo 'unavailable')\""
  echo '}'
} > "$EVIDENCE_DIR/toolchains.json"

# 2. Source provenance.
git -C "$REPO_ROOT" rev-parse HEAD > "$EVIDENCE_DIR/source-commit.txt"
git -C "$REPO_ROOT" log -1 --format='commit %H%nAuthor: %an <%ae>%nDate: %ad%nSubject: %s' \
  > "$EVIDENCE_DIR/source-commit-metadata.txt"

# Generate per-file source tree manifest (deterministic).
git -C "$REPO_ROOT" ls-files -z | sort -z | xargs -0 -I{} sh -c 'echo "$(git -C "'"$REPO_ROOT"'" rev-parse HEAD:"{}")  {}"' \
  > "$EVIDENCE_DIR/source-tree-manifest.txt"

# 3. Go gates.
run_and_log go-vet go vet ./...
run_and_log go-evidence-tests go test -timeout=120s -run "TestTerminalReceipt|TestTerminalLog|TestRunEvidence|TestFinalizeRun|TestEvidence" ./internal/cli/
run_and_log go-tart-tests go test -timeout=120s ./internal/providers/tart/
run_and_log go-lume-tests go test -timeout=60s ./internal/providers/lume/
run_and_log go-shared-tests go test -timeout=60s ./internal/providers/shared/

# 4. Worker gates.
run_and_log worker-typecheck npm run check --prefix worker
run_and_log worker-tests npm test --prefix worker
run_and_log worker-format npm run format:check --prefix worker
run_and_log worker-lint npm run lint --prefix worker
run_and_log worker-build npm run build --prefix worker

# 5. SHA256SUMS for all evidence files (excluding SHA256SUMS itself).
cd "$EVIDENCE_DIR"
find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 shasum -a 256 > SHA256SUMS

echo "Release evidence generated in $EVIDENCE_DIR"
