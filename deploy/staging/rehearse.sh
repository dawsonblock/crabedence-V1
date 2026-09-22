#!/usr/bin/env bash
# rehearse.sh — Mac-side driver for the Stage-A deployment rehearsal:
# a fresh Ubuntu 24.04 VM (Lima/vz, arm64) provisioned end-to-end from
# the verified RC1 public artifacts, then the operational proofs.
#
# Repeatability is the point: `limactl delete crabedence-stg` then this
# script must bring the deployment back to the same verified state.
#
# Prerequisites on the Mac: limactl, and the RC1 public artifacts
# (tarball + sidecars) — verified here before anything is copied.
#
# Usage:
#   ./rehearse.sh [--vm NAME] [--artifacts DIR] [--repo DIR] [--skip-proofs]
#
# Env overrides: VM_NAME, ARTIFACT_DIR, REPO_DIR (repo provides the
# main-only cmd/issue-grant + deploy/staging, overlaid onto the
# qualified RC1 source tree — internal/ is byte-identical to the tag).
set -euo pipefail

VM_NAME="${VM_NAME:-crabedence-stg}"
ARTIFACT_DIR="${ARTIFACT_DIR:-/tmp/rc-verify-test}"
REPO_DIR="${REPO_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
VERSION="v0.52.0-rc.1"
TARBALL="crabedence-${VERSION}.tar.gz"
RUN_PROOFS=1

while [ $# -gt 0 ]; do
  case "$1" in
    --vm) VM_NAME="$2"; shift 2 ;;
    --artifacts) ARTIFACT_DIR="$2"; shift 2 ;;
    --repo) REPO_DIR="$2"; shift 2 ;;
    --skip-proofs) RUN_PROOFS=0; shift ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

step() { printf '\n=== %s ===\n' "$*"; }
guest() { limactl shell "$VM_NAME" -- bash -c "$1"; }

# ---- 1. Verify the artifacts on the Mac before anything ships --------
step "verify RC1 artifacts (host)"
# Subshell: limactl maps the caller's cwd into the guest, so keep the
# driver's cwd inside the repo (host home is mounted there).
( cd "$ARTIFACT_DIR" && sha256sum -c "${TARBALL}.sha256" 2>/dev/null \
    || shasum -a 256 -c "$ARTIFACT_DIR/${TARBALL}.sha256" )

# ---- 2. Fresh VM -----------------------------------------------------
step "create VM $VM_NAME"
if ! limactl list --format '{{.Name}}' | grep -qx "$VM_NAME"; then
  limactl create --name="$VM_NAME" --tty=false \
    --set='.cpus = 4 | .memory = "6GiB" | .disk = "20GiB" | .vmType = "vz"' \
    template:ubuntu-24.04
fi
limactl start "$VM_NAME" 2>&1 | tail -1

# ---- 3. Guest packages + exact toolchain ------------------------------
step "install guest packages + go1.26.5"
guest 'set -e
  sudo apt-get update -qq
  sudo apt-get install -y -qq postgresql-16 postgresql-client jq curl git build-essential >/dev/null
  case "$(uname -m)" in aarch64|arm64) GOARCH=arm64 ;; x86_64) GOARCH=amd64 ;; *) echo "unsupported arch" >&2; exit 1 ;; esac
  curl -fsSL "https://go.dev/dl/go1.26.5.linux-${GOARCH}.tar.gz" -o /tmp/go.tgz
  sudo tar -C /usr/local -xzf /tmp/go.tgz
  /usr/local/go/bin/go version'

# ---- 4. Transfer + re-verify in the guest -----------------------------
step "transfer + verify artifacts in guest"
for f in "$TARBALL" "${TARBALL}.sha256"; do
  limactl copy "$ARTIFACT_DIR/$f" "$VM_NAME:/tmp/"
done
guest "cd /tmp && sha256sum -c ${TARBALL}.sha256"

# ---- 5. Build inside the target environment ---------------------------
step "build crabbox + issue-grant in guest (GOTOOLCHAIN=local)"
guest "set -e
  mkdir -p ~/rc1 && tar -xzf /tmp/$TARBALL -C ~/rc1
  SRC=\$HOME/rc1/crabedence-$VERSION
  cp -r '$REPO_DIR/cmd/issue-grant' \"\$SRC/cmd/\"
  cp -r '$REPO_DIR/deploy/staging' ~/deploy-staging
  chmod -R u+rwX ~/deploy-staging
  cd \"\$SRC\"
  export PATH=/usr/local/go/bin:\$PATH GOTOOLCHAIN=local CGO_ENABLED=0
  go env GOVERSION | grep -qx go1.26.5
  go build -trimpath -ldflags \"-s -w -X github.com/openclaw/crabbox/internal/cli.version=${VERSION#v}\" \
    -o /tmp/bin-crabbox ./cmd/crabbox
  go build -trimpath -o /tmp/bin-issue-grant ./cmd/issue-grant
  sudo install -m 0755 /tmp/bin-crabbox /usr/local/bin/crabbox
  sudo install -m 0755 /tmp/bin-issue-grant /usr/local/bin/issue-grant"

# ---- 6. Deploy: user, db, key, env, unit -------------------------------
step "provision service (db, key, env, systemd)"
guest 'set -e
  sudo rm -rf /opt/staging && sudo cp -r ~/deploy-staging /opt/staging && sudo chmod -R a+rX /opt/staging
  sudo useradd --system --no-create-home --shell /usr/sbin/nologin crabedence 2>/dev/null || true
  sudo install -d -m 0750 -o root -g crabedence /etc/crabedence
  PW="stg-$(openssl rand -hex 12)"
  sudo -u postgres env STAGING_DB_PASSWORD="$PW" bash /opt/staging/bootstrap-db.sh
  sudo openssl genpkey -algorithm ed25519 -out /etc/crabedence/evidence-signing.pem 2>/dev/null
  sudo chown crabedence:crabedence /etc/crabedence/evidence-signing.pem
  sudo chmod 0600 /etc/crabedence/evidence-signing.pem
  printf "CRABEDENCE_DATABASE_URL=postgres://crabedence_staging:%s@127.0.0.1:5432/crabedence_staging\nCRABBOX_EVIDENCE_KEY=/etc/crabedence/evidence-signing.pem\n" "$PW" \
    | sudo tee /etc/crabedence/staging.env >/dev/null
  sudo chown root:crabedence /etc/crabedence/staging.env && sudo chmod 0640 /etc/crabedence/staging.env
  sudo install -m 0644 /opt/staging/crabedence.service /etc/systemd/system/crabedence.service
  sudo systemctl daemon-reload && sudo systemctl enable --now crabedence'

# ---- 7. Proofs ----------------------------------------------------------
if [ "$RUN_PROOFS" = "1" ]; then
  step "operational proofs"
  guest 'cd /opt/staging/proofs
    rc=0
    for p in 00-readiness.sh 01-local.sh 02-direct-read.sh 03-durable-mutation.sh \
             04-restart.sh 05-duplicate-storm.sh 06-pg-interruption.sh \
             07-authority-revocation.sh 08-reconcile-recovery.sh 09-external-provider.sh; do
      echo "--- $p"; sudo ./$p || { s=$?; [ $s -eq 77 ] || rc=$s; }
    done
    exit $rc'
fi

step "rehearsal complete"
echo "VM: $VM_NAME — RC1 $VERSION deployed from verified artifacts"
