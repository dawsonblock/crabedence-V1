#!/usr/bin/env bash
# rehearse.sh — Mac-side driver for the staging deployment rehearsal:
# fresh Ubuntu 24.04 VM(s) provisioned end-to-end from the verified RC1
# public artifacts, then the operational proofs.
#
#   Stage A (default):  one vz/arm64 VM with colocated PostgreSQL.
#   Stage B (--pg-vm):  app VM (any --arch; x86_64 uses qemu emulation)
#                       plus a separate vz/arm64 PostgreSQL 16 VM on the
#                       shared Lima network — a real network boundary.
#
# Repeatability is the point: `limactl delete` then re-run must bring
# the deployment back to the same verified state.
#
# Prerequisites on the Mac: limactl, and the RC1 public artifacts
# (tarball + sidecars) — verified here before anything is copied.
#
# Usage:
#   ./rehearse.sh [--vm NAME] [--arch aarch64|x86_64] [--pg-vm NAME]
#                 [--artifacts DIR] [--repo DIR] [--skip-proofs]
#
# Env overrides: VM_NAME, ARTIFACT_DIR, REPO_DIR (repo provides the
# main-only cmd/issue-grant + deploy/staging, overlaid onto the
# qualified RC1 source tree — internal/ is byte-identical to the tag).
set -euo pipefail

VM_NAME="${VM_NAME:-crabedence-stg}"
PG_VM="${PG_VM:-}"
ARCH="${ARCH:-aarch64}"
ARTIFACT_DIR="${ARTIFACT_DIR:-/tmp/rc-verify-test}"
REPO_DIR="${REPO_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
VERSION="v0.52.0-rc.1"
TARBALL="crabedence-${VERSION}.tar.gz"
RUN_PROOFS=1

while [ $# -gt 0 ]; do
  case "$1" in
    --vm) VM_NAME="$2"; shift 2 ;;
    --arch) ARCH="$2"; shift 2 ;;
    --pg-vm) PG_VM="$2"; shift 2 ;;
    --artifacts) ARTIFACT_DIR="$2"; shift 2 ;;
    --repo) REPO_DIR="$2"; shift 2 ;;
    --skip-proofs) RUN_PROOFS=0; shift ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

step() { printf '\n=== %s ===\n' "$*"; }
guest() { limactl shell "$VM_NAME" -- bash -c "$1"; }
pg_guest() { limactl shell "$PG_VM" -- bash -c "$1"; }

vm_ip() { limactl shell "$1" -- bash -c 'ip -4 addr show | grep -oE "inet 192\.168\.5\.[0-9]+" | head -1 | awk "{print \$2}"'; }

ensure_vm() { # <name> <arch> <cpus> <mem> <disk>
  if ! limactl list --format '{{.Name}}' | grep -qx "$1"; then
    local setexpr=".cpus = $3 | .memory = \"$4\" | .disk = \"$5\""
    if [ "$2" = "aarch64" ]; then setexpr="$setexpr | .vmType = \"vz\""; fi
    limactl create --name="$1" --tty=false --arch "$2" \
      --set="$setexpr" template:ubuntu-24.04
  fi
  limactl start "$1" 2>&1 | tail -1
}

# ---- 1. Verify the artifacts on the Mac before anything ships --------
step "verify RC1 artifacts (host)"
# Subshell: limactl maps the caller's cwd into the guest, so keep the
# driver's cwd inside the repo (host home is mounted there).
( cd "$ARTIFACT_DIR" && sha256sum -c "${TARBALL}.sha256" 2>/dev/null \
    || shasum -a 256 -c "$ARTIFACT_DIR/${TARBALL}.sha256" )

# ---- 2. VMs ------------------------------------------------------------
DB_PASSWORD="stg-$(openssl rand -hex 16)"

if [ -n "$PG_VM" ]; then
  step "create PostgreSQL VM $PG_VM"
  ensure_vm "$PG_VM" aarch64 2 2GiB 10GiB
  step "install + open PostgreSQL 16 on $PG_VM"
  pg_guest 'set -e
    sudo apt-get update -qq
    sudo apt-get install -y -qq postgresql-16 postgresql-client >/dev/null
    sudo -u postgres psql -c "ALTER SYSTEM SET listen_addresses = '"'"'*'"'"';" >/dev/null
    grep -q "192.168.5.0/24" /etc/postgresql/16/main/pg_hba.conf 2>/dev/null || \
      echo "host crabedence_staging crabedence_staging 192.168.5.0/24 scram-sha-256" \
        | sudo -u postgres tee -a /etc/postgresql/16/main/pg_hba.conf >/dev/null
    sudo systemctl restart postgresql'
  pg_guest "sudo -u postgres env STAGING_DB_PASSWORD='$DB_PASSWORD' bash '$REPO_DIR/deploy/staging/bootstrap-db.sh'"
  PG_HOST=$(vm_ip "$PG_VM")
  [ -n "$PG_HOST" ] || { echo "could not determine PG VM address" >&2; exit 1; }
  echo "PostgreSQL 16 on $PG_VM at $PG_HOST:5432"
fi

step "create app VM $VM_NAME ($ARCH)"
ensure_vm "$VM_NAME" "$ARCH" 4 6GiB 20GiB

# ---- 3. Guest packages + exact toolchain ------------------------------
step "install guest packages + go1.26.5"
PG_PKG="postgresql-16 postgresql-client"
[ -n "$PG_VM" ] && PG_PKG="postgresql-client"
guest "set -e
  sudo apt-get update -qq
  sudo apt-get install -y -qq $PG_PKG jq curl git build-essential >/dev/null
  case \"\$(uname -m)\" in aarch64|arm64) GOARCH=arm64 ;; x86_64) GOARCH=amd64 ;; *) echo 'unsupported arch' >&2; exit 1 ;; esac
  curl -fsSL \"https://go.dev/dl/go1.26.5.linux-\${GOARCH}.tar.gz\" -o /tmp/go.tgz
  sudo tar -C /usr/local -xzf /tmp/go.tgz
  /usr/local/go/bin/go version"

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
# staging.env is assembled host-side (staging-only values) and written
# base64-encoded so nothing depends on quoting inside the guest shell.
# STAGING_GITHUB_TOKEN / STAGING_TEST_ISSUE are env-only, never committed.
if [ -n "$PG_VM" ]; then
  DB_DSN="postgres://crabedence_staging:${DB_PASSWORD}@${PG_HOST}:5432/crabedence_staging"
else
  DB_DSN="postgres://crabedence_staging:${DB_PASSWORD}@127.0.0.1:5432/crabedence_staging"
fi
ENV_CONTENT="CRABEDENCE_DATABASE_URL=${DB_DSN}
CRABBOX_EVIDENCE_KEY=/etc/crabedence/evidence-signing.pem"
if [ -n "${STAGING_GITHUB_TOKEN:-}" ]; then
  ENV_CONTENT="${ENV_CONTENT}
CRABBOX_GITHUB_ENABLED=true
CRABBOX_GITHUB_TOKEN=${STAGING_GITHUB_TOKEN}"
fi
[ -n "${STAGING_TEST_ISSUE:-}" ] && ENV_CONTENT="${ENV_CONTENT}
STAGING_TEST_ISSUE=${STAGING_TEST_ISSUE}"
ENV_B64=$(printf '%s\n' "$ENV_CONTENT" | base64)

guest "set -e
  sudo rm -rf /opt/staging && sudo cp -r ~/deploy-staging /opt/staging && sudo chmod -R a+rX /opt/staging
  sudo useradd --system --no-create-home --shell /usr/sbin/nologin crabedence 2>/dev/null || true
  sudo install -d -m 0750 -o root -g crabedence /etc/crabedence
  $( [ -z "$PG_VM" ] && echo "sudo -u postgres env STAGING_DB_PASSWORD='$DB_PASSWORD' bash /opt/staging/bootstrap-db.sh" )
  sudo openssl genpkey -algorithm ed25519 -out /etc/crabedence/evidence-signing.pem 2>/dev/null
  sudo chown crabedence:crabedence /etc/crabedence/evidence-signing.pem
  sudo chmod 0600 /etc/crabedence/evidence-signing.pem
  echo '$ENV_B64' | base64 -d | sudo tee /etc/crabedence/staging.env >/dev/null
  sudo chown root:crabedence /etc/crabedence/staging.env && sudo chmod 0640 /etc/crabedence/staging.env
  sudo install -m 0644 /opt/staging/crabedence.service /etc/systemd/system/crabedence.service
  sudo systemctl daemon-reload && sudo systemctl enable --now crabedence"

# ---- 7. Proofs ----------------------------------------------------------
if [ "$RUN_PROOFS" = "1" ]; then
  step "operational proofs"
  guest 'cd /opt/staging/proofs
    rc=0
    for p in 00-readiness.sh 01-local.sh 02-direct-read.sh 03-durable-mutation.sh \
             04-restart.sh 05-duplicate-storm.sh 06-pg-interruption.sh \
             07-authority-revocation.sh 08-reconcile-recovery.sh 09-external-provider.sh \
             10-host-reboot.sh; do
      echo "--- $p"; sudo ./$p || { s=$?; [ $s -eq 77 ] || rc=$s; }
    done
    exit $rc'
fi

step "rehearsal complete"
echo "app VM: $VM_NAME ($ARCH) — RC1 $VERSION deployed from verified artifacts"
[ -n "$PG_VM" ] && echo "PostgreSQL VM: $PG_VM at $PG_HOST:5432"
