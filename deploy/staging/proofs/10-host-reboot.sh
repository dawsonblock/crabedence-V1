#!/usr/bin/env bash
# Proof — full host reboot. A nested privileged systemd container gives
# genuine cold-boot semantics: `docker restart` re-runs init, re-enables
# units, recreates RuntimeDirectory, reconnects PostgreSQL, and resumes
# the reconciler — the same observable contract as a VM reboot.
#
# Runs on the deployment host (needs docker). On a persistent VM the
# equivalent is `sudo reboot` — this script exists for hosts where the
# guest cannot reboot itself (CI runners, nested environments).
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
need_cmd docker
need_cmd systemctl

CONTAINER=crabedence-reboot-proof
IMG=crabedence-reboot-host:staging

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

# Nested host image: systemd as PID 1.
docker build -q -t "$IMG" - <<'EOF' >/dev/null
FROM ubuntu:24.04
RUN apt-get update -qq && apt-get install -y -qq systemd openssl >/dev/null
CMD ["/usr/lib/systemd/systemd"]
EOF

# The container reaches the external PG via the host gateway; rewrite
# the DSN host accordingly (loopback inside the container is the
# container, not the host).
DSN=$(printf '%s' "$CRABEDENCE_DATABASE_URL" | sed 's|@127\.0\.0\.1:|@host.docker.internal:|; s|@localhost:|@host.docker.internal:|')

docker run -d --privileged --cgroupns=host --name "$CONTAINER" \
  --add-host=host.docker.internal:host-gateway "$IMG" >/dev/null
# Wait for systemd inside.
for i in $(seq 30); do
  docker exec "$CONTAINER" systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break
  sleep 1
done

docker cp /usr/local/bin/crabbox "$CONTAINER":/usr/local/bin/crabbox
docker cp /usr/local/bin/issue-grant "$CONTAINER":/usr/local/bin/issue-grant
docker exec "$CONTAINER" bash -c '
  set -e
  useradd --system --no-create-home --shell /usr/sbin/nologin crabedence 2>/dev/null || true
  install -d -m 0750 -o root -g crabedence /etc/crabedence
'
docker exec -i "$CONTAINER" bash -c "cat > /etc/crabedence/staging.env" <<EOF
CRABEDENCE_DATABASE_URL=$DSN
CRABBOX_EVIDENCE_KEY=/etc/crabedence/evidence-signing.pem
EOF
docker exec "$CONTAINER" bash -c '
  set -e
  openssl genpkey -algorithm ed25519 -out /etc/crabedence/evidence-signing.pem 2>/dev/null || true
  chown crabedence:crabedence /etc/crabedence/evidence-signing.pem
  chmod 0600 /etc/crabedence/evidence-signing.pem /etc/crabedence/staging.env
  cat > /etc/systemd/system/crabedence.service <<UNIT
[Unit]
Description=Crabedence execution service
After=network-online.target
[Service]
Type=simple
User=crabedence
RuntimeDirectory=crabedence
Environment=CRABBOX_MODE=production
Environment=CRABEDENCE_STORE_BACKEND=postgres
EnvironmentFile=/etc/crabedence/staging.env
ExecStart=/usr/local/bin/crabbox serve-exec --socket /run/crabedence/execution.sock
Restart=on-failure
RestartSec=2
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload && systemctl enable --now crabedence
'

cexec() { docker exec "$CONTAINER" bash -c "$1"; }

# Issue a grant + one durable mutation inside the nested host.
cexec 'for i in $(seq 30); do [ -S /run/crabedence/execution.sock ] && break; sleep 1; done'
GID=$(cexec 'set -a; . /etc/crabedence/staging.env; set +a; issue-grant --principal '"$PRINCIPAL"' --capability test.counter.increment' | grep -o '"grant_id": *"[^"]*"' | cut -d'"' -f4)
RK="reboot-proof-$(date +%s%N)"
cexec "crabbox invoke --socket /run/crabedence/execution.sock --capability test.counter.increment \
  --principal $PRINCIPAL --authority-ref $GID --idempotency-key $RK \
  --arguments '{\"counter\":\"reboot\",\"by\":1}'" | grep -q '"status": "SUCCEEDED"' \
  || fail "nested-host mutation failed before reboot"

# Cold boot the nested host.
docker restart "$CONTAINER" >/dev/null
cexec 'for i in $(seq 60); do systemctl is-active crabedence >/dev/null 2>&1 && break; sleep 1; done'
cexec 'systemctl is-active crabedence' || fail "service did not come up after reboot"
cexec 'for i in $(seq 30); do [ -S /run/crabedence/execution.sock ] && break; sleep 1; done'
[ -z "$(cexec 'ls -S /run/crabedence/execution.sock 2>/dev/null; test -S /run/crabedence/execution.sock || echo MISSING' | grep MISSING)" ] \
  || fail "socket missing after reboot"

# Post-reboot: the committed row must still be there, and a replay of the
# same idempotency key must not dispatch again.
rows=$(psql_db "SELECT count(*) FROM execution_requests WHERE idempotency_key='$RK'")
[ "$rows" = "1" ] || fail "expected 1 durable row for $RK after reboot, got $rows"
resp=$(cexec "crabbox invoke --socket /run/crabedence/execution.sock --capability test.counter.increment \
  --principal $PRINCIPAL --authority-ref $GID --idempotency-key $RK \
  --arguments '{\"counter\":\"reboot\",\"by\":1}'")
state=$(psql_db "SELECT state FROM execution_requests WHERE idempotency_key='$RK'")
[ "$(psql_db "SELECT count(*) FROM execution_requests WHERE idempotency_key='$RK'")" = "1" ] \
  || fail "post-reboot replay created a second row"

pass "host reboot: service auto-started, socket recreated, $RK state=$state, replay idempotent"
