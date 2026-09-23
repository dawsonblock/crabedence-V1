# Staging bootstrap package — `v0.52.0-rc.1`

Executable companion to `STAGING.md` at the repository root. Everything
here deploys the **already-qualified RC1 artifacts** — it never deploys
`main`. The RC1 tag (`v0.52.0-rc.1` → `c6385ca`) is immutable; this
package is operational tooling on `main`.

## Contents

| File | Purpose |
|---|---|
| `crabedence.service` | systemd unit — `RuntimeDirectory`-managed socket, `CRABBOX_MODE=production`, postgres backend, hardened sandbox |
| `staging.env.example` | `/etc/crabedence/staging.env` template — staging-only DSN, provisioned evidence key, optional GitHub adapter |
| `bootstrap-db.sh` | Idempotent PostgreSQL role/database bootstrap (schema is applied by the service at first boot) |
| `readiness.sh` | Readiness probe: unit active + socket answers `system.echo` + live registry digest equals `d1de25e9…` |
| `proofs/` | The operational proofs, in execution order |
| `rehearse.sh` | Mac-side driver: fresh Lima/vz Ubuntu 24.04 VM → verified artifacts → in-guest build → deploy → proofs. Repeatability is the point — `limactl delete` then re-run must reproduce the same verified state |
| `cmd/issue-grant` (repo root) | Grant issuance helper — goes through `authority.Store`, never hand-built SQL |

## Bring-up order

```bash
# 1. Provision Ubuntu 24.04 VM + PostgreSQL 16 (staging-only credentials).
# 2. Download + verify RC1 artifacts (STAGING.md §verified-deploy path):
#    sidecar digests, attestation verify, build with go1.26.5 GOTOOLCHAIN=local.
# 3. Install:
sudo install -m 0755 crabbox /usr/local/bin/crabbox
sudo install -m 0755 issue-grant /usr/local/bin/issue-grant
sudo install -m 0644 staging.env.example /etc/crabedence/staging.env   # then edit
sudo install -m 0644 crabedence.service /etc/systemd/system/
sudo install -m 0600 evidence-signing.pem /etc/crabedence/             # provisioned key
# 4. Database:
STAGING_DB_PASSWORD=… PGADMIN_URL=postgres://postgres@pg-host/postgres ./bootstrap-db.sh
# 5. Start:
sudo systemctl daemon-reload && sudo systemctl enable --now crabedence
```

## Proof order (matches STAGING.md)

| Script | Proof | External deps |
|---|---|---|
| `proofs/00-readiness.sh` | gate 1: boot + readiness | none |
| `proofs/01-local.sh` | gate 2: LOCAL capabilities | none |
| `proofs/02-direct-read.sh` | gate 3: DIRECT READ | staging GitHub token + `STAGING_TEST_ISSUE` |
| `proofs/03-durable-mutation.sh` | gate 4: durable MUTATION + replay | none (test provider) |
| `proofs/04-restart.sh` | restart idle + restart during IN_FLIGHT | systemctl |
| `proofs/05-duplicate-storm.sh` | 100-way duplicate storm | none |
| `proofs/06-pg-interruption.sh` | PostgreSQL interruption | root + iptables |
| `proofs/07-authority-revocation.sh` | revocation before dispatch | none |
| `proofs/08-reconcile-recovery.sh` | injected UNKNOWN → reconcile | systemctl |
| `proofs/09-external-provider.sh` | provider death/lookup/CRITICAL | live harness — auto-detects `~/rc1/crabedence-*` (or `CRABEDENCE_SOURCE_DIR`) |
| `proofs/10-host-reboot.sh` | full host reboot → auto-recovery | docker (nested privileged systemd container; on a bare VM use `sudo reboot` instead) |
| `proofs/11-soak.sh` | sustained load + mid-soak restart + PG outage | root; `SOAK_DURATION` secs (default 900) — run post-qualification, pre-canary |

Proofs exit `0` pass, `1` fail, `77` skip (missing prerequisite).
Every durable proof enforces the three-view invariant:
`execution_requests` ↔ `effect_provider_observations` ↔
`evidence_receipt`/`evidence_digest`.

## Known RC1 gaps (do not paper over)

- No `/healthz` or `/metrics` — readiness is the socket probe +
  registry digest. Observability endpoints are the first RC2 runtime
  change.
- The external CRITICAL qualification provider is test-harness-only —
  proof 09 runs the live harness (`TestLiveCritical*`) against the
  staging DSN when a source tree is present; a fully deployed provider
  is still an RC2 deliverable.
- Injected-UNKNOWN counter rows correctly stay UNKNOWN: the
  test-counter provider's state is in-memory, so after a restart there
  is no provider observation to reconcile from — the row cannot prove
  itself and must not be promoted. Real reconciliation to COMMITTED is
  exercised by proof 09's harness path (external provider with a
  durable ledger).
- `journald` is the only log sink; ship with your existing log agent.
