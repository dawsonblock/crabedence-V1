# Staging Deployment Contract — v0.52.0-rc.1

This document defines the staging target for `v0.52.0-rc.1` and the exact
conditions under which it may receive effect authority. It is a contract:
staging exists to prove deployment semantics, not to re-run the test suite.

## Release identity (immutable)

| Field | Value |
|---|---|
| Release | `v0.52.0-rc.1` |
| Tag commit | `c6385cad2a91c004b9cf5659d86b688d7f9263c4` |
| Tag object | `50f0cffd3a86b8da22fb7ef7161f0b100337258c` |
| tar.gz SHA-256 | `c623a3420af0b62576fbf2ee862ea9fad9face11b5c01f6e27a0e817d53109eb` |
| zip SHA-256 | `202b5e3e2679fd8de17d8c80c87efa4231e0f1a8fe6473854edc01daf20d090f` |
| SBOM SHA-256 | `27e57aa99dd682d8d9d6f52111df203416d28c44c1de3c7a95bb2093b057f2e0` |
| evidence bundle SHA-256 | `e3093979511d0b8331a6d5c25c06d639f98f7a7d44b18b27a0d6eea908c6ec25` |
| Registry SHA-256 | `d1de25e9e8f1d7b148c3d8aa19dd6bec64b3573bf22617ac8fbcab36b8d71e41` |
| Toolchain | `go1.26.5`, `GOTOOLCHAIN=local` |

Status: **immutable**. The tag is never moved, assets are never replaced,
and nothing is republished. Runtime defects → `v0.52.0-rc.2` with a new
qualification chain. Pipeline-only fixes live on `main`.

## Target topology

Single Linux VM plus a separate PostgreSQL instance. No Kubernetes.

```
Ubuntu 24.04 LTS VM
├── crabbox serve-exec  (systemd, Unix socket)
├── NEMO planner (client-side, invokes over the socket)
├── external CRITICAL qualification provider (own process, own ledger)
├── journald log capture
└── (metrics via process/journal + DB inspection — see Observability)
PostgreSQL 16
└── dedicated instance or separate VM — NOT the production database
```

Everything under staging uses **staging-only** credentials, authority
records, databases, provider namespaces, and operation tokens. Nothing
shares an identity with production.

## Build and verify before deploy

Staging deploys the qualified bytes, not a fresh build from `main`:

```bash
gh release download v0.52.0-rc.1 --repo dawsonblock/crabedence-V1 \
  --pattern 'crabedence-v0.52.0-rc.1.tar.gz*'
shasum -a 256 -c crabedence-v0.52.0-rc.1.tar.gz.sha256
gh attestation verify crabedence-v0.52.0-rc.1.tar.gz \
  --repo dawsonblock/crabedence-V1 \
  --signer-workflow dawsonblock/crabedence-V1/.github/workflows/release-rc.yml \
  --source-digest c6385cad2a91c004b9cf5659d86b688d7f9263c4
tar xzf crabedence-v0.52.0-rc.1.tar.gz
cd crabedence-v0.52.0-rc.1
export GOTOOLCHAIN=local   # go1.26.5 exactly
scripts/verify-go-toolchain.sh
go build -trimpath -o /usr/local/bin/crabbox ./cmd/crabbox
sha256sum /usr/local/bin/crabbox   # record in deployment manifest
```

## Service configuration

systemd unit (`/etc/systemd/system/crabedence.service`):

```ini
[Unit]
Description=Crabedence execution service (v0.52.0-rc.1)
After=network-online.target

[Service]
Type=simple
User=crabedence
Group=crabedence
RuntimeDirectory=crabedence
RuntimeDirectoryMode=0700
Environment=CRABBOX_MODE=production
Environment=CRABEDENCE_STORE_BACKEND=postgres
Environment=CRABBOX_REPLICAS=1
EnvironmentFile=/etc/crabedence/staging.env
ExecStart=/usr/local/bin/crabbox serve-exec --socket /run/crabedence/execution.sock
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

`/etc/crabedence/staging.env` (mode `0600`, root:crabedence) — the
complete secret/config inventory:

| Variable | Staging value |
|---|---|
| `CRABEDENCE_DATABASE_URL` | `postgres://crabedence_staging:<pw>@<pg-host>:5432/crabedence_staging` |
| `CRABBOX_EVIDENCE_KEY` | `/etc/crabedence/evidence-signing.pem` — **provisioned staging Ed25519 key**, never auto-generated, never the production key |
| `CRABBOX_EVIDENCE_TRUSTED_SIGNERS` | unset (single signer) |
| `CRABBOX_GITHUB_ENABLED` | `true` |
| `CRABBOX_GITHUB_TOKEN` | staging-scoped token only |
| `CRABBOX_GITHUB_API_URL` | unset (real api.github.com) |

`CRABBOX_MODE=production` is mandatory: it forbids silent key generation.
If the evidence key is absent the service must refuse to start.

Do not set `CRABEDENCE_STORE_BACKEND=sqlite` in staging — the point is to
exercise the production store backend.

## Startup identity (provenance evidence)

On every start the service writes, next to the socket:

- `capabilities.json` — registry envelope snapshot
- `runtime-identity.json` — runtime configuration digest

and logs to stderr (journald): `Registry SHA-256: …`, capability
availability report, `Crabedence execution service listening on …`.

Deployment acceptance: the logged registry digest must equal
`d1de25e9e8f1d7b148c3d8aa19dd6bec64b3573bf22617ac8fbcab36b8d71e41`
(the qualified registry). Record it, plus the binary SHA-256, in the
deployment manifest. An incident must be traceable to qualified bytes.

## Database

- Fresh empty database `crabedence_staging` on PostgreSQL 16.
- Schema is applied by the service at startup (`schema_migrations`); no
  hand-applied DDL. First boot on an empty database is itself a test.
- Before any migration-style test later: take a backup and prove a
  restore works — do not treat backup creation as restore proof.
- Separate staging credentials; the production role must not be
  usable here.

## Readiness (what exists in this build)

There is no HTTP `/healthz` or `/metrics` endpoint in this build — that
is a known observability gap to close before stable. Available signals:

```bash
systemctl is-active crabedence                          # process alive
test -S /run/crabedence/execution.sock                  # socket exists
crabbox invoke --socket /run/crabedence/execution.sock \
  --capability system.echo --principal staging@example.com \
  --arguments '{"message":"ready"}'                     # end-to-end probe
journalctl -u crabedence -n 50                          # startup report
psql "$CRABEDENCE_DATABASE_URL" -c \
  "select state, count(*) from execution_requests group by 1"  # backlog
```

A service is "ready" only when the socket accepts an invocation AND the
registry digest in the journal matches the qualified value. Process
liveness alone is not readiness.

Reconciliation backlog (UNKNOWN age/count) is observable through
`execution_requests` in PostgreSQL until a metrics surface exists.

## Authority seeding

Grant issuance uses `authority.Store.IssueGrant` (immutable generations,
`authority_grants` table). There is no dedicated admin CLI in this build;
seed staging grants with a small Go one-off against the staging database
or a reviewed SQL insert matching the `grant_digest` computation — never
by copying production grant rows.

## Traffic gates — in this exact order

Each stage requires the previous stage healthy. Halt on any discrepancy.

1. **Boot + readiness only.** Socket accepts; registry digest matches;
   no durable writes observed.
2. **LOCAL capabilities** (`system.echo`, `system.info`) — no store,
   no provider.
3. **DIRECT READ** (`github.issue.get` against a staging-scoped repo) —
   adapter availability, timeout/error mapping, audit log lines.
4. **Durable MUTATION** — one low-impact capability
   (`test.counter.increment`); confirm one request → one durable record
   → one provider operation → one terminal result.
5. **Restart/reconciliation** — `systemctl restart` while idle, then
   during IN_FLIGHT; confirm recovery, no duplicate dispatch.
6. **Injected UNKNOWN** — disrupt post-dispatch observation on the
   qualification provider; require UNKNOWN (never FAILED), then
   reconcile to terminal via the provider locator.
7. **Supervised CRITICAL** — one capability only, one operation,
   operator watching all three truth sources (below).
8. **Soak** — sustained traffic + multiple restart/recovery cycles.
9. **Production canary** — only after staging is clean.

CRITICAL stays disabled (`CRABBOX_GITHUB_ENABLED` and adapter wiring)
until stage 7. Capability availability is descriptor-aware — never
enable a provider globally because one capability passed.

## Operational proofs (the staging test list)

Not a suite — a short list of real deployment proofs, each with a
pass/fail statement:

| Proof | Expected |
|---|---|
| Restart while idle | service returns, socket restored, no state loss |
| Restart during IN_FLIGHT | execution recovers via locator; provider count stays 1 |
| Provider commits while Crabedence dies | restart → reconcile → COMMITTED; no second provider op |
| PostgreSQL interruption mid-flow | fail-closed or pending; recovers without duplicate effect |
| Provider lookup outage | operation stays UNKNOWN/pending; converges when lookup returns |
| Authority revoked before dispatch | zero provider dispatch |
| Duplicate request storm | one durable identity, one provider op, one terminal outcome |
| One supervised CRITICAL | full chain: authority → durable → provider → digest recompute → receipt |

## Three-view comparison — every durable operation

For each durable staging operation, these must agree:

1. **Crabedence durable ledger** — `execution_requests` row (state,
   provider identity, terminal proof).
2. **Provider's own operation history** — the provider's ledger/API.
3. **Signed receipt / evidence** — Ed25519 receipt, artifact digest.

Any disagreement is a stop, not a retry.

## Rollback

- **Code rollback**: RC1 schema may have advanced durable state —
  do not roll back to a binary that does not understand the current
  schema. Rollback means forward-fix or maintenance mode.
- **Datastore rollback**: never restore a pre-change database over a
  live one. Durable truth outranks snapshots.
- **Manual DB edits** to resolve UNKNOWN are exceptional forensic
  intervention, not normal operations. Reconcile via provider locator.

## Secrets and separation

- All staging secrets live in `/etc/crabedence/staging.env` (or the
  secret manager), injected at deploy — never in the release archive,
  never in evidence.
- Evidence signing key is staging-only and distinct from any future
  production key. Know the rotation procedure before launch.
- If a credential ever appears in evidence or logs, the release is
  blocked until the leak source is fixed and the gate re-run.

## Failure → next RC

Anything that fails a proof and requires a source change becomes
`v0.52.0-rc.2`: new commit, full qualification, new evidence chain,
new tag. RC1 assets are preserved untouched.
