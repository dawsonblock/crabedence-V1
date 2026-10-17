# RC7.5 Ledger Migration and Rollback

Schema v11 → v12, what it does, and how to roll back safely.

## What v12 adds

| Object | Change |
|---|---|
| `recovery_events` | + `prev_event_sha256`, `event_sha256` (hash chain), `claim_uid` (claim generation the event ran under), `authenticated` (1 = written under the chain; 0 = pre-v12 legacy) |
| `recovery_outbox` | New table: durable queue of signed recovery checkpoints awaiting external custody (`seq`, `head_sha256`, `checkpoint_json`, `ack_json`, `created_ms`) |

Migration runs at `OpenLedger` under the ledger's fenced transaction:

1. `ALTER TABLE` adds the columns (idempotent — `duplicate column` is
   tolerated).
2. `CREATE TABLE IF NOT EXISTS recovery_outbox`.
3. `backfillRecoveryChain` hashes every pre-existing event in sequence
   order into the chain, leaving `authenticated = 0` — legacy history
   is bound for tamper-evidence but never retroactively called signed.
4. `PRAGMA user_version = 12` stamps the schema.

A fresh database runs the same path: the base tables are created with
all columns and the backfill is a no-op.

## Guarantees

- **Atomicity per step.** Each `ALTER`/`CREATE` is its own statement;
  the backfill is one transaction. A crash mid-migration leaves the
  ledger at a consistent intermediate point; reopening resumes —
  `duplicate column` tolerance and `event_sha256 = ''` resumption make
  every step idempotent.
- **Read-only inspection of old ledgers.** `InspectLedger` opens the
  database read-only and never migrates — a v11 ledger can be audited
  without being touched.
- **No data rewrite.** Legacy rows keep their original `at_ms`, `kind`,
  `subject`, `detail`; only the chain columns are filled. The chain is
  a commitment *over* history, not a rewrite of it.

## Rollback

**Forward-only, by design.** There is no down-migration: a v12 ledger
read by an older binary sees unknown columns it ignores (`SELECT`
lists are explicit) — except `recovery_outbox`, which older code
simply never reads. The safe downgrade path is:

1. **Before upgrading**, snapshot `ledger.db` (`.backup` or file copy
   with the daemon stopped).
2. **To roll back**, stop the daemon, restore the snapshot, start the
   older binary. Anything recorded under v12 (outbox rows, chain
   columns, post-migration events) is absent from the snapshot — by
   definition it did not exist then.
3. **Never** run a v12 database under an older binary expecting it to
   migrate backwards — it will not, and it must not silently pretend
   the chain columns mean nothing. The columns are inert to old code;
  `authenticated` semantics are a v12 concern.

## Verification after migration

- `SELECT COUNT(*) FROM recovery_events WHERE authenticated = 0` —
  equals the pre-migration event count.
- `VerifyRecoveryEvents` — recomputes the chain; an intact migration
  reports zero findings, mixing legacy and new events seamlessly.
- `PRAGMA user_version` — `12`.
