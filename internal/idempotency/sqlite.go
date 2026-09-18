// SQLite-backed implementation of the durable execution contract.
//
// The schema and semantics mirror the PostgreSQL Store exactly — same
// state graph, same CAS fencing, same monotonic provider observations —
// adapted to SQLite's single-writer model:
//
//   - Database time is unix milliseconds computed by SQLite itself
//     (unixepoch('subsec')), not the application clock. Lease expiry,
//     claim TTLs, and reconcile scheduling are all DB-owned.
//   - FOR UPDATE SKIP LOCKED has no SQLite equivalent; it is not
//     needed. Claim batches are single UPDATE ... RETURNING statements,
//     and SQLite serializes writers — the subselect and the update are
//     one atomic statement, so two workers cannot claim the same row.
//   - The schema advisory lock is replaced by a BEGIN IMMEDIATE
//     transaction (the _txlock=immediate DSN parameter) — one writer at
//     a time makes migration mutually exclusive by construction.
//   - Durability requires WAL + synchronous=FULL, not the commonly
//     recommended NORMAL: SQLite documents that WAL+NORMAL can lose a
//     recently committed transaction after power loss.
package idempotency

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// sqliteNow is the authoritative DB-time expression: unix milliseconds
// computed by SQLite (unixepoch('subsec') has millisecond resolution,
// and 1.7e12 ms fits comfortably in REAL's 53-bit mantissa).
const sqliteNow = `CAST(unixepoch('subsec') * 1000 AS INTEGER)`

// msDuration converts a Go duration into the integer milliseconds unit
// used by all SQLite timestamp columns. It rounds up: a positive
// sub-millisecond duration must not collapse to zero (which would make
// a freshly-granted lease already expired at insert).
func msDuration(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64((d + time.Millisecond - 1) / time.Millisecond)
}

// sqliteTime converts a stored unix-ms integer into time.Time.
func sqliteTime(ms int64) time.Time {
	return time.UnixMilli(ms).UTC()
}

// OpenSQLiteDB opens (creating if necessary) an SQLite database
// configured for the durable store: WAL journal, FULL synchronous,
// foreign keys, 5s busy timeout, in-memory temp store, and BEGIN
// IMMEDIATE for every transaction so read-then-write sequences cannot
// fail with SQLITE_BUSY on upgrade. All per-connection pragmas are
// applied via DSN parameters so pooled connections behave identically.
//
// The ledger carries execution authority and forensic history, so the
// path is hardened before SQLite touches it: the directory must be
// owner-only (0700, created that way if missing), the database file
// must be a regular file (never a symlink), and the DB/WAL/SHM files
// are tightened to 0600. Unsafe locations are rejected rather than
// silently hosting the execution ledger under weak permissions.
func OpenSQLiteDB(path string) (*sql.DB, error) {
	// The DSN carries the durability pragmas as query parameters — a
	// path containing '?' or '#' would let the filename terminate the
	// path early or inject parameters (e.g. weakening synchronous).
	if strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("sqlite path must not contain '?' or '#': %q", path)
	}
	if err := secureSQLitePath(path); err != nil {
		return nil, err
	}
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)"+
		"&_pragma=synchronous(FULL)&_pragma=foreign_keys(ON)"+
		"&_pragma=busy_timeout(5000)&_pragma=temp_store(MEMORY)"+
		"&_txlock=immediate", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// Ping forces the first connection — running the journal_mode(WAL)
	// pragma — which creates the file so permissions can be enforced
	// before the store accepts work.
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to open sqlite ledger %q: %w", path, err)
	}
	if err := secureSQLiteFiles(path); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// secureSQLitePath validates the ledger location before SQLite creates
// anything: the parent directory must exist or be created at 0700, an
// existing directory must not grant group/other access, and an existing
// database file must be a regular file — never a symlink pointing the
// ledger at an unexpected target.
func secureSQLitePath(path string) error {
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to stat sqlite directory %q: %w", dir, err)
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("failed to create sqlite directory %q: %w", dir, err)
		}
	} else {
		if !info.IsDir() {
			return fmt.Errorf("sqlite path parent is not a directory: %q", dir)
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			return fmt.Errorf("sqlite directory %q is accessible by group/other (mode %04o): the durable ledger must live under 0700", dir, perm)
		}
	}

	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to stat sqlite path %q: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("sqlite path %q is a symlink — refusing to write the durable ledger through a link", path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("sqlite path %q is not a regular file", path)
	}
	return nil
}

// secureSQLiteFiles tightens the database file and any WAL/SHM siblings
// to 0600. SQLite creates files at umask-derived permissions (typically
// 0644); the durable ledger must never be group/other-readable. WAL/SHM
// files created later inherit the main file's permissions.
func secureSQLiteFiles(path string) error {
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		fi, err := os.Lstat(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("failed to stat %q: %w", p, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			return fmt.Errorf("sqlite ledger file %q is not a regular file", p)
		}
		if fi.Mode().Perm() != 0o600 {
			if err := os.Chmod(p, 0o600); err != nil {
				return fmt.Errorf("failed to tighten permissions on %q: %w", p, err)
			}
		}
	}
	return nil
}

// SQLiteStore is the embedded single-host implementation of
// EffectStore. It carries the same fencing, monotonic-observation, and
// terminal-proof invariants as the PostgreSQL Store; the storage
// engine changes, the execution semantics do not.
type SQLiteStore struct {
	db       *sql.DB
	leaseCfg LeaseConfig

	// epoch is the cluster epoch this store was admitted under — the
	// same DR-fencing contract as Store.epoch.
	epoch int64

	trustedSigners  map[string]bool
	verifier        EvidenceVerifier
	locatorRedactor func(json.RawMessage) (json.RawMessage, error)
	metrics         StoreMetrics
}

// SetLocatorRedactor installs the locator rewrite hook — see
// Store.SetLocatorRedactor.
func (s *SQLiteStore) SetLocatorRedactor(f func(json.RawMessage) (json.RawMessage, error)) {
	s.locatorRedactor = f
}

func (s *SQLiteStore) evidenceVerifier() EvidenceVerifier {
	if s.verifier != nil {
		return s.verifier
	}
	return signedReceiptVerifier{trustedSigners: s.trustedSigners}
}

// SetEvidenceVerifier installs a custom EvidenceVerifier — see
// Store.SetEvidenceVerifier.
func (s *SQLiteStore) SetEvidenceVerifier(v EvidenceVerifier) {
	s.verifier = v
}

// SetTrustedEvidenceSigners configures the signer fingerprints trusted
// to attest CRITICAL terminal transitions — see
// Store.SetTrustedEvidenceSigners.
func (s *SQLiteStore) SetTrustedEvidenceSigners(fingerprints ...string) {
	s.trustedSigners = make(map[string]bool, len(fingerprints))
	for _, fp := range fingerprints {
		s.trustedSigners[fp] = true
	}
}

// NewSQLiteStore creates an embedded durable store on db. The caller
// should open db via OpenSQLiteDB so every pooled connection carries
// the required pragmas; migrations still run under BEGIN IMMEDIATE
// regardless.
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	return NewSQLiteStoreWithConfig(db, DefaultLeaseConfig)
}

// NewSQLiteStoreWithConfig creates an embedded store with a custom
// lease configuration.
func NewSQLiteStoreWithConfig(db *sql.DB, cfg LeaseConfig) (*SQLiteStore, error) {
	s := &SQLiteStore{db: db, leaseCfg: cfg}
	if err := s.ensureSchema(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to ensure schema: %w", err)
	}
	if err := s.db.QueryRowContext(context.Background(),
		`SELECT epoch FROM cluster_meta WHERE id = 1`).Scan(&s.epoch); err != nil {
		return nil, fmt.Errorf("failed to read cluster epoch: %w", err)
	}
	return s, nil
}

// LeaseConfig returns the store's lease configuration.
func (s *SQLiteStore) LeaseConfig() LeaseConfig {
	return s.leaseCfg
}

// ─── Cluster epoch (DR fencing) ─────────────────────────────────────

// ClusterEpoch returns the epoch this store was admitted under — see
// Store.ClusterEpoch.
func (s *SQLiteStore) ClusterEpoch() int64 {
	return s.epoch
}

// AdvanceClusterEpoch is the embedded counterpart of
// Store.AdvanceClusterEpoch — same CAS contract, and the same
// post-restore recovery declaration: new-effect admission closes
// until CompleteClusterRecovery.
func (s *SQLiteStore) AdvanceClusterEpoch(ctx context.Context, expected int64, reason string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE cluster_meta
		SET epoch = epoch + 1, recovery_required = 1,
		    recovery_completed_at = NULL, recovery_resolution = NULL,
		    advanced_at = `+sqliteNow+`, advance_reason = ?2
		WHERE id = 1 AND epoch = ?1`, expected, nullableString(reason))
	if err != nil {
		return 0, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if rows == 0 {
		var cur int64
		if err := s.db.QueryRowContext(ctx,
			`SELECT epoch FROM cluster_meta WHERE id = 1`).Scan(&cur); err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("%w: cluster epoch already at %d (expected %d)", ClusterEpochMismatch, cur, expected)
	}
	return expected + 1, nil
}

// ClusterRecoveryRequired is the embedded counterpart of
// Store.ClusterRecoveryRequired.
func (s *SQLiteStore) ClusterRecoveryRequired(ctx context.Context) (bool, error) {
	var required int
	if err := s.db.QueryRowContext(ctx,
		`SELECT recovery_required FROM cluster_meta WHERE id = 1`).Scan(&required); err != nil {
		return false, err
	}
	return required != 0, nil
}

// CompleteClusterRecovery is the embedded counterpart of
// Store.CompleteClusterRecovery — same epoch-guarded clear.
func (s *SQLiteStore) CompleteClusterRecovery(ctx context.Context, expected int64, resolution string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE cluster_meta
		SET recovery_required = 0,
		    recovery_completed_at = `+sqliteNow+`,
		    recovery_resolution = ?2
		WHERE id = 1 AND epoch = ?1`, expected, nullableString(resolution))
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		var cur int64
		if err := s.db.QueryRowContext(ctx,
			`SELECT epoch FROM cluster_meta WHERE id = 1`).Scan(&cur); err != nil {
			return err
		}
		return fmt.Errorf("%w: cluster epoch already at %d (expected %d) — cannot complete recovery for an older world",
			ClusterEpochMismatch, cur, expected)
	}
	return nil
}

// checkRecoveryMode is the SQLite counterpart of
// Store.checkRecoveryMode — recovery-blocked admission gets the
// honest CLUSTER_RECOVERY_REQUIRED error, not a lease-conflict
// misclassification.
func (s *SQLiteStore) checkRecoveryMode(ctx context.Context) error {
	var required int
	if err := s.db.QueryRowContext(ctx,
		`SELECT recovery_required FROM cluster_meta WHERE id = 1`).Scan(&required); err != nil {
		return err
	}
	if required != 0 {
		s.metrics.recoveryRejections.Add(1)
		return fmt.Errorf("%w: cluster is in post-restore recovery mode — new-effect admission closed until CompleteClusterRecovery",
			ClusterRecoveryRequired)
	}
	return nil
}

// epochGuardSQL is the SQLite counterpart of Store.epochGuardSQL.
func (s *SQLiteStore) epochGuardSQL() string {
	return fmt.Sprintf("AND (SELECT epoch FROM cluster_meta WHERE id = 1) = %d", s.epoch)
}

// checkEpoch is the SQLite counterpart of Store.checkEpoch. WAL-mode
// readers do not block on the writer, so a pool query here is safe
// even while the calling method holds its write transaction open.
func (s *SQLiteStore) checkEpoch(ctx context.Context) error {
	var cur int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT epoch FROM cluster_meta WHERE id = 1`).Scan(&cur); err != nil {
		return err
	}
	if cur != s.epoch {
		s.metrics.epochRejections.Add(1)
		return fmt.Errorf("%w: store admitted under epoch %d, cluster now at %d — stale executor must restart",
			ClusterEpochMismatch, s.epoch, cur)
	}
	return nil
}

// ─── Schema ──────────────────────────────────────────────────────────

// sqliteSchemaMigration is the embedded counterpart of schemaMigration,
// applying inside the BEGIN IMMEDIATE transaction ensureSchema opens.
type sqliteSchemaMigration struct {
	version int
	name    string
	apply   func(ctx context.Context, tx *sql.Tx) error
}

// sqliteSchemaMigrations carries the same version ceiling as the
// PostgreSQL migration list so SchemaVersion/RequiredSchemaVersion mean
// the same thing on both engines. Versions 3–5 are recorded as applied
// but do nothing: fresh embedded schemas are created with the complete
// column set at version 1, and the PG-specific upgrades (column
// additions for pre-v3 deployments, invalid CONCURRENTLY index repair)
// have no embedded counterpart.
var sqliteSchemaMigrations = []sqliteSchemaMigration{
	{1, "execution_requests_embedded", sqliteMigrationBaseTable},
	{2, "hot_path_indexes", sqliteMigrationHotPathIndexes},
	{3, "provider_observation_columns_folded_into_v1", nil},
	{4, "entered_unknown_at_folded_into_v1", nil},
	{5, "concurrent_index_repair_not_applicable", nil},
	{6, "provider_result_column", sqliteMigrationProviderResultColumn},
	{7, "authority_snapshot_columns_and_audit_indexes", sqliteMigrationAuthoritySnapshot},
	{8, "forensic_record", sqliteMigrationForensic},
	{9, "cluster_epoch_fencing", sqliteMigrationClusterEpoch},
	{10, "result_byte_fidelity_already_text", nil},
	{11, "cluster_recovery_mode", sqliteMigrationClusterRecoveryMode},
}

func (s *SQLiteStore) ensureSchema(ctx context.Context) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	// BEGIN IMMEDIATE (via _txlock=immediate) serializes schema setup:
	// single-writer SQLite makes the PG advisory lock unnecessary.
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("schema transaction failed: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at INTEGER NOT NULL
		)
	`); err != nil {
		return fmt.Errorf("failed to create schema_migrations: %w", err)
	}

	applied := map[int]bool{}
	rows, err := tx.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("failed to read schema_migrations: %w", err)
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	rows.Close()

	for _, m := range sqliteSchemaMigrations {
		if applied[m.version] {
			continue
		}
		if m.apply != nil {
			if err := m.apply(ctx, tx); err != nil {
				return fmt.Errorf("migration %d (%s) failed: %w", m.version, m.name, err)
			}
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?1, ?2, `+sqliteNow+`)
			 ON CONFLICT (version) DO NOTHING`, m.version, m.name); err != nil {
			return fmt.Errorf("failed to record migration %d: %w", m.version, err)
		}
	}

	// Read the version through the open transaction — querying the pool
	// here would deadlock under MaxOpenConns(1), since the sole
	// connection is checked out until ensureSchema returns.
	version, err := schemaVersion(ctx, tx)
	if err != nil {
		return err
	}
	if version < RequiredSchemaVersion {
		return fmt.Errorf("schema version %d < required %d — run migrations before starting",
			version, RequiredSchemaVersion)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("schema commit failed: %w", err)
	}
	return nil
}

// SchemaVersion returns the highest applied schema migration version.
func (s *SQLiteStore) SchemaVersion(ctx context.Context) (int, error) {
	return schemaVersion(ctx, s.db)
}

// sqliteMigrationBaseTable creates the complete ledger schema — the
// same columns the PostgreSQL store reaches after migrations 1–4.
// Timestamps are INTEGER unix milliseconds.
func sqliteMigrationBaseTable(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS execution_requests (
			execution_id TEXT PRIMARY KEY,
			idempotency_key TEXT NOT NULL,
			principal_id TEXT NOT NULL,
			capability_id TEXT NOT NULL,
			request_digest TEXT NOT NULL,
			grant_id TEXT,
			execution_class TEXT NOT NULL,
			state TEXT NOT NULL,
			result TEXT,
			evidence_digest TEXT,
			receipt_version INTEGER NOT NULL DEFAULT 0,
			lease_owner TEXT,
			lease_token TEXT,
			lease_started_at INTEGER,
			lease_expires_at INTEGER,
			lease_generation INTEGER NOT NULL DEFAULT 1,
			provider_id TEXT,
			provider_run_id TEXT,
			provider_status TEXT,
			provider_result TEXT,
			provider_result_digest TEXT,
			provider_receipt_version INTEGER NOT NULL DEFAULT 0,
			provider_observed_at INTEGER,
			terminal_receipt_digest TEXT,
			evidence_receipt TEXT,
			recovery_locator TEXT,
			attempt INTEGER NOT NULL DEFAULT 0,
			version INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			reconcile_owner TEXT,
			reconcile_lease_expires_at INTEGER,
			reconcile_attempt INTEGER NOT NULL DEFAULT 0,
			next_reconcile_at INTEGER,
			last_reconcile_error TEXT,
			entered_unknown_at INTEGER,
			authority_generation INTEGER,
			authority_digest TEXT,
			UNIQUE(principal_id, capability_id, idempotency_key)
		)
	`)
	return err
}

// sqliteMigrationProviderResultColumn adds the immutable provider_result
// column to existing embedded databases — SQLite has no
// ADD COLUMN IF NOT EXISTS, so presence is checked via PRAGMA
// table_info first. Fresh v1 schemas already carry the column.
func sqliteMigrationProviderResultColumn(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(execution_requests)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == "provider_result" {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `ALTER TABLE execution_requests ADD COLUMN provider_result TEXT`)
	return err
}

func sqliteMigrationHotPathIndexes(ctx context.Context, tx *sql.Tx) error {
	for _, ddl := range []string{
		`CREATE INDEX IF NOT EXISTS idx_exec_reconcile
		 ON execution_requests (next_reconcile_at, updated_at)
		 WHERE state = 'UNKNOWN'`,
		`CREATE INDEX IF NOT EXISTS idx_exec_expired_leases
		 ON execution_requests (lease_expires_at)
		 WHERE state IN ('PREPARED', 'EXECUTING', 'IN_FLIGHT')
		   AND lease_expires_at IS NOT NULL`,
	} {
		if _, err := tx.ExecContext(ctx, ddl); err != nil {
			return err
		}
	}
	return nil
}

// sqliteMigrationAuthoritySnapshot mirrors the PG migration 7: the
// immutable authority-snapshot columns plus the forensic audit indexes
// on provider_run_id and grant_id. Fresh v1 schemas already carry the
// columns; existing databases get them via PRAGMA-checked ALTERs.
func sqliteMigrationAuthoritySnapshot(ctx context.Context, tx *sql.Tx) error {
	existing := map[string]bool{}
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(execution_requests)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		existing[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	columns := []struct{ name, def string }{
		{"authority_generation", "INTEGER"},
		{"authority_digest", "TEXT"},
	}
	for _, c := range columns {
		if existing[c.name] {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`ALTER TABLE execution_requests ADD COLUMN `+c.name+` `+c.def); err != nil {
			return fmt.Errorf("column %s: %w", c.name, err)
		}
	}
	for _, ddl := range []string{
		`CREATE INDEX IF NOT EXISTS idx_exec_provider_run
		 ON execution_requests (provider_id, provider_run_id)
		 WHERE provider_run_id IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_exec_grant
		 ON execution_requests (grant_id)
		 WHERE grant_id IS NOT NULL`,
	} {
		if _, err := tx.ExecContext(ctx, ddl); err != nil {
			return err
		}
	}
	return nil
}

// sqliteMigrationForensic mirrors the PG migration 8: the two
// append-only forensic ledgers plus the provider/terminal evidence
// split on the materialized row. Timestamps are INTEGER unix
// milliseconds like the rest of the embedded schema; result_bytes is
// BLOB so the exact asserted payload is preserved byte-for-byte.
func sqliteMigrationForensic(ctx context.Context, tx *sql.Tx) error {
	existing := map[string]bool{}
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(execution_requests)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		existing[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, c := range []string{
		"provider_evidence_digest",
		"terminal_result_digest",
		"terminal_evidence_digest",
	} {
		if existing[c] {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`ALTER TABLE execution_requests ADD COLUMN `+c+` TEXT`); err != nil {
			return fmt.Errorf("column %s: %w", c, err)
		}
	}
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS effect_provider_observations (
			execution_id TEXT NOT NULL,
			sequence INTEGER NOT NULL,
			record_version INTEGER NOT NULL,
			observation_kind TEXT NOT NULL,
			provider_id TEXT,
			provider_run_id TEXT,
			provider_status TEXT,
			result_bytes BLOB,
			result_sha256 TEXT,
			result_canonical_digest TEXT,
			evidence_sha256 TEXT,
			receipt_version INTEGER NOT NULL DEFAULT 0,
			observed_at INTEGER NOT NULL,
			PRIMARY KEY (execution_id, sequence)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_observations_run
		 ON effect_provider_observations (provider_id, provider_run_id)
		 WHERE provider_run_id IS NOT NULL`,
		`CREATE TABLE IF NOT EXISTS effect_events (
			execution_id TEXT NOT NULL,
			sequence INTEGER NOT NULL,
			record_version INTEGER NOT NULL,
			event_type TEXT NOT NULL,
			actor TEXT,
			previous_state TEXT,
			new_state TEXT,
			result_digest TEXT,
			evidence_digest TEXT,
			claim_generation INTEGER,
			occurred_at INTEGER NOT NULL,
			metadata TEXT,
			PRIMARY KEY (execution_id, sequence)
		)`,
	} {
		if _, err := tx.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("forensic record schema: %w", err)
		}
	}
	return nil
}

// sqliteMigrationClusterEpoch mirrors the PG migration 9: the
// single-row cluster_meta table carrying the DR fence epoch, plus
// admitted_epoch on execution_requests for forensic provenance.
// Existing rows backfill to epoch 1 — they were admitted before
// epochs existed, when the implicit epoch was the initial one.
func sqliteMigrationClusterEpoch(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS cluster_meta (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			epoch INTEGER NOT NULL,
			advanced_at INTEGER,
			advance_reason TEXT
		)`); err != nil {
		return fmt.Errorf("cluster_meta table: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cluster_meta (id, epoch, advanced_at, advance_reason)
		VALUES (1, 1, `+sqliteNow+`, 'initial epoch')
		ON CONFLICT (id) DO NOTHING`); err != nil {
		return fmt.Errorf("cluster_meta seed: %w", err)
	}
	existing := map[string]bool{}
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(execution_requests)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		existing[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if !existing["admitted_epoch"] {
		if _, err := tx.ExecContext(ctx,
			`ALTER TABLE execution_requests ADD COLUMN admitted_epoch INTEGER`); err != nil {
			return fmt.Errorf("column admitted_epoch: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE execution_requests SET admitted_epoch = 1 WHERE admitted_epoch IS NULL`); err != nil {
		return fmt.Errorf("backfill admitted_epoch: %w", err)
	}
	return nil
}

// sqliteMigrationClusterRecoveryMode adds the post-restore recovery
// gate to cluster_meta — the embedded counterpart of
// migrationClusterRecoveryMode.
func sqliteMigrationClusterRecoveryMode(ctx context.Context, tx *sql.Tx) error {
	existing := map[string]bool{}
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(cluster_meta)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		existing[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, col := range []struct{ name, ddl string }{
		{"recovery_required", `ALTER TABLE cluster_meta ADD COLUMN recovery_required INTEGER NOT NULL DEFAULT 0`},
		{"recovery_completed_at", `ALTER TABLE cluster_meta ADD COLUMN recovery_completed_at INTEGER`},
		{"recovery_resolution", `ALTER TABLE cluster_meta ADD COLUMN recovery_resolution TEXT`},
	} {
		if existing[col.name] {
			continue
		}
		if _, err := tx.ExecContext(ctx, col.ddl); err != nil {
			return fmt.Errorf("column %s: %w", col.name, err)
		}
	}
	return nil
}

// sqliteInsertEffectEvent mirrors insertEffectEvent for the embedded
// backend: sequence is allocated with MAX+1 inside the mutation's
// transaction (single-writer BEGIN IMMEDIATE serializes all writers),
// and record_version/actor fall back to the post-update row values.
func sqliteInsertEffectEvent(ctx context.Context, tx *sql.Tx, executionID string, ev effectEvent) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO effect_events
			(execution_id, sequence, record_version, event_type, actor,
			 previous_state, new_state, result_digest, evidence_digest,
			 claim_generation, occurred_at, metadata)
		SELECT er.execution_id,
			COALESCE((SELECT MAX(e.sequence) FROM effect_events e
			          WHERE e.execution_id = er.execution_id), 0) + 1,
			er.version, ?2,
			COALESCE(NULLIF(?3, ''), er.lease_owner, er.reconcile_owner),
			NULLIF(?4, ''), COALESCE(NULLIF(?5, ''), er.state),
			NULLIF(?6, ''), NULLIF(?7, ''), NULLIF(?8, 0),
			`+sqliteNow+`, NULLIF(?9, '')
		FROM execution_requests er
		WHERE er.execution_id = ?1
	`, executionID, ev.eventType, ev.actor, ev.previousState, ev.newState,
		ev.resultDigest, ev.evidenceDigest, ev.claimGeneration, ev.metadata)
	return err
}

// sqliteInsertObservationRow mirrors insertObservationRow for the
// embedded backend — see insertObservationRow.
func sqliteInsertObservationRow(ctx context.Context, tx *sql.Tx, executionID, kind string, rawResult []byte, obs ProviderObservation) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO effect_provider_observations
			(execution_id, sequence, record_version, observation_kind,
			 provider_id, provider_run_id, provider_status,
			 result_bytes, result_sha256, result_canonical_digest,
			 evidence_sha256, receipt_version, observed_at)
		SELECT er.execution_id,
			COALESCE((SELECT MAX(o.sequence) FROM effect_provider_observations o
			          WHERE o.execution_id = er.execution_id), 0) + 1,
			er.version, ?2,
			NULLIF(?3, ''), NULLIF(?4, ''), NULLIF(?5, ''),
			?6, NULLIF(?7, ''), NULLIF(?8, ''), NULLIF(?9, ''), ?10,
			`+sqliteNow+`
		FROM execution_requests er
		WHERE er.execution_id = ?1
	`, executionID, kind, obs.ProviderID, obs.ProviderRunID, obs.ProviderStatus,
		nullableBytes(rawResult), sha256Hex(rawResult), obs.ResultDigest,
		obs.EvidenceDigest, obs.ReceiptVersion)
	return err
}

// noteContentionEvent records a LEASE_LOST/CLAIM_LOST forensic hint
// after a fenced write loses its CAS — see Store.noteContentionEvent.
// SQLite needs no FOR UPDATE pre-lock: single-writer BEGIN IMMEDIATE
// already serializes sequence allocation.
func (s *SQLiteStore) noteContentionEvent(ctx context.Context, executionID, eventType, metadata string) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	if err := sqliteInsertEffectEvent(ctx, tx, executionID, effectEvent{
		eventType: eventType,
		metadata:  metadata,
	}); err != nil {
		return
	}
	_ = tx.Commit()
}

// ─── Acquire ─────────────────────────────────────────────────────────

// Acquire attempts to acquire a lease for an execution. Identical
// reclaim matrix to the PostgreSQL store — see Store.Acquire.
func (s *SQLiteStore) Acquire(ctx context.Context, key, principal, capability, digest, grantID, class string, leaseDuration time.Duration) (*AcquireResult, error) {
	return s.AcquireWithAuthority(ctx, key, principal, capability, digest,
		AuthorityBinding{Ref: grantID}, class, leaseDuration)
}

// AcquireWithAuthority is Acquire plus the immutable authority
// snapshot — see Store.AcquireWithAuthority.
func (s *SQLiteStore) AcquireWithAuthority(ctx context.Context, key, principal, capability, digest string, authority AuthorityBinding, class string, leaseDuration time.Duration) (*AcquireResult, error) {
	if err := s.leaseCfg.Validate(leaseDuration); err != nil {
		return nil, err
	}

	leaseToken, err := generateLeaseToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate lease token: %w", err)
	}
	leaseOwner := fmt.Sprintf("pid-%d", currentPID())

	genID, err := generateExecutionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate execution ID: %w", err)
	}
	var executionID string
	var createdAtMs int64
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	// SELECT-guarded INSERT — mirrors Store.AcquireWithAuthority. The
	// BEGIN IMMEDIATE write lock additionally freezes the epoch for
	// this statement's duration, so the guard cannot be raced here.
	// The recovery_required clause closes admission while the cluster
	// reconciles a restored world (RECOVERY_REQUIRED mode).
	err = tx.QueryRowContext(ctx, `
		INSERT INTO execution_requests
			(execution_id, idempotency_key, principal_id, capability_id, request_digest,
			 grant_id, authority_generation, authority_digest, execution_class, state,
			 lease_owner, lease_token, lease_started_at, lease_expires_at,
			 lease_generation, attempt, version, created_at, updated_at, admitted_epoch)
		SELECT ?10, ?1, ?2, ?3, ?4, ?5, ?11, ?12, ?6, 'PREPARED',
				?7, ?8, `+sqliteNow+`, `+sqliteNow+` + ?9,
				1, 0, 1, `+sqliteNow+`, `+sqliteNow+`, cm.epoch
		FROM cluster_meta cm
		WHERE cm.id = 1 AND cm.epoch = `+strconv.FormatInt(s.epoch, 10)+` AND cm.recovery_required = 0
		ON CONFLICT (principal_id, capability_id, idempotency_key) DO NOTHING
		RETURNING execution_id, created_at
	`, key, principal, capability, digest, nullableString(authority.Ref), class,
		leaseOwner, leaseToken, msDuration(leaseDuration),
		genID, authority.Generation, nullableString(authority.Digest),
	).Scan(&executionID, &createdAtMs)

	if err == nil {
		if err := sqliteInsertEffectEvent(ctx, tx, executionID, effectEvent{
			eventType:       EventAcquired,
			actor:           leaseOwner,
			newState:        string(StatePrepared),
			claimGeneration: 1,
		}); err != nil {
			tx.Rollback()
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		s.metrics.acquires.Add(1)
		createdAt := sqliteTime(createdAtMs)
		return &AcquireResult{
			Kind:       LeaseAcquired,
			State:      StatePrepared,
			LeaseToken: leaseToken,
			Generation: 1,
			Record: &Record{
				ExecutionID:         executionID,
				IdempotencyKey:      key,
				PrincipalID:         principal,
				CapabilityID:        capability,
				RequestDigest:       digest,
				GrantID:             authority.Ref,
				AuthorityGeneration: authority.Generation,
				AuthorityDigest:     authority.Digest,
				ExecutionClass:      class,
				State:               StatePrepared,
				LeaseOwner:          leaseOwner,
				LeaseToken:          leaseToken,
				LeaseGeneration:     1,
				Attempt:             0,
				Version:             1,
				CreatedAt:           createdAt,
				UpdatedAt:           createdAt,
				AdmittedEpoch:       s.epoch,
			},
		}, nil
	}

	// Insert did not succeed — key conflict or driver error. Nothing
	// below uses this transaction.
	tx.Rollback()

	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	rec, err := s.lookupByKey(ctx, principal, capability, key)
	if errors.Is(err, sql.ErrNoRows) {
		// No record exists: the INSERT was fenced by the epoch or
		// recovery guard, not the key conflict.
		if epochErr := s.checkEpoch(ctx); epochErr != nil {
			return nil, epochErr
		}
		if recErr := s.checkRecoveryMode(ctx); recErr != nil {
			return nil, recErr
		}
		return nil, fmt.Errorf("%w: acquire raced — key vanished between insert and lookup",
			LeaseStateConflict)
	}
	if err != nil {
		return nil, err
	}

	if rec.RequestDigest != digest {
		return &AcquireResult{Kind: IdempotencyConflict, State: rec.State, Record: rec}, nil
	}
	if rec.State.IsDurablyFinal() {
		return &AcquireResult{Kind: TerminalReplay, State: rec.State, Record: rec}, nil
	}
	if rec.State == StateUnknown {
		return &AcquireResult{Kind: RecoveryRequired, State: rec.State, Record: rec}, nil
	}

	if (rec.State == StatePrepared || rec.State == StateExecuting) && rec.LeaseExpiresAt != nil {
		reclaimed, err := s.reclaimExpiredLease(ctx, rec, leaseToken, leaseOwner, leaseDuration)
		if err != nil {
			return nil, err
		}
		if reclaimed {
			s.metrics.acquires.Add(1)
			return &AcquireResult{
				Kind:       LeaseReclaimed,
				State:      StatePrepared,
				LeaseToken: leaseToken,
				Generation: rec.LeaseGeneration,
				Record:     rec,
			}, nil
		}
		rec, err = s.lookupByKey(ctx, principal, capability, key)
		if err != nil {
			return nil, err
		}
		if rec.State.IsDurablyFinal() {
			return &AcquireResult{Kind: TerminalReplay, State: rec.State, Record: rec}, nil
		}
		if rec.State == StateUnknown {
			return &AcquireResult{Kind: RecoveryRequired, State: rec.State, Record: rec}, nil
		}
	}

	if rec.State == StateInFlight && rec.LeaseExpiresAt != nil {
		marked, err := s.markInFlightExpiredAsUnknown(ctx, rec, leaseOwner)
		if err != nil {
			return nil, err
		}
		if marked {
			return &AcquireResult{Kind: RecoveryRequired, State: StateUnknown, Record: rec}, nil
		}
		rec, err = s.lookupByKey(ctx, principal, capability, key)
		if err != nil {
			return nil, err
		}
		if rec.State.IsDurablyFinal() {
			return &AcquireResult{Kind: TerminalReplay, State: rec.State, Record: rec}, nil
		}
		if rec.State == StateUnknown {
			return &AcquireResult{Kind: RecoveryRequired, State: rec.State, Record: rec}, nil
		}
	}

	if rec.State == StatePrepared && rec.LeaseExpiresAt == nil {
		acquired, err := s.acquireUnleased(ctx, rec, leaseToken, leaseOwner, leaseDuration)
		if err != nil {
			return nil, err
		}
		if acquired {
			return &AcquireResult{
				Kind:       LeaseAcquired,
				State:      StatePrepared,
				LeaseToken: leaseToken,
				Generation: rec.LeaseGeneration,
				Record:     rec,
			}, nil
		}
		rec, err = s.lookupByKey(ctx, principal, capability, key)
		if err != nil {
			return nil, err
		}
		if rec.State.IsDurablyFinal() {
			return &AcquireResult{Kind: TerminalReplay, State: rec.State, Record: rec}, nil
		}
		if rec.State == StateUnknown {
			return &AcquireResult{Kind: RecoveryRequired, State: rec.State, Record: rec}, nil
		}
	}

	return &AcquireResult{Kind: LeaseHeldByOther, State: rec.State, Record: rec}, nil
}

func (s *SQLiteStore) acquireUnleased(ctx context.Context, rec *Record, newToken, newOwner string, duration time.Duration) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		UPDATE execution_requests
		SET lease_owner = ?1, lease_token = ?2,
		    lease_started_at = `+sqliteNow+`,
		    lease_expires_at = `+sqliteNow+` + ?3,
		    lease_generation = lease_generation + 1,
		    version = version + 1, updated_at = `+sqliteNow+`
		WHERE execution_id = ?4
		  AND state = 'PREPARED'
		  AND lease_token IS NULL
		  AND lease_expires_at IS NULL
		  AND version = ?5
		  `+s.epochGuardSQL(), newOwner, newToken, msDuration(duration),
		rec.ExecutionID, rec.Version)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if rows == 0 {
		tx.Rollback()
		return false, s.checkEpoch(ctx)
	}
	if err := sqliteInsertEffectEvent(ctx, tx, rec.ExecutionID, effectEvent{
		eventType:       EventLeaseAcquired,
		actor:           newOwner,
		previousState:   string(StatePrepared),
		newState:        string(StatePrepared),
		claimGeneration: rec.LeaseGeneration + 1,
	}); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	rec.LeaseOwner = newOwner
	rec.LeaseToken = newToken
	rec.LeaseGeneration++
	rec.Version++
	return true, nil
}

func (s *SQLiteStore) reclaimExpiredLease(ctx context.Context, rec *Record, newToken, newOwner string, duration time.Duration) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		UPDATE execution_requests
		SET lease_owner = ?1, lease_token = ?2,
		    lease_started_at = `+sqliteNow+`,
		    lease_expires_at = `+sqliteNow+` + ?3,
		    lease_generation = lease_generation + 1,
		    attempt = attempt + 1, version = version + 1,
		    state = 'PREPARED', updated_at = `+sqliteNow+`
		WHERE execution_id = ?4
		  AND version = ?5
		  AND state IN ('PREPARED', 'EXECUTING')
		  AND lease_expires_at < `+sqliteNow+`
		  AND (SELECT recovery_required FROM cluster_meta WHERE id = 1) = 0
		  `+s.epochGuardSQL(), newOwner, newToken, msDuration(duration),
		rec.ExecutionID, rec.Version)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if rows == 0 {
		tx.Rollback()
		if epochErr := s.checkEpoch(ctx); epochErr != nil {
			return false, epochErr
		}
		// Reclaiming a pre-dispatch record IS new-effect admission —
		// it closes while the cluster reconciles a restored world.
		if recErr := s.checkRecoveryMode(ctx); recErr != nil {
			return false, recErr
		}
		return false, nil
	}
	if err := sqliteInsertEffectEvent(ctx, tx, rec.ExecutionID, effectEvent{
		eventType:       EventLeaseAcquired,
		actor:           newOwner,
		previousState:   string(rec.State),
		newState:        string(StatePrepared),
		claimGeneration: rec.LeaseGeneration + 1,
		metadata:        "expired lease reclaimed",
	}); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	rec.LeaseOwner = newOwner
	rec.LeaseToken = newToken
	rec.LeaseGeneration++
	rec.Attempt++
	rec.Version++
	rec.State = StatePrepared
	return true, nil
}

func (s *SQLiteStore) markInFlightExpiredAsUnknown(ctx context.Context, rec *Record, actor string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = 'UNKNOWN', version = version + 1,
		    lease_owner = NULL, lease_token = NULL,
		    lease_started_at = NULL, lease_expires_at = NULL,
		    reconcile_owner = NULL, reconcile_lease_expires_at = NULL,
		    entered_unknown_at = `+sqliteNow+`,
		    updated_at = `+sqliteNow+`
		WHERE execution_id = ?1
		  AND version = ?2
		  AND state = 'IN_FLIGHT'
		  AND lease_expires_at < `+sqliteNow+`
		  `+s.epochGuardSQL(), rec.ExecutionID, rec.Version)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if rows == 0 {
		tx.Rollback()
		return false, s.checkEpoch(ctx)
	}
	if err := sqliteInsertEffectEvent(ctx, tx, rec.ExecutionID, effectEvent{
		eventType:     EventEnteredUnknown,
		actor:         actor,
		previousState: string(StateInFlight),
		newState:      string(StateUnknown),
		metadata:      "lease expired in flight",
	}); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	rec.State = StateUnknown
	rec.Version++
	s.metrics.unknownEntered.Add(1)
	return true, nil
}

// ─── Lease-fenced transitions ────────────────────────────────────────

// BeginExecution transitions from PREPARED to EXECUTING.
func (s *SQLiteStore) BeginExecution(ctx context.Context, executionID, leaseToken string, leaseGeneration int) error {
	err := s.leaseFencedTransition(ctx, executionID, leaseToken, leaseGeneration, StatePrepared, StateExecuting)
	if err != nil {
		return err
	}
	s.metrics.executing.Add(1)
	return nil
}

// MarkInFlight transitions from EXECUTING to IN_FLIGHT, persisting
// provider_id and the recovery locator atomically. Same ordering as
// the PostgreSQL store: size bound → redactor → denylist on the final
// persisted representation → write.
func (s *SQLiteStore) MarkInFlight(ctx context.Context, executionID, leaseToken string, leaseGeneration int, providerID string, recoveryLocator json.RawMessage) error {
	if len(recoveryLocator) > MaxRecoveryLocatorBytes {
		return fmt.Errorf("%w: recovery locator exceeds %d bytes (got %d)",
			LocatorTooLarge, MaxRecoveryLocatorBytes, len(recoveryLocator))
	}
	if s.locatorRedactor != nil && len(recoveryLocator) > 0 {
		redacted, err := s.locatorRedactor(recoveryLocator)
		if err != nil {
			return fmt.Errorf("recovery locator redaction failed: %w", err)
		}
		if len(redacted) > MaxRecoveryLocatorBytes {
			return fmt.Errorf("%w: redacted recovery locator exceeds %d bytes (got %d)",
				LocatorTooLarge, MaxRecoveryLocatorBytes, len(redacted))
		}
		recoveryLocator = redacted
	}
	if field := forbiddenLocatorField(recoveryLocator); field != "" {
		return fmt.Errorf("%w: recovery locator contains forbidden field %q",
			LocatorContainsSecret, field)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = 'IN_FLIGHT', version = version + 1,
		    provider_id = ?4, recovery_locator = ?5,
		    updated_at = `+sqliteNow+`
		WHERE execution_id = ?1
		  AND state = 'EXECUTING'
		  AND lease_token = ?2
		  AND lease_generation = ?3
		  AND lease_expires_at > `+sqliteNow+`
		  `+s.epochGuardSQL(), executionID, leaseToken, leaseGeneration,
		nullableString(providerID), nullableString(string(recoveryLocator)))
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		tx.Rollback()
		return s.classifyTransitionFailure(ctx, executionID, leaseToken, leaseGeneration, StateExecuting)
	}
	if err := sqliteInsertEffectEvent(ctx, tx, executionID, effectEvent{
		eventType:       EventDispatchStarted,
		previousState:   string(StateExecuting),
		newState:        string(StateInFlight),
		claimGeneration: leaseGeneration,
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.metrics.inFlight.Add(1)
	return nil
}

func (s *SQLiteStore) leaseFencedTransition(ctx context.Context, executionID, leaseToken string, leaseGeneration int, expectedState, newState State) error {
	if !isLegalTransition(expectedState, newState) {
		return fmt.Errorf("%w: illegal transition %s → %s", LeaseStateConflict, expectedState, newState)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = ?1, version = version + 1, updated_at = `+sqliteNow+`
		WHERE execution_id = ?2
		  AND state = ?3
		  AND lease_token = ?4
		  AND lease_generation = ?5
		  AND lease_expires_at > `+sqliteNow+`
		  `+s.epochGuardSQL(), string(newState), executionID, string(expectedState), leaseToken, leaseGeneration)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		// Release our write lock first — classification reads (and its
		// contention annotation) must not contend with our own tx.
		tx.Rollback()
		return s.classifyTransitionFailure(ctx, executionID, leaseToken, leaseGeneration, expectedState)
	}
	if err := sqliteInsertEffectEvent(ctx, tx, executionID, effectEvent{
		eventType:       EventExecutionBegun,
		previousState:   string(expectedState),
		newState:        string(newState),
		claimGeneration: leaseGeneration,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) classifyTransitionFailure(ctx context.Context, executionID, leaseToken string, leaseGeneration int, expectedState State) error {
	if err := s.checkEpoch(ctx); err != nil {
		return err
	}
	s.metrics.fenceRejections.Add(1)
	rec, err := s.Lookup(ctx, executionID)
	if err != nil {
		return fmt.Errorf("%w: execution %s transition failed (lookup error: %v)", LeaseLost, executionID, err)
	}
	if rec.State != expectedState {
		if rec.State.IsDurablyFinal() {
			return fmt.Errorf("%w: execution %s is durably final (%s)", LeaseStateConflict, executionID, rec.State)
		}
		return fmt.Errorf("%w: execution %s expected %s but is %s", LeaseStateConflict, executionID, expectedState, rec.State)
	}
	if rec.LeaseToken != leaseToken {
		s.noteContentionEvent(ctx, executionID, EventLeaseLost, "transition fenced: lease token held by another owner")
		return fmt.Errorf("%w: execution %s token mismatch", LeaseTokenMismatch, executionID)
	}
	if rec.LeaseGeneration != leaseGeneration {
		s.noteContentionEvent(ctx, executionID, EventLeaseLost, "transition fenced: lease generation advanced")
		return fmt.Errorf("%w: execution %s generation %d != %d", LeaseGenerationMismatch, executionID, rec.LeaseGeneration, leaseGeneration)
	}
	return fmt.Errorf("%w: execution %s lease expired", LeaseExpired, executionID)
}

// RenewLease extends the lease for the current holder. MAX() is NULL-
// safe here because the WHERE clause already requires a non-expired
// (non-NULL) lease_expires_at.
func (s *SQLiteStore) RenewLease(ctx context.Context, executionID, leaseToken string, leaseGeneration int, duration time.Duration) error {
	if err := s.leaseCfg.Validate(duration); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		UPDATE execution_requests
		SET lease_expires_at = MAX(lease_expires_at, `+sqliteNow+` + ?1),
		    updated_at = `+sqliteNow+`
		WHERE execution_id = ?2
		  AND lease_token = ?3
		  AND lease_generation = ?4
		  AND lease_expires_at > `+sqliteNow+`
		  AND state NOT IN ('COMMITTED', 'FAILED', 'DENIED', 'UNKNOWN')
		  `+s.epochGuardSQL(), msDuration(duration), executionID, leaseToken, leaseGeneration)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		tx.Rollback()
		return s.classifyRenewalFailure(ctx, executionID, leaseToken, leaseGeneration)
	}
	if err := sqliteInsertEffectEvent(ctx, tx, executionID, effectEvent{
		eventType:       EventLeaseRenewed,
		claimGeneration: leaseGeneration,
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.metrics.leaseRenewals.Add(1)
	return nil
}

func (s *SQLiteStore) classifyRenewalFailure(ctx context.Context, executionID, leaseToken string, leaseGeneration int) error {
	if err := s.checkEpoch(ctx); err != nil {
		return err
	}
	s.metrics.fenceRejections.Add(1)
	rec, err := s.Lookup(ctx, executionID)
	if err != nil {
		return fmt.Errorf("%w: execution %s renewal failed (lookup error: %v)", LeaseLost, executionID, err)
	}
	if rec.State.IsDurablyFinal() || rec.State == StateUnknown {
		return fmt.Errorf("%w: execution %s is terminal (%s)", LeaseStateConflict, executionID, rec.State)
	}
	if rec.LeaseToken != leaseToken {
		s.noteContentionEvent(ctx, executionID, EventLeaseLost, "renewal fenced: lease token held by another owner")
		return fmt.Errorf("%w: execution %s token mismatch", LeaseTokenMismatch, executionID)
	}
	if rec.LeaseGeneration != leaseGeneration {
		s.noteContentionEvent(ctx, executionID, EventLeaseLost, "renewal fenced: lease generation advanced")
		return fmt.Errorf("%w: execution %s generation %d != %d", LeaseGenerationMismatch, executionID, rec.LeaseGeneration, leaseGeneration)
	}
	return fmt.Errorf("%w: execution %s lease expired", LeaseExpired, executionID)
}

// AbandonPreDispatch transitions PREPARED or EXECUTING back to
// lease-less PREPARED — see Store.AbandonPreDispatch.
func (s *SQLiteStore) AbandonPreDispatch(ctx context.Context, executionID, leaseToken string, leaseGeneration int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = 'PREPARED', version = version + 1,
		    lease_owner = NULL, lease_token = NULL,
		    lease_started_at = NULL, lease_expires_at = NULL,
		    updated_at = `+sqliteNow+`
		WHERE execution_id = ?1
		  AND state IN ('PREPARED', 'EXECUTING')
		  AND lease_token = ?2
		  AND lease_generation = ?3
		  AND lease_expires_at > `+sqliteNow+`
		  `+s.epochGuardSQL(), executionID, leaseToken, leaseGeneration)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		tx.Rollback()
		return s.classifyAbandonFailure(ctx, executionID, leaseToken, leaseGeneration)
	}
	if err := sqliteInsertEffectEvent(ctx, tx, executionID, effectEvent{
		eventType:       EventAbandonedPreDispatch,
		newState:        string(StatePrepared),
		claimGeneration: leaseGeneration,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) classifyAbandonFailure(ctx context.Context, executionID, leaseToken string, leaseGeneration int) error {
	if err := s.checkEpoch(ctx); err != nil {
		return err
	}
	s.metrics.fenceRejections.Add(1)
	rec, err := s.Lookup(ctx, executionID)
	if err != nil {
		return fmt.Errorf("%w: execution %s abandon failed (lookup error: %v)", LeaseLost, executionID, err)
	}
	if rec.State != StatePrepared && rec.State != StateExecuting {
		if rec.State.IsDurablyFinal() {
			return fmt.Errorf("%w: execution %s is durably final (%s)", LeaseStateConflict, executionID, rec.State)
		}
		return fmt.Errorf("%w: execution %s cannot abandon from %s (dispatch boundary crossed)", LeaseStateConflict, executionID, rec.State)
	}
	if rec.LeaseToken != leaseToken {
		s.noteContentionEvent(ctx, executionID, EventLeaseLost, "abandon fenced: lease token held by another owner")
		return fmt.Errorf("%w: execution %s token mismatch", LeaseTokenMismatch, executionID)
	}
	if rec.LeaseGeneration != leaseGeneration {
		s.noteContentionEvent(ctx, executionID, EventLeaseLost, "abandon fenced: lease generation advanced")
		return fmt.Errorf("%w: execution %s generation %d != %d", LeaseGenerationMismatch, executionID, rec.LeaseGeneration, leaseGeneration)
	}
	return fmt.Errorf("%w: execution %s lease expired", LeaseExpired, executionID)
}

// ─── Finalization ────────────────────────────────────────────────────

// Finalize atomically finalizes an execution with an immutable
// terminal receipt — identical policy to Store.Finalize: receipt
// identity validation, unified terminal proof policy, lease fencing,
// and provider-identity monotonicity.
func (s *SQLiteStore) Finalize(ctx context.Context, executionID, leaseToken string, leaseGeneration int, expectedState State, receipt TerminalReceipt) error {
	if !receipt.TerminalStatus.IsDurablyFinal() {
		return fmt.Errorf("invalid terminal status %s: Finalize requires a durably-final state (COMMITTED, FAILED, or DENIED)", receipt.TerminalStatus)
	}

	// Validate receipt fields before any state work — identical
	// fail-closed rules as Store.Finalize.
	if receipt.ReceiptVersion < 0 {
		return fmt.Errorf("invalid receipt_version %d", receipt.ReceiptVersion)
	}
	if len(receipt.CanonicalResult) > MaxResultBytes {
		return fmt.Errorf("%w: canonical result is %d bytes (max %d)",
			ResultTooLarge, len(receipt.CanonicalResult), MaxResultBytes)
	}
	if len(receipt.EvidenceReceipt) > MaxEvidenceReceiptBytes {
		return fmt.Errorf("%w: evidence receipt is %d bytes (max %d)",
			EvidenceReceiptTooLarge, len(receipt.EvidenceReceipt), MaxEvidenceReceiptBytes)
	}
	// Same convention as Store.Finalize: the result column keeps the
	// asserted bytes verbatim (replay fidelity); canonicalization
	// happens inside Digest().
	if _, err := canonicalizeJSON(receipt.CanonicalResult); err != nil {
		return fmt.Errorf("canonical result is not well-formed JSON: %w", err)
	}

	if !isLegalTransition(expectedState, receipt.TerminalStatus) {
		return fmt.Errorf("%w: illegal finalization transition %s → %s", LeaseStateConflict, expectedState, receipt.TerminalStatus)
	}

	existing, err := s.Lookup(ctx, executionID)
	if err != nil {
		return fmt.Errorf("finalize lookup failed: %w", err)
	}

	if receipt.ExecutionID != "" && receipt.ExecutionID != executionID {
		return fmt.Errorf("receipt identity mismatch: receipt execution_id %s != row execution_id %s", receipt.ExecutionID, executionID)
	}
	if receipt.Capability != "" && receipt.Capability != existing.CapabilityID {
		return fmt.Errorf("receipt identity mismatch: receipt capability %s != row capability_id %s", receipt.Capability, existing.CapabilityID)
	}
	if receipt.Principal != "" && receipt.Principal != existing.PrincipalID {
		return fmt.Errorf("receipt identity mismatch: receipt principal %s != row principal_id %s", receipt.Principal, existing.PrincipalID)
	}
	if receipt.RequestDigest != "" && receipt.RequestDigest != existing.RequestDigest {
		return fmt.Errorf("receipt identity mismatch: receipt request_digest %s != row request_digest %s", receipt.RequestDigest, existing.RequestDigest)
	}

	receipt.ExecutionID = executionID
	receipt.Capability = existing.CapabilityID
	receipt.Principal = existing.PrincipalID
	receipt.RequestDigest = existing.RequestDigest

	receiptDigest, err := receipt.Digest()
	if err != nil {
		return fmt.Errorf("failed to compute terminal receipt digest: %w", err)
	}

	if existing.State.IsDurablyFinal() {
		if existing.TerminalReceiptDigest == receiptDigest {
			return nil
		}
		return fmt.Errorf("FINALIZATION_CONFLICT: execution %s already finalized with different receipt (existing digest %s, new digest %s)",
			executionID, existing.TerminalReceiptDigest, receiptDigest)
	}

	var verified *VerifiedEvidence
	if existing.ExecutionClass == "CRITICAL" {
		verified, err = s.evidenceVerifier().Verify(ctx, existing, receipt, receipt.TerminalStatus)
		if err != nil {
			s.metrics.criticalEvidenceDenied.Add(1)
			return fmt.Errorf("CRITICAL finalization to %s requires a verified signed evidence receipt: %w", receipt.TerminalStatus, err)
		}
	}
	if err := ValidateTerminalTransition(existing, receipt.TerminalStatus, receipt, verified); err != nil {
		s.metrics.criticalEvidenceDenied.Add(1)
		return err
	}

	terminalResultSHA := sha256Hex(receipt.CanonicalResult)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = ?1, result = ?2, evidence_digest = ?3, receipt_version = ?4,
		    provider_id = COALESCE(?5, provider_id),
		    provider_run_id = COALESCE(?6, provider_run_id),
		    terminal_receipt_digest = ?7, evidence_receipt = ?13,
		    terminal_result_digest = ?14, terminal_evidence_digest = ?15,
		    lease_owner = NULL, lease_token = NULL,
		    lease_started_at = NULL, lease_expires_at = NULL,
		    recovery_locator = NULL,
		    version = version + 1, updated_at = `+sqliteNow+`
		WHERE execution_id = ?8
		  AND state = ?9
		  AND lease_token = ?10
		  AND lease_generation = ?11
		  AND lease_expires_at > `+sqliteNow+`
		  AND version = ?12
		  AND (provider_id IS NULL OR ?5 IS NULL OR provider_id = ?5)
		  AND (provider_run_id IS NULL OR ?6 IS NULL OR provider_run_id = ?6)
		  `+s.epochGuardSQL(), string(receipt.TerminalStatus),
		nullableString(string(receipt.CanonicalResult)),
		nullableString(receipt.EvidenceDigest),
		receipt.ReceiptVersion,
		nullableString(receipt.ProviderID),
		nullableString(receipt.ProviderRunID),
		receiptDigest,
		executionID, string(expectedState), leaseToken, leaseGeneration, existing.Version,
		nullableString(string(receipt.EvidenceReceipt)),
		nullableString(terminalResultSHA), nullableString(receipt.EvidenceDigest))
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		// Release our write lock — the classification lookups (and any
		// contention annotation) must not contend with our own tx.
		tx.Rollback()
		current, lookupErr := s.Lookup(ctx, executionID)
		if lookupErr == nil && current.State.IsDurablyFinal() {
			if current.TerminalReceiptDigest == receiptDigest {
				return nil
			}
			return fmt.Errorf("FINALIZATION_CONFLICT: execution %s already finalized with different receipt (existing digest %s, new digest %s)",
				executionID, current.TerminalReceiptDigest, receiptDigest)
		}
		if lookupErr == nil &&
			current.State == expectedState &&
			current.LeaseToken == leaseToken &&
			current.LeaseGeneration == leaseGeneration &&
			providerIdentityContradicts(
				current.ProviderID, receipt.ProviderID,
				current.ProviderRunID, receipt.ProviderRunID) {
			s.metrics.observationConflicts.Add(1)
			return fmt.Errorf("%w: execution %s terminal receipt contradicts stored provider observation", ProviderObservationConflict, executionID)
		}
		return s.classifyTransitionFailure(ctx, executionID, leaseToken, leaseGeneration, expectedState)
	}
	if err := sqliteInsertEffectEvent(ctx, tx, executionID, effectEvent{
		eventType:       EventTerminalResolved,
		previousState:   string(expectedState),
		newState:        string(receipt.TerminalStatus),
		resultDigest:    terminalResultSHA,
		evidenceDigest:  receipt.EvidenceDigest,
		claimGeneration: leaseGeneration,
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if receipt.TerminalStatus == StateCommitted {
		s.metrics.committed.Add(1)
	} else {
		s.metrics.failed.Add(1)
	}
	return nil
}

// ─── Recovery ────────────────────────────────────────────────────────

// EnterRecovery transitions a record to UNKNOWN — see Store.EnterRecovery.
func (s *SQLiteStore) EnterRecovery(ctx context.Context, executionID string, expectedState State, expectedVersion int) error {
	if !isLegalTransition(expectedState, StateUnknown) {
		return fmt.Errorf("%w: illegal recovery transition %s → UNKNOWN (only IN_FLIGHT may enter recovery)", LeaseStateConflict, expectedState)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = 'UNKNOWN', version = version + 1,
		    lease_owner = NULL, lease_token = NULL,
		    lease_started_at = NULL, lease_expires_at = NULL,
		    reconcile_owner = NULL, reconcile_lease_expires_at = NULL,
		    entered_unknown_at = `+sqliteNow+`,
		    updated_at = `+sqliteNow+`
		WHERE execution_id = ?1
		  AND state = ?2
		  AND version = ?3
		  `+s.epochGuardSQL(), executionID, string(expectedState), expectedVersion)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		tx.Rollback()
		if err := s.checkEpoch(ctx); err != nil {
			return err
		}
		return fmt.Errorf("%w: execution %s enter recovery CAS failed (state/version mismatch)", LeaseStateConflict, executionID)
	}
	if err := sqliteInsertEffectEvent(ctx, tx, executionID, effectEvent{
		eventType:     EventEnteredUnknown,
		previousState: string(expectedState),
		newState:      string(StateUnknown),
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.metrics.unknownEntered.Add(1)
	return nil
}

// EnterRecoveryWithObservation transitions to UNKNOWN while persisting
// the provider observation atomically — see
// Store.EnterRecoveryWithObservation. The result column is JSON text;
// canonicalizeObservation guarantees byte-stable comparison.
func (s *SQLiteStore) EnterRecoveryWithObservation(ctx context.Context, executionID string, expectedState State, expectedVersion int, obs ProviderObservation) error {
	if !isLegalTransition(expectedState, StateUnknown) {
		return fmt.Errorf("%w: illegal recovery transition %s → UNKNOWN (only IN_FLIGHT may enter recovery)", LeaseStateConflict, expectedState)
	}
	rawResult := obs.Result
	obs, err := canonicalizeObservation(obs)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = 'UNKNOWN', version = version + 1,
		    lease_owner = NULL, lease_token = NULL,
		    lease_started_at = NULL, lease_expires_at = NULL,
		    reconcile_owner = NULL, reconcile_lease_expires_at = NULL,
		    entered_unknown_at = `+sqliteNow+`,
		    provider_id = COALESCE(?4, provider_id),
		    provider_run_id = COALESCE(?5, provider_run_id),
		    provider_status = COALESCE(?6, provider_status),
		    result = COALESCE(?10, result),
		    provider_result = COALESCE(?11, provider_result),
		    provider_result_digest = COALESCE(?7, provider_result_digest),
		    provider_receipt_version = COALESCE(NULLIF(?8, 0), provider_receipt_version),
		    provider_observed_at = `+sqliteNow+`,
		    evidence_digest = COALESCE(?9, evidence_digest),
		    provider_evidence_digest = COALESCE(?9, provider_evidence_digest),
		    updated_at = `+sqliteNow+`
		WHERE execution_id = ?1
		  AND state = ?2
		  AND version = ?3
		  AND (provider_id IS NULL OR ?4 IS NULL OR provider_id = ?4)
		  AND (provider_run_id IS NULL OR ?5 IS NULL OR provider_run_id = ?5)
		  AND (provider_status IS NULL OR ?6 IS NULL OR provider_status = ?6)
		  AND (result IS NULL OR ?10 IS NULL OR result = ?10)
		  AND (provider_result IS NULL OR ?11 IS NULL OR provider_result = ?11)
		  AND (provider_result_digest IS NULL OR ?7 IS NULL OR provider_result_digest = ?7)
		  AND (provider_receipt_version IS NULL OR provider_receipt_version = 0 OR NULLIF(?8, 0) IS NULL OR provider_receipt_version = ?8)
		  AND (evidence_digest IS NULL OR ?9 IS NULL OR evidence_digest = ?9)
		  AND (provider_evidence_digest IS NULL OR ?9 IS NULL OR provider_evidence_digest = ?9)
		  `+s.epochGuardSQL(), executionID, string(expectedState), expectedVersion,
		nullableString(obs.ProviderID), nullableString(obs.ProviderRunID),
		nullableString(obs.ProviderStatus), nullableString(obs.ResultDigest),
		obs.ReceiptVersion,
		nullableString(obs.EvidenceDigest), nullableString(string(obs.Result)),
		nullableString(string(obs.Result)))
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		tx.Rollback()
		return s.classifyEnterRecoveryFailure(ctx, executionID, expectedState, expectedVersion)
	}
	if err := sqliteInsertObservationRow(ctx, tx, executionID, ObservationRecovery, rawResult, obs); err != nil {
		return err
	}
	if err := sqliteInsertEffectEvent(ctx, tx, executionID, effectEvent{
		eventType:      EventEnteredUnknown,
		previousState:  string(expectedState),
		newState:       string(StateUnknown),
		resultDigest:   obs.ResultDigest,
		evidenceDigest: obs.EvidenceDigest,
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.metrics.unknownEntered.Add(1)
	return nil
}

func (s *SQLiteStore) classifyEnterRecoveryFailure(ctx context.Context, executionID string, expectedState State, expectedVersion int) error {
	if err := s.checkEpoch(ctx); err != nil {
		return err
	}
	s.metrics.fenceRejections.Add(1)
	rec, err := s.Lookup(ctx, executionID)
	if err != nil {
		return err
	}
	if rec.State != expectedState || rec.Version != expectedVersion {
		return fmt.Errorf("%w: execution %s enter recovery with observation CAS failed (state/version mismatch)", LeaseStateConflict, executionID)
	}
	s.metrics.observationConflicts.Add(1)
	return fmt.Errorf("%w: execution %s observation contradicts stored provider data", ProviderObservationConflict, executionID)
}

// RecordProviderObservation durably records provider response metadata
// — identical monotonic/lease-fenced semantics to
// Store.RecordProviderObservation.
func (s *SQLiteStore) RecordProviderObservation(ctx context.Context, executionID, leaseToken string, leaseGeneration int, obs ProviderObservation) error {
	rawResult := obs.Result
	obs, err := canonicalizeObservation(obs)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `
		UPDATE execution_requests
		SET provider_id = COALESCE(?4, provider_id),
		    provider_run_id = COALESCE(?5, provider_run_id),
		    provider_status = COALESCE(?6, provider_status),
		    result = COALESCE(?7, result),
		    provider_result = COALESCE(?11, provider_result),
		    provider_result_digest = COALESCE(?8, provider_result_digest),
		    evidence_digest = COALESCE(?9, evidence_digest),
		    provider_evidence_digest = COALESCE(?9, provider_evidence_digest),
		    provider_receipt_version = COALESCE(NULLIF(?10, 0), provider_receipt_version),
		    provider_observed_at = `+sqliteNow+`,
		    updated_at = `+sqliteNow+`
		WHERE execution_id = ?1
		  AND (
		    (state = 'IN_FLIGHT' AND lease_token = ?2 AND lease_generation = ?3)
		    OR state = 'UNKNOWN'
		  )
		  AND (provider_id IS NULL OR ?4 IS NULL OR provider_id = ?4)
		  AND (provider_run_id IS NULL OR ?5 IS NULL OR provider_run_id = ?5)
		  AND (provider_status IS NULL OR ?6 IS NULL OR provider_status = ?6)
		  AND (result IS NULL OR ?7 IS NULL OR result = ?7)
		  AND (provider_result IS NULL OR ?11 IS NULL OR provider_result = ?11)
		  AND (provider_result_digest IS NULL OR ?8 IS NULL OR provider_result_digest = ?8)
		  AND (evidence_digest IS NULL OR ?9 IS NULL OR evidence_digest = ?9)
		  AND (provider_evidence_digest IS NULL OR ?9 IS NULL OR provider_evidence_digest = ?9)
		  AND (provider_receipt_version IS NULL OR provider_receipt_version = 0 OR NULLIF(?10, 0) IS NULL OR provider_receipt_version = ?10)
		  `+s.epochGuardSQL(), executionID, nullableString(leaseToken), leaseGeneration,
		nullableString(obs.ProviderID), nullableString(obs.ProviderRunID),
		nullableString(obs.ProviderStatus), nullableString(string(obs.Result)),
		nullableString(obs.ResultDigest), nullableString(obs.EvidenceDigest),
		obs.ReceiptVersion, nullableString(string(obs.Result)))
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		tx.Rollback()
		return s.classifyObservationFailure(ctx, executionID, leaseToken, leaseGeneration)
	}
	// A fenced IN_FLIGHT write is a dispatch observation; an UNKNOWN
	// write is recovery-side — see Store.RecordProviderObservation.
	var state string
	if err := tx.QueryRowContext(ctx,
		`SELECT state FROM execution_requests WHERE execution_id = ?1`,
		executionID).Scan(&state); err != nil {
		return err
	}
	kind, eventType := ObservationDispatch, EventProviderObserved
	if state == string(StateUnknown) {
		kind, eventType = ObservationReconciliation, EventReconciliationObserved
	}
	if err := sqliteInsertObservationRow(ctx, tx, executionID, kind, rawResult, obs); err != nil {
		return err
	}
	if err := sqliteInsertEffectEvent(ctx, tx, executionID, effectEvent{
		eventType:       eventType,
		resultDigest:    obs.ResultDigest,
		evidenceDigest:  obs.EvidenceDigest,
		claimGeneration: leaseGeneration,
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.metrics.observationWrites.Add(1)
	return nil
}

func (s *SQLiteStore) classifyObservationFailure(ctx context.Context, executionID, leaseToken string, leaseGeneration int) error {
	if err := s.checkEpoch(ctx); err != nil {
		return err
	}
	s.metrics.fenceRejections.Add(1)
	rec, err := s.Lookup(ctx, executionID)
	if err != nil {
		return err
	}
	if rec.State == StateInFlight &&
		(rec.LeaseToken != leaseToken || rec.LeaseGeneration != leaseGeneration) {
		s.noteContentionEvent(ctx, executionID, EventLeaseLost, "observation fenced: lease held by another owner")
		return fmt.Errorf("%w: execution %s observation rejected (lease token/generation mismatch)", LeaseStateConflict, executionID)
	}
	if rec.State != StateInFlight && rec.State != StateUnknown {
		return fmt.Errorf("%w: execution %s observation rejected (state %s)", LeaseStateConflict, executionID, rec.State)
	}
	s.metrics.observationConflicts.Add(1)
	return fmt.Errorf("%w: execution %s observation contradicts stored provider observation", ProviderObservationConflict, executionID)
}

// RecoverExpiredPreDispatch normalizes a crashed PREPARED/EXECUTING
// record to lease-less PREPARED — see Store.RecoverExpiredPreDispatch.
func (s *SQLiteStore) RecoverExpiredPreDispatch(ctx context.Context, executionID string, expectedVersion int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = 'PREPARED',
		    lease_owner = NULL, lease_token = NULL,
		    lease_started_at = NULL, lease_expires_at = NULL,
		    reconcile_owner = NULL, reconcile_lease_expires_at = NULL,
		    next_reconcile_at = NULL,
		    version = version + 1, updated_at = `+sqliteNow+`
		WHERE execution_id = ?1
		  AND state IN ('PREPARED', 'EXECUTING')
		  AND version = ?2
		  AND lease_expires_at IS NOT NULL
		  AND lease_expires_at < `+sqliteNow+`
		  `+s.epochGuardSQL(), executionID, expectedVersion)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		tx.Rollback()
		if err := s.checkEpoch(ctx); err != nil {
			return err
		}
		return fmt.Errorf("%w: execution %s recover expired pre-dispatch CAS failed (state/version/expiry mismatch)", LeaseStateConflict, executionID)
	}
	if err := sqliteInsertEffectEvent(ctx, tx, executionID, effectEvent{
		eventType: EventLeaseLost,
		newState:  string(StatePrepared),
		metadata:  "expired pre-dispatch lease recovered",
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// ScrubStaleRecoveryLocators clears recovery_locator on UNKNOWN records
// past the retention window measured from entered_unknown_at — see
// Store.ScrubStaleRecoveryLocators.
func (s *SQLiteStore) ScrubStaleRecoveryLocators(ctx context.Context, olderThan time.Duration) (int64, error) {
	if olderThan <= 0 {
		return 0, fmt.Errorf("locator retention must be positive")
	}
	if err := s.checkEpoch(ctx); err != nil {
		return 0, err
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET recovery_locator = NULL
		WHERE state = 'UNKNOWN'
		  AND recovery_locator IS NOT NULL
		  AND COALESCE(entered_unknown_at, created_at) < `+sqliteNow+` - ?1
		  `+s.epochGuardSQL(), msDuration(olderThan))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ResolveRecovery resolves an UNKNOWN record to a durably final state
// — identical proof policy and provider-identity monotonicity to
// Store.ResolveRecovery.
func (s *SQLiteStore) ResolveRecovery(ctx context.Context, executionID string, expectedVersion int, result RecoveryResult) error {
	decision := result.Decision
	var newState State
	switch decision {
	case RecoveryCommitted:
		newState = StateCommitted
	case RecoveryFailed:
		newState = StateFailed
	case RecoveryUnknown:
		result, err := s.db.ExecContext(ctx, `
			UPDATE execution_requests
			SET updated_at = `+sqliteNow+`
			WHERE execution_id = ?1 AND state = 'UNKNOWN' AND version = ?2
			  `+s.epochGuardSQL(), executionID, expectedVersion)
		if err != nil {
			return err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if rows == 0 {
			if err := s.checkEpoch(ctx); err != nil {
				return err
			}
			return fmt.Errorf("%w: execution %s recovery-unknown CAS failed (state/version mismatch)", LeaseStateConflict, executionID)
		}
		return nil
	case RecoveryRetryable:
		return fmt.Errorf("%w: RecoveryRetryable is not permitted — post-dispatch uncertainty cannot become retryable without proven safety (CRAB-V1-020)", LeaseStateConflict)
	case RecoveryConflict:
		return fmt.Errorf("%w: execution %s recovery conflict", LeaseStateConflict, executionID)
	default:
		return fmt.Errorf("unknown recovery decision: %s", decision)
	}

	// Validate the resolver's material before any state work — the
	// same fail-closed canonicalization and digest honesty rules as
	// the dispatch observation path. The result column stores the
	// canonical form.
	if len(result.EvidenceReceipt) > MaxEvidenceReceiptBytes {
		return fmt.Errorf("%w: evidence receipt is %d bytes (max %d)",
			EvidenceReceiptTooLarge, len(result.EvidenceReceipt), MaxEvidenceReceiptBytes)
	}
	rawResolverResult := result.Result
	robs, err := canonicalizeObservation(ProviderObservation{
		ProviderID:     result.ProviderID,
		ProviderRunID:  result.ProviderRunID,
		Result:         result.Result,
		EvidenceDigest: result.EvidenceDigest,
		ReceiptVersion: result.ReceiptVersion,
	})
	if err != nil {
		return err
	}

	existingRec, lookupErr := s.Lookup(ctx, executionID)
	if lookupErr != nil {
		return fmt.Errorf("recovery lookup failed: %w", lookupErr)
	}
	receipt := TerminalReceipt{
		ExecutionID:     executionID,
		Capability:      existingRec.CapabilityID,
		Principal:       existingRec.PrincipalID,
		RequestDigest:   existingRec.RequestDigest,
		CanonicalResult: result.Result,
		EvidenceDigest:  result.EvidenceDigest,
		ReceiptVersion:  result.ReceiptVersion,
		ProviderID:      result.ProviderID,
		ProviderRunID:   result.ProviderRunID,
		TerminalStatus:  newState,
		EvidenceReceipt: result.EvidenceReceipt,
	}

	var verified *VerifiedEvidence
	if existingRec.ExecutionClass == "CRITICAL" {
		v, verr := s.evidenceVerifier().Verify(ctx, existingRec, receipt, newState)
		if verr != nil {
			return fmt.Errorf("CRITICAL recovery to %s requires a verified signed evidence receipt: %w", decision, verr)
		}
		verified = v
	}
	if err := ValidateTerminalTransition(existingRec, newState, receipt, verified); err != nil {
		s.metrics.criticalEvidenceDenied.Add(1)
		return err
	}

	receiptDigest, err := receipt.Digest()
	if err != nil {
		return fmt.Errorf("failed to compute recovery receipt digest: %w", err)
	}

	// Result and evidence_digest are NOT guarded — recovery legitimately
	// produces a different evidence capture than the dispatch-time
	// observation (e.g. a listing object vs. the create response) and the
	// resolver's canonical values are the terminal output. COALESCE
	// preserves the stored observation when the resolver sends an empty
	// field rather than nulling it.
	terminalResultSHA := sha256Hex(result.Result)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result2, err := tx.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = ?1,
		    result = COALESCE(?2, result),
		    evidence_digest = COALESCE(?3, evidence_digest),
		    receipt_version = ?4,
		    provider_id = COALESCE(?5, provider_id),
		    provider_run_id = COALESCE(?6, provider_run_id),
		    terminal_receipt_digest = ?7, evidence_receipt = ?10,
		    terminal_result_digest = ?11, terminal_evidence_digest = ?12,
		    reconcile_owner = NULL, reconcile_lease_expires_at = NULL,
		    next_reconcile_at = NULL, last_reconcile_error = NULL,
		    recovery_locator = NULL,
		    version = version + 1, updated_at = `+sqliteNow+`
		WHERE execution_id = ?8 AND state = 'UNKNOWN' AND version = ?9
		  AND (provider_id IS NULL OR ?5 IS NULL OR provider_id = ?5)
		  AND (provider_run_id IS NULL OR ?6 IS NULL OR provider_run_id = ?6)
		  `+s.epochGuardSQL(), string(newState),
		nullableString(string(result.Result)),
		nullableString(result.EvidenceDigest),
		result.ReceiptVersion,
		nullableString(result.ProviderID),
		nullableString(result.ProviderRunID),
		receiptDigest,
		executionID, expectedVersion,
		nullableString(string(result.EvidenceReceipt)),
		nullableString(terminalResultSHA), nullableString(result.EvidenceDigest))
	if err != nil {
		return err
	}
	rows, err := result2.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		tx.Rollback()
		if err := s.checkEpoch(ctx); err != nil {
			return err
		}
		// Distinguish a state/version CAS failure from a provider-
		// observation contradiction, which is a different failure class.
		// When state and version still match, only the provider-identity
		// guards can have rejected the write.
		rec, lerr := s.Lookup(ctx, executionID)
		if lerr != nil {
			return fmt.Errorf("execution %s recovery resolution failed (lookup: %v)", executionID, lerr)
		}
		if rec.State == StateUnknown && rec.Version == expectedVersion {
			s.metrics.observationConflicts.Add(1)
			return fmt.Errorf("%w: execution %s recovery result contradicts stored provider observation", ProviderObservationConflict, executionID)
		}
		return fmt.Errorf("%w: execution %s recovery resolution CAS failed (state/version mismatch)", LeaseStateConflict, executionID)
	}
	// The resolver's result is itself a provider observation — ledger
	// it when it carries provider material (see Store.ResolveRecovery).
	// rawResolverResult preserves the exact asserted bytes.
	if result.ProviderID != "" || result.ProviderRunID != "" ||
		len(rawResolverResult) > 0 || result.EvidenceDigest != "" {
		if err := sqliteInsertObservationRow(ctx, tx, executionID,
			ObservationReconciliation, rawResolverResult, robs); err != nil {
			return err
		}
	}
	if err := sqliteInsertEffectEvent(ctx, tx, executionID, effectEvent{
		eventType:      EventTerminalResolved,
		previousState:  string(StateUnknown),
		newState:       string(newState),
		resultDigest:   terminalResultSHA,
		evidenceDigest: result.EvidenceDigest,
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.metrics.reconcileResolutions.Add(1)
	if newState == StateCommitted {
		s.metrics.committed.Add(1)
	} else {
		s.metrics.failed.Add(1)
	}
	return nil
}

// ─── Reconciliation work distribution ────────────────────────────────
//
// SQLite has no FOR UPDATE SKIP LOCKED and does not need it: a claim is
// a single UPDATE ... RETURNING statement, which executes under the
// write lock — the candidate subselect and the update are one atomic
// statement, so two workers can never claim the same row.

// ClaimUnknownBatch atomically claims up to batchSize UNKNOWN records —
// see Store.ClaimUnknownBatch.
func (s *SQLiteStore) ClaimUnknownBatch(ctx context.Context, owner string, batchSize int, claimDuration time.Duration) ([]*Record, error) {
	if batchSize <= 0 {
		batchSize = 100
	}
	if claimDuration <= 0 {
		claimDuration = 5 * time.Minute
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `
		UPDATE execution_requests
		SET reconcile_owner = ?1,
		    reconcile_lease_expires_at = `+sqliteNow+` + ?2,
		    reconcile_attempt = reconcile_attempt + 1,
		    version = version + 1,
		    updated_at = `+sqliteNow+`
		WHERE execution_id IN (
			SELECT execution_id FROM execution_requests
			WHERE state = 'UNKNOWN'
			  AND (reconcile_owner IS NULL
			       OR reconcile_lease_expires_at < `+sqliteNow+`)
			  AND (next_reconcile_at IS NULL
			       OR next_reconcile_at <= `+sqliteNow+`)
			ORDER BY updated_at
			LIMIT ?3
		)
		`+s.epochGuardSQL()+`
		RETURNING `+selectColumns,
		owner,
		msDuration(claimDuration),
		batchSize,
	)
	if err != nil {
		return nil, fmt.Errorf("claim unknown batch failed: %w", err)
	}
	recs, err := scanSQLiteRecords(rows)
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		tx.Rollback()
		if err := s.checkEpoch(ctx); err != nil {
			return nil, err
		}
		return recs, nil
	}
	for _, rec := range recs {
		if err := sqliteInsertEffectEvent(ctx, tx, rec.ExecutionID, effectEvent{
			eventType:       EventReconciliationClaimed,
			actor:           owner,
			previousState:   string(StateUnknown),
			claimGeneration: rec.ReconcileAttempt,
		}); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.metrics.reconcileClaims.Add(int64(len(recs)))
	return recs, nil
}

// ClaimExpiredBatch atomically claims expired-lease records for crash
// recovery — see Store.ClaimExpiredBatch.
func (s *SQLiteStore) ClaimExpiredBatch(ctx context.Context, owner string, batchSize int, claimDuration time.Duration) ([]*Record, error) {
	if batchSize <= 0 {
		batchSize = 100
	}
	if claimDuration <= 0 {
		claimDuration = 5 * time.Minute
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `
		UPDATE execution_requests
		SET reconcile_owner = ?1,
		    reconcile_lease_expires_at = `+sqliteNow+` + ?2,
		    version = version + 1,
		    updated_at = `+sqliteNow+`
		WHERE execution_id IN (
			SELECT execution_id FROM execution_requests
			WHERE state IN ('PREPARED', 'EXECUTING', 'IN_FLIGHT')
			  AND lease_expires_at IS NOT NULL
			  AND lease_expires_at < `+sqliteNow+`
			  AND (reconcile_owner IS NULL
			       OR reconcile_lease_expires_at < `+sqliteNow+`)
			ORDER BY updated_at
			LIMIT ?3
		)
		`+s.epochGuardSQL()+`
		RETURNING `+selectColumns,
		owner,
		msDuration(claimDuration),
		batchSize,
	)
	if err != nil {
		return nil, fmt.Errorf("claim expired batch failed: %w", err)
	}
	recs, err := scanSQLiteRecords(rows)
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		tx.Rollback()
		if err := s.checkEpoch(ctx); err != nil {
			return nil, err
		}
		return recs, nil
	}
	// Each claimed record's previous lease holder lost its lease to
	// expiry — the claim is the forensic record of that loss.
	for _, rec := range recs {
		if err := sqliteInsertEffectEvent(ctx, tx, rec.ExecutionID, effectEvent{
			eventType:       EventLeaseLost,
			actor:           owner,
			previousState:   string(rec.State),
			claimGeneration: rec.LeaseGeneration,
			metadata:        "lease expired; claimed for recovery",
		}); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.metrics.reconcileClaims.Add(int64(len(recs)))
	return recs, nil
}

// ReleaseReconcileClaim releases a claim with DB-computed backoff —
// see Store.ReleaseReconcileClaim.
func (s *SQLiteStore) ReleaseReconcileClaim(ctx context.Context, executionID string, expectedVersion int, backoffDuration time.Duration, lastError string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		UPDATE execution_requests
		SET reconcile_owner = NULL,
		    reconcile_lease_expires_at = NULL,
		    next_reconcile_at = CASE
		        WHEN state = 'UNKNOWN' AND ?1 > 0
		            THEN `+sqliteNow+` + ?1
		        ELSE NULL
		    END,
		    last_reconcile_error = ?2,
		    version = version + 1,
		    updated_at = `+sqliteNow+`
		WHERE execution_id = ?3
		  AND version = ?4
		  `+s.epochGuardSQL(), msDuration(backoffDuration),
		nullableString(lastError), executionID, expectedVersion)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		// Release our write lock before the standalone forensic
		// insert — BEGIN IMMEDIATE would contend with our own tx.
		tx.Rollback()
		if err := s.checkEpoch(ctx); err != nil {
			return err
		}
		s.noteContentionEvent(ctx, executionID, EventClaimLost, "release reconcile claim CAS failed")
		return fmt.Errorf("%w: execution %s release reconcile claim CAS failed (state/version mismatch)", LeaseStateConflict, executionID)
	}
	if err := sqliteInsertEffectEvent(ctx, tx, executionID, effectEvent{
		eventType: EventClaimReleased,
		metadata:  lastError,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// SuspendReconciliation dead-letters an UNKNOWN record — see
// Store.SuspendReconciliation.
func (s *SQLiteStore) SuspendReconciliation(ctx context.Context, executionID string, expectedVersion int, reason string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		UPDATE execution_requests
		SET reconcile_owner = NULL,
		    reconcile_lease_expires_at = NULL,
		    next_reconcile_at = `+sqliteNow+` + ?4,
		    last_reconcile_error = ?1,
		    version = version + 1,
		    updated_at = `+sqliteNow+`
		WHERE execution_id = ?2
		  AND state = 'UNKNOWN'
		  AND version = ?3
		  `+s.epochGuardSQL(), nullableString(reason), executionID, expectedVersion,
		msDuration(100*365*24*time.Hour))
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		tx.Rollback()
		if err := s.checkEpoch(ctx); err != nil {
			return err
		}
		s.noteContentionEvent(ctx, executionID, EventClaimLost, "suspend reconciliation CAS failed")
		return fmt.Errorf("%w: execution %s suspend reconciliation CAS failed (state/version mismatch)", LeaseStateConflict, executionID)
	}
	if err := sqliteInsertEffectEvent(ctx, tx, executionID, effectEvent{
		eventType: EventReconciliationSuspended,
		metadata:  reason,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// RenewReconcileClaim extends an active claim to
// MAX(current, now + duration) — see Store.RenewReconcileClaim. The
// WHERE clause requires a live claim, so MAX never sees NULL.
func (s *SQLiteStore) RenewReconcileClaim(ctx context.Context, executionID string, expectedVersion int, duration time.Duration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		UPDATE execution_requests
		SET reconcile_lease_expires_at = MAX(
		        reconcile_lease_expires_at,
		        `+sqliteNow+` + ?1),
		    updated_at = `+sqliteNow+`
		WHERE execution_id = ?2
		  AND state = 'UNKNOWN'
		  AND version = ?3
		  AND reconcile_lease_expires_at > `+sqliteNow+`
		  `+s.epochGuardSQL(), msDuration(duration), executionID, expectedVersion)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		tx.Rollback()
		if err := s.checkEpoch(ctx); err != nil {
			return err
		}
		s.noteContentionEvent(ctx, executionID, EventClaimLost, "renew reconcile claim failed")
		return fmt.Errorf("%w: execution %s renew reconcile claim failed (expired or version mismatch)", LeaseStateConflict, executionID)
	}
	if err := sqliteInsertEffectEvent(ctx, tx, executionID, effectEvent{
		eventType: EventClaimRenewed,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// ─── Lookup ──────────────────────────────────────────────────────────

// Lookup retrieves a record by execution ID.
func (s *SQLiteStore) Lookup(ctx context.Context, executionID string) (*Record, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+selectColumns+` FROM execution_requests WHERE execution_id = ?1`,
		executionID)
	if err != nil {
		return nil, err
	}
	recs, err := scanSQLiteRecords(rows)
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return nil, sql.ErrNoRows
	}
	return recs[0], nil
}

// LookupByKey retrieves a record by idempotency key.
func (s *SQLiteStore) LookupByKey(ctx context.Context, principal, capability, key string) (*Record, error) {
	return s.lookupByKey(ctx, principal, capability, key)
}

func (s *SQLiteStore) lookupByKey(ctx context.Context, principal, capability, key string) (*Record, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+selectColumns+` FROM execution_requests
		 WHERE principal_id = ?1 AND capability_id = ?2 AND idempotency_key = ?3`,
		principal, capability, key)
	if err != nil {
		return nil, err
	}
	recs, err := scanSQLiteRecords(rows)
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return nil, sql.ErrNoRows
	}
	return recs[0], nil
}

// ─── Listing ─────────────────────────────────────────────────────────

// ListUnknown returns all records in UNKNOWN state.
func (s *SQLiteStore) ListUnknown(ctx context.Context) ([]*Record, error) {
	return s.listByStates(ctx, []State{StateUnknown})
}

// ListExpiredLeases returns non-terminal records with expired leases.
func (s *SQLiteStore) ListExpiredLeases(ctx context.Context) ([]*Record, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+selectColumns+` FROM execution_requests
		 WHERE state IN ('PREPARED', 'EXECUTING', 'IN_FLIGHT')
		   AND lease_expires_at IS NOT NULL
		   AND lease_expires_at < `+sqliteNow+`
		 ORDER BY updated_at`)
	if err != nil {
		return nil, err
	}
	return scanSQLiteRecords(rows)
}

// ListStuck returns all records needing attention.
func (s *SQLiteStore) ListStuck(ctx context.Context) ([]*Record, error) {
	stuck, err := s.ListExpiredLeases(ctx)
	if err != nil {
		return nil, err
	}
	unknown, err := s.ListUnknown(ctx)
	if err != nil {
		return nil, err
	}
	return append(stuck, unknown...), nil
}

func (s *SQLiteStore) listByStates(ctx context.Context, states []State) ([]*Record, error) {
	placeholders := ""
	args := make([]any, len(states))
	for i, st := range states {
		if i > 0 {
			placeholders += ","
		}
		placeholders += fmt.Sprintf("?%d", i+1)
		args[i] = string(st)
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT `+selectColumns+` FROM execution_requests
		 WHERE state IN (`+placeholders+`) ORDER BY updated_at`, args...)
	if err != nil {
		return nil, err
	}
	return scanSQLiteRecords(rows)
}

// scanSQLiteRecords scans the shared selectColumns projection,
// converting INTEGER unix-ms columns into time.Time.
func scanSQLiteRecords(rows *sql.Rows) ([]*Record, error) {
	defer rows.Close()

	var records []*Record
	for rows.Next() {
		var rec Record
		var resultJSON, providerResultJSON []byte
		var leaseOwner, leaseToken, providerID, providerRunID, terminalDigest sql.NullString
		var providerStatus, providerResultDigest string
		var providerObservedAt sql.NullInt64
		var evidenceReceipt, recoveryLocator []byte
		var leaseStartedAt, leaseExpiresAt sql.NullInt64
		var recOwner, lastRecErr sql.NullString
		var recLeaseExp, nextRecAt, enteredUnknownAt sql.NullInt64
		var createdAt, updatedAt int64
		if err := rows.Scan(
			&rec.ExecutionID, &rec.IdempotencyKey, &rec.PrincipalID,
			&rec.CapabilityID, &rec.RequestDigest, &rec.GrantID,
			&rec.ExecutionClass, &rec.State, &resultJSON,
			&rec.EvidenceDigest, &rec.ReceiptVersion,
			&leaseOwner, &leaseToken, &leaseStartedAt, &leaseExpiresAt,
			&rec.LeaseGeneration,
			&providerID, &providerRunID, &providerStatus, &providerResultDigest,
			&rec.ProviderReceiptVersion, &providerObservedAt,
			&terminalDigest, &evidenceReceipt, &recoveryLocator,
			&rec.Attempt, &rec.Version, &createdAt, &updatedAt,
			&recOwner, &recLeaseExp, &rec.ReconcileAttempt, &nextRecAt, &lastRecErr,
			&enteredUnknownAt, &providerResultJSON,
			&rec.AuthorityGeneration, &rec.AuthorityDigest,
			&rec.ProviderEvidenceDigest, &rec.TerminalResultDigest,
			&rec.TerminalEvidenceDigest, &rec.AdmittedEpoch,
		); err != nil {
			return nil, err
		}
		rec.CreatedAt = sqliteTime(createdAt)
		rec.UpdatedAt = sqliteTime(updatedAt)
		rec.ProviderStatus = providerStatus
		rec.ProviderResultDigest = providerResultDigest
		if providerObservedAt.Valid {
			t := sqliteTime(providerObservedAt.Int64)
			rec.ProviderObservedAt = &t
		}
		if enteredUnknownAt.Valid {
			t := sqliteTime(enteredUnknownAt.Int64)
			rec.EnteredUnknownAt = &t
		}
		rec.Result = json.RawMessage(resultJSON)
		rec.ProviderResult = json.RawMessage(providerResultJSON)
		if leaseOwner.Valid {
			rec.LeaseOwner = leaseOwner.String
		}
		if leaseToken.Valid {
			rec.LeaseToken = leaseToken.String
		}
		if leaseStartedAt.Valid {
			t := sqliteTime(leaseStartedAt.Int64)
			rec.LeaseStartedAt = &t
		}
		if leaseExpiresAt.Valid {
			t := sqliteTime(leaseExpiresAt.Int64)
			rec.LeaseExpiresAt = &t
		}
		if providerID.Valid {
			rec.ProviderID = providerID.String
		}
		if providerRunID.Valid {
			rec.ProviderRunID = providerRunID.String
		}
		if terminalDigest.Valid {
			rec.TerminalReceiptDigest = terminalDigest.String
		}
		if len(evidenceReceipt) > 0 {
			rec.EvidenceReceipt = json.RawMessage(evidenceReceipt)
		}
		if len(recoveryLocator) > 0 {
			rec.RecoveryLocator = json.RawMessage(recoveryLocator)
		}
		if recOwner.Valid {
			rec.ReconcileOwner = recOwner.String
		}
		if recLeaseExp.Valid {
			t := sqliteTime(recLeaseExp.Int64)
			rec.ReconcileLeaseExpiresAt = &t
		}
		if nextRecAt.Valid {
			t := sqliteTime(nextRecAt.Int64)
			rec.NextReconcileAt = &t
		}
		if lastRecErr.Valid {
			rec.LastReconcileError = lastRecErr.String
		}
		records = append(records, &rec)
	}
	return records, rows.Err()
}

// ─── Forensic reads ──────────────────────────────────────────────────

// ListEffectEvents returns the execution's ordered forensic event
// history — see Store.ListEffectEvents.
func (s *SQLiteStore) ListEffectEvents(ctx context.Context, executionID string) ([]EffectEvent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT execution_id, sequence, record_version, event_type,
		       COALESCE(actor, ''), COALESCE(previous_state, ''),
		       COALESCE(new_state, ''), COALESCE(result_digest, ''),
		       COALESCE(evidence_digest, ''), COALESCE(claim_generation, 0),
		       occurred_at, COALESCE(metadata, '')
		FROM effect_events
		WHERE execution_id = ?1
		ORDER BY sequence`, executionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []EffectEvent
	for rows.Next() {
		var ev EffectEvent
		var occurredAtMs int64
		if err := rows.Scan(&ev.ExecutionID, &ev.Sequence, &ev.RecordVersion,
			&ev.EventType, &ev.Actor, &ev.PreviousState, &ev.NewState,
			&ev.ResultDigest, &ev.EvidenceDigest, &ev.ClaimGeneration,
			&occurredAtMs, &ev.Metadata); err != nil {
			return nil, err
		}
		ev.OccurredAt = sqliteTime(occurredAtMs)
		events = append(events, ev)
	}
	return events, rows.Err()
}

// ListProviderObservations returns the execution's immutable provider-
// observation ledger rows in commit order — see
// Store.ListProviderObservations.
func (s *SQLiteStore) ListProviderObservations(ctx context.Context, executionID string) ([]ObservationRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT execution_id, sequence, record_version, observation_kind,
		       COALESCE(provider_id, ''), COALESCE(provider_run_id, ''),
		       COALESCE(provider_status, ''), result_bytes,
		       COALESCE(result_sha256, ''), COALESCE(result_canonical_digest, ''),
		       COALESCE(evidence_sha256, ''), receipt_version, observed_at
		FROM effect_provider_observations
		WHERE execution_id = ?1
		ORDER BY sequence`, executionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var recs []ObservationRecord
	for rows.Next() {
		var r ObservationRecord
		var resultBytes *string
		var observedAtMs int64
		if err := rows.Scan(&r.ExecutionID, &r.Sequence, &r.RecordVersion,
			&r.Kind, &r.ProviderID, &r.ProviderRunID, &r.ProviderStatus,
			&resultBytes, &r.ResultSHA256, &r.ResultCanonicalDigest,
			&r.EvidenceSHA256, &r.ReceiptVersion, &observedAtMs); err != nil {
			return nil, err
		}
		if resultBytes != nil {
			r.ResultBytes = json.RawMessage(*resultBytes)
		}
		r.ObservedAt = sqliteTime(observedAtMs)
		recs = append(recs, r)
	}
	return recs, rows.Err()
}
