package idempotency

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// openSQLiteStore opens an embedded store on a temp file. No daemon,
// no CRABBOX_TEST_DATABASE_URL — the SQLite suite always runs.
func openSQLiteStore(t *testing.T) *SQLiteStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "db", "crabedence-test.db")
	db, err := OpenSQLiteDB(path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	return store
}

// sqliteDigest is a deterministic request digest for tests.
func sqliteDigest(s string) string {
	d, err := ComputeDigestFromRaw(1, "alice", "cap.mut",
		json.RawMessage(fmt.Sprintf(`{"q":%q}`, s)), "", "MUTATION")
	if err != nil {
		panic(err)
	}
	return d
}

func sqliteReceipt(execID, capID, principal, digest, providerID, runID string, status State) TerminalReceipt {
	return TerminalReceipt{
		ExecutionID:     execID,
		Capability:      capID,
		Principal:       principal,
		RequestDigest:   digest,
		CanonicalResult: json.RawMessage(`{"ok":true}`),
		ReceiptVersion:  3,
		ProviderID:      providerID,
		ProviderRunID:   runID,
		TerminalStatus:  status,
	}
}

func TestSQLiteStoreHappyPath(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("a")

	acq, err := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
	if err != nil || acq.Kind != LeaseAcquired {
		t.Fatalf("acquire: %v kind=%v", err, acq.Kind)
	}
	rec := acq.Record

	// Same key + digest while lease held → held by other.
	acq2, err := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
	if err != nil || acq2.Kind != LeaseHeldByOther {
		t.Fatalf("re-acquire: %v kind=%v", err, acq2.Kind)
	}
	// Different digest → idempotency conflict.
	acq3, err := s.Acquire(ctx, "k1", "alice", "cap.mut", sqliteDigest("b"), "", "MUTATION", 5*time.Minute)
	if err != nil || acq3.Kind != IdempotencyConflict {
		t.Fatalf("conflict acquire: %v kind=%v", err, acq3.Kind)
	}

	if err := s.BeginExecution(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatalf("begin: %v", err)
	}
	locator := json.RawMessage(`{"external_token":"tok-1"}`)
	if err := s.MarkInFlight(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, "prov", locator); err != nil {
		t.Fatalf("mark in flight: %v", err)
	}

	// Status-only observation must persist (regression: no skip).
	obs := ProviderObservation{ProviderID: "prov", ProviderStatus: "SUCCEEDED"}
	if err := s.RecordProviderObservation(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, obs); err != nil {
		t.Fatalf("observe: %v", err)
	}

	receipt := sqliteReceipt(rec.ExecutionID, "cap.mut", "alice", digest, "prov", "run-1", StateCommitted)
	if err := s.Finalize(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, StateInFlight, receipt); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	final, err := s.Lookup(ctx, rec.ExecutionID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if final.State != StateCommitted || final.ProviderRunID != "run-1" {
		t.Fatalf("final: %s run=%q", final.State, final.ProviderRunID)
	}

	// Idempotent replay returns the stored terminal record.
	acq4, err := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
	if err != nil || acq4.Kind != TerminalReplay || acq4.Record.State != StateCommitted {
		t.Fatalf("replay: %v kind=%v state=%v", err, acq4.Kind, acq4.Record.State)
	}
}

func TestSQLiteStoreStaleFencing(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("a")

	acq, _ := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
	rec := acq.Record
	if err := s.BeginExecution(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatalf("begin: %v", err)
	}
	// Wrong token → LeaseTokenMismatch.
	if err := s.MarkInFlight(ctx, rec.ExecutionID, "bad-token", acq.Generation, "", nil); !errors.Is(err, LeaseTokenMismatch) {
		t.Fatalf("want LeaseTokenMismatch, got %v", err)
	}
	// Wrong generation → LeaseGenerationMismatch.
	if err := s.MarkInFlight(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation+99, "", nil); !errors.Is(err, LeaseGenerationMismatch) {
		t.Fatalf("want LeaseGenerationMismatch, got %v", err)
	}
}

func TestSQLiteStoreExpiredInFlightBecomesUnknown(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("a")

	// A long lease: acquire→begin→mark must never race expiry, or the
	// test fails on machine timing instead of the expired-IN_FLIGHT
	// semantics it asserts. Expiry is forced explicitly below.
	acq, _ := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", time.Minute)
	rec := acq.Record
	if err := s.BeginExecution(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := s.MarkInFlight(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, "prov", nil); err != nil {
		t.Fatalf("in flight: %v", err)
	}
	if err := s.ExpireLeaseForTest(ctx, rec.ExecutionID); err != nil {
		t.Fatal(err)
	}

	// Expired IN_FLIGHT must NOT be reclaimed — it becomes UNKNOWN.
	acq2, err := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", time.Minute)
	if err != nil || acq2.Kind != RecoveryRequired {
		t.Fatalf("want RecoveryRequired, got %v err=%v", acq2.Kind, err)
	}
	rec2, _ := s.Lookup(ctx, rec.ExecutionID)
	if rec2.State != StateUnknown {
		t.Fatalf("state = %s, want UNKNOWN", rec2.State)
	}
	if rec2.EnteredUnknownAt == nil {
		t.Fatal("entered_unknown_at not set")
	}
}

func TestSQLiteStoreAbandonAndReclaim(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("a")

	acq, _ := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
	rec := acq.Record
	if err := s.BeginExecution(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := s.AbandonPreDispatch(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatalf("abandon: %v", err)
	}
	// Lease-less PREPARED reacquires immediately.
	acq2, err := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
	if err != nil || acq2.Kind != LeaseAcquired {
		t.Fatalf("reacquire: %v kind=%v", err, acq2.Kind)
	}
}

func TestSQLiteStoreReconcileClaimLifecycle(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("a")

	acq, _ := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
	rec := acq.Record
	s.BeginExecution(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation)
	s.MarkInFlight(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, "prov", nil)
	if err := s.EnterRecovery(ctx, rec.ExecutionID, StateInFlight, rec.Version+2); err != nil {
		t.Fatalf("enter recovery: %v", err)
	}
	// ^ EnterRecovery bumps version twice from acquire? No — BeginExecution
	// and MarkInFlight each bump once. Recompute from the record.
	cur, _ := s.Lookup(ctx, rec.ExecutionID)
	if cur.State != StateUnknown {
		t.Fatalf("state=%s want UNKNOWN", cur.State)
	}

	claimed, err := s.ClaimUnknownBatch(ctx, "w1", 10, time.Minute)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: %v n=%d", err, len(claimed))
	}
	if claimed[0].ReconcileOwner != "w1" {
		t.Fatalf("owner=%q", claimed[0].ReconcileOwner)
	}
	// Second worker cannot claim while the first holds it.
	claimed2, err := s.ClaimUnknownBatch(ctx, "w2", 10, time.Minute)
	if err != nil || len(claimed2) != 0 {
		t.Fatalf("double claim: %v n=%d", err, len(claimed2))
	}
	// Renewal extends the live claim.
	if err := s.RenewReconcileClaim(ctx, rec.ExecutionID, claimed[0].Version, time.Minute); err != nil {
		t.Fatalf("renew: %v", err)
	}
	// Resolve to FAILED (recovery) with proof fields.
	res := RecoveryResult{
		Decision:       RecoveryFailed,
		EvidenceDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ReceiptVersion: 3,
		ProviderID:     "prov",
		Result:         json.RawMessage(`{"no_effect":true}`),
	}
	if err := s.ResolveRecovery(ctx, rec.ExecutionID, claimed[0].Version, res); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	final, _ := s.Lookup(ctx, rec.ExecutionID)
	if final.State != StateFailed {
		t.Fatalf("state=%s want FAILED", final.State)
	}
}

func TestSQLiteStoreProviderIdentityMonotonic(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("a")

	acq, _ := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
	rec := acq.Record
	s.BeginExecution(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation)
	s.MarkInFlight(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, "prov-A", nil)

	// Observation establishes provider identity.
	obs := ProviderObservation{ProviderID: "prov-A", ProviderRunID: "run-1", ProviderStatus: "SUCCEEDED"}
	if err := s.RecordProviderObservation(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, obs); err != nil {
		t.Fatalf("observe: %v", err)
	}
	// Contradictory observation → typed conflict.
	bad := ProviderObservation{ProviderID: "prov-B"}
	if err := s.RecordProviderObservation(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, bad); !errors.Is(err, ProviderObservationConflict) {
		t.Fatalf("want ProviderObservationConflict, got %v", err)
	}
	// Terminal receipt with a different provider → conflict, not overwrite.
	receipt := sqliteReceipt(rec.ExecutionID, "cap.mut", "alice", digest, "prov-B", "run-9", StateCommitted)
	if err := s.Finalize(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, StateInFlight, receipt); !errors.Is(err, ProviderObservationConflict) {
		t.Fatalf("finalize want ProviderObservationConflict, got %v", err)
	}
	// Confirming receipt finalizes.
	ok := sqliteReceipt(rec.ExecutionID, "cap.mut", "alice", digest, "prov-A", "run-1", StateCommitted)
	if err := s.Finalize(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, StateInFlight, ok); err != nil {
		t.Fatalf("finalize: %v", err)
	}
}

func TestSQLiteStoreLocatorDenylist(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("a")

	acq, _ := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
	rec := acq.Record
	s.BeginExecution(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation)
	locator := json.RawMessage(`{"client_secret":"abc"}`)
	if err := s.MarkInFlight(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, "prov", locator); !errors.Is(err, LocatorContainsSecret) {
		t.Fatalf("want LocatorContainsSecret, got %v", err)
	}
}

// TestSQLiteStoreConcurrentAcquire hammers the single-writer path:
// N goroutines racing on one idempotency identity must produce
// exactly one lease holder — busy_timeout plus CAS fencing, not
// application locks.
func TestSQLiteStoreConcurrentAcquire(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("a")

	const n = 32
	type outcome struct {
		kind AcquireResultKind
		err  error
	}
	results := make(chan outcome, n)
	for i := 0; i < n; i++ {
		go func() {
			acq, err := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
			if err != nil {
				results <- outcome{err: err}
				return
			}
			results <- outcome{kind: acq.Kind}
		}()
	}
	acquired := 0
	for i := 0; i < n; i++ {
		r := <-results
		if r.err != nil {
			// Any error — e.g. a SQLITE_BUSY that outlasted busy_timeout —
			// means the serialized-writer path is failing, not fencing.
			t.Fatalf("concurrent acquire errored: %v", r.err)
		}
		switch r.kind {
		case LeaseAcquired:
			acquired++
		case LeaseHeldByOther:
		default:
			t.Fatalf("concurrent acquire: unexpected kind %s", r.kind)
		}
	}
	if acquired != 1 {
		t.Fatalf("concurrent acquire: %d winners, want exactly 1", acquired)
	}
}

func TestSQLiteStoreSchemaVersion(t *testing.T) {
	s := openSQLiteStore(t)
	v, err := s.SchemaVersion(context.Background())
	if err != nil || v < RequiredSchemaVersion {
		t.Fatalf("schema version %v err=%v", v, err)
	}
}

// A path containing DSN metacharacters must be rejected — otherwise it
// could silently truncate the filename or override durability pragmas.
func TestOpenSQLiteDBRejectsDSNMetachars(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a?b.db", "a#b.db"} {
		if _, err := OpenSQLiteDB(filepath.Join(dir, name)); err == nil {
			t.Fatalf("path %q: want rejection, got nil", name)
		}
	}
}

// The durable ledger carries execution authority and forensic history —
// it must never be group/other-accessible. OpenSQLiteDB creates missing
// directories at 0700, rejects group/other-accessible existing
// directories and symlinked database paths, and tightens the database
// file itself to 0600.
func TestOpenSQLiteDBPermissionHardening(t *testing.T) {
	base := t.TempDir()

	// Missing directory is created at 0700; the DB file lands at 0600.
	dbPath := filepath.Join(base, "ledger", "e.db")
	db, err := OpenSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	dirInfo, err := os.Stat(filepath.Dir(dbPath))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("created dir mode = %04o, want 0700", perm)
	}
	fileInfo, err := os.Lstat(dbPath)
	if err != nil {
		t.Fatalf("stat db: %v", err)
	}
	if perm := fileInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("db file mode = %04o, want 0600", perm)
	}
	db.Close()

	// A group/other-accessible existing directory is rejected.
	loose := filepath.Join(base, "loose")
	if err := os.MkdirAll(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSQLiteDB(filepath.Join(loose, "e.db")); err == nil {
		t.Error("expected rejection of group/other-accessible directory")
	}

	// A symlinked database path is rejected — the ledger must never be
	// written through a link to an unexpected target.
	target := filepath.Join(base, "ledger", "real.db")
	link := filepath.Join(base, "ledger", "link.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := OpenSQLiteDB(link); err == nil {
		t.Error("expected rejection of symlinked database path")
	}

	// A pre-existing loose-permission DB file is tightened to 0600.
	preexisting := filepath.Join(base, "ledger", "old.db")
	if err := os.WriteFile(preexisting, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	db2, err := OpenSQLiteDB(preexisting)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	fi, err := os.Lstat(preexisting)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("pre-existing db mode = %04o, want 0600 after tighten", perm)
	}
}

// TestSQLiteMigrationForwardCompat simulates opening a pre-v6 embedded
// database: a ledger shaped like the original v1 schema (no
// provider_result, no authority columns) with schema_migrations
// recorded through v5. NewSQLiteStore must apply migrations 6–7
// atomically — BEGIN IMMEDIATE makes a crash mid-migration roll back
// rather than half-apply — and the result must serve AcquireWithAuthority.
func TestSQLiteMigrationForwardCompat(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "db", "legacy.db")
	db, err := OpenSQLiteDB(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// Build the pre-v6 table shape and record migrations 1–5.
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE execution_requests (
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
			UNIQUE(principal_id, capability_id, idempotency_key)
		)
	`); err != nil {
		t.Fatalf("create legacy table: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at INTEGER NOT NULL
		)
	`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	for v := 1; v <= 5; v++ {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?1, 'legacy', 1)`, v); err != nil {
			t.Fatalf("seed migration %d: %v", v, err)
		}
	}

	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore on legacy schema: %v", err)
	}
	v, err := store.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if v != RequiredSchemaVersion {
		t.Fatalf("schema version = %d, want %d", v, RequiredSchemaVersion)
	}

	// The migrated store must serve the v7 contract: authority
	// snapshot columns written at Acquire.
	acq, err := store.AcquireWithAuthority(ctx, "k1", "alice", "cap.mut", "d1",
		AuthorityBinding{Ref: "g1", Generation: 3, Digest: "deadbeef"},
		"MUTATION", 5*time.Minute)
	if err != nil {
		t.Fatalf("AcquireWithAuthority: %v", err)
	}
	if !acq.Acquired() {
		t.Fatalf("expected acquisition, got %s", acq.Kind)
	}
	rec, err := store.LookupByKey(ctx, "alice", "cap.mut", "k1")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if rec.AuthorityGeneration != 3 || rec.AuthorityDigest != "deadbeef" {
		t.Errorf("authority snapshot not persisted: gen=%d digest=%q",
			rec.AuthorityGeneration, rec.AuthorityDigest)
	}
}

// TestSQLiteMigrationIdempotent verifies re-opening a migrated
// database records no new versions and fails nothing — migrations are
// idempotent, never half-applied.
func TestSQLiteMigrationIdempotent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "db", "e.db")
	db, err := OpenSQLiteDB(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	if _, err := NewSQLiteStore(db); err != nil {
		t.Fatalf("first NewSQLiteStore: %v", err)
	}
	if _, err := NewSQLiteStore(db); err != nil {
		t.Fatalf("second NewSQLiteStore: %v", err)
	}
	var count int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != RequiredSchemaVersion {
		t.Errorf("expected %d recorded migrations, got %d", RequiredSchemaVersion, count)
	}
}

// TestSQLiteMigrationCrashConsistency proves the migration-atomicity
// contract the DR runbook depends on: a migration killed before its
// transaction commits leaves zero torn state — no partial DDL, no
// version row — and the next startup replays it cleanly to the
// required version. The simulation uses the same BEGIN/DDL/record
// sequence ensureSchema runs, rolled back mid-flight.
func TestSQLiteMigrationCrashConsistency(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "db", "crash-migrate.db")
	db, err := OpenSQLiteDB(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// First construction brings the schema to the required version.
	s1, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	v, err := s1.SchemaVersion(ctx)
	if err != nil || v != RequiredSchemaVersion {
		t.Fatalf("version = %d, %v — want %d", v, err, RequiredSchemaVersion)
	}

	// Simulate a torn migration attempt: BEGIN, apply DDL + record
	// the version, then ROLLBACK before commit — the state a killed
	// process leaves behind.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx,
		`ALTER TABLE cluster_meta ADD COLUMN crash_probe INTEGER`); err != nil {
		t.Fatalf("torn DDL: %v", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, name, applied_at) VALUES (999, 'crashed', 1)`); err != nil {
		t.Fatalf("torn version record: %v", err)
	}
	tx.Rollback() // the "crash" — nothing must persist

	// Reopen: the schema is untouched and still at the required
	// version — no torn column, no phantom version.
	s2, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("reopen after torn migration: %v", err)
	}
	v, err = s2.SchemaVersion(ctx)
	if err != nil || v != RequiredSchemaVersion {
		t.Fatalf("post-crash version = %d, %v — want %d", v, err, RequiredSchemaVersion)
	}
	var probe int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pragma_table_info('cluster_meta') WHERE name = 'crash_probe'`).Scan(&probe); err != nil {
		t.Fatal(err)
	}
	if probe != 0 {
		t.Fatal("torn migration leaked its uncommitted DDL")
	}
	// The store is fully functional on the rolled-back world.
	acq, err := s2.Acquire(ctx, "post-crash", "alice", "cap.mut", sqliteDigest("pc"), "", "MUTATION", time.Minute)
	if err != nil {
		t.Fatalf("acquire after torn migration: %v", err)
	}
	if !acq.Acquired() {
		t.Fatalf("post-crash acquire kind = %s", acq.Kind)
	}
}

// TestSQLiteMigrationTornAppliedState covers the inverse corruption:
// a schema_migrations row claims a version whose DDL is absent (as a
// botched manual edit or a restored snapshot taken mid-migration
// could produce). The store must fail honestly at first use — never
// silently operate against a schema that is not what the version
// record claims.
func TestSQLiteMigrationTornAppliedState(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "db", "torn.db")
	db, err := OpenSQLiteDB(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	s, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	// Tear: drop the recovery column while claiming v11 applied.
	if _, err := db.ExecContext(ctx,
		`ALTER TABLE cluster_meta RENAME TO cluster_meta_bak`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE cluster_meta (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			epoch INTEGER NOT NULL,
			advanced_at INTEGER,
			advance_reason TEXT
		)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO cluster_meta (id, epoch) SELECT id, epoch FROM cluster_meta_bak`); err != nil {
		t.Fatal(err)
	}
	db.ExecContext(ctx, `DROP TABLE cluster_meta_bak`)

	// SchemaVersion reports v11 — but the first recovery-mode read
	// must fail honestly rather than misread the missing column.
	if v, err := s.SchemaVersion(ctx); err != nil || v != RequiredSchemaVersion {
		t.Fatalf("version = %d, %v — torn state should still report %d", v, err, RequiredSchemaVersion)
	}
	if _, err := s.ClusterRecoveryRequired(ctx); err == nil {
		t.Fatal("torn schema must surface an error, not silently succeed")
	}
}
