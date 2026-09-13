// Package idempotency provides the durable execution contract store
// backed by PostgreSQL.
//
// The store owns lease time (via clock_timestamp()), enforces lease
// fencing inside SQL, and makes blind duplicate side effects impossible.
// See docs/spec/durable-execution-contract.md for the frozen invariants.
package idempotency

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ─── Record ───────────────────────────────────────────────────────────

// Record is a stored execution record.
type Record struct {
	ExecutionID            string          `json:"execution_id"`
	IdempotencyKey         string          `json:"idempotency_key"`
	PrincipalID            string          `json:"principal_id"`
	CapabilityID           string          `json:"capability_id"`
	RequestDigest          string          `json:"request_digest"`
	GrantID                string          `json:"grant_id"`
	ExecutionClass         string          `json:"execution_class"`
	State                  State           `json:"state"`
	Result                 json.RawMessage `json:"result,omitempty"`
	EvidenceDigest         string          `json:"evidence_digest,omitempty"`
	ReceiptVersion         int             `json:"receipt_version,omitempty"`
	LeaseOwner             string          `json:"lease_owner,omitempty"`
	LeaseToken             string          `json:"lease_token,omitempty"`
	LeaseStartedAt         *time.Time      `json:"lease_started_at,omitempty"`
	LeaseExpiresAt         *time.Time      `json:"lease_expires_at,omitempty"`
	LeaseGeneration        int             `json:"lease_generation,omitempty"`
	ProviderID             string          `json:"provider_id,omitempty"`
	ProviderRunID          string          `json:"provider_run_id,omitempty"`
	ProviderStatus         string          `json:"provider_status,omitempty"`
	ProviderResultDigest   string          `json:"provider_result_digest,omitempty"`
	ProviderReceiptVersion int             `json:"provider_receipt_version,omitempty"`
	ProviderObservedAt     *time.Time      `json:"provider_observed_at,omitempty"`
	TerminalReceiptDigest  string          `json:"terminal_receipt_digest,omitempty"`
	EvidenceReceipt        json.RawMessage `json:"evidence_receipt,omitempty"`
	RecoveryLocator        json.RawMessage `json:"recovery_locator,omitempty"`
	Attempt                int             `json:"attempt,omitempty"`
	Version                int             `json:"version"`
	CreatedAt              time.Time       `json:"created_at"`
	UpdatedAt              time.Time       `json:"updated_at"`

	// Reconciliation work distribution fields.
	ReconcileOwner          string     `json:"reconcile_owner,omitempty"`
	ReconcileLeaseExpiresAt *time.Time `json:"reconcile_lease_expires_at,omitempty"`
	ReconcileAttempt        int        `json:"reconcile_attempt,omitempty"`
	NextReconcileAt         *time.Time `json:"next_reconcile_at,omitempty"`
	LastReconcileError      string     `json:"last_reconcile_error,omitempty"`
}

// ─── Store ───────────────────────────────────────────────────────────

// Store is the durable execution contract store backed by PostgreSQL.
type Store struct {
	db       *sql.DB
	leaseCfg LeaseConfig

	// trustedSigners is the set of evidence-receipt signer fingerprints
	// (SHA-256 of the Ed25519 public key) authorized to attest CRITICAL
	// terminal transitions. When empty, CRITICAL finalization and
	// definitive recovery fail closed — a syntactically valid evidence
	// digest is never sufficient proof on its own.
	trustedSigners map[string]bool

	// verifier authenticates terminal receipts for CRITICAL
	// transitions. Nil means the default signedReceiptVerifier bound
	// to trustedSigners.
	verifier EvidenceVerifier

	// locatorRedactor optionally rewrites a recovery locator before it
	// is persisted — e.g. to encrypt or strip sensitive extension data
	// for compatibility providers that still need raw arguments.
	// Applied in MarkInFlight after the size bound and denylist check.
	locatorRedactor func(json.RawMessage) (json.RawMessage, error)
}

// SetLocatorRedactor installs a hook that rewrites recovery locators
// before durable storage. Use it to encrypt or redact locator payloads
// for compatibility providers that cannot minimize to pure lookup
// coordinates. Passing nil disables the hook.
func (s *Store) SetLocatorRedactor(f func(json.RawMessage) (json.RawMessage, error)) {
	s.locatorRedactor = f
}

// evidenceVerifier returns the configured EvidenceVerifier, defaulting
// to the signed-receipt verifier bound to trustedSigners.
func (s *Store) evidenceVerifier() EvidenceVerifier {
	if s.verifier != nil {
		return s.verifier
	}
	return signedReceiptVerifier{store: s}
}

// SetEvidenceVerifier installs a custom EvidenceVerifier for CRITICAL
// terminal transitions. Passing nil restores the default signed-receipt
// verifier. Intended for tests and alternative attestation backends.
func (s *Store) SetEvidenceVerifier(v EvidenceVerifier) {
	s.verifier = v
}

// SetTrustedEvidenceSigners configures the signer fingerprints trusted
// to attest CRITICAL terminal transitions. Each fingerprint is the
// lowercase hex SHA-256 of an Ed25519 public key — see
// internal/evidence. Replacing the set is an administrative operation;
// call it once at store initialization.
func (s *Store) SetTrustedEvidenceSigners(fingerprints ...string) {
	s.trustedSigners = make(map[string]bool, len(fingerprints))
	for _, fp := range fingerprints {
		s.trustedSigners[fp] = true
	}
}

// NewStore creates a new durable execution store with default lease config.
func NewStore(db *sql.DB) (*Store, error) {
	return NewStoreWithConfig(db, DefaultLeaseConfig)
}

// NewStoreWithConfig creates a store with a custom lease configuration.
func NewStoreWithConfig(db *sql.DB, cfg LeaseConfig) (*Store, error) {
	s := &Store{db: db, leaseCfg: cfg}
	if err := s.ensureSchema(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to ensure schema: %w", err)
	}
	return s, nil
}

// ─── Schema ──────────────────────────────────────────────────────────

// RequiredSchemaVersion is the minimum schema version this build
// requires. Startup verifies the migrated schema reaches this version —
// a database older than the code fails closed rather than running
// against a partial schema.
const RequiredSchemaVersion = 3

// schemaMigration is one versioned, idempotent schema change. Each
// migration must be safe to re-run (IF NOT EXISTS / addColumnIfMissing)
// and is recorded in schema_migrations so applied versions are tracked
// explicitly rather than inferred from column presence.
type schemaMigration struct {
	version int
	name    string
	apply   func(ctx context.Context, conn *sql.Conn) error
}

// schemaMigrations is the ordered, versioned migration list. New schema
// changes are appended — never edit a shipped migration.
var schemaMigrations = []schemaMigration{
	{1, "execution_requests_base", migrationBaseTable},
	{2, "hot_path_indexes", migrationHotPathIndexes},
	{3, "provider_observation_columns", migrationObservationColumns},
}

func (s *Store) ensureSchema(ctx context.Context) error {
	// Serialize all schema DDL across replicas (and parallel test
	// binaries) on a single dedicated connection. CREATE INDEX
	// CONCURRENTLY holds SHARE UPDATE EXCLUSIVE while it waits for
	// snapshots; a concurrent CREATE TABLE/ALTER TABLE that blocks on
	// that lock inside an open transaction deadlocks the build. The
	// advisory lock makes the whole migration phase mutually exclusive.
	//
	// Try-lock polling is deliberate: a session blocked inside
	// pg_advisory_lock holds an open transaction that CONCURRENTLY
	// waits on, recreating the deadlock cycle through the advisory
	// lock itself. pg_try_advisory_lock never waits.
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	// Advisory lock key: arbitrary stable constant for schema migration.
	for {
		var locked bool
		if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(727301)`).Scan(&locked); err != nil {
			return fmt.Errorf("schema advisory lock failed: %w", err)
		}
		if locked {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	defer conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(727301)`)

	if _, err := conn.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
		)
	`); err != nil {
		return fmt.Errorf("failed to create schema_migrations: %w", err)
	}

	applied := map[int]bool{}
	rows, err := conn.QueryContext(ctx, `SELECT version FROM schema_migrations`)
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

	for _, m := range schemaMigrations {
		if applied[m.version] {
			continue
		}
		if err := m.apply(ctx, conn); err != nil {
			return fmt.Errorf("migration %d (%s) failed: %w", m.version, m.name, err)
		}
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, name) VALUES ($1, $2)
			 ON CONFLICT (version) DO NOTHING`, m.version, m.name); err != nil {
			return fmt.Errorf("failed to record migration %d: %w", m.version, err)
		}
	}

	// Startup check: the migrated schema must satisfy this build's
	// required version. Fails closed on an incomplete schema.
	version, err := s.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	if version < RequiredSchemaVersion {
		return fmt.Errorf("schema version %d < required %d — run migrations before starting",
			version, RequiredSchemaVersion)
	}
	return nil
}

// SchemaVersion returns the highest applied schema migration version
// (0 when no migrations have been recorded).
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v *int
	err := s.db.QueryRowContext(ctx,
		`SELECT MAX(version) FROM schema_migrations`).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("failed to read schema version: %w", err)
	}
	if v == nil {
		return 0, nil
	}
	return *v, nil
}

// migrationBaseTable creates execution_requests and brings legacy
// deployments forward: missing columns, state-name migration.
func migrationBaseTable(ctx context.Context, conn *sql.Conn) error {
	_, err := conn.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS execution_requests (
			execution_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			idempotency_key TEXT NOT NULL,
			principal_id TEXT NOT NULL,
			capability_id TEXT NOT NULL,
			request_digest TEXT NOT NULL,
			grant_id TEXT,
			execution_class TEXT NOT NULL,
			state TEXT NOT NULL,
			result JSONB,
			evidence_digest TEXT,
			receipt_version INTEGER NOT NULL DEFAULT 0,
			lease_owner TEXT,
			lease_token TEXT,
			lease_started_at TIMESTAMPTZ,
			lease_expires_at TIMESTAMPTZ,
			lease_generation INTEGER NOT NULL DEFAULT 1,
			provider_id TEXT,
			provider_run_id TEXT,
			terminal_receipt_digest TEXT,
			evidence_receipt JSONB,
			recovery_locator JSONB,
			attempt INTEGER NOT NULL DEFAULT 0,
			version INTEGER NOT NULL DEFAULT 1,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE(principal_id, capability_id, idempotency_key)
		)
	`)
	if err != nil {
		// gen_random_uuid might not be available without pgcrypto —
		// fall back to a TEXT primary key with a Go-generated UUID.
		_, err = conn.ExecContext(ctx, `
			CREATE TABLE IF NOT EXISTS execution_requests (
				execution_id TEXT PRIMARY KEY,
				idempotency_key TEXT NOT NULL,
				principal_id TEXT NOT NULL,
				capability_id TEXT NOT NULL,
				request_digest TEXT NOT NULL,
				grant_id TEXT,
				execution_class TEXT NOT NULL,
				state TEXT NOT NULL,
				result JSONB,
				evidence_digest TEXT,
				receipt_version INTEGER NOT NULL DEFAULT 0,
				lease_owner TEXT,
				lease_token TEXT,
				lease_started_at TIMESTAMPTZ,
				lease_expires_at TIMESTAMPTZ,
				lease_generation INTEGER NOT NULL DEFAULT 1,
				provider_id TEXT,
				provider_run_id TEXT,
				terminal_receipt_digest TEXT,
				evidence_receipt JSONB,
				recovery_locator JSONB,
				attempt INTEGER NOT NULL DEFAULT 0,
				version INTEGER NOT NULL DEFAULT 1,
				created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				UNIQUE(principal_id, capability_id, idempotency_key)
			)
		`)
		if err != nil {
			return err
		}
	}

	// Bring legacy deployments forward — every statement is idempotent.
	// Migration failures must propagate: store initialization fails
	// closed if schema alteration or state migration fails.
	columns := []struct{ name, def string }{
		{"lease_started_at", "TIMESTAMPTZ"},
		{"lease_generation", "INTEGER NOT NULL DEFAULT 1"},
		{"provider_id", "TEXT"},
		{"provider_run_id", "TEXT"},
		{"terminal_receipt_digest", "TEXT"},
		{"recovery_locator", "JSONB"},
		{"reconcile_owner", "TEXT"},
		{"reconcile_lease_expires_at", "TIMESTAMPTZ"},
		{"reconcile_attempt", "INTEGER NOT NULL DEFAULT 0"},
		{"next_reconcile_at", "TIMESTAMPTZ"},
		{"last_reconcile_error", "TEXT"},
		{"evidence_receipt", "JSONB"},
		// Legacy columns from earlier versions.
		{"receipt_version", "INTEGER NOT NULL DEFAULT 0"},
		{"lease_owner", "TEXT"},
		{"lease_token", "TEXT"},
		{"lease_expires_at", "TIMESTAMPTZ"},
		{"attempt", "INTEGER NOT NULL DEFAULT 0"},
		{"version", "INTEGER NOT NULL DEFAULT 1"},
	}
	for _, c := range columns {
		if _, err := conn.ExecContext(ctx,
			fmt.Sprintf(`ALTER TABLE execution_requests ADD COLUMN IF NOT EXISTS %s %s`, c.name, c.def)); err != nil {
			return fmt.Errorf("column %s: %w", c.name, err)
		}
	}

	// Migrate old state names to the current vocabulary.
	return migrateStateNames(ctx, conn)
}

// migrationObservationColumns adds the durable provider-observation
// columns written by RecordProviderObservation.
func migrationObservationColumns(ctx context.Context, conn *sql.Conn) error {
	columns := []struct{ name, def string }{
		{"provider_status", "TEXT"},
		{"provider_result_digest", "TEXT"},
		{"provider_receipt_version", "INTEGER NOT NULL DEFAULT 0"},
		{"provider_observed_at", "TIMESTAMPTZ"},
	}
	for _, c := range columns {
		if _, err := conn.ExecContext(ctx,
			fmt.Sprintf(`ALTER TABLE execution_requests ADD COLUMN IF NOT EXISTS %s %s`, c.name, c.def)); err != nil {
			return fmt.Errorf("column %s: %w", c.name, err)
		}
	}
	return nil
}

// migrationHotPathIndexes creates the partial indexes for the two hot
// maintenance queries — UNKNOWN records needing reconciliation, and
// active records with expired leases. CONCURRENTLY is used so first
// deployment on a large ledger does not block writes; CONCURRENTLY
// cannot run inside a transaction and two concurrent builds deadlock
// each other, so the caller must hold the schema advisory lock on conn.
func migrationHotPathIndexes(ctx context.Context, conn *sql.Conn) error {
	indexes := []string{
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_exec_reconcile
		 ON execution_requests (next_reconcile_at, updated_at)
		 WHERE state = 'UNKNOWN'`,
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_exec_expired_leases
		 ON execution_requests (lease_expires_at)
		 WHERE state IN ('PREPARED', 'EXECUTING', 'IN_FLIGHT')
		   AND lease_expires_at IS NOT NULL`,
	}
	for _, idx := range indexes {
		if _, err := conn.ExecContext(ctx, idx); err != nil {
			return err
		}
	}
	return nil
}

// migrateStateNames updates pre-v1 state vocabulary in place. No-op on
// schemas that already use the current names.
func migrateStateNames(ctx context.Context, conn *sql.Conn) error {
	migrations := map[string]string{
		"RESERVED":                "PREPARED",
		"DISPATCHING":             "EXECUTING",
		"SUCCEEDED":               "COMMITTED",
		"RECONCILIATION_REQUIRED": "UNKNOWN",
		"RECOVERY_REQUIRED":       "UNKNOWN",
		"AMBIGUOUS":               "UNKNOWN",
	}
	for old, newVal := range migrations {
		if _, err := conn.ExecContext(ctx, `UPDATE execution_requests SET state = $1 WHERE state = $2`, newVal, old); err != nil {
			return fmt.Errorf("failed to migrate state %s -> %s: %w", old, newVal, err)
		}
	}
	return nil
}

// ─── Lease token generation ──────────────────────────────────────────

// generateLeaseToken generates a cryptographically unguessable lease token.
func generateLeaseToken() (string, error) {
	b := make([]byte, 32) // 256 bits
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generateExecutionID generates a UUID v4 application-side.
// This replaces the gen_random_uuid() database default, making
// the insert path independent of the pgcrypto extension.
func generateExecutionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// Set version 4 (random) and variant bits.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// ─── Acquire (reservation) ───────────────────────────────────────────

// Acquire attempts to acquire a lease for an execution.
//
// This replaces the old Reserve/ReserveWithLease methods. It returns
// a typed AcquireResult that prevents callers from inferring semantics
// from state names.
//
// The reclaim matrix is encoded in the SQL:
//   - PREPARED + expired → reclaim allowed
//   - EXECUTING + expired → reclaim allowed (dispatch boundary not crossed)
//   - IN_FLIGHT + expired → reclaim forbidden → transition to UNKNOWN
//   - UNKNOWN → no dispatch (RECOVERY_REQUIRED)
//   - COMMITTED/FAILED/DENIED → immutable replay
func (s *Store) Acquire(ctx context.Context, key, principal, capability, digest, grantID, class string, leaseDuration time.Duration) (*AcquireResult, error) {
	if err := s.leaseCfg.Validate(leaseDuration); err != nil {
		return nil, err
	}

	leaseToken, err := generateLeaseToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate lease token: %w", err)
	}
	leaseOwner := fmt.Sprintf("pid-%d", currentPID())

	// First, try to atomically INSERT a new PREPARED record with a lease.
	// PostgreSQL owns the timestamps via clock_timestamp().
	// execution_id is generated application-side (UUID v4) so the insert
	// works whether or not the pgcrypto extension is available.
	genID, err := generateExecutionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate execution ID: %w", err)
	}
	var executionID string
	var createdAt time.Time
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO execution_requests
			(execution_id, idempotency_key, principal_id, capability_id, request_digest,
			 grant_id, execution_class, state,
			 lease_owner, lease_token, lease_started_at, lease_expires_at,
			 lease_generation, attempt, version)
		VALUES ($10, $1, $2, $3, $4, $5, $6, 'PREPARED',
				$7, $8, clock_timestamp(), clock_timestamp() + make_interval(secs => $9),
				1, 0, 1)
		ON CONFLICT (principal_id, capability_id, idempotency_key) DO NOTHING
		RETURNING execution_id, created_at
	`, key, principal, capability, digest, nullableString(grantID), class,
		leaseOwner, leaseToken, pgInterval(leaseDuration),
		genID,
	).Scan(&executionID, &createdAt)

	if err == nil {
		// Insert succeeded — THIS caller acquired the lease.
		return &AcquireResult{
			Kind:       LeaseAcquired,
			State:      StatePrepared,
			LeaseToken: leaseToken,
			Generation: 1,
			Record: &Record{
				ExecutionID:     executionID,
				IdempotencyKey:  key,
				PrincipalID:     principal,
				CapabilityID:    capability,
				RequestDigest:   digest,
				GrantID:         grantID,
				ExecutionClass:  class,
				State:           StatePrepared,
				LeaseOwner:      leaseOwner,
				LeaseToken:      leaseToken,
				LeaseGeneration: 1,
				Attempt:         0,
				Version:         1,
				CreatedAt:       createdAt,
				UpdatedAt:       createdAt,
			},
		}, nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	// ON CONFLICT DO NOTHING — the key already exists. Read it.
	rec, err := s.lookupByKey(ctx, principal, capability, key)
	if err != nil {
		return nil, err
	}

	// Different digest → idempotency conflict.
	if rec.RequestDigest != digest {
		return &AcquireResult{
			Kind:   IdempotencyConflict,
			State:  rec.State,
			Record: rec,
		}, nil
	}

	// Durably final → immutable replay.
	if rec.State.IsDurablyFinal() {
		return &AcquireResult{
			Kind:   TerminalReplay,
			State:  rec.State,
			Record: rec,
		}, nil
	}

	// UNKNOWN → recovery required, no dispatch.
	if rec.State == StateUnknown {
		return &AcquireResult{
			Kind:   RecoveryRequired,
			State:  rec.State,
			Record: rec,
		}, nil
	}

	// PREPARED or EXECUTING with expired lease → reclaim.
	// Also handle PREPARED with no lease (after AbandonPreDispatch) —
	// acquire immediately since no one holds the lease.
	if (rec.State == StatePrepared || rec.State == StateExecuting) && rec.LeaseExpiresAt != nil {
		reclaimed, err := s.reclaimExpiredLease(ctx, rec, leaseToken, leaseOwner, leaseDuration)
		if err != nil {
			return nil, err
		}
		if reclaimed {
			return &AcquireResult{
				Kind:       LeaseReclaimed,
				State:      StatePrepared,
				LeaseToken: leaseToken,
				Generation: rec.LeaseGeneration,
				Record:     rec,
			}, nil
		}
		// Another caller reclaimed between our read and CAS — re-read.
		rec, err = s.lookupByKey(ctx, principal, capability, key)
		if err != nil {
			return nil, err
		}
		// Re-check after race.
		if rec.State.IsDurablyFinal() {
			return &AcquireResult{Kind: TerminalReplay, State: rec.State, Record: rec}, nil
		}
		if rec.State == StateUnknown {
			return &AcquireResult{Kind: RecoveryRequired, State: rec.State, Record: rec}, nil
		}
	}

	// IN_FLIGHT with expired lease → transition to UNKNOWN, return recovery required.
	if rec.State == StateInFlight && rec.LeaseExpiresAt != nil {
		marked, err := s.markInFlightExpiredAsUnknown(ctx, rec)
		if err != nil {
			return nil, err
		}
		if marked {
			return &AcquireResult{
				Kind:   RecoveryRequired,
				State:  StateUnknown,
				Record: rec,
			}, nil
		}
		// Another caller marked it — re-read.
		rec, err = s.lookupByKey(ctx, principal, capability, key)
		if err != nil {
			return nil, err
		}
		// P2 #7: Re-check IsDurablyFinal after re-read. Another worker
		// may have finalized the record between our initial read
		// and this re-read. A durably-final record must return
		// TerminalReplay, not LeaseHeldByOther.
		if rec.State.IsDurablyFinal() {
			return &AcquireResult{Kind: TerminalReplay, State: rec.State, Record: rec}, nil
		}
		if rec.State == StateUnknown {
			return &AcquireResult{Kind: RecoveryRequired, State: rec.State, Record: rec}, nil
		}
	}

	// PREPARED with no lease (after AbandonPreDispatch) → acquire
	// immediately. The lease was explicitly released before expiry,
	// so there is no holder to contend with.
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
		// Another caller acquired — re-read.
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

	// Same digest, non-terminal, lease still valid → held by other.
	return &AcquireResult{
		Kind:   LeaseHeldByOther,
		State:  rec.State,
		Record: rec,
	}, nil
}

// acquireUnleased atomically acquires a PREPARED record that has no
// active lease (lease_token IS NULL, lease_expires_at IS NULL). This
// happens after AbandonPreDispatch releases the lease before expiry.
func (s *Store) acquireUnleased(ctx context.Context, rec *Record, newToken, newOwner string, duration time.Duration) (bool, error) {
	result, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET lease_owner = $1, lease_token = $2,
		    lease_started_at = clock_timestamp(),
		    lease_expires_at = clock_timestamp() + make_interval(secs => $3),
		    lease_generation = lease_generation + 1,
		    version = version + 1, updated_at = clock_timestamp()
		WHERE execution_id = $4
		  AND state = 'PREPARED'
		  AND lease_token IS NULL
		  AND lease_expires_at IS NULL
		  AND version = $5
	`, newOwner, newToken, pgInterval(duration),
		rec.ExecutionID, rec.Version)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if rows == 0 {
		return false, nil
	}
	rec.LeaseOwner = newOwner
	rec.LeaseToken = newToken
	rec.LeaseGeneration++
	rec.Version++
	return true, nil
}

// reclaimExpiredLease atomically takes over an expired lease for
// PREPARED or EXECUTING states. The dispatch boundary was NOT crossed.
// Generation increments to function as a fencing epoch.
func (s *Store) reclaimExpiredLease(ctx context.Context, rec *Record, newToken, newOwner string, duration time.Duration) (bool, error) {
	result, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET lease_owner = $1, lease_token = $2,
		    lease_started_at = clock_timestamp(),
		    lease_expires_at = clock_timestamp() + make_interval(secs => $3),
		    lease_generation = lease_generation + 1,
		    attempt = attempt + 1, version = version + 1,
		    state = 'PREPARED', updated_at = clock_timestamp()
		WHERE execution_id = $4
		  AND version = $5
		  AND state IN ('PREPARED', 'EXECUTING')
		  AND lease_expires_at < clock_timestamp()
	`, newOwner, newToken, pgInterval(duration),
		rec.ExecutionID, rec.Version)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if rows == 0 {
		return false, nil
	}
	// Update in-memory record.
	rec.LeaseOwner = newOwner
	rec.LeaseToken = newToken
	rec.LeaseGeneration++
	rec.Attempt++
	rec.Version++
	rec.State = StatePrepared
	return true, nil
}

// markInFlightExpiredAsUnknown transitions an expired IN_FLIGHT record
// to UNKNOWN. The side effect may have occurred — never blind-retry.
func (s *Store) markInFlightExpiredAsUnknown(ctx context.Context, rec *Record) (bool, error) {
	result, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = 'UNKNOWN', version = version + 1,
		    lease_owner = NULL, lease_token = NULL,
		    lease_started_at = NULL, lease_expires_at = NULL,
		    updated_at = clock_timestamp()
		WHERE execution_id = $1
		  AND version = $2
		  AND state = 'IN_FLIGHT'
		  AND lease_expires_at < clock_timestamp()
	`, rec.ExecutionID, rec.Version)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if rows == 0 {
		return false, nil
	}
	rec.State = StateUnknown
	rec.Version++
	return true, nil
}

// ─── Lease-fenced transitions ────────────────────────────────────────

// BeginExecution transitions from PREPARED to EXECUTING.
// Only the active lease holder may transition. The lease must be
// unexpired (checked inside SQL).
func (s *Store) BeginExecution(ctx context.Context, executionID, leaseToken string, leaseGeneration int) error {
	return s.leaseFencedTransition(ctx, executionID, leaseToken, leaseGeneration, StatePrepared, StateExecuting)
}

// MarkInFlight transitions from EXECUTING to IN_FLIGHT.
// This crosses the dispatch boundary — persist BEFORE the provider call.
// After this point, a crash means the side effect may have occurred.
//
// providerID and recoveryLocator are persisted atomically with the
// state transition so that a crashed execution carries the information
// needed for provider-specific reconciliation.
func (s *Store) MarkInFlight(ctx context.Context, executionID, leaseToken string, leaseGeneration int, providerID string, recoveryLocator json.RawMessage) error {
	if len(recoveryLocator) > MaxRecoveryLocatorBytes {
		return fmt.Errorf("%w: recovery locator exceeds %d bytes (got %d)",
			LocatorTooLarge, MaxRecoveryLocatorBytes, len(recoveryLocator))
	}
	if field := forbiddenLocatorField(recoveryLocator); field != "" {
		return fmt.Errorf("%w: recovery locator contains forbidden field %q",
			LocatorContainsSecret, field)
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
	result, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = 'IN_FLIGHT', version = version + 1,
		    provider_id = $4, recovery_locator = $5,
		    updated_at = clock_timestamp()
		WHERE execution_id = $1
		  AND state = 'EXECUTING'
		  AND lease_token = $2
		  AND lease_generation = $3
		  AND lease_expires_at > clock_timestamp()
	`, executionID, leaseToken, leaseGeneration,
		nullableString(providerID), nullableBytes(recoveryLocator))
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return s.classifyTransitionFailure(ctx, executionID, leaseToken, leaseGeneration, StateExecuting)
	}
	return nil
}

// forbiddenLocatorFields is a denylist of JSON object keys that must
// never appear in a persisted recovery locator. Locators are lookup
// coordinates — an execution- or provider-generated correlation token
// ("external_token") is fine; credential material is not.
var forbiddenLocatorFields = map[string]bool{
	"password":       true,
	"passwd":         true,
	"secret":         true,
	"client_secret":  true,
	"api_key":        true,
	"apikey":         true,
	"private_key":    true,
	"privatekey":     true,
	"authorization":  true,
	"credentials":    true,
	"access_token":   true,
	"refresh_token":  true,
	"bearer":         true,
	"session_cookie": true,
}

// forbiddenLocatorField returns the first denied key found anywhere in
// the locator JSON tree, or "" when the locator is clean. Keys are
// compared case-insensitively after separator normalization.
func forbiddenLocatorField(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "" // non-JSON locators are size-bounded; key scanning is N/A
	}
	return findForbiddenKey(v)
}

func findForbiddenKey(v any) string {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			norm := strings.ToLower(strings.ReplaceAll(k, "-", "_"))
			if forbiddenLocatorFields[norm] {
				return k
			}
			if f := findForbiddenKey(val); f != "" {
				return f
			}
		}
	case []any:
		for _, item := range t {
			if f := findForbiddenKey(item); f != "" {
				return f
			}
		}
	}
	return ""
}

// legalTransitions defines the allowed state transitions.
// This enforces the lifecycle graph inside the Store rather than
// relying on caller convention.
//
// DENIED is excluded: it is a wire-level admission status, not a
// durable store state. Admission denial happens in the service layer
// before the idempotency envelope, so no code path persists StateDenied.
// The constant is retained in IsDurablyFinal/IsCallerTerminal for
// backward compatibility with any pre-existing DENIED records.
var legalTransitions = map[State][]State{
	StatePrepared:  {StateExecuting},
	StateExecuting: {StateInFlight, StatePrepared},
	StateInFlight:  {StateCommitted, StateFailed, StateUnknown},
	StateUnknown:   {StateCommitted, StateFailed},
}

// isLegalTransition checks whether a state transition is allowed by
// the lifecycle graph. Terminal states have no outgoing transitions.
func isLegalTransition(from, to State) bool {
	if from.IsDurablyFinal() {
		return false // Terminal states are immutable.
	}
	allowed, ok := legalTransitions[from]
	if !ok {
		return false
	}
	for _, s := range allowed {
		if s == to {
			return true
		}
	}
	return false
}

// leaseFencedTransition performs a state transition with full lease
// fencing enforced inside the SQL statement.
//
// In addition to lease fencing, this enforces the legal transition
// matrix — only transitions defined in legalTransitions are permitted.
func (s *Store) leaseFencedTransition(ctx context.Context, executionID, leaseToken string, leaseGeneration int, expectedState, newState State) error {
	if !isLegalTransition(expectedState, newState) {
		return fmt.Errorf("%w: illegal transition %s → %s", LeaseStateConflict, expectedState, newState)
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = $1, version = version + 1, updated_at = clock_timestamp()
		WHERE execution_id = $2
		  AND state = $3
		  AND lease_token = $4
		  AND lease_generation = $5
		  AND lease_expires_at > clock_timestamp()
	`, string(newState), executionID, string(expectedState), leaseToken, leaseGeneration)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return s.classifyTransitionFailure(ctx, executionID, leaseToken, leaseGeneration, expectedState)
	}
	return nil
}

// classifyTransitionFailure determines the specific lease error for a
// failed transition by inspecting the current record state.
func (s *Store) classifyTransitionFailure(ctx context.Context, executionID, leaseToken string, leaseGeneration int, expectedState State) error {
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
		return fmt.Errorf("%w: execution %s token mismatch", LeaseTokenMismatch, executionID)
	}
	if rec.LeaseGeneration != leaseGeneration {
		return fmt.Errorf("%w: execution %s generation %d != %d", LeaseGenerationMismatch, executionID, rec.LeaseGeneration, leaseGeneration)
	}
	// Token and generation match but rows affected was 0 → expired.
	return fmt.Errorf("%w: execution %s lease expired", LeaseExpired, executionID)
}

// ─── Lease renewal ──────────────────────────────────────────────────

// RenewLease extends the lease for the current holder. Only the
// active lease token and generation may renew. The lease must be
// unexpired (checked inside SQL). PostgreSQL computes the new expiry.
func (s *Store) RenewLease(ctx context.Context, executionID, leaseToken string, leaseGeneration int, duration time.Duration) error {
	if err := s.leaseCfg.Validate(duration); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET lease_expires_at = GREATEST(lease_expires_at, clock_timestamp() + make_interval(secs => $1)),
		    updated_at = clock_timestamp()
		WHERE execution_id = $2
		  AND lease_token = $3
		  AND lease_generation = $4
		  AND lease_expires_at > clock_timestamp()
		  AND state NOT IN ('COMMITTED', 'FAILED', 'DENIED', 'UNKNOWN')
	`, pgInterval(duration),
		executionID, leaseToken, leaseGeneration)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return s.classifyRenewalFailure(ctx, executionID, leaseToken, leaseGeneration)
	}
	return nil
}

func (s *Store) classifyRenewalFailure(ctx context.Context, executionID, leaseToken string, leaseGeneration int) error {
	rec, err := s.Lookup(ctx, executionID)
	if err != nil {
		return fmt.Errorf("%w: execution %s renewal failed (lookup error: %v)", LeaseLost, executionID, err)
	}
	if rec.State.IsDurablyFinal() || rec.State == StateUnknown {
		return fmt.Errorf("%w: execution %s is terminal (%s)", LeaseStateConflict, executionID, rec.State)
	}
	if rec.LeaseToken != leaseToken {
		return fmt.Errorf("%w: execution %s token mismatch", LeaseTokenMismatch, executionID)
	}
	if rec.LeaseGeneration != leaseGeneration {
		return fmt.Errorf("%w: execution %s generation %d != %d", LeaseGenerationMismatch, executionID, rec.LeaseGeneration, leaseGeneration)
	}
	return fmt.Errorf("%w: execution %s lease expired", LeaseExpired, executionID)
}

// ─── Abandon pre-dispatch ────────────────────────────────────────────

// AbandonPreDispatch transitions from PREPARED or EXECUTING back to
// PREPARED and releases the lease. This allows the next caller to
// reclaim immediately without waiting for expiry. Safe because the
// dispatch boundary was not crossed.
func (s *Store) AbandonPreDispatch(ctx context.Context, executionID, leaseToken string, leaseGeneration int) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = 'PREPARED', version = version + 1,
		    lease_owner = NULL, lease_token = NULL,
		    lease_started_at = NULL, lease_expires_at = NULL,
		    updated_at = clock_timestamp()
		WHERE execution_id = $1
		  AND state IN ('PREPARED', 'EXECUTING')
		  AND lease_token = $2
		  AND lease_generation = $3
		  AND lease_expires_at > clock_timestamp()
	`, executionID, leaseToken, leaseGeneration)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return s.classifyTransitionFailure(ctx, executionID, leaseToken, leaseGeneration, StatePrepared)
	}
	return nil
}

// ─── Immutable finalization ─────────────────────────────────────────

// Finalize atomically finalizes an execution with an immutable terminal
// receipt. Only the active lease holder may finalize. The lease must
// be unexpired (checked inside SQL).
//
// Behavior:
//   - First valid finalization → durably final (COMMITTED/FAILED/DENIED)
//   - Same canonical receipt again → ALREADY_FINALIZED (idempotent)
//   - Different receipt for same execution → FINALIZATION_CONFLICT
//
// The entire terminal receipt is compared, not just state + evidence.
func (s *Store) Finalize(ctx context.Context, executionID, leaseToken string, leaseGeneration int, expectedState State, receipt TerminalReceipt) error {
	// Reject non-durably-final terminal statuses. Finalize is a
	// durably-final transition — the receipt must target COMMITTED,
	// FAILED, or DENIED. Passing UNKNOWN, PREPARED, EXECUTING, or
	// IN_FLIGHT is a contract violation.
	if !receipt.TerminalStatus.IsDurablyFinal() {
		return fmt.Errorf("invalid terminal status %s: Finalize requires a durably-final state (COMMITTED, FAILED, or DENIED)", receipt.TerminalStatus)
	}

	// Enforce the legal transition matrix for finalization:
	//   COMMITTED, FAILED → only from IN_FLIGHT (post-dispatch)
	// DENIED is not a reachable durable state — admission denial
	// happens in the service layer before the idempotency envelope.
	// This prevents illegal transitions like PREPARED → COMMITTED.
	if !isLegalTransition(expectedState, receipt.TerminalStatus) {
		return fmt.Errorf("%w: illegal finalization transition %s → %s", LeaseStateConflict, expectedState, receipt.TerminalStatus)
	}

	// First check if already finalized (idempotent replay or conflict).
	existing, err := s.Lookup(ctx, executionID)
	if err != nil {
		return fmt.Errorf("finalize lookup failed: %w", err)
	}

	// P1 #4: Validate receipt identity matches the database row.
	// The terminal receipt is an immutable record — its identity
	// fields must match the execution being finalized. A mismatch
	// means the receipt describes a different execution.
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

	// Populate identity fields from the authoritative row, not the
	// caller. This ensures the canonical receipt digest is computed
	// from the store's truth, not caller-supplied values.
	receipt.ExecutionID = executionID
	receipt.Capability = existing.CapabilityID
	receipt.Principal = existing.PrincipalID
	receipt.RequestDigest = existing.RequestDigest

	// P2 #9: Store assigns FinalizedAt authoritatively. The store
	// uses clock_timestamp() so the timestamp is deterministic and
	// tied to the database transaction, not the caller's clock.
	// We set it before computing the digest so the canonical receipt
	// includes a meaningful finalized-at timestamp.
	// (The actual DB update uses clock_timestamp() for updated_at;
	// we approximate FinalizedAt with the same transaction time by
	// reading it after the UPDATE. For the digest, we use a zero
	// value and exclude it — see TerminalReceipt.Digest().)
	receiptDigest, err := receipt.Digest()
	if err != nil {
		return fmt.Errorf("failed to compute terminal receipt digest: %w", err)
	}

	if existing.State.IsDurablyFinal() {
		// Already finalized — compare the full receipt. Proof policy was
		// enforced on the first transition; an identical replay is
		// idempotent and a different receipt is a conflict.
		if existing.TerminalReceiptDigest == receiptDigest {
			return nil // ALREADY_FINALIZED — idempotent replay.
		}
		return fmt.Errorf("FINALIZATION_CONFLICT: execution %s already finalized with different receipt (existing digest %s, new digest %s)",
			executionID, existing.TerminalReceiptDigest, receiptDigest)
	}

	// Unified terminal policy — identical to ResolveRecovery's. For
	// CRITICAL, authenticate the receipt through the evidence boundary
	// first, then enforce the outcome requirement. A caller that
	// bypasses DispatchExecutor cannot finalize CRITICAL without
	// provider-correlated authenticated proof.
	var verified *VerifiedEvidence
	if existing.ExecutionClass == "CRITICAL" {
		verified, err = s.evidenceVerifier().Verify(ctx, existing, receipt, receipt.TerminalStatus)
		if err != nil {
			return fmt.Errorf("CRITICAL finalization to %s requires a verified signed evidence receipt: %w", receipt.TerminalStatus, err)
		}
	}
	if err := ValidateTerminalTransition(existing, receipt.TerminalStatus, receipt, verified); err != nil {
		return err
	}

	// Not yet durably final — perform CAS transition.
	result, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = $1, result = $2, evidence_digest = $3, receipt_version = $4,
		    provider_id = $5, provider_run_id = $6,
		    terminal_receipt_digest = $7, evidence_receipt = $13,
		    lease_owner = NULL, lease_token = NULL,
		    lease_started_at = NULL, lease_expires_at = NULL,
		    recovery_locator = NULL,
		    version = version + 1, updated_at = clock_timestamp()
		WHERE execution_id = $8
		  AND state = $9
		  AND lease_token = $10
		  AND lease_generation = $11
		  AND lease_expires_at > clock_timestamp()
		  AND version = $12
	`, string(receipt.TerminalStatus),
		nullableBytes(receipt.CanonicalResult),
		nullableString(receipt.EvidenceDigest),
		receipt.ReceiptVersion,
		nullableString(receipt.ProviderID),
		nullableString(receipt.ProviderRunID),
		receiptDigest,
		executionID, string(expectedState), leaseToken, leaseGeneration, existing.Version,
		nullableBytes(receipt.EvidenceReceipt))
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		// CAS lost — another writer may have finalized concurrently.
		// Re-read and check for idempotent replay before reporting
		// a conflict. Two workers finalizing with identical receipts
		// must both succeed, not produce a false conflict.
		current, lookupErr := s.Lookup(ctx, executionID)
		if lookupErr == nil && current.State.IsDurablyFinal() && current.TerminalReceiptDigest == receiptDigest {
			return nil // Concurrent identical finalization — idempotent.
		}
		return s.classifyTransitionFailure(ctx, executionID, leaseToken, leaseGeneration, expectedState)
	}
	return nil
}

// ─── Recovery ────────────────────────────────────────────────────────

// EnterRecovery transitions a record to UNKNOWN for reconciliation.
// This is used for IN_FLIGHT records where the lease has expired
// (the side effect may have occurred) or for records where the
// handler returned an ambiguous result.
//
// Enforces the legal transition matrix: only IN_FLIGHT → UNKNOWN is
// permitted. Terminal states (COMMITTED, FAILED, DENIED) and
// pre-dispatch states (PREPARED, EXECUTING) cannot enter recovery —
// PREPARED/EXECUTING records are safe to reclaim, not reconcile.
//
// Uses CAS with expected state to prevent overwriting a state that
// changed after it was read.
func (s *Store) EnterRecovery(ctx context.Context, executionID string, expectedState State, expectedVersion int) error {
	if !isLegalTransition(expectedState, StateUnknown) {
		return fmt.Errorf("%w: illegal recovery transition %s → UNKNOWN (only IN_FLIGHT may enter recovery)", LeaseStateConflict, expectedState)
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = 'UNKNOWN', version = version + 1,
		    lease_owner = NULL, lease_token = NULL,
		    lease_started_at = NULL, lease_expires_at = NULL,
		    reconcile_owner = NULL, reconcile_lease_expires_at = NULL,
		    updated_at = clock_timestamp()
		WHERE execution_id = $1
		  AND state = $2
		  AND version = $3
	`, executionID, string(expectedState), expectedVersion)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("%w: execution %s enter recovery CAS failed (state/version mismatch)", LeaseStateConflict, executionID)
	}
	return nil
}

// EnterRecoveryWithObservation transitions a record to UNKNOWN while
// persisting a provider observation. This is used when the provider
// returned a result but Finalize could not commit (lease expiry,
// CAS conflict, etc.). The observation preserves the provider's
// identity and evidence so the recovery resolver can correlate.
//
// The observation fields (provider_id, provider_run_id, evidence)
// are written atomically with the UNKNOWN transition. Unlike
// Finalize, this does NOT create a terminal receipt — the record
// remains UNKNOWN pending reconciliation.
func (s *Store) EnterRecoveryWithObservation(ctx context.Context, executionID string, expectedState State, expectedVersion int, obs ProviderObservation) error {
	if !isLegalTransition(expectedState, StateUnknown) {
		return fmt.Errorf("%w: illegal recovery transition %s → UNKNOWN (only IN_FLIGHT may enter recovery)", LeaseStateConflict, expectedState)
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = 'UNKNOWN', version = version + 1,
		    lease_owner = NULL, lease_token = NULL,
		    lease_started_at = NULL, lease_expires_at = NULL,
		    reconcile_owner = NULL, reconcile_lease_expires_at = NULL,
		    provider_id = $4, provider_run_id = $5,
		    provider_status = $6, provider_result_digest = $7,
		    provider_receipt_version = $8,
		    provider_observed_at = clock_timestamp(),
		    evidence_digest = $9, result = $10,
		    updated_at = clock_timestamp()
		WHERE execution_id = $1
		  AND state = $2
		  AND version = $3
	`, executionID, string(expectedState), expectedVersion,
		nullableString(obs.ProviderID), nullableString(obs.ProviderRunID),
		nullableString(obs.ProviderStatus), nullableString(obs.ResultDigest),
		obs.ReceiptVersion,
		nullableString(obs.EvidenceDigest), nullableBytes(obs.Result))
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("%w: execution %s enter recovery with observation CAS failed (state/version mismatch)", LeaseStateConflict, executionID)
	}
	return nil
}

// ProviderObservation is the provider's durable response snapshot:
// the observation the recovery resolver needs most if the terminal
// transition cannot be committed.
type ProviderObservation struct {
	ProviderID    string
	ProviderRunID string
	// ProviderStatus is the provider-reported outcome ("SUCCEEDED",
	// "FAILED", "UNKNOWN", ...) as the dispatcher classified it.
	ProviderStatus string
	// Result is the provider's result payload (canonicalized before
	// storage so byte-level key ordering cannot create false
	// conflicts).
	Result json.RawMessage
	// ResultDigest is the SHA-256 of the canonical result. When Result
	// is supplied without a digest, the store computes it.
	ResultDigest   string
	EvidenceDigest string
	ReceiptVersion int
	// ObservedAt is populated by the store from clock_timestamp() —
	// database time is authoritative. Caller-supplied values are
	// ignored.
	ObservedAt time.Time
}

// RecordProviderObservation durably records a provider's response
// metadata independently of the terminal state transition. It is the
// fix for the "observation lost on CAS failure" class of bug: the
// dispatcher calls it immediately after the provider returns, before
// evidence validation and Finalize, so the observation survives even
// when the record races into UNKNOWN.
//
// Semantics:
//   - IN_FLIGHT: the write is lease-fenced (token + generation must
//     match); the lease need not be unexpired — an expired lease whose
//     record has not yet been claimed is still the legitimate owner.
//   - UNKNOWN: the write is accepted unconditionally — the record
//     already raced past the lease holder and this observation is the
//     freshest provider truth the resolver will ever see.
//   - Any other state (terminal, PREPARED, EXECUTING): rejected.
//
// The write is monotonic. Supplied fields fill NULL columns and are
// re-checked against existing values inside the same UPDATE:
// re-recording an identical observation is idempotent; a contradictory
// provider_id, run ID, status, result, or evidence digest is rejected
// with ProviderObservationConflict. A stale worker can therefore never
// overwrite a newer observation. The version is deliberately NOT
// incremented — an observation is additive metadata, and bumping the
// CAS token would invalidate reconciliation claims in flight.
func (s *Store) RecordProviderObservation(ctx context.Context, executionID, leaseToken string, leaseGeneration int, obs ProviderObservation) error {
	// Canonicalize the result so byte-level key ordering cannot create
	// a false conflict, and derive the result digest when omitted.
	result := obs.Result
	resultDigest := obs.ResultDigest
	if len(result) > 0 {
		if canonical, err := canonicalizeJSON(result); err == nil {
			result = canonical
		}
		if resultDigest == "" {
			sum := sha256.Sum256(result)
			resultDigest = hex.EncodeToString(sum[:])
		}
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET provider_id = COALESCE($4::text, provider_id),
		    provider_run_id = COALESCE($5::text, provider_run_id),
		    provider_status = COALESCE($6::text, provider_status),
		    result = COALESCE($7::jsonb, result),
		    provider_result_digest = COALESCE($8::text, provider_result_digest),
		    evidence_digest = COALESCE($9::text, evidence_digest),
		    provider_receipt_version = COALESCE(NULLIF($10::int, 0), provider_receipt_version),
		    provider_observed_at = clock_timestamp(),
		    updated_at = clock_timestamp()
		WHERE execution_id = $1
		  AND (
		    (state = 'IN_FLIGHT' AND lease_token = $2 AND lease_generation = $3)
		    OR state = 'UNKNOWN'
		  )
		  -- Monotonic: every supplied field must equal any value
		  -- already stored; contradictions reject the whole write.
		  AND (provider_id IS NULL OR $4::text IS NULL OR provider_id = $4::text)
		  AND (provider_run_id IS NULL OR $5::text IS NULL OR provider_run_id = $5::text)
		  AND (provider_status IS NULL OR $6::text IS NULL OR provider_status = $6::text)
		  AND (result IS NULL OR $7::jsonb IS NULL OR result = $7::jsonb)
		  AND (provider_result_digest IS NULL OR $8::text IS NULL OR provider_result_digest = $8::text)
		  AND (evidence_digest IS NULL OR $9::text IS NULL OR evidence_digest = $9::text)
	`, executionID, nullableString(leaseToken), leaseGeneration,
		nullableString(obs.ProviderID), nullableString(obs.ProviderRunID),
		nullableString(obs.ProviderStatus), nullableString(string(result)),
		nullableString(resultDigest), nullableString(obs.EvidenceDigest),
		obs.ReceiptVersion)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return s.classifyObservationFailure(ctx, executionID, leaseToken, leaseGeneration)
	}
	return nil
}

// classifyObservationFailure distinguishes a rejected write caused by
// conflicting stored observation data from one caused by a bad state
// or stale lease, so callers get the correct typed error.
func (s *Store) classifyObservationFailure(ctx context.Context, executionID, leaseToken string, leaseGeneration int) error {
	rec, err := s.Lookup(ctx, executionID)
	if err != nil {
		return err
	}
	if rec.State == StateInFlight &&
		(rec.LeaseToken != leaseToken || rec.LeaseGeneration != leaseGeneration) {
		return fmt.Errorf("%w: execution %s observation rejected (lease token/generation mismatch)", LeaseStateConflict, executionID)
	}
	if rec.State != StateInFlight && rec.State != StateUnknown {
		return fmt.Errorf("%w: execution %s observation rejected (state %s)", LeaseStateConflict, executionID, rec.State)
	}
	return fmt.Errorf("%w: execution %s observation contradicts stored provider observation", ProviderObservationConflict, executionID)
}

// RecoverExpiredPreDispatch normalizes a crashed PREPARED or EXECUTING
// record whose execution lease has expired: it resets the record to a
// lease-less PREPARED and clears the reconciliation claim in one CAS
// update. After this, the record is no longer eligible for expired-
// lease claiming (lease_expires_at IS NULL), so reconciliation does
// not claim/release-churn on it every cycle — and the next Acquire()
// reacquires it immediately via the lease-less PREPARED path.
func (s *Store) RecoverExpiredPreDispatch(ctx context.Context, executionID string, expectedVersion int) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = 'PREPARED',
		    lease_owner = NULL, lease_token = NULL,
		    lease_started_at = NULL, lease_expires_at = NULL,
		    reconcile_owner = NULL, reconcile_lease_expires_at = NULL,
		    next_reconcile_at = NULL,
		    version = version + 1, updated_at = clock_timestamp()
		WHERE execution_id = $1
		  AND state IN ('PREPARED', 'EXECUTING')
		  AND version = $2
		  AND lease_expires_at IS NOT NULL
		  AND lease_expires_at < clock_timestamp()
	`, executionID, expectedVersion)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("%w: execution %s recover expired pre-dispatch CAS failed (state/version/expiry mismatch)", LeaseStateConflict, executionID)
	}
	return nil
}

// ScrubStaleRecoveryLocators clears recovery_locator on UNKNOWN records
// older than the given retention (measured from created_at). Recovery
// locators may carry operation-identifying data; records that remain
// unresolved past the retention window keep their UNKNOWN state but
// stop retaining the locator. Returns the number of scrubbed records.
func (s *Store) ScrubStaleRecoveryLocators(ctx context.Context, olderThan time.Duration) (int64, error) {
	if olderThan <= 0 {
		return 0, fmt.Errorf("locator retention must be positive")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET recovery_locator = NULL
		WHERE state = 'UNKNOWN'
		  AND recovery_locator IS NOT NULL
		  AND created_at < clock_timestamp() - make_interval(secs => $1)
	`, pgInterval(olderThan))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ResolveRecovery resolves an UNKNOWN record to a durably final state
// using a recovery result. Uses CAS with expected state=UNKNOWN to
// prevent overwriting a state that changed after it was read.
//
// The recovery result must include evidence for any definitive
// conclusion (COMMITTED or FAILED).
func (s *Store) ResolveRecovery(ctx context.Context, executionID string, expectedVersion int, result RecoveryResult) error {
	decision := result.Decision
	var newState State
	switch decision {
	case RecoveryCommitted:
		newState = StateCommitted
	case RecoveryFailed:
		newState = StateFailed
	case RecoveryUnknown:
		// Still unknown — no state change, just touch updated_at.
		// P1 #3: Check RowsAffected to detect stale CAS. A zero-row
		// update means the record advanced to a different version
		// since we read it. Return STATE_CONFLICT so the caller knows
		// its view is stale.
		result, err := s.db.ExecContext(ctx, `
			UPDATE execution_requests
			SET updated_at = clock_timestamp()
			WHERE execution_id = $1 AND state = 'UNKNOWN' AND version = $2
		`, executionID, expectedVersion)
		if err != nil {
			return err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if rows == 0 {
			return fmt.Errorf("%w: execution %s recovery-unknown CAS failed (state/version mismatch)", LeaseStateConflict, executionID)
		}
		return nil
	case RecoveryRetryable:
		// CRAB-V1-020: post-dispatch uncertainty cannot become retryable
		// without evidence. RecoveryRetryable is rejected at the store
		// level because the store cannot distinguish UNKNOWN from
		// expired IN_FLIGHT (where the side effect may have occurred)
		// from a hypothetical safe-retry source. A generic retry path
		// here would allow blind redispatch of potentially-executed
		// operations.
		return fmt.Errorf("%w: RecoveryRetryable is not permitted — post-dispatch uncertainty cannot become retryable without proven safety (CRAB-V1-020)", LeaseStateConflict)
	case RecoveryConflict:
		return fmt.Errorf("%w: execution %s recovery conflict", LeaseStateConflict, executionID)
	default:
		return fmt.Errorf("unknown recovery decision: %s", decision)
	}

	// P1 #7: Build recovery receipts from the same canonical builder
	// as normal finalization. Use the record loaded below to populate
	// identity fields (capability, principal, request_digest) so
	// recovery-finalized and normally-finalized receipts use the
	// same complete schema.
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

	// Unified terminal policy — identical to Finalize's. A definitive
	// conclusion (COMMITTED or FAILED) must cross the same proof
	// boundary regardless of how the record reached the terminal state.
	// For CRITICAL this means an authenticated signed attestation:
	// COMMITTED requires COMPLETED proof; FAILED requires NO_EFFECT
	// proof — claiming a CRITICAL execution definitively failed without
	// proof could allow a retry of an already-executed side effect.
	var verified *VerifiedEvidence
	if existingRec.ExecutionClass == "CRITICAL" {
		v, verr := s.evidenceVerifier().Verify(ctx, existingRec, receipt, newState)
		if verr != nil {
			return fmt.Errorf("CRITICAL recovery to %s requires a verified signed evidence receipt: %w", decision, verr)
		}
		verified = v
	}
	if err := ValidateTerminalTransition(existingRec, newState, receipt, verified); err != nil {
		return err
	}

	receiptDigest, err := receipt.Digest()
	if err != nil {
		return fmt.Errorf("failed to compute recovery receipt digest: %w", err)
	}

	result2, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = $1, result = $2, evidence_digest = $3, receipt_version = $4,
		    provider_id = $5, provider_run_id = $6,
		    terminal_receipt_digest = $7, evidence_receipt = $10,
		    reconcile_owner = NULL, reconcile_lease_expires_at = NULL,
		    next_reconcile_at = NULL, last_reconcile_error = NULL,
		    recovery_locator = NULL,
		    version = version + 1, updated_at = clock_timestamp()
		WHERE execution_id = $8 AND state = 'UNKNOWN' AND version = $9
	`, string(newState),
		nullableBytes(result.Result),
		nullableString(result.EvidenceDigest),
		result.ReceiptVersion,
		nullableString(result.ProviderID),
		nullableString(result.ProviderRunID),
		receiptDigest,
		executionID, expectedVersion,
		nullableBytes(result.EvidenceReceipt))
	if err != nil {
		return err
	}
	rows, err := result2.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("%w: execution %s recovery resolution CAS failed (state/version mismatch)", LeaseStateConflict, executionID)
	}
	return nil
}

// ─── Reconciliation work distribution ────────────────────────────────
//
// UNKNOWN records need provider-specific resolution. Multiple service
// replicas may run reconciliation workers concurrently. ClaimUnknownBatch
// claims a batch of UNKNOWN records using FOR UPDATE SKIP LOCKED so
// that each record is processed by exactly one worker per claim window.
//
// After claiming, the worker calls the resolver. On resolution, the
// claim fields are cleared by ResolveRecovery. On failure or continued
// UNKNOWN, ReleaseReconcileClaim sets next_reconcile_at with exponential
// backoff and records last_reconcile_error.

// selectColumns is the canonical column list for all record reads.
// It includes the reconciliation work distribution fields.
const selectColumns = `execution_id, idempotency_key, principal_id, capability_id,
	request_digest, COALESCE(grant_id, ''), execution_class, state,
	result, COALESCE(evidence_digest, ''), COALESCE(receipt_version, 0),
	lease_owner, lease_token, lease_started_at, lease_expires_at,
	COALESCE(lease_generation, 1),
	provider_id, provider_run_id, COALESCE(provider_status, ''),
	COALESCE(provider_result_digest, ''), COALESCE(provider_receipt_version, 0),
	provider_observed_at, terminal_receipt_digest, evidence_receipt, recovery_locator,
	COALESCE(attempt, 0), COALESCE(version, 1), created_at, updated_at,
	reconcile_owner, reconcile_lease_expires_at,
	COALESCE(reconcile_attempt, 0), next_reconcile_at, last_reconcile_error`

// selectColumnsER is selectColumns qualified with the `er` alias, for
// use in UPDATE ... FROM ... RETURNING statements where the FROM clause
// makes unqualified column names ambiguous.
const selectColumnsER = `er.execution_id, er.idempotency_key, er.principal_id, er.capability_id,
	er.request_digest, COALESCE(er.grant_id, ''), er.execution_class, er.state,
	er.result, COALESCE(er.evidence_digest, ''), COALESCE(er.receipt_version, 0),
	er.lease_owner, er.lease_token, er.lease_started_at, er.lease_expires_at,
	COALESCE(er.lease_generation, 1),
	er.provider_id, er.provider_run_id, COALESCE(er.provider_status, ''),
	COALESCE(er.provider_result_digest, ''), COALESCE(er.provider_receipt_version, 0),
	er.provider_observed_at, er.terminal_receipt_digest, er.evidence_receipt, er.recovery_locator,
	COALESCE(er.attempt, 0), COALESCE(er.version, 1), er.created_at, er.updated_at,
	er.reconcile_owner, er.reconcile_lease_expires_at,
	COALESCE(er.reconcile_attempt, 0), er.next_reconcile_at, er.last_reconcile_error`

// pgInterval converts a Go duration into a PostgreSQL interval
// expression argument. make_interval(secs => x) accepts arbitrary
// magnitudes — unlike "N microseconds" string casts, which overflow the
// interval field for large durations.
func pgInterval(d time.Duration) float64 {
	return d.Seconds()
}

// ClaimUnknownBatch atomically claims up to batchSize UNKNOWN records
// for reconciliation. Uses FOR UPDATE SKIP LOCKED so that multiple
// concurrent workers do not process the same records.
//
// A record is claimable when:
//   - state = 'UNKNOWN'
//   - No active reconcile claim (owner IS NULL or lease expired)
//   - Not waiting for backoff (next_reconcile_at IS NULL or <= now)
//
// The claim sets reconcile_owner and reconcile_lease_expires_at, and
// increments reconcile_attempt and version. The returned records have
// the updated version — pass it to ResolveRecovery or
// ReleaseReconcileClaim.
func (s *Store) ClaimUnknownBatch(ctx context.Context, owner string, batchSize int, claimDuration time.Duration) ([]*Record, error) {
	if batchSize <= 0 {
		batchSize = 100
	}
	if claimDuration <= 0 {
		claimDuration = 5 * time.Minute
	}
	rows, err := s.db.QueryContext(ctx, `
		WITH claimed AS (
			SELECT execution_id FROM execution_requests
			WHERE state = 'UNKNOWN'
			  AND (reconcile_owner IS NULL
			       OR reconcile_lease_expires_at < clock_timestamp())
			  AND (next_reconcile_at IS NULL
			       OR next_reconcile_at <= clock_timestamp())
			ORDER BY updated_at
			LIMIT $3
			FOR UPDATE SKIP LOCKED
		)
		UPDATE execution_requests er
		SET reconcile_owner = $1,
		    reconcile_lease_expires_at = clock_timestamp() + make_interval(secs => $2),
		    reconcile_attempt = er.reconcile_attempt + 1,
		    version = er.version + 1,
		    updated_at = clock_timestamp()
		FROM claimed
		WHERE er.execution_id = claimed.execution_id
		RETURNING `+selectColumnsER,
		owner,
		pgInterval(claimDuration),
		batchSize,
	)
	if err != nil {
		return nil, fmt.Errorf("claim unknown batch failed: %w", err)
	}
	return scanRecordsWithReconcile(rows)
}

// ReleaseReconcileClaim releases a claimed record back to the
// reconciliation/expired-lease pool. The caller provides a backoff
// duration — the database computes next_reconcile_at using
// clock_timestamp() so scheduling time is DB-owned, not
// app-clock-dependent. This prevents replicas with skewed clocks
// from distorting retry timing.
//
// The claim fields (reconcile_owner, reconcile_lease_expires_at)
// are cleared regardless of record state — this method works for
// both UNKNOWN resolution claims and expired-lease crash claims.
//
// Uses CAS on version to prevent releasing a claim that was already
// superseded.
func (s *Store) ReleaseReconcileClaim(ctx context.Context, executionID string, expectedVersion int, backoffDuration time.Duration, lastError string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET reconcile_owner = NULL,
		    reconcile_lease_expires_at = NULL,
		    next_reconcile_at = CASE
		        WHEN state = 'UNKNOWN' AND make_interval(secs => $1) > '0'::interval
		            THEN clock_timestamp() + make_interval(secs => $1)
		        ELSE NULL
		    END,
		    last_reconcile_error = $2,
		    version = version + 1,
		    updated_at = clock_timestamp()
		WHERE execution_id = $3
		  AND version = $4
	`, pgInterval(backoffDuration),
		nullableString(lastError), executionID, expectedVersion)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("%w: execution %s release reconcile claim CAS failed (state/version mismatch)", LeaseStateConflict, executionID)
	}
	return nil
}

// RenewReconcileClaim extends an active reconciliation claim. This is
// the reconciliation equivalent of RenewLease — a long-running resolver
// can renew its claim to prevent another worker from reclaiming the
// same UNKNOWN record.
//
// The claim is extended to GREATEST(current, clock_timestamp() +
// duration) so renewal cannot shorten an existing claim.
func (s *Store) RenewReconcileClaim(ctx context.Context, executionID string, expectedVersion int, duration time.Duration) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET reconcile_lease_expires_at = GREATEST(
		        reconcile_lease_expires_at,
		        clock_timestamp() + make_interval(secs => $1)),
		    updated_at = clock_timestamp()
		WHERE execution_id = $2
		  AND state = 'UNKNOWN'
		  AND version = $3
		  AND reconcile_lease_expires_at > clock_timestamp()
	`, pgInterval(duration),
		executionID, expectedVersion)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("%w: execution %s renew reconcile claim failed (expired or version mismatch)", LeaseStateConflict, executionID)
	}
	return nil
}

// ClaimExpiredBatch atomically claims a batch of PREPARED/EXECUTING/
// IN_FLIGHT records whose execution leases have expired. Uses
// FOR UPDATE SKIP LOCKED so multiple workers do not process the
// same expired records.
//
// Unlike ClaimUnknownBatch (which claims for resolution), this
// claims for crash recovery — the caller inspects each record's
// state to decide whether it needs reconciliation or simple
// re-dispatch.
//
// The claim uses the reconcile_owner/reconcile_lease_expires_at
// fields (shared with UNKNOWN claiming) to avoid adding yet
// another claim namespace.
func (s *Store) ClaimExpiredBatch(ctx context.Context, owner string, batchSize int, claimDuration time.Duration) ([]*Record, error) {
	if batchSize <= 0 {
		batchSize = 100
	}
	if claimDuration <= 0 {
		claimDuration = 5 * time.Minute
	}
	rows, err := s.db.QueryContext(ctx, `
		WITH claimed AS (
			SELECT execution_id FROM execution_requests
			WHERE state IN ('PREPARED', 'EXECUTING', 'IN_FLIGHT')
			  AND lease_expires_at IS NOT NULL
			  AND lease_expires_at < clock_timestamp()
			  AND (reconcile_owner IS NULL
			       OR reconcile_lease_expires_at < clock_timestamp())
			ORDER BY updated_at
			LIMIT $3
			FOR UPDATE SKIP LOCKED
		)
		UPDATE execution_requests er
		SET reconcile_owner = $1,
		    reconcile_lease_expires_at = clock_timestamp() + make_interval(secs => $2),
		    version = er.version + 1,
		    updated_at = clock_timestamp()
		FROM claimed
		WHERE er.execution_id = claimed.execution_id
		RETURNING `+selectColumnsER,
		owner,
		pgInterval(claimDuration),
		batchSize,
	)
	if err != nil {
		return nil, fmt.Errorf("claim expired batch failed: %w", err)
	}
	return scanRecordsWithReconcile(rows)
}

// ─── Lookup ─────────────────────────────────────────────────────────

// Lookup retrieves a record by execution ID.
func (s *Store) Lookup(ctx context.Context, executionID string) (*Record, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+selectColumns+` FROM execution_requests WHERE execution_id = $1`,
		executionID)
	if err != nil {
		return nil, err
	}
	recs, err := scanRecordsWithReconcile(rows)
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return nil, sql.ErrNoRows
	}
	return recs[0], nil
}

// LookupByKey retrieves a record by idempotency key.
func (s *Store) LookupByKey(ctx context.Context, principal, capability, key string) (*Record, error) {
	return s.lookupByKey(ctx, principal, capability, key)
}

func (s *Store) lookupByKey(ctx context.Context, principal, capability, key string) (*Record, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+selectColumns+` FROM execution_requests
		 WHERE principal_id = $1 AND capability_id = $2 AND idempotency_key = $3`,
		principal, capability, key)
	if err != nil {
		return nil, err
	}
	recs, err := scanRecordsWithReconcile(rows)
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
func (s *Store) ListUnknown(ctx context.Context) ([]*Record, error) {
	return s.listByStates(ctx, []State{StateUnknown})
}

// ListExpiredLeases returns all PREPARED/EXECUTING/IN_FLIGHT records
// whose lease has expired. These need recovery.
func (s *Store) ListExpiredLeases(ctx context.Context) ([]*Record, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+selectColumns+` FROM execution_requests
		 WHERE state IN ('PREPARED', 'EXECUTING', 'IN_FLIGHT')
		   AND lease_expires_at IS NOT NULL
		   AND lease_expires_at < clock_timestamp()
		 ORDER BY updated_at`)
	if err != nil {
		return nil, err
	}
	return scanRecordsWithReconcile(rows)
}

// ListStuck returns all records needing attention: UNKNOWN or
// expired-lease stuck in PREPARED/EXECUTING/IN_FLIGHT.
func (s *Store) ListStuck(ctx context.Context) ([]*Record, error) {
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

func (s *Store) listByStates(ctx context.Context, states []State) ([]*Record, error) {
	placeholders := ""
	args := make([]any, len(states))
	for i, st := range states {
		if i > 0 {
			placeholders += ","
		}
		placeholders += fmt.Sprintf("$%d", i+1)
		args[i] = string(st)
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT `+selectColumns+` FROM execution_requests
		 WHERE state IN (`+placeholders+`) ORDER BY updated_at`, args...)
	if err != nil {
		return nil, err
	}
	return scanRecordsWithReconcile(rows)
}

func scanRecordsWithReconcile(rows *sql.Rows) ([]*Record, error) {
	defer rows.Close()

	var records []*Record
	for rows.Next() {
		var rec Record
		var resultJSON []byte
		var leaseOwner, leaseToken, providerID, providerRunID, terminalDigest sql.NullString
		var providerStatus, providerResultDigest string
		var providerObservedAt sql.NullTime
		var evidenceReceipt, recoveryLocator []byte
		var leaseStartedAt, leaseExpiresAt sql.NullTime
		var recOwner, lastRecErr sql.NullString
		var recLeaseExp, nextRecAt sql.NullTime
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
			&rec.Attempt, &rec.Version, &rec.CreatedAt, &rec.UpdatedAt,
			&recOwner, &recLeaseExp, &rec.ReconcileAttempt, &nextRecAt, &lastRecErr,
		); err != nil {
			return nil, err
		}
		rec.ProviderStatus = providerStatus
		rec.ProviderResultDigest = providerResultDigest
		if providerObservedAt.Valid {
			t := providerObservedAt.Time
			rec.ProviderObservedAt = &t
		}
		rec.Result = json.RawMessage(resultJSON)
		if leaseOwner.Valid {
			rec.LeaseOwner = leaseOwner.String
		}
		if leaseToken.Valid {
			rec.LeaseToken = leaseToken.String
		}
		if leaseStartedAt.Valid {
			t := leaseStartedAt.Time
			rec.LeaseStartedAt = &t
		}
		if leaseExpiresAt.Valid {
			t := leaseExpiresAt.Time
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
			t := recLeaseExp.Time
			rec.ReconcileLeaseExpiresAt = &t
		}
		if nextRecAt.Valid {
			t := nextRecAt.Time
			rec.NextReconcileAt = &t
		}
		if lastRecErr.Valid {
			rec.LastReconcileError = lastRecErr.String
		}
		records = append(records, &rec)
	}
	return records, rows.Err()
}

// DefaultLeaseDuration is the default lease duration for new reservations.
const DefaultLeaseDuration = 5 * time.Minute

// migrateState maps legacy state names to the new vocabulary.
// Used only by migrateStateNames for database migration of existing rows.
func migrateState(s State) State {
	switch s {
	case "RESERVED":
		return StatePrepared
	case "DISPATCHING":
		return StateExecuting
	case "SUCCEEDED":
		return StateCommitted
	case "RECONCILIATION_REQUIRED":
		return StateUnknown
	default:
		return s
	}
}

// LeaseConfig returns the store's lease configuration.
// Used by DispatchExecutor to derive heartbeat parameters.
func (s *Store) LeaseConfig() LeaseConfig {
	return s.leaseCfg
}

// ─── Helpers ────────────────────────────────────────────────────────

func currentPID() int {
	return osGetpid()
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
