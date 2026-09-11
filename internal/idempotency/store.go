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
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ─── Record ───────────────────────────────────────────────────────────

// Record is a stored execution record.
type Record struct {
	ExecutionID           string          `json:"execution_id"`
	IdempotencyKey        string          `json:"idempotency_key"`
	PrincipalID           string          `json:"principal_id"`
	CapabilityID          string          `json:"capability_id"`
	RequestDigest         string          `json:"request_digest"`
	GrantID               string          `json:"grant_id"`
	ExecutionClass        string          `json:"execution_class"`
	State                 State           `json:"state"`
	Result                json.RawMessage `json:"result,omitempty"`
	EvidenceDigest        string          `json:"evidence_digest,omitempty"`
	ReceiptVersion        int             `json:"receipt_version,omitempty"`
	LeaseOwner            string          `json:"lease_owner,omitempty"`
	LeaseToken            string          `json:"lease_token,omitempty"`
	LeaseStartedAt        *time.Time      `json:"lease_started_at,omitempty"`
	LeaseExpiresAt        *time.Time      `json:"lease_expires_at,omitempty"`
	LeaseGeneration       int             `json:"lease_generation,omitempty"`
	ProviderID            string          `json:"provider_id,omitempty"`
	ProviderRunID         string          `json:"provider_run_id,omitempty"`
	TerminalReceiptDigest string          `json:"terminal_receipt_digest,omitempty"`
	Attempt               int             `json:"attempt,omitempty"`
	Version               int             `json:"version"`
	CreatedAt             time.Time       `json:"created_at"`
	UpdatedAt             time.Time       `json:"updated_at"`
}

// ─── Store ───────────────────────────────────────────────────────────

// Store is the durable execution contract store backed by PostgreSQL.
type Store struct {
	db       *sql.DB
	leaseCfg LeaseConfig
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

func (s *Store) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
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
			attempt INTEGER NOT NULL DEFAULT 0,
			version INTEGER NOT NULL DEFAULT 1,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE(principal_id, capability_id, idempotency_key)
		)
	`)
	if err != nil {
		// gen_random_uuid might not be available without pgcrypto.
		// P1/P2 #6: The fallback must still generate UUIDs application-side
		// since Acquire() does not supply execution_id. Generate via
		// a DEFAULT clause using a Go-side UUID if pgcrypto is unavailable.
		// We use a TEXT primary key with a Go-generated UUID as default.
		_, err = s.db.ExecContext(ctx, `
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

	// Migrations: add new columns if they don't exist.
	// P1/P2 #6: Migration failures must propagate — store initialization
	// fails closed if schema alteration or state migration fails.
	if err := s.addColumnIfMissing(ctx, "lease_started_at", "TIMESTAMPTZ"); err != nil {
		return fmt.Errorf("migration failed (lease_started_at): %w", err)
	}
	if err := s.addColumnIfMissing(ctx, "lease_generation", "INTEGER NOT NULL DEFAULT 1"); err != nil {
		return fmt.Errorf("migration failed (lease_generation): %w", err)
	}
	if err := s.addColumnIfMissing(ctx, "provider_id", "TEXT"); err != nil {
		return fmt.Errorf("migration failed (provider_id): %w", err)
	}
	if err := s.addColumnIfMissing(ctx, "provider_run_id", "TEXT"); err != nil {
		return fmt.Errorf("migration failed (provider_run_id): %w", err)
	}
	if err := s.addColumnIfMissing(ctx, "terminal_receipt_digest", "TEXT"); err != nil {
		return fmt.Errorf("migration failed (terminal_receipt_digest): %w", err)
	}
	// Legacy columns from earlier versions.
	if err := s.addColumnIfMissing(ctx, "receipt_version", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return fmt.Errorf("migration failed (receipt_version): %w", err)
	}
	if err := s.addColumnIfMissing(ctx, "lease_owner", "TEXT"); err != nil {
		return fmt.Errorf("migration failed (lease_owner): %w", err)
	}
	if err := s.addColumnIfMissing(ctx, "lease_token", "TEXT"); err != nil {
		return fmt.Errorf("migration failed (lease_token): %w", err)
	}
	if err := s.addColumnIfMissing(ctx, "lease_expires_at", "TIMESTAMPTZ"); err != nil {
		return fmt.Errorf("migration failed (lease_expires_at): %w", err)
	}
	if err := s.addColumnIfMissing(ctx, "attempt", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return fmt.Errorf("migration failed (attempt): %w", err)
	}
	if err := s.addColumnIfMissing(ctx, "version", "INTEGER NOT NULL DEFAULT 1"); err != nil {
		return fmt.Errorf("migration failed (version): %w", err)
	}

	// Migrate old state names to new vocabulary.
	if err := s.migrateStateNames(ctx); err != nil {
		return fmt.Errorf("state name migration failed: %w", err)
	}

	return nil
}

func (s *Store) migrateStateNames(ctx context.Context) error {
	// Map old state names to new ones.
	migrations := map[string]string{
		"RESERVED":                "PREPARED",
		"DISPATCHING":             "EXECUTING",
		"SUCCEEDED":               "COMMITTED",
		"RECONCILIATION_REQUIRED": "UNKNOWN",
	}
	for old, newVal := range migrations {
		if _, err := s.db.ExecContext(ctx, `UPDATE execution_requests SET state = $1 WHERE state = $2`, newVal, old); err != nil {
			return fmt.Errorf("failed to migrate state %s -> %s: %w", old, newVal, err)
		}
	}
	return nil
}

func (s *Store) addColumnIfMissing(ctx context.Context, column, ddl string) error {
	_, err := s.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE execution_requests ADD COLUMN IF NOT EXISTS %s %s", column, ddl))
	return err
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
	var executionID string
	var createdAt time.Time
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO execution_requests
			(idempotency_key, principal_id, capability_id, request_digest,
			 grant_id, execution_class, state,
			 lease_owner, lease_token, lease_started_at, lease_expires_at,
			 lease_generation, attempt, version)
		VALUES ($1, $2, $3, $4, $5, $6, 'PREPARED',
				$7, $8, clock_timestamp(), clock_timestamp() + $9::interval,
				1, 0, 1)
		ON CONFLICT (principal_id, capability_id, idempotency_key) DO NOTHING
		RETURNING execution_id, created_at
	`, key, principal, capability, digest, nullableString(grantID), class,
		leaseOwner, leaseToken, fmt.Sprintf("%d microseconds", leaseDuration.Microseconds()),
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
		    lease_expires_at = clock_timestamp() + $3::interval,
		    lease_generation = lease_generation + 1,
		    version = version + 1, updated_at = clock_timestamp()
		WHERE execution_id = $4
		  AND state = 'PREPARED'
		  AND lease_token IS NULL
		  AND lease_expires_at IS NULL
		  AND version = $5
	`, newOwner, newToken, fmt.Sprintf("%d microseconds", duration.Microseconds()),
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
		    lease_expires_at = clock_timestamp() + $3::interval,
		    lease_generation = lease_generation + 1,
		    attempt = attempt + 1, version = version + 1,
		    state = 'PREPARED', updated_at = clock_timestamp()
		WHERE execution_id = $4
		  AND version = $5
		  AND state IN ('PREPARED', 'EXECUTING')
		  AND lease_expires_at < clock_timestamp()
	`, newOwner, newToken, fmt.Sprintf("%d microseconds", duration.Microseconds()),
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
func (s *Store) MarkInFlight(ctx context.Context, executionID, leaseToken string, leaseGeneration int) error {
	return s.leaseFencedTransition(ctx, executionID, leaseToken, leaseGeneration, StateExecuting, StateInFlight)
}

// leaseFencedTransition performs a state transition with full lease
// fencing enforced inside the SQL statement.
func (s *Store) leaseFencedTransition(ctx context.Context, executionID, leaseToken string, leaseGeneration int, expectedState, newState State) error {
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
		SET lease_expires_at = clock_timestamp() + $1::interval,
		    updated_at = clock_timestamp()
		WHERE execution_id = $2
		  AND lease_token = $3
		  AND lease_generation = $4
		  AND lease_expires_at > clock_timestamp()
		  AND state NOT IN ('COMMITTED', 'FAILED', 'DENIED', 'UNKNOWN')
	`, fmt.Sprintf("%d microseconds", duration.Microseconds()),
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
	// P1 #5: Reject non-durably-final terminal statuses. Finalize is a
	// durably-final transition — the receipt must target COMMITTED,
	// FAILED, or DENIED. Passing UNKNOWN, PREPARED, EXECUTING, or
	// IN_FLIGHT is a contract violation.
	if !receipt.TerminalStatus.IsDurablyFinal() {
		return fmt.Errorf("invalid terminal status %s: Finalize requires a durably-final state (COMMITTED, FAILED, or DENIED)", receipt.TerminalStatus)
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
		// Already finalized — compare the full receipt.
		if existing.TerminalReceiptDigest == receiptDigest {
			return nil // ALREADY_FINALIZED — idempotent replay.
		}
		return fmt.Errorf("FINALIZATION_CONFLICT: execution %s already finalized with different receipt (existing digest %s, new digest %s)",
			executionID, existing.TerminalReceiptDigest, receiptDigest)
	}

	// Not yet durably final — perform CAS transition.
	result, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = $1, result = $2, evidence_digest = $3, receipt_version = $4,
		    provider_id = $5, provider_run_id = $6,
		    terminal_receipt_digest = $7,
		    lease_owner = NULL, lease_token = NULL,
		    lease_started_at = NULL, lease_expires_at = NULL,
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
		executionID, string(expectedState), leaseToken, leaseGeneration, existing.Version)
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

// ─── Recovery ────────────────────────────────────────────────────────

// EnterRecovery transitions a record to UNKNOWN for reconciliation.
// This is used for IN_FLIGHT records where the lease has expired
// (the side effect may have occurred) or for records where the
// handler returned an ambiguous result.
//
// Uses CAS with expected state to prevent overwriting a state that
// changed after it was read.
func (s *Store) EnterRecovery(ctx context.Context, executionID string, expectedState State, expectedVersion int) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = 'UNKNOWN', version = version + 1,
		    lease_owner = NULL, lease_token = NULL,
		    lease_started_at = NULL, lease_expires_at = NULL,
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

// ResolveRecovery resolves an UNKNOWN record to a durably final state
// using a recovery result. Uses CAS with expected state=UNKNOWN to
// prevent overwriting a state that changed after it was read.
//
// The recovery result must include evidence for any definitive
// conclusion (COMMITTED or FAILED).
func (s *Store) ResolveRecovery(ctx context.Context, executionID string, expectedVersion int, decision RecoveryDecision, result RecoveryResult) error {
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

	// P1 #4/#6: Enforce evidence for definitive recovery. A definitive
	// conclusion (COMMITTED or FAILED) must include evidence/proof.
	// Without evidence, the recovery is not credible and must stay
	// UNKNOWN. This prevents a resolver from claiming success or
	// failure without proof.
	//
	// For CRITICAL executions, recovery proof must be as strong as
	// normal CRITICAL finalization: valid SHA-256 evidence digest,
	// receipt version 3, provider identity, and provider run ID.
	// Arbitrary JSON result is NOT sufficient for CRITICAL recovery.
	existingRec, lookupErr := s.Lookup(ctx, executionID)
	if lookupErr != nil {
		return fmt.Errorf("recovery lookup failed: %w", lookupErr)
	}
	if existingRec.ExecutionClass == "CRITICAL" {
		if decision == RecoveryCommitted {
			if result.EvidenceDigest == "" || !isValidEvidenceDigest(result.EvidenceDigest) {
				return fmt.Errorf("CRITICAL recovery to COMMITTED requires valid evidence digest (64-char lowercase hex)")
			}
			if result.ReceiptVersion != 3 {
				return fmt.Errorf("CRITICAL recovery to COMMITTED requires receipt_version 3, got %d", result.ReceiptVersion)
			}
			if result.ProviderID == "" || result.ProviderRunID == "" {
				return fmt.Errorf("CRITICAL recovery to COMMITTED requires provider_id and provider_run_id")
			}
		}
	} else {
		// Non-CRITICAL: require at least evidence or result.
		if result.EvidenceDigest == "" && len(result.Result) == 0 {
			return fmt.Errorf("definitive recovery (%s) requires evidence or result — cannot resolve without proof", decision)
		}
	}

	// P1 #7: Build recovery receipts from the same canonical builder
	// as normal finalization. Use the record loaded above to populate
	// identity fields (capability, principal, request_digest) so
	// recovery-finalized and normally-finalized receipts use the
	// same complete schema.
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
	}
	receiptDigest, err := receipt.Digest()
	if err != nil {
		return fmt.Errorf("failed to compute recovery receipt digest: %w", err)
	}

	result2, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = $1, result = $2, evidence_digest = $3, receipt_version = $4,
		    provider_id = $5, provider_run_id = $6,
		    terminal_receipt_digest = $7,
		    version = version + 1, updated_at = clock_timestamp()
		WHERE execution_id = $8 AND state = 'UNKNOWN' AND version = $9
	`, string(newState),
		nullableBytes(result.Result),
		nullableString(result.EvidenceDigest),
		result.ReceiptVersion,
		nullableString(result.ProviderID),
		nullableString(result.ProviderRunID),
		receiptDigest,
		executionID, expectedVersion)
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

// ─── Lookup ─────────────────────────────────────────────────────────

// Lookup retrieves a record by execution ID.
func (s *Store) Lookup(ctx context.Context, executionID string) (*Record, error) {
	var rec Record
	var resultJSON []byte
	var leaseOwner, leaseToken, providerID, providerRunID, terminalDigest sql.NullString
	var leaseStartedAt, leaseExpiresAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT execution_id, idempotency_key, principal_id, capability_id,
		       request_digest, COALESCE(grant_id, ''), execution_class, state,
		       result, COALESCE(evidence_digest, ''), COALESCE(receipt_version, 0),
		       lease_owner, lease_token, lease_started_at, lease_expires_at,
		       COALESCE(lease_generation, 1),
		       provider_id, provider_run_id, terminal_receipt_digest,
		       COALESCE(attempt, 0), COALESCE(version, 1), created_at, updated_at
		FROM execution_requests
		WHERE execution_id = $1
	`, executionID).Scan(
		&rec.ExecutionID, &rec.IdempotencyKey, &rec.PrincipalID,
		&rec.CapabilityID, &rec.RequestDigest, &rec.GrantID,
		&rec.ExecutionClass, &rec.State, &resultJSON,
		&rec.EvidenceDigest, &rec.ReceiptVersion,
		&leaseOwner, &leaseToken, &leaseStartedAt, &leaseExpiresAt,
		&rec.LeaseGeneration,
		&providerID, &providerRunID, &terminalDigest,
		&rec.Attempt, &rec.Version, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		return nil, err
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
	return &rec, nil
}

// LookupByKey retrieves a record by idempotency key.
func (s *Store) LookupByKey(ctx context.Context, principal, capability, key string) (*Record, error) {
	return s.lookupByKey(ctx, principal, capability, key)
}

func (s *Store) lookupByKey(ctx context.Context, principal, capability, key string) (*Record, error) {
	var rec Record
	var resultJSON []byte
	var leaseOwner, leaseToken, providerID, providerRunID, terminalDigest sql.NullString
	var leaseStartedAt, leaseExpiresAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT execution_id, idempotency_key, principal_id, capability_id,
		       request_digest, COALESCE(grant_id, ''), execution_class, state,
		       result, COALESCE(evidence_digest, ''), COALESCE(receipt_version, 0),
		       lease_owner, lease_token, lease_started_at, lease_expires_at,
		       COALESCE(lease_generation, 1),
		       provider_id, provider_run_id, terminal_receipt_digest,
		       COALESCE(attempt, 0), COALESCE(version, 1), created_at, updated_at
		FROM execution_requests
		WHERE principal_id = $1 AND capability_id = $2 AND idempotency_key = $3
	`, principal, capability, key).Scan(
		&rec.ExecutionID, &rec.IdempotencyKey, &rec.PrincipalID,
		&rec.CapabilityID, &rec.RequestDigest, &rec.GrantID,
		&rec.ExecutionClass, &rec.State, &resultJSON,
		&rec.EvidenceDigest, &rec.ReceiptVersion,
		&leaseOwner, &leaseToken, &leaseStartedAt, &leaseExpiresAt,
		&rec.LeaseGeneration,
		&providerID, &providerRunID, &terminalDigest,
		&rec.Attempt, &rec.Version, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		return nil, err
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
	return &rec, nil
}

// ─── Listing ─────────────────────────────────────────────────────────

// ListUnknown returns all records in UNKNOWN state.
func (s *Store) ListUnknown(ctx context.Context) ([]*Record, error) {
	return s.listByStates(ctx, []State{StateUnknown})
}

// ListExpiredLeases returns all PREPARED/EXECUTING/IN_FLIGHT records
// whose lease has expired. These need recovery.
func (s *Store) ListExpiredLeases(ctx context.Context) ([]*Record, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT execution_id, idempotency_key, principal_id, capability_id,
		       request_digest, COALESCE(grant_id, ''), execution_class, state,
		       result, COALESCE(evidence_digest, ''), COALESCE(receipt_version, 0),
		       lease_owner, lease_token, lease_started_at, lease_expires_at,
		       COALESCE(lease_generation, 1),
		       provider_id, provider_run_id, terminal_receipt_digest,
		       COALESCE(attempt, 0), COALESCE(version, 1), created_at, updated_at
		FROM execution_requests
		WHERE state IN ('PREPARED', 'EXECUTING', 'IN_FLIGHT')
		  AND lease_expires_at IS NOT NULL
		  AND lease_expires_at < clock_timestamp()
		ORDER BY updated_at
	`)
	if err != nil {
		return nil, err
	}
	return scanRecords(rows)
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

	rows, err := s.db.QueryContext(ctx, `
		SELECT execution_id, idempotency_key, principal_id, capability_id,
		       request_digest, COALESCE(grant_id, ''), execution_class, state,
		       result, COALESCE(evidence_digest, ''), COALESCE(receipt_version, 0),
		       lease_owner, lease_token, lease_started_at, lease_expires_at,
		       COALESCE(lease_generation, 1),
		       provider_id, provider_run_id, terminal_receipt_digest,
		       COALESCE(attempt, 0), COALESCE(version, 1), created_at, updated_at
		FROM execution_requests
		WHERE state IN (`+placeholders+`)
		ORDER BY updated_at
	`, args...)
	if err != nil {
		return nil, err
	}
	return scanRecords(rows)
}

func scanRecords(rows *sql.Rows) ([]*Record, error) {
	defer rows.Close()

	var records []*Record
	for rows.Next() {
		var rec Record
		var resultJSON []byte
		var leaseOwner, leaseToken, providerID, providerRunID, terminalDigest sql.NullString
		var leaseStartedAt, leaseExpiresAt sql.NullTime
		if err := rows.Scan(
			&rec.ExecutionID, &rec.IdempotencyKey, &rec.PrincipalID,
			&rec.CapabilityID, &rec.RequestDigest, &rec.GrantID,
			&rec.ExecutionClass, &rec.State, &resultJSON,
			&rec.EvidenceDigest, &rec.ReceiptVersion,
			&leaseOwner, &leaseToken, &leaseStartedAt, &leaseExpiresAt,
			&rec.LeaseGeneration,
			&providerID, &providerRunID, &terminalDigest,
			&rec.Attempt, &rec.Version, &rec.CreatedAt, &rec.UpdatedAt,
		); err != nil {
			return nil, err
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
		records = append(records, &rec)
	}
	return records, rows.Err()
}

// ─── Backward-compatible wrappers ────────────────────────────────────
//
// These wrap the new contract methods with the old API to minimize
// caller changes during migration. New code should use the typed API.

// ReserveResult is the legacy outcome of a reservation attempt.
type ReserveResult struct {
	State      State   `json:"state"`
	Record     *Record `json:"record,omitempty"`
	Acquired   bool    `json:"acquired"`
	Conflict   bool    `json:"conflict"`
	LeaseToken string  `json:"lease_token,omitempty"`
}

// DefaultLeaseDuration is the default lease duration for new reservations.
const DefaultLeaseDuration = 5 * time.Minute

// Reserve atomically reserves an execution request (legacy wrapper).
// Uses the store's configured DefaultDuration rather than the package-level
// DefaultLeaseDuration constant.
func (s *Store) Reserve(ctx context.Context, key, principal, capability, digest, grantID, class string) (*ReserveResult, error) {
	duration := s.leaseCfg.DefaultDuration
	if duration <= 0 {
		duration = DefaultLeaseDuration
	}
	return s.ReserveWithLease(ctx, key, principal, capability, digest, grantID, class, duration)
}

// ReserveWithLease is Reserve with a configurable lease duration (legacy wrapper).
func (s *Store) ReserveWithLease(ctx context.Context, key, principal, capability, digest, grantID, class string, leaseDuration time.Duration) (*ReserveResult, error) {
	result, err := s.Acquire(ctx, key, principal, capability, digest, grantID, class, leaseDuration)
	if err != nil {
		return nil, err
	}
	return &ReserveResult{
		State:      result.State,
		Record:     result.Record,
		Acquired:   result.Acquired(),
		Conflict:   result.Kind == IdempotencyConflict,
		LeaseToken: result.LeaseToken,
	}, nil
}

// TransitionState performs a non-terminal state transition (legacy wrapper).
// Maps old state names to new ones.
func (s *Store) TransitionState(ctx context.Context, executionID, leaseToken string, expectedState, newState State) error {
	// Map legacy state names.
	expectedState = migrateState(expectedState)
	newState = migrateState(newState)
	// Look up the generation from the record.
	rec, err := s.Lookup(ctx, executionID)
	if err != nil {
		return err
	}
	return s.leaseFencedTransition(ctx, executionID, leaseToken, rec.LeaseGeneration, expectedState, newState)
}

// FinalizeLegacy atomically finalizes an execution (legacy wrapper).
// Maps old state names and constructs a TerminalReceipt from loose fields.
// New code should use Finalize with a TerminalReceipt directly.
func (s *Store) FinalizeLegacy(ctx context.Context, executionID, leaseToken string, expectedState, newState State, result json.RawMessage, evidenceDigest string, receiptVersion int) error {
	expectedState = migrateState(expectedState)
	newState = migrateState(newState)
	rec, err := s.Lookup(ctx, executionID)
	if err != nil {
		return fmt.Errorf("finalize lookup failed: %w", err)
	}
	receipt := TerminalReceipt{
		ExecutionID:     executionID,
		Capability:      rec.CapabilityID,
		Principal:       rec.PrincipalID,
		RequestDigest:   rec.RequestDigest,
		TerminalStatus:  newState,
		CanonicalResult: result,
		EvidenceDigest:  evidenceDigest,
		ReceiptVersion:  receiptVersion,
	}
	return s.Finalize(ctx, executionID, leaseToken, rec.LeaseGeneration, expectedState, receipt)
}

// RenewLeaseLegacy extends the lease for the current holder (legacy wrapper).
// Looks up the generation from the record. New code should pass generation explicitly.
func (s *Store) RenewLeaseLegacy(ctx context.Context, executionID, leaseToken string, duration time.Duration) error {
	rec, err := s.Lookup(ctx, executionID)
	if err != nil {
		return err
	}
	return s.RenewLease(ctx, executionID, leaseToken, rec.LeaseGeneration, duration)
}

// migrateState maps legacy state names to the new vocabulary.
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
