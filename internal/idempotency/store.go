// Package idempotency provides durable idempotency storage for the
// Crabedence execution service.
//
// Idempotency lives below the NEMO process — in Crabedence itself.
// This ensures that a process crash does not cause re-invocation,
// and that concurrent identical requests converge on one execution.
//
// The store implements a lease-based lifecycle contract:
//
//		reserve (atomic INSERT)
//		    │
//		    ▼
//		 PREPARED + lease acquired
//		    │
//		    ▼
//		 EXECUTING (lease held)
//		    │
//		┌───┼───┐
//		▼   ▼   ▼
//	 COMMITTED / FAILED / UNKNOWN
//
// Only the lease owner may transition state. Lease expiry allows
// recovery of crashed executions without duplicate dispatch.
package idempotency

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// State represents the lifecycle state of an execution request.
type State string

const (
	// StateReserved means the request has been reserved but not yet dispatched.
	// The caller that performed the INSERT owns the reservation.
	StateReserved State = "RESERVED"

	// StateDispatching means the request is being dispatched to the provider.
	// The lease holder is actively executing.
	StateDispatching State = "DISPATCHING"

	// StateInFlight means the provider has accepted the request.
	StateInFlight State = "IN_FLIGHT"

	// StateSucceeded means the provider returned a definitive success.
	StateSucceeded State = "SUCCEEDED"

	// StateFailed means the provider returned a definitive failure.
	StateFailed State = "FAILED"

	// StateDenied means admission denied the request before dispatch.
	StateDenied State = "DENIED"

	// StateUnknown means the provider may have executed but the terminal
	// outcome cannot be established.
	StateUnknown State = "UNKNOWN"

	// StateReconciliationRequired means the request needs reconciliation.
	StateReconciliationRequired State = "RECONCILIATION_REQUIRED"
)

// IsTerminal returns true if the state is terminal (no further transitions).
func (s State) IsTerminal() bool {
	switch s {
	case StateSucceeded, StateFailed, StateDenied, StateUnknown:
		return true
	}
	return false
}

// Record is a stored idempotency record.
type Record struct {
	ExecutionID    string          `json:"execution_id"`
	IdempotencyKey string          `json:"idempotency_key"`
	PrincipalID    string          `json:"principal_id"`
	CapabilityID   string          `json:"capability_id"`
	RequestDigest  string          `json:"request_digest"`
	GrantID        string          `json:"grant_id"`
	ExecutionClass string          `json:"execution_class"`
	State          State           `json:"state"`
	Result         json.RawMessage `json:"result,omitempty"`
	EvidenceDigest string          `json:"evidence_digest,omitempty"`
	ReceiptVersion int             `json:"receipt_version,omitempty"`
	LeaseOwner     string          `json:"lease_owner,omitempty"`
	LeaseToken     string          `json:"lease_token,omitempty"`
	LeaseExpiresAt *time.Time      `json:"lease_expires_at,omitempty"`
	Attempt        int             `json:"attempt,omitempty"`
	Version        int             `json:"version"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

// ReserveResult is the outcome of a reservation attempt.
type ReserveResult struct {
	// State is the current state of the record.
	State State `json:"state"`

	// Record is the existing record if found, or nil if newly reserved.
	Record *Record `json:"record,omitempty"`

	// Acquired is true if THIS caller created the reservation and may dispatch.
	// Only Acquired == true callers may proceed to dispatch.
	// Acquired == false means another caller owns the reservation
	// or the record already exists in some state.
	Acquired bool `json:"acquired"`

	// Conflict is true if the same key was used with a different request.
	Conflict bool `json:"conflict"`

	// LeaseToken is the ownership token for the new reservation.
	// Only valid when Acquired is true.
	LeaseToken string `json:"lease_token,omitempty"`
}

// Store is the durable idempotency store backed by PostgreSQL.
type Store struct {
	db *sql.DB
}

// NewStore creates a new durable idempotency store.
func NewStore(db *sql.DB) (*Store, error) {
	store := &Store{db: db}
	if err := store.ensureSchema(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to ensure schema: %w", err)
	}
	return store, nil
}

// ensureSchema creates the execution_requests table if it doesn't exist.
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
			lease_expires_at TIMESTAMPTZ,
			attempt INTEGER NOT NULL DEFAULT 0,
			version INTEGER NOT NULL DEFAULT 1,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE(principal_id, capability_id, idempotency_key)
		)
	`)
	if err != nil {
		// gen_random_uuid might not be available without pgcrypto
		_, err = s.db.ExecContext(ctx, `
			CREATE TABLE IF NOT EXISTS execution_requests (
				execution_id UUID PRIMARY KEY,
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
				lease_expires_at TIMESTAMPTZ,
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

	// Migration: add lease columns if they don't exist (for existing tables).
	s.addColumnIfMissing(ctx, "receipt_version", "INTEGER NOT NULL DEFAULT 0")
	s.addColumnIfMissing(ctx, "lease_owner", "TEXT")
	s.addColumnIfMissing(ctx, "lease_token", "TEXT")
	s.addColumnIfMissing(ctx, "lease_expires_at", "TIMESTAMPTZ")
	s.addColumnIfMissing(ctx, "attempt", "INTEGER NOT NULL DEFAULT 0")
	s.addColumnIfMissing(ctx, "version", "INTEGER NOT NULL DEFAULT 1")

	return nil
}

func (s *Store) addColumnIfMissing(ctx context.Context, column, ddl string) {
	// Best-effort migration; errors are ignored (column already exists).
	s.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE execution_requests ADD COLUMN IF NOT EXISTS %s %s", column, ddl))
}

// generateLeaseToken generates a cryptographically random lease token.
func generateLeaseToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// DefaultLeaseDuration is the default lease duration for new reservations.
const DefaultLeaseDuration = 5 * time.Minute

// Reserve atomically reserves an execution request.
//
// Uses INSERT ... ON CONFLICT DO NOTHING to atomically reserve.
// If the insert succeeds, the caller acquires the reservation
// and a lease token, and may proceed to dispatch.
// If the insert conflicts (key exists), we read the existing record
// and compare digests.
//
// If the key exists with the same request digest:
//   - Terminal state: return the stored result (Acquired=false)
//   - Non-terminal state: return IN_FLIGHT (Acquired=false)
//   - Non-terminal + expired lease: reclaim and return Acquired=true
//
// If the key exists with a different request digest:
//   - Return CONFLICT (never re-execute)
func (s *Store) Reserve(ctx context.Context, key, principal, capability, digest, grantID, class string) (*ReserveResult, error) {
	return s.ReserveWithLease(ctx, key, principal, capability, digest, grantID, class, DefaultLeaseDuration)
}

// ReserveWithLease is Reserve with a configurable lease duration.
func (s *Store) ReserveWithLease(ctx context.Context, key, principal, capability, digest, grantID, class string, leaseDuration time.Duration) (*ReserveResult, error) {
	leaseToken, err := generateLeaseToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate lease token: %w", err)
	}
	leaseOwner := fmt.Sprintf("pid-%d", currentPID())
	leaseExpires := time.Now().Add(leaseDuration)

	// First, try to atomically INSERT a new RESERVED record with a lease.
	// ON CONFLICT DO NOTHING means if the key already exists, no rows are inserted.
	var executionID string
	var createdAt time.Time
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO execution_requests
			(idempotency_key, principal_id, capability_id, request_digest,
			 grant_id, execution_class, state,
			 lease_owner, lease_token, lease_expires_at, attempt, version)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 0, 1)
		ON CONFLICT (principal_id, capability_id, idempotency_key) DO NOTHING
		RETURNING execution_id, created_at
	`, key, principal, capability, digest, nullableString(grantID), class,
		string(StateReserved), leaseOwner, leaseToken, leaseExpires,
	).Scan(&executionID, &createdAt)

	if err == nil {
		// Insert succeeded — THIS caller acquired the reservation and the lease.
		return &ReserveResult{
			State:      StateReserved,
			Acquired:   true,
			LeaseToken: leaseToken,
			Record: &Record{
				ExecutionID:    executionID,
				IdempotencyKey: key,
				PrincipalID:    principal,
				CapabilityID:   capability,
				RequestDigest:  digest,
				GrantID:        grantID,
				ExecutionClass: class,
				State:          StateReserved,
				LeaseOwner:     leaseOwner,
				LeaseToken:     leaseToken,
				LeaseExpiresAt: &leaseExpires,
				Attempt:        0,
				Version:        1,
				CreatedAt:      createdAt,
				UpdatedAt:      createdAt,
			},
		}, nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	// ON CONFLICT DO NOTHING returned no rows — the key already exists.
	// Read the existing record to check the digest and lease status.
	rec, err := s.lookupByKey(ctx, principal, capability, key)
	if err != nil {
		return nil, err
	}

	// Check if the digest matches
	if rec.RequestDigest != digest {
		return &ReserveResult{
			State:    rec.State,
			Record:   rec,
			Conflict: true,
		}, nil
	}

	// Same digest — check if the record is terminal.
	if rec.State.IsTerminal() {
		return &ReserveResult{
			State:    rec.State,
			Record:   rec,
			Acquired: false,
		}, nil
	}

	// Same digest, non-terminal — check if the lease has expired.
	// If expired, attempt to reclaim atomically.
	if rec.LeaseExpiresAt != nil && time.Now().After(*rec.LeaseExpiresAt) {
		reclaimed, err := s.reclaimLease(ctx, rec, leaseToken, leaseOwner, leaseExpires)
		if err != nil {
			return nil, err
		}
		if reclaimed {
			return &ReserveResult{
				State:      StateReserved,
				Acquired:   true,
				LeaseToken: leaseToken,
				Record:     rec,
			}, nil
		}
		// Another caller reclaimed between our read and CAS — fall through.
	}

	// Same digest, non-terminal, lease still valid — another caller owns it.
	return &ReserveResult{
		State:    rec.State,
		Record:   rec,
		Acquired: false,
	}, nil
}

// reclaimLease atomically takes over an expired lease using CAS.
// Returns true if this caller now owns the lease.
func (s *Store) reclaimLease(ctx context.Context, rec *Record, newToken, newOwner string, newExpiry time.Time) (bool, error) {
	result, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET lease_owner = $1, lease_token = $2, lease_expires_at = $3,
		    attempt = attempt + 1, version = version + 1,
		    state = $4, updated_at = NOW()
		WHERE execution_id = $5
		  AND version = $6
		  AND lease_token = $7
		  AND lease_expires_at < NOW()
	`, newOwner, newToken, newExpiry, string(StateReserved), rec.ExecutionID, rec.Version, rec.LeaseToken)
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

	// Update the in-memory record.
	rec.LeaseOwner = newOwner
	rec.LeaseToken = newToken
	rec.LeaseExpiresAt = &newExpiry
	rec.Attempt++
	rec.Version++
	rec.State = StateReserved
	return true, nil
}

// Finalize atomically finalizes an execution with CAS semantics.
//
// Only the current lease holder may finalize. The expected state
// must match. This prevents:
//   - Duplicate dispatch (non-lease-holders cannot finalize)
//   - State races (expected state must match)
//   - Blind overwrites (version check)
//
// For terminal finalization, this is immutable: a second identical
// finalize is idempotent, but a conflicting receipt is rejected.
func (s *Store) Finalize(ctx context.Context, executionID, leaseToken string, expectedState State, newState State, result json.RawMessage, evidenceDigest string, receiptVersion int) error {
	// First check if already finalized (idempotent replay).
	existing, err := s.Lookup(ctx, executionID)
	if err != nil {
		return fmt.Errorf("finalize lookup failed: %w", err)
	}

	if existing.State.IsTerminal() {
		// Already finalized — check for conflict.
		if existing.State != newState {
			return fmt.Errorf("FINALIZATION_CONFLICT: execution %s already finalized as %s, cannot finalize as %s", executionID, existing.State, newState)
		}
		// Same terminal state — idempotent replay. Check evidence consistency.
		if evidenceDigest != "" && existing.EvidenceDigest != "" && evidenceDigest != existing.EvidenceDigest {
			return fmt.Errorf("FINALIZATION_CONFLICT: execution %s has evidence %s, new finalize claims %s", executionID, existing.EvidenceDigest, evidenceDigest)
		}
		return nil
	}

	// Not yet terminal — perform CAS transition.
	result2, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = $1, result = $2, evidence_digest = $3, receipt_version = $4,
		    lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL,
		    version = version + 1, updated_at = NOW()
		WHERE execution_id = $5
		  AND state = $6
		  AND lease_token = $7
		  AND version = $8
	`, string(newState), nullableBytes(result), nullableString(evidenceDigest), receiptVersion,
		executionID, string(expectedState), leaseToken, existing.Version)
	if err != nil {
		return err
	}
	rows, err := result2.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		// CAS failed — either state changed, lease lost, or version mismatch.
		return fmt.Errorf("FINALIZE_CAS_FAILED: execution %s state transition %s→%s rejected (lost lease or state changed)", executionID, expectedState, newState)
	}
	return nil
}

// TransitionState performs a non-terminal state transition with CAS.
// Only the lease holder may transition.
func (s *Store) TransitionState(ctx context.Context, executionID, leaseToken string, expectedState, newState State) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = $1, version = version + 1, updated_at = NOW()
		WHERE execution_id = $2
		  AND state = $3
		  AND lease_token = $4
	`, string(newState), executionID, string(expectedState), leaseToken)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("TRANSITION_CAS_FAILED: execution %s %s→%s rejected (not lease holder or state mismatch)", executionID, expectedState, newState)
	}
	return nil
}

// RenewLease extends the lease for the current holder.
// Only the current lease token may renew.
func (s *Store) RenewLease(ctx context.Context, executionID, leaseToken string, duration time.Duration) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET lease_expires_at = NOW() + $1, updated_at = NOW()
		WHERE execution_id = $2
		  AND lease_token = $3
		  AND state NOT IN ('SUCCEEDED', 'FAILED', 'DENIED', 'UNKNOWN')
	`, duration, executionID, leaseToken)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("LEASE_RENEWAL_REJECTED: execution %s lease renewal rejected (not holder or already terminal)", executionID)
	}
	return nil
}

// SetState updates the state of an execution request.
// DEPRECATED: Use Finalize or TransitionState instead.
// This method is retained for backward compatibility with the
// reconciliation worker but should be migrated.
func (s *Store) SetState(ctx context.Context, executionID string, state State, result json.RawMessage, evidenceDigest string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = $1, result = $2, evidence_digest = $3, updated_at = NOW()
		WHERE execution_id = $4
	`, string(state), nullableBytes(result), nullableString(evidenceDigest), executionID)
	return err
}

// SetStateWithVersion updates state with CAS (expected version).
func (s *Store) SetStateWithVersion(ctx context.Context, executionID string, expectedVersion int, state State, result json.RawMessage, evidenceDigest string) error {
	result2, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = $1, result = $2, evidence_digest = $3, version = version + 1, updated_at = NOW()
		WHERE execution_id = $4 AND version = $5
	`, string(state), nullableBytes(result), nullableString(evidenceDigest), executionID, expectedVersion)
	if err != nil {
		return err
	}
	rows, err := result2.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("SET_STATE_CAS_FAILED: execution %s version %d transition to %s rejected", executionID, expectedVersion, state)
	}
	return nil
}

// Lookup retrieves a record by execution ID.
func (s *Store) Lookup(ctx context.Context, executionID string) (*Record, error) {
	var rec Record
	var resultJSON []byte
	var leaseOwner, leaseToken sql.NullString
	var leaseExpiresAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT execution_id, idempotency_key, principal_id, capability_id,
		       request_digest, COALESCE(grant_id, ''), execution_class, state,
		       result, COALESCE(evidence_digest, ''), COALESCE(receipt_version, 0),
		       lease_owner, lease_token, lease_expires_at,
		       COALESCE(attempt, 0), COALESCE(version, 1), created_at, updated_at
		FROM execution_requests
		WHERE execution_id = $1
	`, executionID).Scan(
		&rec.ExecutionID, &rec.IdempotencyKey, &rec.PrincipalID,
		&rec.CapabilityID, &rec.RequestDigest, &rec.GrantID,
		&rec.ExecutionClass, &rec.State, &resultJSON,
		&rec.EvidenceDigest, &rec.ReceiptVersion,
		&leaseOwner, &leaseToken, &leaseExpiresAt,
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
	if leaseExpiresAt.Valid {
		t := leaseExpiresAt.Time
		rec.LeaseExpiresAt = &t
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
	var leaseOwner, leaseToken sql.NullString
	var leaseExpiresAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT execution_id, idempotency_key, principal_id, capability_id,
		       request_digest, COALESCE(grant_id, ''), execution_class, state,
		       result, COALESCE(evidence_digest, ''), COALESCE(receipt_version, 0),
		       lease_owner, lease_token, lease_expires_at,
		       COALESCE(attempt, 0), COALESCE(version, 1), created_at, updated_at
		FROM execution_requests
		WHERE principal_id = $1 AND capability_id = $2 AND idempotency_key = $3
	`, principal, capability, key).Scan(
		&rec.ExecutionID, &rec.IdempotencyKey, &rec.PrincipalID,
		&rec.CapabilityID, &rec.RequestDigest, &rec.GrantID,
		&rec.ExecutionClass, &rec.State, &resultJSON,
		&rec.EvidenceDigest, &rec.ReceiptVersion,
		&leaseOwner, &leaseToken, &leaseExpiresAt,
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
	if leaseExpiresAt.Valid {
		t := leaseExpiresAt.Time
		rec.LeaseExpiresAt = &t
	}
	return &rec, nil
}

// ListUnknown returns all records in UNKNOWN or RECONCILIATION_REQUIRED state.
func (s *Store) ListUnknown(ctx context.Context) ([]*Record, error) {
	return s.listByStates(ctx, []State{StateUnknown, StateReconciliationRequired})
}

// ListExpiredLeases returns all non-terminal records whose lease has expired.
// These are executions where the previous holder crashed and the
// execution needs recovery.
func (s *Store) ListExpiredLeases(ctx context.Context) ([]*Record, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT execution_id, idempotency_key, principal_id, capability_id,
		       request_digest, COALESCE(grant_id, ''), execution_class, state,
		       result, COALESCE(evidence_digest, ''), COALESCE(receipt_version, 0),
		       lease_owner, lease_token, lease_expires_at,
		       COALESCE(attempt, 0), COALESCE(version, 1), created_at, updated_at
		FROM execution_requests
		WHERE state IN ('RESERVED', 'DISPATCHING', 'IN_FLIGHT')
		  AND lease_expires_at IS NOT NULL
		  AND lease_expires_at < NOW()
		ORDER BY updated_at
	`)
	if err != nil {
		return nil, err
	}
	return scanRecords(rows)
}

// ListStuck returns all non-terminal records that need attention:
// either UNKNOWN, RECONCILIATION_REQUIRED, or expired-lease stuck
// in RESERVED/DISPATCHING/IN_FLIGHT.
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
		       lease_owner, lease_token, lease_expires_at,
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
		var leaseOwner, leaseToken sql.NullString
		var leaseExpiresAt sql.NullTime
		if err := rows.Scan(
			&rec.ExecutionID, &rec.IdempotencyKey, &rec.PrincipalID,
			&rec.CapabilityID, &rec.RequestDigest, &rec.GrantID,
			&rec.ExecutionClass, &rec.State, &resultJSON,
			&rec.EvidenceDigest, &rec.ReceiptVersion,
			&leaseOwner, &leaseToken, &leaseExpiresAt,
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
		if leaseExpiresAt.Valid {
			t := leaseExpiresAt.Time
			rec.LeaseExpiresAt = &t
		}
		records = append(records, &rec)
	}
	return records, rows.Err()
}

// currentPID returns the current process ID (for lease owner identity).
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
