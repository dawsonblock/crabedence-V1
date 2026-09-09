// Package idempotency provides durable idempotency storage for the
// Crabedence execution service.
//
// Idempotency lives below the NEMO process — in Crabedence itself.
// This ensures that a process crash does not cause re-invocation,
// and that concurrent identical requests converge on one execution.
package idempotency

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// State represents the lifecycle state of an execution request.
type State string

const (
	// StateReserved means the request has been reserved but not yet dispatched.
	StateReserved State = "RESERVED"

	// StateDispatching means the request is being dispatched to the provider.
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
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

// ReserveResult is the outcome of a reservation attempt.
type ReserveResult struct {
	// State is the current state of the record.
	State State `json:"state"`

	// Record is the existing record if found, or nil if newly reserved.
	Record *Record `json:"record,omitempty"`

	// Conflict is true if the same key was used with a different request.
	Conflict bool `json:"conflict"`
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
				created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				UNIQUE(principal_id, capability_id, idempotency_key)
			)
		`)
		if err != nil {
			return err
		}
	}
	return nil
}

// Reserve atomically reserves an execution request.
//
// If the key is new, a RESERVED record is inserted and the caller
// may proceed to dispatch.
//
// If the key exists with the same request digest:
//   - Terminal state: return the stored result
//   - Non-terminal state: return IN_FLIGHT
//
// If the key exists with a different request digest:
//   - Return CONFLICT (never re-execute)
func (s *Store) Reserve(ctx context.Context, key, principal, capability, digest, grantID, class string) (*ReserveResult, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Try to find existing record
	var rec Record
	var resultJSON []byte
	err = tx.QueryRowContext(ctx, `
		SELECT execution_id, idempotency_key, principal_id, capability_id,
		       request_digest, COALESCE(grant_id, ''), execution_class, state,
		       result, COALESCE(evidence_digest, ''), created_at, updated_at
		FROM execution_requests
		WHERE principal_id = $1 AND capability_id = $2 AND idempotency_key = $3
	`, principal, capability, key).Scan(
		&rec.ExecutionID, &rec.IdempotencyKey, &rec.PrincipalID,
		&rec.CapabilityID, &rec.RequestDigest, &rec.GrantID,
		&rec.ExecutionClass, &rec.State, &resultJSON,
		&rec.EvidenceDigest, &rec.CreatedAt, &rec.UpdatedAt,
	)

	if err == nil {
		// Record exists — check digest
		rec.Result = json.RawMessage(resultJSON)
		if rec.RequestDigest != digest {
			return &ReserveResult{
				State:    rec.State,
				Record:   &rec,
				Conflict: true,
			}, tx.Commit()
		}
		// Same digest — return existing state
		return &ReserveResult{
			State:  rec.State,
			Record: &rec,
		}, tx.Commit()
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	// No existing record — insert new RESERVED record
	var executionID string
	err = tx.QueryRowContext(ctx, `
		INSERT INTO execution_requests
			(idempotency_key, principal_id, capability_id, request_digest,
			 grant_id, execution_class, state)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING execution_id, created_at
	`, key, principal, capability, digest, nullableString(grantID), class, string(StateReserved)).Scan(&executionID, &rec.CreatedAt)
	if err != nil {
		return nil, err
	}
	rec.ExecutionID = executionID
	rec.IdempotencyKey = key
	rec.PrincipalID = principal
	rec.CapabilityID = capability
	rec.RequestDigest = digest
	rec.GrantID = grantID
	rec.ExecutionClass = class
	rec.State = StateReserved
	rec.UpdatedAt = rec.CreatedAt

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &ReserveResult{
		State:  StateReserved,
		Record: &rec,
	}, nil
}

// SetState updates the state of an execution request.
func (s *Store) SetState(ctx context.Context, executionID string, state State, result json.RawMessage, evidenceDigest string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE execution_requests
		SET state = $1, result = $2, evidence_digest = $3, updated_at = NOW()
		WHERE execution_id = $4
	`, string(state), nullableBytes(result), nullableString(evidenceDigest), executionID)
	return err
}

// Lookup retrieves a record by execution ID.
func (s *Store) Lookup(ctx context.Context, executionID string) (*Record, error) {
	var rec Record
	var resultJSON []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT execution_id, idempotency_key, principal_id, capability_id,
		       request_digest, COALESCE(grant_id, ''), execution_class, state,
		       result, COALESCE(evidence_digest, ''), created_at, updated_at
		FROM execution_requests
		WHERE execution_id = $1
	`, executionID).Scan(
		&rec.ExecutionID, &rec.IdempotencyKey, &rec.PrincipalID,
		&rec.CapabilityID, &rec.RequestDigest, &rec.GrantID,
		&rec.ExecutionClass, &rec.State, &resultJSON,
		&rec.EvidenceDigest, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	rec.Result = json.RawMessage(resultJSON)
	return &rec, nil
}

// LookupByKey retrieves a record by idempotency key.
func (s *Store) LookupByKey(ctx context.Context, principal, capability, key string) (*Record, error) {
	var rec Record
	var resultJSON []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT execution_id, idempotency_key, principal_id, capability_id,
		       request_digest, COALESCE(grant_id, ''), execution_class, state,
		       result, COALESCE(evidence_digest, ''), created_at, updated_at
		FROM execution_requests
		WHERE principal_id = $1 AND capability_id = $2 AND idempotency_key = $3
	`, principal, capability, key).Scan(
		&rec.ExecutionID, &rec.IdempotencyKey, &rec.PrincipalID,
		&rec.CapabilityID, &rec.RequestDigest, &rec.GrantID,
		&rec.ExecutionClass, &rec.State, &resultJSON,
		&rec.EvidenceDigest, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	rec.Result = json.RawMessage(resultJSON)
	return &rec, nil
}

// ListUnknown returns all records in UNKNOWN or RECONCILIATION_REQUIRED state.
func (s *Store) ListUnknown(ctx context.Context) ([]*Record, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT execution_id, idempotency_key, principal_id, capability_id,
		       request_digest, COALESCE(grant_id, ''), execution_class, state,
		       result, COALESCE(evidence_digest, ''), created_at, updated_at
		FROM execution_requests
		WHERE state IN ('UNKNOWN', 'RECONCILIATION_REQUIRED')
		ORDER BY updated_at
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*Record
	for rows.Next() {
		var rec Record
		var resultJSON []byte
		if err := rows.Scan(
			&rec.ExecutionID, &rec.IdempotencyKey, &rec.PrincipalID,
			&rec.CapabilityID, &rec.RequestDigest, &rec.GrantID,
			&rec.ExecutionClass, &rec.State, &resultJSON,
			&rec.EvidenceDigest, &rec.CreatedAt, &rec.UpdatedAt,
		); err != nil {
			return nil, err
		}
		rec.Result = json.RawMessage(resultJSON)
		records = append(records, &rec)
	}
	return records, rows.Err()
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
