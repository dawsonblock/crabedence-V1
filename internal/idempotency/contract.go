// Package idempotency provides the durable execution contract types.
//
// This file freezes the contract vocabulary: states, lease errors,
// acquire results, terminal receipts, and recovery decisions. The
// Store implementation in store.go satisfies these types.
package idempotency

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// ─── State vocabulary ─────────────────────────────────────────────────

// State represents the lifecycle state of an execution request.
type State string

const (
	// StatePrepared means no external dispatch has occurred.
	StatePrepared State = "PREPARED"

	// StateExecuting means an executor owns a lease and is preparing
	// dispatch. The dispatch boundary has NOT been crossed.
	StateExecuting State = "EXECUTING"

	// StateInFlight means the dispatch boundary has been crossed and
	// the effect may have occurred. Persisted before the provider call.
	StateInFlight State = "IN_FLIGHT"

	// StateUnknown means the durable store cannot currently determine
	// the real-world result. Caller-terminal but not durably-final.
	StateUnknown State = "UNKNOWN"

	// StateCommitted means the operation durably succeeded.
	StateCommitted State = "COMMITTED"

	// StateFailed means the operation definitively failed.
	StateFailed State = "FAILED"

	// StateDenied means admission denied the request before dispatch.
	StateDenied State = "DENIED"
)

// IsCallerTerminal returns true if the state is terminal from the
// caller's perspective — callers must not retry.
func (s State) IsCallerTerminal() bool {
	switch s {
	case StateCommitted, StateFailed, StateDenied, StateUnknown:
		return true
	}
	return false
}

// IsDurablyFinal returns true if the state is durably final — no
// further mutations are permitted, including by reconciliation.
func (s State) IsDurablyFinal() bool {
	switch s {
	case StateCommitted, StateFailed, StateDenied:
		return true
	}
	return false
}

// IsTerminal is retained for backward compatibility with code that
// treats UNKNOWN as terminal. Prefer IsCallerTerminal or IsDurablyFinal.
func (s State) IsTerminal() bool {
	return s.IsCallerTerminal()
}

// ─── Lease configuration ──────────────────────────────────────────────

// LeaseConfig defines the lease policy enforced by the store.
type LeaseConfig struct {
	DefaultDuration time.Duration
	MaxDuration     time.Duration
	RenewalWindow   time.Duration
}

// DefaultLeaseConfig is the default lease policy.
var DefaultLeaseConfig = LeaseConfig{
	DefaultDuration: 5 * time.Minute,
	MaxDuration:     30 * time.Minute,
	RenewalWindow:   1 * time.Minute,
}

// Validate checks a requested lease duration against the policy.
// Returns an error for zero, negative, or excessive durations.
func (c LeaseConfig) Validate(requested time.Duration) error {
	if requested <= 0 {
		return LeaseErrorInvalidDuration
	}
	if c.MaxDuration > 0 && requested > c.MaxDuration {
		return LeaseErrorInvalidDuration
	}
	return nil
}

// ─── Typed lease errors ──────────────────────────────────────────────

// LeaseError is a typed error for lease failures.
type LeaseError string

const (
	LeaseLost                 LeaseError = "LEASE_LOST"
	LeaseExpired              LeaseError = "LEASE_EXPIRED"
	LeaseTokenMismatch        LeaseError = "LEASE_TOKEN_MISMATCH"
	LeaseGenerationMismatch   LeaseError = "LEASE_GENERATION_MISMATCH"
	LeaseStateConflict        LeaseError = "STATE_CONFLICT"
	LeaseRecoveryRequired     LeaseError = "RECOVERY_REQUIRED"
	LeaseErrorInvalidDuration LeaseError = "INVALID_DURATION"
)

func (e LeaseError) Error() string { return string(e) }

// ─── Acquire result ──────────────────────────────────────────────────

// AcquireResultKind is the typed outcome of a lease acquisition attempt.
type AcquireResultKind string

const (
	LeaseAcquired       AcquireResultKind = "ACQUIRED"
	LeaseHeldByOther    AcquireResultKind = "HELD_BY_OTHER"
	LeaseReclaimed      AcquireResultKind = "RECLAIMED"
	TerminalReplay      AcquireResultKind = "TERMINAL_REPLAY"
	RecoveryRequired    AcquireResultKind = "RECOVERY_REQUIRED"
	IdempotencyConflict AcquireResultKind = "IDEMPOTENCY_CONFLICT"
)

// AcquireResult is the typed outcome of a reservation/acquisition.
type AcquireResult struct {
	Kind       AcquireResultKind `json:"kind"`
	State      State             `json:"state"`
	Record     *Record           `json:"record,omitempty"`
	LeaseToken string            `json:"lease_token,omitempty"`
	Generation int               `json:"generation,omitempty"`
}

// Acquired returns true if this caller acquired the lease and may
// proceed to dispatch.
func (r AcquireResult) Acquired() bool {
	return r.Kind == LeaseAcquired || r.Kind == LeaseReclaimed
}

// ─── Terminal receipt ────────────────────────────────────────────────

// TerminalReceipt is the canonical, immutable terminal record for an
// execution. It is hashed to detect duplicate and conflicting
// finalization.
type TerminalReceipt struct {
	ExecutionID     string          `json:"execution_id"`
	Capability      string          `json:"capability"`
	Principal       string          `json:"principal"`
	RequestDigest   string          `json:"request_digest"`
	TerminalStatus  State           `json:"terminal_status"`
	CanonicalResult json.RawMessage `json:"canonical_result,omitempty"`
	ProviderID      string          `json:"provider_id"`
	ProviderRunID   string          `json:"provider_run_id"`
	EvidenceDigest  string          `json:"evidence_digest,omitempty"`
	ReceiptVersion  int             `json:"receipt_version,omitempty"`
	FinalizedAt     time.Time       `json:"finalized_at"`
}

// Digest computes the SHA-256 digest of the canonical terminal receipt.
// This provides a simple equality test for duplicate finalization and
// makes conflict detection precise.
func (r TerminalReceipt) Digest() (string, error) {
	canonical, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(canonical)
	return hex.EncodeToString(hash[:]), nil
}

// ─── Recovery ────────────────────────────────────────────────────────

// RecoveryDecision is the typed outcome of a recovery resolution.
type RecoveryDecision string

const (
	RecoveryCommitted RecoveryDecision = "COMMITTED"
	RecoveryFailed    RecoveryDecision = "FAILED"
	RecoveryUnknown   RecoveryDecision = "UNKNOWN"
	RecoveryRetryable RecoveryDecision = "RETRYABLE"
	RecoveryConflict  RecoveryDecision = "CONFLICT"
)

// RecoveryResult is the typed result of a recovery resolution.
type RecoveryResult struct {
	Decision       RecoveryDecision `json:"decision"`
	Result         json.RawMessage  `json:"result,omitempty"`
	EvidenceDigest string           `json:"evidence_digest,omitempty"`
	ReceiptVersion int              `json:"receipt_version,omitempty"`
	ProviderID     string           `json:"provider_id,omitempty"`
	ProviderRunID  string           `json:"provider_run_id,omitempty"`
}

// RecoveryResolver queries a provider to determine if an operation
// actually happened. Resolvers are registered per provider/capability.
type RecoveryResolver interface {
	Resolve(ctx Ctx, record *Record) (RecoveryResult, error)
}

// Ctx is an alias for context.Context to avoid importing context in
// this types-only file. The interface is satisfied by context.Context.
type Ctx interface {
	Deadline() (time.Time, bool)
	Done() <-chan struct{}
	Err() error
	Value(key any) any
}

// ─── Backward-compatible state aliases ───────────────────────────────
//
// These map old state names to new ones for any code that has not yet
// been migrated. New code must use the canonical names above.

const (
	// Deprecated: use StatePrepared
	StateReserved State = "PREPARED"
	// Deprecated: use StateExecuting
	StateDispatching State = "EXECUTING"
	// Deprecated: use StateCommitted
	StateSucceeded State = "COMMITTED"
	// Deprecated: UNKNOWN replaces RECONCILIATION_REQUIRED
	StateReconciliationRequired State = "UNKNOWN"
)
