// Package idempotency provides the durable execution contract types.
//
// This file freezes the contract vocabulary: states, lease errors,
// acquire results, terminal receipts, and recovery decisions. The
// Store implementation in store.go satisfies these types.
package idempotency

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
//
// DefaultDuration is used by the legacy Reserve() wrapper when no
// explicit duration is provided. New code should use Acquire() with
// an explicit duration.
//
// MaxDuration is the maximum allowed lease duration. Requests for
// longer durations are rejected by Validate().
//
// RenewalWindow is the window before lease expiry during which a
// lease holder should attempt renewal. It is advisory — the store
// does not enforce it. It is reserved for future use by lease
// auto-renewal helpers. Currently no code reads this field.
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

// ─── Clock ────────────────────────────────────────────────────────────

// Clock provides the current time. The store uses clock_timestamp()
// in PostgreSQL for live deployments, but tests can inject a
// deterministic clock to control lease expiry without sleeping.
type Clock interface {
	Now() time.Time
}

// SystemClock returns the real wall-clock time.
type SystemClock struct{}

// Now returns time.Now().
func (SystemClock) Now() time.Time { return time.Now() }

// FixedClock returns a fixed time. Useful for deterministic tests.
type FixedClock struct {
	T time.Time
}

// Now returns the fixed time.
func (c FixedClock) Now() time.Time { return c.T }

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
//
// FinalizedAt is excluded from the digest because the store assigns it
// from clock_timestamp() inside the database transaction — the caller
// cannot know it before computing the digest. Including a zero value
// would make the digest meaningless. The digest binds the immutable
// receipt content (identity, result, provider, evidence, version) but
// not the transient finalization timestamp.
func (r TerminalReceipt) Digest() (string, error) {
	// P2 #8: Canonicalize the result JSON before hashing. A json.RawMessage
	// preserves the original byte ordering of object keys, which means
	// {"a":1,"b":2} and {"b":2,"a":1} produce different digests despite
	// being semantically identical. Parse and re-marshal with sorted keys
	// so the digest is canonical.
	canonicalResult, err := canonicalizeJSON(r.CanonicalResult)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize result: %w", err)
	}

	// Marshal with FinalizedAt excluded.
	canonical, err := json.Marshal(struct {
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
	}{
		ExecutionID:     r.ExecutionID,
		Capability:      r.Capability,
		Principal:       r.Principal,
		RequestDigest:   r.RequestDigest,
		TerminalStatus:  r.TerminalStatus,
		CanonicalResult: canonicalResult,
		ProviderID:      r.ProviderID,
		ProviderRunID:   r.ProviderRunID,
		EvidenceDigest:  r.EvidenceDigest,
		ReceiptVersion:  r.ReceiptVersion,
	})
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(canonical)
	return hex.EncodeToString(hash[:]), nil
}

// canonicalizeJSON parses a json.RawMessage and re-marshals it with
// sorted object keys. This ensures that semantically identical JSON
// produces identical byte sequences for digest computation.
// nil or empty input returns nil (which omits the field).
func canonicalizeJSON(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
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
	Resolve(ctx context.Context, record *Record) (RecoveryResult, error)
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
