package idempotency

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// ─── Forensic record ─────────────────────────────────────────────────
//
// Every durable execution carries two append-only forensic ledgers in
// addition to the materialized execution_requests row:
//
//   - effect_provider_observations: the immutable record of every
//     provider observation the system accepted. Each row preserves the
//     exact result bytes the caller asserted the provider returned, a
//     store-computed SHA-256 of those bytes, and the canonicalized
//     digest used for monotonic matching — so a forensic auditor can
//     verify SHA256(result_bytes) == result_sha256 and correlate the
//     canonical digest with execution_requests.provider_result_digest.
//   - effect_events: the ordered event history of the execution —
//     acquisition, lease lifecycle, dispatch boundary crossing,
//     observations, recovery entry, reconciliation claims, and terminal
//     resolution — each stamped with the record version it was written
//     against and database-owned time.
//
// Ledger rows are inserted inside the same transaction as the
// materialized-row update they describe, so a forensic entry can never
// exist without the mutation it records (or vice versa). Rows are never
// updated or deleted; sequence is allocated per execution under the
// mutation's row lock, which serializes all writers to that execution.
//
// The materialized row remains the read projection: the ledgers are
// the source of truth for "what exactly did the provider say" and
// "what happened, in order" — questions the projection answers only
// approximately.

// Effect event types recorded in effect_events.
const (
	EventAcquired                = "ACQUIRED"
	EventLeaseAcquired           = "LEASE_ACQUIRED"
	EventLeaseRenewed            = "LEASE_RENEWED"
	EventExecutionBegun          = "EXECUTION_BEGUN"
	EventDispatchStarted         = "DISPATCH_STARTED"
	EventProviderObserved        = "PROVIDER_OBSERVED"
	EventEnteredUnknown          = "ENTERED_UNKNOWN"
	EventReconciliationClaimed   = "RECONCILIATION_CLAIMED"
	EventReconciliationObserved  = "RECONCILIATION_OBSERVED"
	EventReconciliationSuspended = "RECONCILIATION_SUSPENDED"
	EventClaimReleased           = "CLAIM_RELEASED"
	EventClaimRenewed            = "CLAIM_RENEWED"
	EventTerminalResolved        = "TERMINAL_RESOLVED"
	EventAbandonedPreDispatch    = "ABANDONED_PRE_DISPATCH"
	EventLeaseLost               = "LEASE_LOST"
	EventClaimLost               = "CLAIM_LOST"
)

// Observation kinds recorded in effect_provider_observations.
const (
	// ObservationDispatch is an observation written by the dispatching
	// worker while it still holds the execution lease (IN_FLIGHT).
	ObservationDispatch = "dispatch"
	// ObservationRecovery is an observation carried atomically by the
	// IN_FLIGHT → UNKNOWN recovery transition.
	ObservationRecovery = "recovery"
	// ObservationReconciliation is an observation written against an
	// UNKNOWN record — either a late dispatch observation accepted
	// unconditionally, or the reconciler's provider lookup.
	ObservationReconciliation = "reconciliation"
)

// effectEvent is the payload of one forensic event row.
type effectEvent struct {
	eventType       string
	actor           string
	previousState   string
	newState        string
	resultDigest    string
	evidenceDigest  string
	claimGeneration int
	metadata        string
}

// EffectEvent is one row of an execution's forensic event history.
type EffectEvent struct {
	ExecutionID     string    `json:"execution_id"`
	Sequence        int       `json:"sequence"`
	RecordVersion   int       `json:"record_version"`
	EventType       string    `json:"event_type"`
	Actor           string    `json:"actor,omitempty"`
	PreviousState   string    `json:"previous_state,omitempty"`
	NewState        string    `json:"new_state,omitempty"`
	ResultDigest    string    `json:"result_digest,omitempty"`
	EvidenceDigest  string    `json:"evidence_digest,omitempty"`
	ClaimGeneration int       `json:"claim_generation,omitempty"`
	OccurredAt      time.Time `json:"occurred_at"`
	Metadata        string    `json:"metadata,omitempty"`
}

// ObservationRecord is one row of the immutable provider-observation
// ledger. ResultBytes are the exact bytes the caller asserted the
// provider returned (pre-canonicalization); ResultSHA256 is computed
// by the store over those bytes so the ledger is self-verifying.
type ObservationRecord struct {
	ExecutionID           string          `json:"execution_id"`
	Sequence              int             `json:"sequence"`
	RecordVersion         int             `json:"record_version"`
	Kind                  string          `json:"kind"`
	ProviderID            string          `json:"provider_id,omitempty"`
	ProviderRunID         string          `json:"provider_run_id,omitempty"`
	ProviderStatus        string          `json:"provider_status,omitempty"`
	ResultBytes           json.RawMessage `json:"result_bytes,omitempty"`
	ResultSHA256          string          `json:"result_sha256,omitempty"`
	ResultCanonicalDigest string          `json:"result_canonical_digest,omitempty"`
	EvidenceSHA256        string          `json:"evidence_sha256,omitempty"`
	ReceiptVersion        int             `json:"receipt_version,omitempty"`
	ObservedAt            time.Time       `json:"observed_at"`
}

// sha256Hex returns the lowercase hex SHA-256 of b, or "" for empty
// input so callers can store "" → NULL.
func sha256Hex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
