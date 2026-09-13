package idempotency

import (
	"context"
	"fmt"

	"github.com/openclaw/crabbox/internal/evidence"
)

// EvidenceOutcome is the semantic verdict an authenticated attestation
// carries about the external world: whether the side effect provably
// happened. It is deliberately distinct from the durable state name —
// COMMITTED requires COMPLETED proof; FAILED requires NO_EFFECT proof.
type EvidenceOutcome string

const (
	// EvidenceOutcomeCompleted attests the external effect occurred.
	EvidenceOutcomeCompleted EvidenceOutcome = "COMPLETED"
	// EvidenceOutcomeNoEffect attests the external effect provably did
	// not occur — the required proof for any definitive FAILED outcome.
	EvidenceOutcomeNoEffect EvidenceOutcome = "NO_EFFECT"
)

// VerifiedEvidence is what remains after an EvidenceVerifier has crossed
// the authenticated-evidence boundary: a signature by a trusted signer
// verified against a full binding (execution, request, provider, run ID,
// outcome, evidence digest), receipt version supported, and every field
// matched against the durable record. The store consumes only this type
// for CRITICAL decisions — callers cannot satisfy CRITICAL proof by
// supplying strings.
//
// Scope note: the attestation authenticates that a trusted signer
// signed this digest and this outcome claim. The digest itself is
// honest only because the dispatcher/reconciler recomputes it from the
// provider's evidence artifact bytes before signing — a handler- or
// resolver-supplied digest string is never signed. CRITICAL terminal
// outcomes that lack a verifiable artifact are not attested and fail
// closed to UNKNOWN.
type VerifiedEvidence struct {
	EvidenceDigest string
	ReceiptVersion int
	ProviderID     string
	ProviderRunID  string
	Outcome        EvidenceOutcome
	ExecutionID    string
	RequestDigest  string
}

// EvidenceVerifier authenticates a terminal receipt against a durable
// record for a requested terminal target. A nil *VerifiedEvidence result
// means the receipt could not be authenticated.
type EvidenceVerifier interface {
	Verify(ctx context.Context, record *Record, receipt TerminalReceipt, target State) (*VerifiedEvidence, error)
}

// signedReceiptVerifier is the default EvidenceVerifier. It requires a
// V3 Ed25519-signed effect receipt from a trusted signer, bound to the
// record's execution/request identity, the receipt's provider identity
// and evidence digest, and the required outcome for the target state.
type signedReceiptVerifier struct {
	store *Store
}

func (v signedReceiptVerifier) Verify(_ context.Context, record *Record, receipt TerminalReceipt, target State) (*VerifiedEvidence, error) {
	if receipt.EvidenceDigest == "" || !isValidEvidenceDigest(receipt.EvidenceDigest) {
		return nil, fmt.Errorf("invalid evidence digest (64-char lowercase hex required)")
	}
	if receipt.ReceiptVersion != 3 {
		return nil, fmt.Errorf("unsupported receipt_version %d (must be 3)", receipt.ReceiptVersion)
	}
	if receipt.ProviderID == "" || receipt.ProviderRunID == "" {
		return nil, fmt.Errorf("provider_id and provider_run_id are required")
	}
	outcome := evidence.OutcomeCompleted
	verifiedOutcome := EvidenceOutcomeCompleted
	if target == StateFailed {
		outcome = evidence.OutcomeNoEffect
		verifiedOutcome = EvidenceOutcomeNoEffect
	}
	if err := evidence.VerifyReceipt(receipt.EvidenceReceipt, evidence.Binding{
		ExecutionID:    record.ExecutionID,
		Capability:     record.CapabilityID,
		Principal:      record.PrincipalID,
		RequestDigest:  record.RequestDigest,
		ProviderID:     receipt.ProviderID,
		ProviderRunID:  receipt.ProviderRunID,
		Outcome:        outcome,
		EvidenceSHA256: receipt.EvidenceDigest,
	}, v.store.trustedSigners); err != nil {
		return nil, err
	}
	return &VerifiedEvidence{
		EvidenceDigest: receipt.EvidenceDigest,
		ReceiptVersion: receipt.ReceiptVersion,
		ProviderID:     receipt.ProviderID,
		ProviderRunID:  receipt.ProviderRunID,
		Outcome:        verifiedOutcome,
		ExecutionID:    record.ExecutionID,
		RequestDigest:  record.RequestDigest,
	}, nil
}

// ValidateTerminalTransition is the single terminal-decision policy for
// the durable store. Finalize (normal path) and ResolveRecovery
// (recovery path) both invoke it, so proof requirements cannot drift
// between how a record reached its terminal state.
//
// Rules:
//   - target must be COMMITTED or FAILED. DENIED is an admission
//     concept and is never a durable terminal target here.
//   - CRITICAL: a VerifiedEvidence attestation produced by the store's
//     configured EvidenceVerifier is mandatory. COMMITTED requires a
//     COMPLETED attestation; FAILED requires NO_EFFECT.
//   - non-CRITICAL: a definitive terminal state requires at least an
//     evidence digest or a result payload.
func ValidateTerminalTransition(record *Record, target State, receipt TerminalReceipt, verified *VerifiedEvidence) error {
	if target != StateCommitted && target != StateFailed {
		return fmt.Errorf("invalid terminal target %s: must be COMMITTED or FAILED", target)
	}
	if record == nil {
		return fmt.Errorf("terminal transition requires a record")
	}
	if record.ExecutionClass == "CRITICAL" {
		if verified == nil {
			return fmt.Errorf("CRITICAL transition to %s requires authenticated evidence", target)
		}
		want := EvidenceOutcomeCompleted
		if target == StateFailed {
			want = EvidenceOutcomeNoEffect
		}
		if verified.Outcome != want {
			return fmt.Errorf("CRITICAL transition to %s requires %s proof, got %s", target, want, verified.Outcome)
		}
		return nil
	}
	if receipt.EvidenceDigest == "" && len(receipt.CanonicalResult) == 0 {
		return fmt.Errorf("definitive transition to %s requires evidence or result — cannot terminate without proof", target)
	}
	return nil
}
