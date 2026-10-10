package idempotency

import (
	"context"
	"database/sql"
	"fmt"
	"time"

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
// It carries the trusted signer set directly so both storage engines
// (PostgreSQL Store, embedded SQLiteStore) share one verifier.
type signedReceiptVerifier struct {
	trustedSigners map[string]bool
}

func (v signedReceiptVerifier) Verify(_ context.Context, record *Record, receipt TerminalReceipt, target State) (*VerifiedEvidence, error) {
	if receipt.EvidenceDigest == "" || !isValidEvidenceDigest(receipt.EvidenceDigest) {
		return nil, fmt.Errorf("invalid evidence digest (64-char lowercase hex required)")
	}
	if receipt.ReceiptVersion != 3 {
		return nil, fmt.Errorf("unsupported receipt_version %d (must be 3)", receipt.ReceiptVersion)
	}
	outcome := evidence.OutcomeCompleted
	verifiedOutcome := EvidenceOutcomeCompleted
	if target == StateFailed {
		outcome = evidence.OutcomeNoEffect
		verifiedOutcome = EvidenceOutcomeNoEffect
	}
	if receipt.ProviderID == "" {
		return nil, fmt.Errorf("provider_id is required")
	}
	// COMPLETED proof must name the provider operation that ran.
	// NO_EFFECT has no operation identity — nothing ran — so a missing
	// provider_run_id is correct rather than a defect.
	if outcome == evidence.OutcomeCompleted && receipt.ProviderRunID == "" {
		return nil, fmt.Errorf("provider_run_id is required for COMPLETED proof")
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
	}, v.trustedSigners); err != nil {
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

// ─── Terminal evidence enumeration ───────────────────────────────────
//
// TerminalEvidence enumerates every terminal execution as a checkpoint
// reference, in terminal_seq order — the durable terminalization-commit
// order assigned transactionally with each terminal write. The
// enumeration is append-only by construction: a record that terminalizes
// late lands at the end, never mid-history, so previously issued
// checkpoints keep verifying as legitimate prefixes. A terminal record
// lacking a ledger position (a NULL terminal_seq — only possible for a
// rolling-upgrade straggler that escaped open-time repair) is a
// fail-closed error, never a silently skipped row. The timestamp is
// truncated to milliseconds: SQLite stores millisecond integers while
// PostgreSQL keeps microseconds, and the truncation is what makes the
// canonical form engine-independent.

// TerminalEvidence implements the SQLite engine.
func (s *SQLiteStore) TerminalEvidence(ctx context.Context) ([]evidence.TerminalRef, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT terminal_seq, execution_id, state, request_digest,
		       COALESCE(terminal_result_digest, ''),
		       COALESCE(terminal_evidence_digest, ''),
		       COALESCE(terminal_receipt_digest, ''),
		       COALESCE(provider_id, ''), COALESCE(provider_run_id, ''),
		       updated_at
		FROM execution_requests
		WHERE state IN ('COMMITTED', 'FAILED', 'DENIED')
		ORDER BY terminal_seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var refs []evidence.TerminalRef
	for rows.Next() {
		var ref evidence.TerminalRef
		var seq sql.NullInt64
		var updatedAt int64
		if err := rows.Scan(&seq, &ref.ExecutionID, &ref.State, &ref.RequestDigest,
			&ref.TerminalResultDigest, &ref.TerminalEvidenceDigest,
			&ref.TerminalReceiptDigest, &ref.ProviderID, &ref.ProviderRunID,
			&updatedAt); err != nil {
			return nil, err
		}
		if !seq.Valid {
			return nil, fmt.Errorf("terminal record %s (%s) has no terminal_seq — the evidence ledger is incomplete; reopen the store to run the repair pass", ref.ExecutionID, ref.State)
		}
		ref.Seq = seq.Int64
		ref.UpdatedAt = sqliteTime(updatedAt).Truncate(time.Millisecond).Format(time.RFC3339Nano)
		refs = append(refs, ref)
	}
	return refs, rows.Err()
}

// TerminalEvidence implements the PostgreSQL engine.
func (s *Store) TerminalEvidence(ctx context.Context) ([]evidence.TerminalRef, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT terminal_seq, execution_id, state, request_digest,
		       COALESCE(terminal_result_digest, ''),
		       COALESCE(terminal_evidence_digest, ''),
		       COALESCE(terminal_receipt_digest, ''),
		       COALESCE(provider_id, ''), COALESCE(provider_run_id, ''),
		       updated_at
		FROM execution_requests
		WHERE state IN ('COMMITTED', 'FAILED', 'DENIED')
		ORDER BY terminal_seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var refs []evidence.TerminalRef
	for rows.Next() {
		var ref evidence.TerminalRef
		var seq sql.NullInt64
		var updatedAt time.Time
		if err := rows.Scan(&seq, &ref.ExecutionID, &ref.State, &ref.RequestDigest,
			&ref.TerminalResultDigest, &ref.TerminalEvidenceDigest,
			&ref.TerminalReceiptDigest, &ref.ProviderID, &ref.ProviderRunID,
			&updatedAt); err != nil {
			return nil, err
		}
		if !seq.Valid {
			return nil, fmt.Errorf("terminal record %s (%s) has no terminal_seq — the evidence ledger is incomplete; reopen the store to run the repair pass", ref.ExecutionID, ref.State)
		}
		ref.Seq = seq.Int64
		ref.UpdatedAt = updatedAt.UTC().Truncate(time.Millisecond).Format(time.RFC3339Nano)
		refs = append(refs, ref)
	}
	return refs, rows.Err()
}
