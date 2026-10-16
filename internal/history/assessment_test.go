package history

import (
	"testing"
)

// Re-ingesting a receipt under a changed trust set must mint a new
// assessment — the observation stays immutable and deduped while the
// trust layer records the new verdict. This is the acceptance case
// for separating evidence from trust: a newly trusted signer turns
// the same stored receipt VERIFIED without rewriting the record.
func TestAssessmentReIngestUnderNewTrust(t *testing.T) {
	_, evidenceDir, _, signerFP := settledLedger(t)
	s := openStore(t)

	// First ingest: the signer is not trusted — the observation is
	// recorded, the verdict is UNVERIFIED.
	if _, err := s.IngestEvidenceDir(evidenceDir, map[string]bool{}, nil); err != nil {
		t.Fatal(err)
	}
	rcpts, err := s.Query(QueryOpts{Kinds: []string{KindReceipt}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rcpts) != 1 {
		t.Fatalf("expected 1 receipt event, got %d", len(rcpts))
	}
	key := rcpts[0].DedupeKey
	eff, err := s.EffectiveAssessment(key, "receipt-v1", TrustSetSHA256(map[string]bool{}))
	if err != nil {
		t.Fatal(err)
	}
	if eff.Result != AssessmentUnverified {
		t.Fatalf("untrusted receipt effective result %s, want UNVERIFIED", eff.Result)
	}

	// Second ingest: same receipt, signer now trusted. The event is
	// deduped — the observation did not change — but a new verdict
	// lands under the new trust set.
	n, err := s.IngestEvidenceDir(evidenceDir, map[string]bool{signerFP: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = n
	newTrust := TrustSetSHA256(map[string]bool{signerFP: true})
	eff, err = s.EffectiveAssessment(key, "receipt-v1", newTrust)
	if err != nil {
		t.Fatal(err)
	}
	if eff.Result != AssessmentVerified {
		t.Fatalf("newly trusted receipt effective result %s, want VERIFIED", eff.Result)
	}
	// And the earlier verdict remains for audit — nothing rewrote it.
	all, err := s.Assessments(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 2 {
		t.Fatalf("expected both assessments preserved, got %d", len(all))
	}
}

// A verdict minted under a different trust set reports STALE under
// the new policy — a policy change can never silently launder a
// rejection into trust.
func TestAssessmentStaleUnderPolicyChange(t *testing.T) {
	_, evidenceDir, _, signerFP := settledLedger(t)
	s := openStore(t)
	if _, err := s.IngestEvidenceDir(evidenceDir, map[string]bool{signerFP: true}, nil); err != nil {
		t.Fatal(err)
	}
	rcpts, err := s.Query(QueryOpts{Kinds: []string{KindReceipt}})
	if err != nil {
		t.Fatal(err)
	}
	key := rcpts[0].DedupeKey
	// Query under a different trust set than the one that produced
	// the only verdict: the answer is STALE, never the old VERIFIED.
	eff, err := s.EffectiveAssessment(key, "receipt-v1", TrustSetSHA256(map[string]bool{"other-fp": true}))
	if err != nil {
		t.Fatal(err)
	}
	if eff.Result != AssessmentStale {
		t.Fatalf("cross-policy result %s, want STALE", eff.Result)
	}
}

// Two verifiers disagreeing on the current record produce CONFLICTED
// rather than silently picking a winner.
func TestAssessmentConflictedVerdicts(t *testing.T) {
	s := openStore(t)
	trustSHA := TrustSetSHA256(map[string]bool{"a": true})
	err := s.RecordAssessment(
		&Assessment{SubjectKey: "receipt:x", Verifier: "v-one", RulesVersion: "r1",
			TrustSetSHA: trustSHA, InputSHA: "in1", Result: AssessmentVerified},
		&Assessment{SubjectKey: "receipt:x", Verifier: "v-two", RulesVersion: "r1",
			TrustSetSHA: trustSHA, InputSHA: "in1", Result: AssessmentRejected},
	)
	if err != nil {
		t.Fatal(err)
	}
	eff, err := s.EffectiveAssessment("receipt:x", "r1", trustSHA)
	if err != nil {
		t.Fatal(err)
	}
	if eff.Result != AssessmentConflicted {
		t.Fatalf("conflicting verdicts reported %s, want CONFLICTED", eff.Result)
	}
}

// An identical re-assessment is idempotent; a never-assessed subject
// reports UNVERIFIED.
func TestAssessmentDedupeAndUnverified(t *testing.T) {
	s := openStore(t)
	a := &Assessment{SubjectKey: "doc:y", Verifier: "v", RulesVersion: "r1",
		TrustSetSHA: "ts", InputSHA: "in", Result: AssessmentVerified}
	if err := s.RecordAssessment(a, a); err != nil {
		t.Fatal(err)
	}
	all, err := s.Assessments("doc:y")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("identical assessments should dedupe, got %d", len(all))
	}
	eff, err := s.EffectiveAssessment("never:seen", "r1", "ts")
	if err != nil {
		t.Fatal(err)
	}
	if eff.Result != AssessmentUnverified {
		t.Fatalf("unassessed subject reported %s, want UNVERIFIED", eff.Result)
	}
}
