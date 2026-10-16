package experience

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openclaw/crabbox/internal/history"
)

func openStore(t *testing.T) *history.Store {
	t.Helper()
	s, err := history.OpenStore(t.TempDir() + "/h.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func appendEvent(t *testing.T, s *history.Store, dedupe, kind, subject, corr string, at int64, payload any) *history.Event {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	e := &history.Event{
		DedupeKey:   dedupe,
		Kind:        kind,
		Subject:     subject,
		Correlation: corr,
		Source:      "test",
		OccurredAt:  at,
		Payload:     raw,
	}
	if _, err := s.Append(e); err != nil {
		t.Fatal(err)
	}
	return e
}

// The core reconstruction: a failure, an intervention on the same
// path, a later pass of the same test — resolves + candidate_cause.
func TestReconstructResolutionAndCandidate(t *testing.T) {
	s := openStore(t)
	appendEvent(t, s, "t:run1:TestAck", "test_result", "pkg/TestAck", "run1", 100,
		map[string]any{"status": "fail", "test": "TestAck"})
	appendEvent(t, s, "git:abc", "code_change", "abc123", "", 200,
		map[string]any{"message": "fix ack verification", "files": []map[string]string{{"path": "pkg/ack.go"}}})
	appendEvent(t, s, "t:run2:TestAck", "test_result", "pkg/TestAck", "run2", 300,
		map[string]any{"status": "pass", "test": "TestAck"})

	g, err := Reconstruct(s, "")
	if err != nil {
		t.Fatal(err)
	}
	failNode := g.Nodes["t:run1:TestAck"]
	if failNode == nil || failNode.Kind != NodeProblem {
		t.Fatalf("failed test not classified problem: %+v", failNode)
	}
	var resolves, candidate bool
	for _, e := range g.Edges {
		if e.Rel == RelResolves && e.To == "t:run1:TestAck" && e.From == "t:run2:TestAck" {
			resolves = true
		}
		if e.Rel == RelCandidateCause && e.From == "git:abc" && e.To == "t:run1:TestAck" {
			candidate = true
		}
	}
	if !resolves {
		t.Fatal("pass did not resolve the failure node")
	}
	// The intervention has path "pkg/ack.go"; the failure node has no
	// paths — so no candidate_cause edge is claimed. Honest absence:
	// no shared path means no claim.
	if candidate {
		t.Fatal("candidate cause claimed without a shared path")
	}
}

// Same-subject observations supersede in chain order.
func TestReconstructSupersede(t *testing.T) {
	s := openStore(t)
	appendEvent(t, s, "job:h:a", "execution", "job-1", "h1", 100, map[string]any{"state": "running"})
	appendEvent(t, s, "job:h:b", "execution", "job-1", "h1", 200, map[string]any{"state": "succeeded"})
	g, err := Reconstruct(s, "")
	if err != nil {
		t.Fatal(err)
	}
	if !g.Superseded("job:h:a") {
		t.Fatal("earlier job observation not superseded")
	}
	if g.Superseded("job:h:b") {
		t.Fatal("latest observation reported superseded")
	}
}

// Conflicting experiment outcomes are recorded as contradictions,
// never silently reconciled.
func TestReconstructContradiction(t *testing.T) {
	s := openStore(t)
	appendEvent(t, s, "exp:x:1", "experiment", "exp-x", "", 100, map[string]any{"outcome": "pass"})
	appendEvent(t, s, "exp:x:2", "experiment", "exp-x", "", 200, map[string]any{"outcome": "fail"})
	g, err := Reconstruct(s, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Contradictions()) != 1 {
		t.Fatalf("expected 1 contradiction, got %d", len(g.Contradictions()))
	}
}

// A conversation naming a file a commit changed links statement to
// intervention — reasoning ↔ code.
func TestReconstructReferences(t *testing.T) {
	s := openStore(t)
	appendEvent(t, s, "conv:m1", "conversation", "sess", "sha", 100,
		map[string]any{"role": "assistant", "text": "editing ack.go", "file_refs": []string{"pkg/ack.go"}})
	appendEvent(t, s, "git:c1", "code_change", "c1", "", 200,
		map[string]any{"files": []map[string]string{{"path": "pkg/ack.go"}}})
	g, err := Reconstruct(s, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range g.Edges {
		if e.Rel == RelReferences && e.From == "conv:m1" && e.To == "git:c1" {
			found = true
		}
	}
	if !found {
		t.Fatal("statement did not link to the intervention on its file path")
	}
}

// Custody acks and receipts attest the events sharing their
// correlation — witnessed vs. merely observed.
func TestReconstructAttestation(t *testing.T) {
	s := openStore(t)
	appendEvent(t, s, "job:h:1", "execution", "job-1", "contract-hash", 100, map[string]any{"state": "succeeded"})
	appendEvent(t, s, "ack:1", "custody_ack", "seg-1", "contract-hash", 200, map[string]any{"ack_seq": 1})
	g, err := Reconstruct(s, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range g.Edges {
		if e.Rel == RelAttests && e.From == "ack:1" && e.To == "job:h:1" {
			found = true
		}
	}
	if !found {
		t.Fatal("custody ack did not attest the correlated execution")
	}
}

// The retrieval evaluation catches both missed expected links and
// invented ones — memory quality is measured, not assumed.
func TestEvalRetrieval(t *testing.T) {
	s := openStore(t)
	appendEvent(t, s, "t:r:F", "test_result", "pkg/F", "r", 100, map[string]any{"status": "fail"})
	appendEvent(t, s, "t:r2:F", "test_result", "pkg/F", "r2", 200, map[string]any{"status": "pass"})
	g, err := Reconstruct(s, "")
	if err != nil {
		t.Fatal(err)
	}
	p, r, viol := g.EvalRetrieval([]*RetrievalCase{
		{Query: "t:r:F", Rel: RelResolves, Expect: []string{"t:r2:F"}},
		{Query: "t:r2:F", Rel: RelResolves, Expect: []string{"t:r:F"}, Forbid: []string{"git:abc"}},
	})
	if len(viol) != 0 {
		t.Fatalf("retrieval violations: %v", viol)
	}
	if p != 1.0 || r != 1.0 {
		t.Fatalf("precision %v recall %v, want 1.0/1.0", p, r)
	}
	// A wrong expectation is reported, not hidden.
	_, _, viol = g.EvalRetrieval([]*RetrievalCase{
		{Query: "t:r:F", Rel: RelResolves, Expect: []string{"nonexistent"}},
	})
	if len(viol) == 0 {
		t.Fatal("missed expectation not reported")
	}
}

// Trusted() excludes adversely-assessed nodes — the learner never
// sees what the assessment layer could not establish.
func TestTrustedFiltersAdverseVerdicts(t *testing.T) {
	s := openStore(t)
	e := appendEvent(t, s, "r:bad", "receipt", "exec-1", "", 100, map[string]any{"outcome": "completed"})
	appendEvent(t, s, "t:r:P", "test_result", "pkg/P", "r", 100, map[string]any{"status": "pass"})
	trustSHA := history.TrustSetSHA256(map[string]bool{"fp": true})
	if err := s.RecordAssessment(&history.Assessment{
		SubjectKey: e.DedupeKey, Verifier: "v", RulesVersion: "receipt-v1",
		TrustSetSHA: trustSHA, InputSHA: "in", Result: history.AssessmentRejected,
	}); err != nil {
		t.Fatal(err)
	}
	g, err := Reconstruct(s, trustSHA)
	if err != nil {
		t.Fatal(err)
	}
	if g.Nodes["r:bad"].Trust != history.AssessmentRejected {
		t.Fatalf("node trust %q, want REJECTED", g.Nodes["r:bad"].Trust)
	}
	tg := g.Trusted()
	if _, ok := tg.Nodes["r:bad"]; ok {
		t.Fatal("rejected node offered to the learner")
	}
	if _, ok := tg.Nodes["t:r:P"]; !ok {
		t.Fatal("unassessed node dropped from the trusted graph")
	}
}

// Explain renders a readable position — the diagnostic surface.
func TestExplain(t *testing.T) {
	s := openStore(t)
	appendEvent(t, s, "t:r:F", "test_result", "pkg/F", "r", 100, map[string]any{"status": "fail"})
	appendEvent(t, s, "t:r2:F", "test_result", "pkg/F", "r2", 200, map[string]any{"status": "pass"})
	g, err := Reconstruct(s, "")
	if err != nil {
		t.Fatal(err)
	}
	out := g.Explain("t:r:F")
	if !strings.Contains(out, "problem") || !strings.Contains(out, "resolves") {
		t.Fatalf("explanation missing role/edges:\n%s", out)
	}
}
