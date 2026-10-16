package research

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openclaw/crabbox/internal/dream"
	"github.com/openclaw/crabbox/internal/experience"
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

func appendEvent(t *testing.T, s *history.Store, dedupe, kind, subject string, at int64, payload any) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(&history.Event{
		DedupeKey: dedupe, Kind: kind, Subject: subject, Source: "test",
		OccurredAt: at, Payload: raw,
	}); err != nil {
		t.Fatal(err)
	}
}

func testEnvelope(t *testing.T) *dream.Envelope {
	t.Helper()
	env := &dream.Envelope{Arms: []dream.Params{
		{TimeoutSeconds: 60, MemoryMB: 256, CPUs: 1, DiskMB: 512, MaxOutputBytes: 4096},
		{TimeoutSeconds: 300, MemoryMB: 1024, CPUs: 2, DiskMB: 2048, MaxOutputBytes: 16384},
	}}
	if err := env.Validate(); err != nil {
		t.Fatal(err)
	}
	return env
}

// A subject failing repeatedly is one signature, not three problems —
// and an unresolved one ranks ahead of a resolved one.
func TestDiagnoseGroupsAndRanks(t *testing.T) {
	s := openStore(t)
	appendEvent(t, s, "t:r1:F", "test_result", "pkg/F", 100, map[string]any{"status": "fail"})
	appendEvent(t, s, "t:r2:F", "test_result", "pkg/F", 200, map[string]any{"status": "fail"})
	appendEvent(t, s, "t:r3:F", "test_result", "pkg/F", 300, map[string]any{"status": "fail"})
	appendEvent(t, s, "t:r1:G", "test_result", "pkg/G", 100, map[string]any{"status": "fail"})
	appendEvent(t, s, "t:r4:G", "test_result", "pkg/G", 400, map[string]any{"status": "pass"})
	g, err := experience.Reconstruct(s, "")
	if err != nil {
		t.Fatal(err)
	}
	sigs := Diagnose(g)
	if len(sigs) != 2 {
		t.Fatalf("expected 2 signatures, got %d", len(sigs))
	}
	if sigs[0].Subject != "pkg/F" || sigs[0].Resolved {
		t.Fatalf("unresolved recurring failure not ranked first: %+v", sigs[0])
	}
	if sigs[0].Count != 3 {
		t.Fatalf("recurrence count %d, want 3", sigs[0].Count)
	}
	if !sigs[1].Resolved {
		t.Fatal("resolved signature reported unresolved")
	}
}

// Plan: unresolved trusted signature + an untried arm → experiment;
// all arms tried → escalate; adverse verdict → untrusted.
func TestPlanDecisions(t *testing.T) {
	s := openStore(t)
	appendEvent(t, s, "t:r1:F", "test_result", "pkg/F", 100, map[string]any{"status": "fail"})
	g, err := experience.Reconstruct(s, "")
	if err != nil {
		t.Fatal(err)
	}
	env := testEnvelope(t)
	task := dream.Task{ID: "fam-1", Features: map[string]string{"image": "img"}}

	ps := Plan(g, env, nil, task, map[int]bool{0: true})
	if len(ps) != 1 || ps[0].Decision != decideExperiment {
		t.Fatalf("expected experiment proposal, got %+v", ps)
	}
	if ps[0].Experiment.Arm != 1 {
		t.Fatalf("chose tried arm: %+v", ps[0].Experiment)
	}
	ps = Plan(g, env, nil, task, map[int]bool{0: true, 1: true})
	if ps[0].Decision != decideEscalate {
		t.Fatalf("all-arms-tried should escalate, got %+v", ps[0])
	}
}

// The promotion gate refuses thin evidence and absent advantage —
// optimism is not a substitute for outcomes.
func TestPromotionGate(t *testing.T) {
	if r := CheckPromotion(PromotionEvidence{RealizedOutcomes: 1, ReplayDelta: 0.5}); !strings.Contains(r, "insufficient") {
		t.Fatalf("thin evidence not refused: %q", r)
	}
	if r := CheckPromotion(PromotionEvidence{RealizedOutcomes: 10, UntrustedNodes: 2, ReplayDelta: 0.5}); !strings.Contains(r, "adverse") {
		t.Fatalf("adverse verdicts not refused: %q", r)
	}
	if r := CheckPromotion(PromotionEvidence{RealizedOutcomes: 10, ReplayDelta: 0.0}); !strings.Contains(r, "no verified advantage") {
		t.Fatalf("zero delta not refused: %q", r)
	}
	if r := CheckPromotion(PromotionEvidence{RealizedOutcomes: 10, ReplayDelta: 0.25}); r != "" {
		t.Fatalf("sufficient evidence + advantage refused: %q", r)
	}
}
