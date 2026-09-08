package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNewRunEvidenceNormalizesStatus(t *testing.T) {
	ev := NewRunEvidence(RunEvidenceInput{
		Provider:  "hetzner",
		ExitCode:  0,
		TotalMs:   5000,
		CommandMs: 3000,
		SyncMs:    2000,
	})
	if ev.RunStatus != RunStatusSucceeded {
		t.Fatalf("status = %q, want succeeded", ev.RunStatus)
	}
	if ev.SchemaVersion != 1 {
		t.Fatalf("schema_version = %d, want 1", ev.SchemaVersion)
	}
	if ev.EvidenceType != "run" {
		t.Fatalf("evidence_type = %q, want run", ev.EvidenceType)
	}
}

func TestNewRunEvidenceClassifiesFailure(t *testing.T) {
	ev := NewRunEvidence(RunEvidenceInput{
		Provider:  "mxc",
		ExitCode:  42,
		TotalMs:   1000,
		CommandMs: 800,
	})
	if ev.RunStatus != RunStatusFailed {
		t.Fatalf("status = %q, want failed", ev.RunStatus)
	}
	if ev.ErrorKind != RunErrorCommandExit {
		t.Fatalf("error_kind = %q, want command-exit", ev.ErrorKind)
	}
}

func TestRunEvidenceDigestIsConsistent(t *testing.T) {
	ev := NewRunEvidence(RunEvidenceInput{
		Provider:  "aws",
		LeaseID:   "cbx_test001",
		ExitCode:  0,
		TotalMs:   10000,
		CommandMs: 5000,
		SyncMs:    5000,
		StartedAt: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		EndedAt:   time.Date(2026, 1, 1, 12, 0, 10, 0, time.UTC),
	})
	if ev.Digest == "" {
		t.Fatal("digest is empty")
	}
	if !VerifyRunEvidenceDigest(ev) {
		t.Fatal("digest verification failed")
	}
}

func TestRunEvidenceDigestDetectsTampering(t *testing.T) {
	ev := NewRunEvidence(RunEvidenceInput{
		Provider:  "gcp",
		ExitCode:  0,
		TotalMs:   3000,
		CommandMs: 2000,
		SyncMs:    1000,
	})
	// Tamper with a field after digest computation.
	ev.ExitCode = 1
	if VerifyRunEvidenceDigest(ev) {
		t.Fatal("digest verification should fail after tampering")
	}
}

func TestNewRunEvidenceTruncatesTimestampsToMilliseconds(t *testing.T) {
	// Sub-millisecond precision must be truncated so Go and TypeScript
	// produce identical timestamp strings for cross-language digest
	// compatibility.
	startedAt := time.Date(2026, 1, 15, 12, 30, 0, 123456789, time.UTC)
	endedAt := time.Date(2026, 1, 15, 12, 30, 5, 987654321, time.UTC)
	ev := NewRunEvidence(RunEvidenceInput{
		Provider:  "hetzner",
		ExitCode:  0,
		TotalMs:   5000,
		CommandMs: 3000,
		SyncMs:    2000,
		StartedAt: startedAt,
		EndedAt:   endedAt,
	})
	wantStarted := "2026-01-15T12:30:00.123Z"
	wantEnded := "2026-01-15T12:30:05.987Z"
	if ev.StartedAt != wantStarted {
		t.Fatalf("started_at = %q, want %q", ev.StartedAt, wantStarted)
	}
	if ev.EndedAt != wantEnded {
		t.Fatalf("ended_at = %q, want %q", ev.EndedAt, wantEnded)
	}
	// Digest must verify with the truncated timestamps.
	if !VerifyRunEvidenceDigest(ev) {
		t.Fatal("digest verification failed with truncated timestamps")
	}
}

func TestRunEvidenceMarshalJSONRecomputesDigest(t *testing.T) {
	ev := RunEvidenceV1{
		SchemaVersion: 1,
		EvidenceType:  "run",
		Provider:      "azure",
		ExitCode:      0,
		RunStatus:     RunStatusSucceeded,
		TotalMs:       2000,
		CommandMs:     1500,
		SyncMs:        500,
	}
	// Digest is empty; MarshalJSON should compute it.
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded RunEvidenceV1
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Digest == "" {
		t.Fatal("digest was not computed by MarshalJSON")
	}
	if !VerifyRunEvidenceDigest(decoded) {
		t.Fatal("digest from MarshalJSON is invalid")
	}
}

func TestRunEvidenceFromTimingReport(t *testing.T) {
	report := TimingReport{
		Provider:      "hetzner",
		LeaseID:       "cbx_test002",
		Slug:          "test-lease",
		ExitCode:      1,
		RunStatus:     RunStatusFailed,
		ErrorKind:     RunErrorCommandExit,
		TotalMs:       8000,
		CommandMs:     6000,
		SyncMs:        2000,
		SyncDelegated: false,
		BlockedStage:  "user-command",
		RetryLikely:   "false",
		Artifacts:     []runArtifact{{Kind: "log", Path: "/tmp/run.log", Bytes: 1024}},
	}
	ev := RunEvidenceFromTimingReport(report)
	if ev.Provider != "hetzner" {
		t.Fatalf("provider = %q", ev.Provider)
	}
	if ev.RunStatus != RunStatusFailed {
		t.Fatalf("status = %q", ev.RunStatus)
	}
	if ev.BlockedStage != "user-command" {
		t.Fatalf("blocked_stage = %q", ev.BlockedStage)
	}
	if len(ev.Artifacts) != 1 || ev.Artifacts[0].Bytes != 1024 {
		t.Fatalf("artifacts = %+v", ev.Artifacts)
	}
	if !VerifyRunEvidenceDigest(ev) {
		t.Fatal("digest invalid")
	}
}

func TestRunEvidenceFromRunResult(t *testing.T) {
	result := RunResult{
		ExitCode:      0,
		Status:        RunStatusSucceeded,
		Provider:      "mxc",
		LeaseID:       "cbx_mxc_001",
		Command:       3 * time.Second,
		Total:         5 * time.Second,
		SyncDelegated: true,
		CommandText:   "npm test",
		Artifacts:     []RunArtifact{{Kind: "junit", Path: "test-results.xml"}},
	}
	ev := RunEvidenceFromRunResult(result)
	if ev.Provider != "mxc" {
		t.Fatalf("provider = %q", ev.Provider)
	}
	if ev.SyncDelegated != true {
		t.Fatal("sync_delegated not set")
	}
	if ev.CommandText != "npm test" {
		t.Fatalf("command_text = %q", ev.CommandText)
	}
	if !VerifyRunEvidenceDigest(ev) {
		t.Fatal("digest invalid")
	}
}

func TestRunEvidenceSummary(t *testing.T) {
	ev := NewRunEvidence(RunEvidenceInput{
		Provider:     "aws",
		LeaseID:      "cbx_test003",
		ExitCode:     1,
		BlockedStage: "sync",
		RetryLikely:  "true",
		TotalMs:      5000,
	})
	summary := ev.Summary()
	for _, want := range []string{"provider=aws", "status=failed", "exit=1", "total=5000ms", "lease=cbx_test003", "blocked=sync", "retry=true"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary %q missing %q", summary, want)
		}
	}
}

func TestRunEvidenceJSONRoundTrip(t *testing.T) {
	ev := NewRunEvidence(RunEvidenceInput{
		Provider:      "daytona",
		LeaseID:       "cbx_day_001",
		RunID:         "run_001",
		ExitCode:      0,
		RunStatus:     RunStatusSucceeded,
		TotalMs:       12000,
		CommandMs:     8000,
		SyncMs:        4000,
		SyncDelegated: true,
		RunnerPhases:  []RunnerPhase{{Name: "command", Ms: 8000}},
		SyncPhases:    []TimingPhase{{Name: "rsync", Ms: 3000}, {Name: "git_hydrate", Ms: 1000}},
		StartedAt:     time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		EndedAt:       time.Date(2026, 1, 1, 12, 0, 12, 0, time.UTC),
	})
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded RunEvidenceV1
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !VerifyRunEvidenceDigest(decoded) {
		t.Fatal("digest invalid after round-trip")
	}
	if decoded.Provider != ev.Provider || decoded.RunID != ev.RunID {
		t.Fatalf("round-trip mismatch: %+v vs %+v", decoded, ev)
	}
	if len(decoded.RunnerPhases) != 1 || decoded.RunnerPhases[0].Name != "command" {
		t.Fatalf("runner_phases = %+v", decoded.RunnerPhases)
	}
	if len(decoded.SyncPhases) != 2 {
		t.Fatalf("sync_phases = %+v", decoded.SyncPhases)
	}
}
