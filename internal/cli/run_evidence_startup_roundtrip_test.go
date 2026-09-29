package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestStartupConfirmEvidenceRoundTrip verifies that startup_confirm data
// survives a Go encode → Go strict parse → digest verification round-trip.
// This is the Go side of the Go↔worker round-trip test.
func TestStartupConfirmEvidenceRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		sc   *RunEvidenceStartupConfirm
	}{
		{
			name: "timeout-window-success",
			sc: &RunEvidenceStartupConfirm{
				Stage:      "timeout-window",
				DurationMs: 812,
				Ready:      true,
			},
		},
		{
			name: "file-handoff-failure-with-exit",
			sc: &RunEvidenceStartupConfirm{
				Stage:         "file-handoff",
				DurationMs:    250,
				Ready:         false,
				ProcessExited: true,
				Retryable:     false,
			},
		},
		{
			name: "process-exit-retryable",
			sc: &RunEvidenceStartupConfirm{
				Stage:         "process-exit",
				DurationMs:    100,
				Ready:         false,
				ProcessExited: true,
				Retryable:     true,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := NewRunEvidence(RunEvidenceInput{
				Provider:       "tart",
				LeaseID:        "cbx_test",
				Slug:           "test-slug",
				RunID:          "run_test",
				CommandText:    "echo hello",
				ExitCode:       0,
				RunStatus:      "succeeded",
				TotalMs:        1000,
				CommandMs:      500,
				SyncMs:         200,
				StartupConfirm: tc.sc,
			})
			// Marshal to canonical JSON.
			data, err := ev.MarshalJSON()
			if err != nil {
				t.Fatalf("MarshalJSON: %v", err)
			}
			// Verify the startup_confirm field is present in the JSON.
			if !strings.Contains(string(data), `"startup_confirm"`) {
				t.Fatalf("startup_confirm not found in JSON: %s", data)
			}
			// Parse back with the strict parser.
			parsed, err := ParseRunEvidenceV1(data)
			if err != nil {
				t.Fatalf("ParseRunEvidenceV1: %v", err)
			}
			// Verify the startup_confirm field round-tripped.
			if parsed.StartupConfirm == nil {
				t.Fatal("parsed.StartupConfirm is nil")
			}
			if parsed.StartupConfirm.Stage != tc.sc.Stage {
				t.Errorf("stage: got %q, want %q", parsed.StartupConfirm.Stage, tc.sc.Stage)
			}
			if parsed.StartupConfirm.DurationMs != tc.sc.DurationMs {
				t.Errorf("duration_ms: got %d, want %d", parsed.StartupConfirm.DurationMs, tc.sc.DurationMs)
			}
			if parsed.StartupConfirm.Ready != tc.sc.Ready {
				t.Errorf("ready: got %v, want %v", parsed.StartupConfirm.Ready, tc.sc.Ready)
			}
			if parsed.StartupConfirm.ProcessExited != tc.sc.ProcessExited {
				t.Errorf("process_exited: got %v, want %v", parsed.StartupConfirm.ProcessExited, tc.sc.ProcessExited)
			}
			if parsed.StartupConfirm.Retryable != tc.sc.Retryable {
				t.Errorf("retryable: got %v, want %v", parsed.StartupConfirm.Retryable, tc.sc.Retryable)
			}
			// Verify the digest is unchanged.
			if parsed.Digest != ev.Digest {
				t.Fatalf("digest changed: original %s, parsed %s", ev.Digest, parsed.Digest)
			}
			// Verify the digest is correct.
			if !VerifyRunEvidenceDigest(parsed) {
				t.Fatal("digest verification failed")
			}
		})
	}
}

// TestStartupConfirmFromSummaryConversion verifies the single conversion
// function between the timing-report StartupConfirmSummary (camelCase) and
// the evidence-wire RunEvidenceStartupConfirm (snake_case).
func TestStartupConfirmFromSummaryConversion(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		if got := StartupConfirmFromSummary(nil); got != nil {
			t.Fatalf("expected nil, got %v", got)
		}
	})
	t.Run("full", func(t *testing.T) {
		s := &StartupConfirmSummary{
			Stage:         "timeout-window",
			DurationMs:    812,
			Ready:         true,
			ProcessExited: false,
			Retryable:     true,
		}
		got := StartupConfirmFromSummary(s)
		if got == nil {
			t.Fatal("expected non-nil")
		}
		if got.Stage != s.Stage {
			t.Errorf("stage: got %q, want %q", got.Stage, s.Stage)
		}
		if got.DurationMs != s.DurationMs {
			t.Errorf("duration_ms: got %d, want %d", got.DurationMs, s.DurationMs)
		}
		if got.Ready != s.Ready {
			t.Errorf("ready: got %v, want %v", got.Ready, s.Ready)
		}
		if got.ProcessExited != s.ProcessExited {
			t.Errorf("process_exited: got %v, want %v", got.ProcessExited, s.ProcessExited)
		}
		if got.Retryable != s.Retryable {
			t.Errorf("retryable: got %v, want %v", got.Retryable, s.Retryable)
		}
	})
}

// TestStartupConfirmEvidenceWorkerAcceptance generates evidence with
// startup_confirm in Go, then verifies that the worker validator would
// accept the structural shape (no unknown fields, correct types).
// This simulates the Go→TypeScript direction.
func TestStartupConfirmEvidenceWorkerAcceptance(t *testing.T) {
	ev := NewRunEvidence(RunEvidenceInput{
		Provider:  "tart",
		LeaseID:   "cbx_test",
		RunID:     "run_test",
		ExitCode:  0,
		RunStatus: "succeeded",
		TotalMs:   1000,
		CommandMs: 500,
		SyncMs:    200,
		StartupConfirm: &RunEvidenceStartupConfirm{
			Stage:      "timeout-window",
			DurationMs: 812,
			Ready:      true,
		},
	})
	data, err := ev.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	// Parse the JSON into a generic map to simulate what the worker receives.
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	// Verify the startup_confirm field has the correct snake_case keys.
	sc, ok := generic["startup_confirm"].(map[string]any)
	if !ok {
		t.Fatal("startup_confirm is not an object")
	}
	requiredKeys := []string{"stage", "duration_ms", "ready"}
	for _, key := range requiredKeys {
		if _, ok := sc[key]; !ok {
			t.Errorf("startup_confirm missing required key %q", key)
		}
	}
	// Verify no camelCase keys leaked through.
	camelKeys := []string{"durationMs", "processExited"}
	for _, key := range camelKeys {
		if _, ok := sc[key]; ok {
			t.Errorf("startup_confirm contains camelCase key %q (should be snake_case)", key)
		}
	}
}
