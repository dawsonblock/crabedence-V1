package cli

import (
	"testing"
)

// TestRunStatusInvariantMatrix pins the allowed relationships between
// exit_code, run_status, and error_kind. This is the complete matrix for the
// frozen run-status invariant (Phase 4 of the evidence hardening plan).
//
// Rules:
//   exit_code == 0 + run_status=succeeded       → valid (error_kind optional)
//   exit_code != 0 + run_status=failed          → valid (error_kind optional)
//   any exit_code + run_status=timed-out        → valid only if error_kind set
//   any exit_code + run_status=canceled         → valid only if error_kind set
//   any other run_status                        → invalid
//   succeeded + exit_code != 0                  → invalid
//   failed + exit_code == 0                     → invalid
func TestRunStatusInvariantMatrix(t *testing.T) {
	cases := []struct {
		name      string
		exitCode  int
		status    RunStatus
		errorKind RunErrorKind
		valid     bool
	}{
		// succeeded
		{"succeeded exit=0 no error_kind", 0, "succeeded", "", true},
		{"succeeded exit=0 with error_kind", 0, "succeeded", "some-error", true},
		{"succeeded exit=1 invalid", 1, "succeeded", "", false},
		{"succeeded exit=-1 invalid", -1, "succeeded", "", false},

		// failed
		{"failed exit=1 no error_kind", 1, "failed", "", true},
		{"failed exit=1 with error_kind", 1, "failed", "command-exit", true},
		{"failed exit=42 with error_kind", 42, "failed", "oom", true},
		{"failed exit=0 invalid", 0, "failed", "", false},

		// timed-out
		{"timed-out exit=124 with error_kind", 124, "timed-out", "timeout", true},
		{"timed-out exit=0 with error_kind", 0, "timed-out", "timeout", true},
		{"timed-out without error_kind invalid", 124, "timed-out", "", false},

		// canceled
		{"canceled exit=130 with error_kind", 130, "canceled", "canceled", true},
		{"canceled exit=0 with error_kind", 0, "canceled", "canceled", true},
		{"canceled without error_kind invalid", 130, "canceled", "", false},

		// invalid statuses
		{"unknown status invalid", 0, "unknown", "", false},
		{"empty status invalid", 0, "", "", false},
		{"running status invalid", 0, "running", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := RunEvidenceV1{
				SchemaVersion: 1,
				EvidenceType:  "run",
				Provider:      "test",
				ExitCode:      tc.exitCode,
				RunStatus:     tc.status,
				ErrorKind:     tc.errorKind,
			}
			err := validateRunStatusInvariant(ev)
			if tc.valid && err != nil {
				t.Fatalf("expected valid, got error: %v", err)
			}
			if !tc.valid && err == nil {
				t.Fatal("expected invalid, got no error")
			}
		})
	}
}
