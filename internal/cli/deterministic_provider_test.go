package cli

import (
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// deterministicProvider is a test provider that produces configurable,
// deterministic results for E2E evidence and receipt tests. It does not
// require any external infrastructure.
type deterministicProvider struct{}

func (deterministicProvider) Name() string      { return "deterministic-test" }
func (deterministicProvider) Aliases() []string { return nil }
func (deterministicProvider) Spec() ProviderSpec {
	return ProviderSpec{
		Name:        "deterministic-test",
		Family:      "deterministic-test",
		Kind:        ProviderKindDelegatedRun,
		Targets:     []TargetSpec{{OS: targetLinux}},
		Coordinator: CoordinatorNever,
	}
}
func (deterministicProvider) RegisterFlags(*flag.FlagSet, Config) any { return nil }
func (deterministicProvider) ApplyFlags(*Config, *flag.FlagSet, any) error {
	return nil
}
func (p deterministicProvider) Configure(Config, Runtime) (Backend, error) {
	return deterministicBackend{spec: p.Spec()}, nil
}

// deterministicBackend produces a RunResult with configurable exit code,
// output, and startup confirmation via package-level hooks.
type deterministicBackend struct {
	spec ProviderSpec
}

// deterministicRunConfig controls the next Run() output.
var deterministicRunConfig = struct {
	ExitCode       int
	Status         RunStatus
	ErrorKind      RunErrorKind
	CommandText    string
	LogExcerpt     string
	StartupConfirm *StartupConfirmSummary
}{
	ExitCode:    0,
	Status:      RunStatusSucceeded,
	CommandText: "echo hello",
	LogExcerpt:  "hello\n",
}

func (b deterministicBackend) Spec() ProviderSpec { return b.spec }
func (b deterministicBackend) Warmup(context.Context, WarmupRequest) error {
	return nil
}
func (b deterministicBackend) Run(context.Context, RunRequest) (RunResult, error) {
	cfg := deterministicRunConfig
	result := RunResult{
		Provider:    b.spec.Name,
		LeaseID:     "cbx_deterministic",
		Slug:        "deterministic-test",
		ExitCode:    cfg.ExitCode,
		Status:      cfg.Status,
		ErrorKind:   cfg.ErrorKind,
		CommandText: cfg.CommandText,
		LogExcerpt:  cfg.LogExcerpt,
		Command:     100 * time.Millisecond,
		Total:       500 * time.Millisecond,
	}
	if cfg.StartupConfirm != nil {
		result.StartupConfirm = cfg.StartupConfirm
	}
	return result, nil
}
func (b deterministicBackend) List(context.Context, ListRequest) ([]LeaseView, error) {
	return nil, nil
}
func (b deterministicBackend) Status(context.Context, StatusRequest) (StatusView, error) {
	return StatusView{}, nil
}
func (b deterministicBackend) Stop(context.Context, StopRequest) error { return nil }

// TestDeterministicProviderGeneratesValidEvidence verifies that a
// deterministic test provider produces evidence that passes Go's own
// strict validation and digest verification. This is the foundation
// for E2E interop tests: if Go can't generate valid evidence, nothing
// downstream can verify it.
func TestDeterministicProviderGeneratesValidEvidence(t *testing.T) {
	deterministicRunConfig = struct {
		ExitCode       int
		Status         RunStatus
		ErrorKind      RunErrorKind
		CommandText    string
		LogExcerpt     string
		StartupConfirm *StartupConfirmSummary
	}{
		ExitCode:    0,
		Status:      RunStatusSucceeded,
		CommandText: "echo hello",
		LogExcerpt:  "hello\n",
		StartupConfirm: &StartupConfirmSummary{
			Stage:      "timeout-window",
			DurationMs: 100,
			Ready:      true,
		},
	}

	result, err := deterministicBackend{spec: deterministicProvider{}.Spec()}.Run(context.Background(), RunRequest{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	ev := NewRunEvidence(RunEvidenceInput{
		Provider:       result.Provider,
		LeaseID:        result.LeaseID,
		Slug:           result.Slug,
		RunID:          "run_deterministic_001",
		CommandText:    result.CommandText,
		ExitCode:       result.ExitCode,
		RunStatus:      result.Status,
		TotalMs:        result.Total.Milliseconds(),
		CommandMs:      result.Command.Milliseconds(),
		StartupConfirm: StartupConfirmFromSummary(result.StartupConfirm),
	})

	data, err := ev.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	parsed, err := ParseRunEvidenceV1(data)
	if err != nil {
		t.Fatalf("ParseRunEvidenceV1: %v", err)
	}
	if err := ValidateRunEvidenceV1(parsed); err != nil {
		t.Fatalf("ValidateRunEvidenceV1: %v", err)
	}
	if !VerifyRunEvidenceDigest(parsed) {
		t.Fatal("digest verification failed")
	}
	if parsed.StartupConfirm == nil {
		t.Fatal("startup_confirm missing from parsed evidence")
	}
	if parsed.StartupConfirm.Stage != "timeout-window" {
		t.Fatalf("startup_confirm.stage=%q", parsed.StartupConfirm.Stage)
	}
}

// TestDeterministicProviderEvidenceAcceptedByCoordinator verifies the
// full E2E flow: deterministic provider → evidence generation →
// coordinator finish request → coordinator receives valid evidence.
// The mock coordinator validates the evidence shape to ensure it
// matches what the TypeScript worker expects.
func TestDeterministicProviderEvidenceAcceptedByCoordinator(t *testing.T) {
	deterministicRunConfig = struct {
		ExitCode       int
		Status         RunStatus
		ErrorKind      RunErrorKind
		CommandText    string
		LogExcerpt     string
		StartupConfirm *StartupConfirmSummary
	}{
		ExitCode:    0,
		Status:      RunStatusSucceeded,
		CommandText: "npm test",
		LogExcerpt:  "all tests passed\n",
		StartupConfirm: &StartupConfirmSummary{
			Stage:      "timeout-window",
			DurationMs: 200,
			Ready:      true,
		},
	}

	result, err := deterministicBackend{spec: deterministicProvider{}.Spec()}.Run(context.Background(), RunRequest{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	ev := NewRunEvidence(RunEvidenceInput{
		Provider:       result.Provider,
		LeaseID:        result.LeaseID,
		Slug:           result.Slug,
		RunID:          "run_e2e_001",
		CommandText:    result.CommandText,
		ExitCode:       result.ExitCode,
		RunStatus:      result.Status,
		TotalMs:        result.Total.Milliseconds(),
		CommandMs:      result.Command.Milliseconds(),
		StartupConfirm: StartupConfirmFromSummary(result.StartupConfirm),
	})

	var finishBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/runs/run_e2e_001/finish" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&finishBody); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(`{"run":{"id":"run_e2e_001","leaseID":"cbx_deterministic","owner":"alice@example.com","org":"example-org","provider":"deterministic-test","class":"standard","serverType":"test","command":["npm","test"],"state":"succeeded","phase":"succeeded","exitCode":0,"logBytes":0,"logTruncated":false,"startedAt":"2026-01-15T12:00:00Z"}}`))
	}))
	defer server.Close()

	client := CoordinatorClient{BaseURL: server.URL, Client: server.Client()}
	if _, err := client.FinishRun(context.Background(), "run_e2e_001", 0, 100*time.Millisecond, 400*time.Millisecond, "", false, nil, nil, FailureClassification{}, nil, &ev); err != nil {
		t.Fatal(err)
	}

	// Verify the coordinator received valid evidence.
	evidence, ok := finishBody["evidence"].(map[string]any)
	if !ok {
		t.Fatalf("evidence missing from finish body: %#v", finishBody)
	}
	if evidence["schema_version"] != float64(1) {
		t.Fatalf("schema_version=%v", evidence["schema_version"])
	}
	if evidence["evidence_type"] != "run" {
		t.Fatalf("evidence_type=%v", evidence["evidence_type"])
	}
	if evidence["provider"] != "deterministic-test" {
		t.Fatalf("provider=%v", evidence["provider"])
	}
	if evidence["run_status"] != "succeeded" {
		t.Fatalf("run_status=%v", evidence["run_status"])
	}
	digest, ok := evidence["digest"].(string)
	if !ok || len(digest) != 64 {
		t.Fatalf("digest invalid: %v", evidence["digest"])
	}
	// Verify startup_confirm was propagated.
	sc, ok := evidence["startup_confirm"].(map[string]any)
	if !ok {
		t.Fatal("startup_confirm missing from evidence sent to coordinator")
	}
	if sc["stage"] != "timeout-window" {
		t.Fatalf("startup_confirm.stage=%v", sc["stage"])
	}
	if sc["ready"] != true {
		t.Fatalf("startup_confirm.ready=%v", sc["ready"])
	}
	// Verify no camelCase keys leaked.
	for key := range sc {
		if key != "stage" && key != "duration_ms" && key != "ready" &&
			key != "process_exited" && key != "retryable" {
			t.Fatalf("startup_confirm contains unknown key %q", key)
		}
	}
}

// TestDeterministicProviderFailureEvidenceWithStartupConfirm verifies
// that a failed run with startup confirmation failure produces valid
// evidence with the correct status invariant and startup_confirm fields.
func TestDeterministicProviderFailureEvidenceWithStartupConfirm(t *testing.T) {
	deterministicRunConfig = struct {
		ExitCode       int
		Status         RunStatus
		ErrorKind      RunErrorKind
		CommandText    string
		LogExcerpt     string
		StartupConfirm *StartupConfirmSummary
	}{
		ExitCode:    1,
		Status:      RunStatusFailed,
		ErrorKind:   RunErrorCommandExit,
		CommandText: "npm test",
		LogExcerpt:  "tests failed\n",
		StartupConfirm: &StartupConfirmSummary{
			Stage:         "file-handoff",
			DurationMs:    50,
			Ready:         false,
			ProcessExited: true,
			Retryable:     false,
		},
	}

	result, err := deterministicBackend{spec: deterministicProvider{}.Spec()}.Run(context.Background(), RunRequest{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	ev := NewRunEvidence(RunEvidenceInput{
		Provider:       result.Provider,
		LeaseID:        result.LeaseID,
		Slug:           result.Slug,
		RunID:          "run_fail_001",
		CommandText:    result.CommandText,
		ExitCode:       result.ExitCode,
		RunStatus:      result.Status,
		ErrorKind:      result.ErrorKind,
		TotalMs:        result.Total.Milliseconds(),
		CommandMs:      result.Command.Milliseconds(),
		StartupConfirm: StartupConfirmFromSummary(result.StartupConfirm),
	})

	data, err := ev.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	parsed, err := ParseRunEvidenceV1(data)
	if err != nil {
		t.Fatalf("ParseRunEvidenceV1: %v", err)
	}
	if err := ValidateRunEvidenceV1(parsed); err != nil {
		t.Fatalf("ValidateRunEvidenceV1: %v", err)
	}
	if !VerifyRunEvidenceDigest(parsed) {
		t.Fatal("digest verification failed")
	}
	if parsed.RunStatus != "failed" {
		t.Fatalf("run_status=%q, want failed", parsed.RunStatus)
	}
	if parsed.ExitCode != 1 {
		t.Fatalf("exit_code=%d, want 1", parsed.ExitCode)
	}
	if parsed.StartupConfirm == nil {
		t.Fatal("startup_confirm missing")
	}
	if parsed.StartupConfirm.Ready != false {
		t.Fatalf("startup_confirm.ready=%v, want false", parsed.StartupConfirm.Ready)
	}
	if parsed.StartupConfirm.ProcessExited != true {
		t.Fatalf("startup_confirm.process_exited=%v, want true", parsed.StartupConfirm.ProcessExited)
	}
}

// TestGoEvidenceJSONShapeMatchesWorkerExpectations verifies that
// Go-generated evidence JSON has the exact field names and structure
// the TypeScript worker validator expects. This is a structural
// cross-runtime interop check: if Go emits a field the worker doesn't
// recognize, or omits a field the worker requires, the evidence would
// be rejected.
func TestGoEvidenceJSONShapeMatchesWorkerExpectations(t *testing.T) {
	cases := []struct {
		name  string
		input RunEvidenceInput
	}{
		{
			name: "minimal-succeeded",
			input: RunEvidenceInput{
				Provider: "test", LeaseID: "cbx_001", RunID: "run_001",
				ExitCode: 0, RunStatus: RunStatusSucceeded,
				TotalMs: 1000, CommandMs: 500,
			},
		},
		{
			name: "failed-with-error-kind",
			input: RunEvidenceInput{
				Provider: "test", LeaseID: "cbx_002", RunID: "run_002",
				ExitCode: 1, RunStatus: RunStatusFailed, ErrorKind: RunErrorCommandExit,
				TotalMs: 2000, CommandMs: 1500,
			},
		},
		{
			name: "timeout-with-startup-confirm",
			input: RunEvidenceInput{
				Provider: "test", LeaseID: "cbx_003", RunID: "run_003",
				ExitCode: 124, RunStatus: RunStatusTimedOut, ErrorKind: RunErrorTimeout,
				TotalMs: 30000, CommandMs: 29000,
				StartupConfirm: &RunEvidenceStartupConfirm{
					Stage: "timeout-window", DurationMs: 30000, Ready: false,
				},
			},
		},
		{
			name: "with-phases-and-artifacts",
			input: RunEvidenceInput{
				Provider: "test", LeaseID: "cbx_004", RunID: "run_004",
				ExitCode: 0, RunStatus: RunStatusSucceeded,
				TotalMs: 5000, CommandMs: 3000, SyncMs: 2000,
				RunnerPhases: []RunnerPhase{
					{Name: "lease", Ms: 1000},
					{Name: "command", Ms: 3000},
				},
				SyncPhases: []TimingPhase{
					{Name: "rsync", Ms: 1500},
					{Name: "git", Ms: 500},
				},
				CommandPhases: []TimingPhase{
					{Name: "exec", Ms: 2900},
					{Name: "teardown", Ms: 100},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := NewRunEvidence(tc.input)
			data, err := ev.MarshalJSON()
			if err != nil {
				t.Fatalf("MarshalJSON: %v", err)
			}
			var raw map[string]any
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatalf("json.Unmarshal: %v", err)
			}
			// Verify required top-level fields the worker expects.
			required := []string{"schema_version", "evidence_type", "provider", "exit_code", "run_status", "digest"}
			for _, key := range required {
				if _, ok := raw[key]; !ok {
					t.Errorf("missing required field %q in JSON: %s", key, data)
				}
			}
			// Verify schema_version is exactly 1.
			if raw["schema_version"] != float64(1) {
				t.Errorf("schema_version=%v, want 1", raw["schema_version"])
			}
			// Verify evidence_type is "run".
			if raw["evidence_type"] != "run" {
				t.Errorf("evidence_type=%v, want run", raw["evidence_type"])
			}
			// Verify digest is a 64-char hex string.
			digest, ok := raw["digest"].(string)
			if !ok || len(digest) != 64 {
				t.Errorf("digest invalid: %v", raw["digest"])
			}
			// Verify no camelCase keys in startup_confirm.
			if sc, ok := raw["startup_confirm"].(map[string]any); ok {
				for key := range sc {
					if strings.ContainsAny(key, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
						t.Errorf("startup_confirm contains camelCase key %q", key)
					}
				}
			}
			// Verify the evidence can be re-parsed and validated.
			parsed, err := ParseRunEvidenceV1(data)
			if err != nil {
				t.Fatalf("ParseRunEvidenceV1: %v", err)
			}
			if err := ValidateRunEvidenceV1(parsed); err != nil {
				t.Fatalf("ValidateRunEvidenceV1: %v", err)
			}
			if !VerifyRunEvidenceDigest(parsed) {
				t.Fatal("digest verification failed")
			}
		})
	}
}
