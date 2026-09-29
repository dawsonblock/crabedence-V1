package cli

import (
	"crypto/ed25519"
	"testing"
)

func TestBuildTerminalBundleProducesConsistentEvidenceAndReceipt(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub

	outcome := FinalRunOutcome{
		ExitCode:    0,
		RunStatus:   RunStatusSucceeded,
		Command:     []string{"echo", "hello"},
		CommandText: "echo hello",
		Provider:    "tart",
		LeaseID:     "cbx_test001",
		Slug:        "test-slug",
		RunID:       "run_test001",
		Timing: TimingReport{
			TotalMs:   100,
			CommandMs: 80,
			SyncMs:    20,
		},
		TerminalLog: runLogSnapshot{
			Log:        "hello\n",
			FullSHA256: sha256Digest([]byte("hello\n")),
		},
	}

	bundle, err := BuildTerminalBundle(outcome, priv)
	if err != nil {
		t.Fatalf("BuildTerminalBundle: %v", err)
	}

	// Evidence digest must match receipt binding.
	if bundle.Receipt.EvidenceSHA256 != bundle.Evidence.Digest {
		t.Fatalf("evidence binding mismatch: receipt=%s evidence=%s",
			bundle.Receipt.EvidenceSHA256, bundle.Evidence.Digest)
	}

	// Receipt must be V3.
	if bundle.Receipt.SchemaVersion != terminalReceiptSchemaVersion {
		t.Fatalf("expected schema version %d, got %d",
			terminalReceiptSchemaVersion, bundle.Receipt.SchemaVersion)
	}

	// Receipt must have a valid signature.
	if err := verifyTerminalRunReceiptSignature(bundle.Receipt); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}

	// Evidence must have a valid digest.
	if !VerifyRunEvidenceDigest(bundle.Evidence) {
		t.Fatal("evidence digest verification failed")
	}
}

func TestBuildTerminalBundleIsImmutable(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	outcome := FinalRunOutcome{
		ExitCode:    0,
		RunStatus:   RunStatusSucceeded,
		Command:     []string{"true"},
		CommandText: "true",
		Provider:    "tart",
		LeaseID:     "cbx_immutable001",
		RunID:       "run_immutable001",
		Timing: TimingReport{
			TotalMs:   50,
			CommandMs: 50,
			SyncMs:    0,
		},
		TerminalLog: runLogSnapshot{
			Log:        "",
			FullSHA256: sha256Digest([]byte("")),
		},
	}

	bundle1, err := BuildTerminalBundle(outcome, priv)
	if err != nil {
		t.Fatalf("first BuildTerminalBundle: %v", err)
	}

	// Mutate the outcome after the bundle was built. The bundle must not
	// change because it was already built from the original outcome.
	outcome.ExitCode = 1
	outcome.RunStatus = RunStatusFailed

	// Build a second bundle from the mutated outcome — it should differ.
	bundle2, err := BuildTerminalBundle(outcome, priv)
	if err != nil {
		t.Fatalf("second BuildTerminalBundle: %v", err)
	}

	if bundle1.Receipt.ExitCode == bundle2.Receipt.ExitCode {
		t.Fatal("mutating outcome after bundle construction should produce a different bundle, but exit codes match")
	}

	// The first bundle's evidence must still reflect the original outcome.
	if bundle1.Evidence.ExitCode != 0 {
		t.Fatalf("original bundle evidence was mutated: exit_code=%d", bundle1.Evidence.ExitCode)
	}
	if bundle1.Receipt.ExitCode != 0 {
		t.Fatalf("original bundle receipt was mutated: exit_code=%d", bundle1.Receipt.ExitCode)
	}
}

func TestBuildTerminalBundleRejectsNilKey(t *testing.T) {
	outcome := FinalRunOutcome{
		ExitCode:    0,
		RunStatus:   RunStatusSucceeded,
		Command:     []string{"true"},
		CommandText: "true",
		Provider:    "tart",
		LeaseID:     "cbx_nokey001",
		RunID:       "run_nokey001",
	}
	_, err := BuildTerminalBundle(outcome, nil)
	if err == nil {
		t.Fatal("expected error for nil signing key, got nil")
	}
}

func TestBuildTerminalBundleSelfVerifiesFailedRun(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	outcome := FinalRunOutcome{
		ExitCode:    1,
		RunStatus:   RunStatusFailed,
		ErrorKind:   RunErrorCommandExit,
		Command:     []string{"false"},
		CommandText: "false",
		Provider:    "tart",
		LeaseID:     "cbx_fail001",
		RunID:       "run_fail001",
		Timing: TimingReport{
			TotalMs:   30,
			CommandMs: 30,
			SyncMs:    0,
		},
		TerminalLog: runLogSnapshot{
			Log:        "",
			FullSHA256: sha256Digest([]byte("")),
		},
	}

	bundle, err := BuildTerminalBundle(outcome, priv)
	if err != nil {
		t.Fatalf("BuildTerminalBundle for failed run: %v", err)
	}

	if bundle.Evidence.ExitCode != 1 {
		t.Fatalf("expected exit_code=1, got %d", bundle.Evidence.ExitCode)
	}
	if bundle.Evidence.RunStatus != RunStatusFailed {
		t.Fatalf("expected run_status=failed, got %s", bundle.Evidence.RunStatus)
	}
	if bundle.Receipt.EvidenceSHA256 != bundle.Evidence.Digest {
		t.Fatal("evidence binding mismatch for failed run")
	}
}

func TestAuxiliaryErrorFormat(t *testing.T) {
	err := &AuxiliaryError{Op: "write evidence json", Err: exit(7, "disk full")}
	if err.Error() != "write evidence json: disk full" {
		t.Fatalf("unexpected error format: %s", err.Error())
	}
}

func TestAuxiliaryErrorsJoinsMultiple(t *testing.T) {
	err1 := &AuxiliaryError{Op: "op1", Err: exit(1, "err1")}
	err2 := &AuxiliaryError{Op: "op2", Err: exit(2, "err2")}
	joined := auxiliaryErrors(err1, err2)
	if joined == nil {
		t.Fatal("expected joined error, got nil")
	}
	// Should contain both operations.
	msg := joined.Error()
	if !contains(msg, "op1") || !contains(msg, "op2") {
		t.Fatalf("expected both ops in joined error, got: %s", msg)
	}
}

func TestAuxiliaryErrorsReturnsNilForNoErrors(t *testing.T) {
	if auxiliaryErrors(nil, nil) != nil {
		t.Fatal("expected nil for no errors")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
