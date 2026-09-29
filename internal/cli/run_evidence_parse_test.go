package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// validEvidenceJSON returns a minimal valid evidence JSON document for testing.
func validEvidenceJSON() string {
	return `{
		"schema_version": 1,
		"evidence_type": "run",
		"provider": "tart",
		"exit_code": 0,
		"run_status": "succeeded",
		"total_ms": 10,
		"command_ms": 10,
		"sync_ms": 0,
		"digest": "910e0b1191fa68e5fd23d8386abdaf4073f758198f1812bae322d8abb16a2a08"
	}`
}

func TestParseRunEvidenceV1AcceptsValid(t *testing.T) {
	ev, err := ParseRunEvidenceV1([]byte(validEvidenceJSON()))
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if ev.SchemaVersion != 1 {
		t.Fatalf("expected schema_version=1, got %d", ev.SchemaVersion)
	}
	if ev.Provider != "tart" {
		t.Fatalf("expected provider=tart, got %s", ev.Provider)
	}
}

func TestParseRunEvidenceV1RejectsUnknownField(t *testing.T) {
	data := strings.Replace(validEvidenceJSON(), `"digest":`, `"unknown_field": "x", "digest":`, 1)
	_, err := ParseRunEvidenceV1([]byte(data))
	if err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected 'unknown field' error, got: %v", err)
	}
}

func TestParseRunEvidenceV1RejectsDuplicateKey(t *testing.T) {
	data := strings.Replace(validEvidenceJSON(),
		`"provider": "tart",`,
		`"provider": "tart", "provider": "aws",`, 1)
	_, err := ParseRunEvidenceV1([]byte(data))
	if err == nil {
		t.Fatal("expected error for duplicate key, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("expected 'duplicate key' error, got: %v", err)
	}
}

func TestParseRunEvidenceV1RejectsTrailingData(t *testing.T) {
	data := validEvidenceJSON() + `{"extra": "object"}`
	_, err := ParseRunEvidenceV1([]byte(data))
	if err == nil {
		t.Fatal("expected error for trailing data, got nil")
	}
	if !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("expected 'trailing' error, got: %v", err)
	}
}

func TestParseRunEvidenceV1RejectsNonObject(t *testing.T) {
	_, err := ParseRunEvidenceV1([]byte(`[1, 2, 3]`))
	if err == nil {
		t.Fatal("expected error for array, got nil")
	}
}

func TestParseRunEvidenceV1RejectsEmpty(t *testing.T) {
	_, err := ParseRunEvidenceV1([]byte(``))
	if err == nil {
		t.Fatal("expected error for empty input, got nil")
	}
}

func TestValidateRunEvidenceV1RejectsSucceededWithNonZeroExit(t *testing.T) {
	ev := RunEvidenceV1{
		SchemaVersion: 1,
		EvidenceType:  "run",
		Provider:      "tart",
		ExitCode:      1,
		RunStatus:     "succeeded",
	}
	err := ValidateRunEvidenceV1(ev)
	if err == nil {
		t.Fatal("expected error for succeeded with exit_code=1, got nil")
	}
	if !strings.Contains(err.Error(), "succeeded") {
		t.Fatalf("expected succeeded-related error, got: %v", err)
	}
}

func TestValidateRunEvidenceV1RejectsFailedWithZeroExit(t *testing.T) {
	ev := RunEvidenceV1{
		SchemaVersion: 1,
		EvidenceType:  "run",
		Provider:      "tart",
		ExitCode:      0,
		RunStatus:     "failed",
	}
	err := ValidateRunEvidenceV1(ev)
	if err == nil {
		t.Fatal("expected error for failed with exit_code=0, got nil")
	}
	if !strings.Contains(err.Error(), "failed") {
		t.Fatalf("expected failed-related error, got: %v", err)
	}
}

func TestValidateRunEvidenceV1RejectsNegativeTiming(t *testing.T) {
	ev := RunEvidenceV1{
		SchemaVersion: 1,
		EvidenceType:  "run",
		Provider:      "tart",
		ExitCode:      0,
		RunStatus:     "succeeded",
		TotalMs:       -1,
	}
	err := ValidateRunEvidenceV1(ev)
	if err == nil {
		t.Fatal("expected error for negative total_ms, got nil")
	}
	if !strings.Contains(err.Error(), "total_ms") {
		t.Fatalf("expected total_ms error, got: %v", err)
	}
}

func TestValidateRunEvidenceV1RejectsInvalidRunStatus(t *testing.T) {
	ev := RunEvidenceV1{
		SchemaVersion: 1,
		EvidenceType:  "run",
		Provider:      "tart",
		ExitCode:      0,
		RunStatus:     "unknown",
	}
	err := ValidateRunEvidenceV1(ev)
	if err == nil {
		t.Fatal("expected error for invalid run_status, got nil")
	}
	if !strings.Contains(err.Error(), "run_status") {
		t.Fatalf("expected run_status error, got: %v", err)
	}
}

func TestValidateRunEvidenceV1AcceptsTimedOutWithErrorKind(t *testing.T) {
	ev := RunEvidenceV1{
		SchemaVersion: 1,
		EvidenceType:  "run",
		Provider:      "tart",
		ExitCode:      124,
		RunStatus:     "timed-out",
		ErrorKind:     "timeout",
	}
	if err := ValidateRunEvidenceV1(ev); err != nil {
		t.Fatalf("expected success for timed-out with error_kind, got: %v", err)
	}
}

func TestValidateRunEvidenceV1RejectsTimedOutWithoutErrorKind(t *testing.T) {
	ev := RunEvidenceV1{
		SchemaVersion: 1,
		EvidenceType:  "run",
		Provider:      "tart",
		ExitCode:      124,
		RunStatus:     "timed-out",
	}
	err := ValidateRunEvidenceV1(ev)
	if err == nil {
		t.Fatal("expected error for timed-out without error_kind, got nil")
	}
}

func TestVerifyRunEvidenceDigestErrorReturnsMismatch(t *testing.T) {
	ev := RunEvidenceV1{
		SchemaVersion: 1,
		EvidenceType:  "run",
		Provider:      "tart",
		ExitCode:      0,
		RunStatus:     "succeeded",
		TotalMs:       10,
		CommandMs:     10,
		SyncMs:        0,
		Digest:        "0000000000000000000000000000000000000000000000000000000000000000",
	}
	err := VerifyRunEvidenceDigestError(ev)
	if err == nil {
		t.Fatal("expected digest mismatch error, got nil")
	}
}

func TestVerifyRunEvidenceDigestErrorAcceptsValid(t *testing.T) {
	ev := RunEvidenceV1{
		SchemaVersion: 1,
		EvidenceType:  "run",
		Provider:      "tart",
		ExitCode:      0,
		RunStatus:     "succeeded",
		TotalMs:       10,
		CommandMs:     10,
		SyncMs:        0,
	}
	// Compute the correct digest.
	ev.Digest = runEvidenceDigest(ev)
	if err := VerifyRunEvidenceDigestError(ev); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

// TestParseRunEvidenceV1RoundtripsWithJSONMarshal ensures the strict parser
// accepts JSON that json.Marshal produces for a RunEvidenceV1.
func TestParseRunEvidenceV1RoundtripsWithJSONMarshal(t *testing.T) {
	ev := RunEvidenceV1{
		SchemaVersion: 1,
		EvidenceType:  "run",
		Provider:      "aws",
		ExitCode:      0,
		RunStatus:     "succeeded",
		TotalMs:       100,
		CommandMs:     80,
		SyncMs:        20,
	}
	ev.Digest = runEvidenceDigest(ev)
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRunEvidenceV1(data)
	if err != nil {
		t.Fatalf("strict parser rejected json.Marshal output: %v", err)
	}
	if parsed.Digest != ev.Digest {
		t.Fatalf("digest mismatch after roundtrip: %s != %s", parsed.Digest, ev.Digest)
	}
}
