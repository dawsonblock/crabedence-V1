package idempotency

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// contract_test.go provides non-live contract coverage for the
// durable execution contract. These tests do not require a database
// and run as part of the effect-fabric-contract gate.

// ─── LeaseConfig validation ────────────────────────────────────────────

func TestLeaseConfigValidate(t *testing.T) {
	cfg := LeaseConfig{
		DefaultDuration: 5 * time.Minute,
		MaxDuration:     30 * time.Minute,
		RenewalWindow:   1 * time.Minute,
	}

	tests := []struct {
		name     string
		duration time.Duration
		wantErr  bool
	}{
		{"valid", 5 * time.Minute, false},
		{"zero", 0, true},
		{"negative", -time.Minute, true},
		{"exceeds max", 31 * time.Minute, true},
		{"at max", 30 * time.Minute, false},
		{"short", time.Second, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cfg.Validate(tt.duration)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate(%v) error = %v, wantErr %v", tt.duration, err, tt.wantErr)
			}
		})
	}
}

func TestLeaseConfigValidateNoMaxDuration(t *testing.T) {
	cfg := LeaseConfig{
		DefaultDuration: 5 * time.Minute,
		MaxDuration:     0, // no max
	}
	// Any positive duration should be accepted when MaxDuration is 0.
	if err := cfg.Validate(24 * time.Hour); err != nil {
		t.Errorf("Validate(24h) with MaxDuration=0 should pass, got: %v", err)
	}
	// Zero and negative still rejected.
	if err := cfg.Validate(0); err == nil {
		t.Error("Validate(0) should fail even with MaxDuration=0")
	}
}

// ─── AcquireResult ────────────────────────────────────────────────────

func TestAcquireResultAcquired(t *testing.T) {
	tests := []struct {
		kind     AcquireResultKind
		acquired bool
	}{
		{LeaseAcquired, true},
		{LeaseReclaimed, true},
		{LeaseHeldByOther, false},
		{TerminalReplay, false},
		{RecoveryRequired, false},
		{IdempotencyConflict, false},
	}
	for _, tt := range tests {
		r := AcquireResult{Kind: tt.kind}
		if got := r.Acquired(); got != tt.acquired {
			t.Errorf("Kind=%s: Acquired() = %v, want %v", tt.kind, got, tt.acquired)
		}
	}
}

// ─── TerminalReceipt digest ──────────────────────────────────────────

func TestTerminalReceiptDigestDeterminism(t *testing.T) {
	receipt := TerminalReceipt{
		ExecutionID:     "exec-123",
		Capability:      "test.counter.increment",
		Principal:       "alice@example.com",
		RequestDigest:   "digest-abc",
		TerminalStatus:  StateCommitted,
		CanonicalResult: json.RawMessage(`{"value":42}`),
		ProviderID:      "local",
		ProviderRunID:   "run-1",
		EvidenceDigest:  "ev-digest",
		ReceiptVersion:  3,
		FinalizedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	d1, err := receipt.Digest()
	if err != nil {
		t.Fatal(err)
	}
	d2, err := receipt.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Error("digest should be deterministic")
	}
}

func TestTerminalReceiptDigestExcludesFinalizedAt(t *testing.T) {
	base := TerminalReceipt{
		ExecutionID:     "exec-123",
		Capability:      "test.counter.increment",
		Principal:       "alice@example.com",
		RequestDigest:   "digest-abc",
		TerminalStatus:  StateCommitted,
		CanonicalResult: json.RawMessage(`{"value":42}`),
		ProviderID:      "local",
		ProviderRunID:   "run-1",
		EvidenceDigest:  "ev-digest",
		ReceiptVersion:  3,
	}

	// Same receipt with different FinalizedAt should produce the same digest.
	r1 := base
	r1.FinalizedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r2 := base
	r2.FinalizedAt = time.Date(2026, 6, 15, 12, 30, 0, 0, time.UTC)

	d1, _ := r1.Digest()
	d2, _ := r2.Digest()
	if d1 != d2 {
		t.Error("digest should exclude FinalizedAt — different timestamps produced different digests")
	}
}

func TestTerminalReceiptDigestDifferentResults(t *testing.T) {
	r1 := TerminalReceipt{
		ExecutionID:     "exec-1",
		Capability:      "cap",
		Principal:       "alice",
		RequestDigest:   "d",
		TerminalStatus:  StateCommitted,
		CanonicalResult: json.RawMessage(`{"value":1}`),
	}
	r2 := TerminalReceipt{
		ExecutionID:     "exec-1",
		Capability:      "cap",
		Principal:       "alice",
		RequestDigest:   "d",
		TerminalStatus:  StateCommitted,
		CanonicalResult: json.RawMessage(`{"value":2}`),
	}
	d1, _ := r1.Digest()
	d2, _ := r2.Digest()
	if d1 == d2 {
		t.Error("different results should produce different digests")
	}
}

func TestTerminalReceiptDigestDifferentProviderRunID(t *testing.T) {
	r1 := TerminalReceipt{
		ExecutionID:    "exec-1",
		TerminalStatus: StateCommitted,
		ProviderRunID:  "run-A",
	}
	r2 := TerminalReceipt{
		ExecutionID:    "exec-1",
		TerminalStatus: StateCommitted,
		ProviderRunID:  "run-B",
	}
	d1, _ := r1.Digest()
	d2, _ := r2.Digest()
	if d1 == d2 {
		t.Error("different provider_run_id should produce different digests")
	}
}

func TestTerminalReceiptDigestDifferentReceiptVersion(t *testing.T) {
	r1 := TerminalReceipt{
		ExecutionID:    "exec-1",
		TerminalStatus: StateCommitted,
		ReceiptVersion: 2,
	}
	r2 := TerminalReceipt{
		ExecutionID:    "exec-1",
		TerminalStatus: StateCommitted,
		ReceiptVersion: 3,
	}
	d1, _ := r1.Digest()
	d2, _ := r2.Digest()
	if d1 == d2 {
		t.Error("different receipt_version should produce different digests")
	}
}

// ─── RecoveryDecision ─────────────────────────────────────────────────

func TestRecoveryDecisionValues(t *testing.T) {
	// Verify the typed recovery decisions exist and are distinct.
	decisions := []RecoveryDecision{
		RecoveryCommitted,
		RecoveryFailed,
		RecoveryUnknown,
		RecoveryRetryable,
		RecoveryConflict,
	}
	seen := map[RecoveryDecision]bool{}
	for _, d := range decisions {
		if seen[d] {
			t.Errorf("duplicate recovery decision: %s", d)
		}
		seen[d] = true
	}
}

// ─── LeaseError types ─────────────────────────────────────────────────

func TestLeaseErrorValues(t *testing.T) {
	errors := []LeaseError{
		LeaseLost,
		LeaseExpired,
		LeaseTokenMismatch,
		LeaseGenerationMismatch,
		LeaseStateConflict,
		LeaseRecoveryRequired,
		LeaseErrorInvalidDuration,
	}
	seen := map[LeaseError]bool{}
	for _, e := range errors {
		if seen[e] {
			t.Errorf("duplicate lease error: %s", e)
		}
		seen[e] = true
		if e.Error() != string(e) {
			t.Errorf("LeaseError.Error() = %q, want %q", e.Error(), string(e))
		}
	}
}

// ─── AcquireResultKind values ─────────────────────────────────────────

func TestAcquireResultKindValues(t *testing.T) {
	kinds := []AcquireResultKind{
		LeaseAcquired,
		LeaseHeldByOther,
		LeaseReclaimed,
		TerminalReplay,
		RecoveryRequired,
		IdempotencyConflict,
	}
	seen := map[AcquireResultKind]bool{}
	for _, k := range kinds {
		if seen[k] {
			t.Errorf("duplicate acquire result kind: %s", k)
		}
		seen[k] = true
	}
}

// ─── State name backward compatibility ────────────────────────────────

// ─── Clock interface ─────────────────────────────────────────────────

func TestFixedClock(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := FixedClock{T: fixed}
	if got := clock.Now(); !got.Equal(fixed) {
		t.Errorf("FixedClock.Now() = %v, want %v", got, fixed)
	}
}

func TestSystemClock(t *testing.T) {
	clock := SystemClock{}
	before := time.Now()
	got := clock.Now()
	after := time.Now()
	if got.Before(before) || got.After(after) {
		t.Errorf("SystemClock.Now() = %v, not between %v and %v", got, before, after)
	}
}

// ─── RecoveryRetryable rejection ─────────────────────────────────────

// TestRecoveryRetryableRejected verifies that the contract rejects
// RecoveryRetryable at the type level — it is a violation of
// CRAB-V1-020 for post-dispatch uncertainty to become retryable
// without evidence. The store's ResolveRecovery rejects this
// decision. This test verifies the decision type exists (for
// structured error reporting) but is not a valid recovery path.
func TestRecoveryRetryableExists(t *testing.T) {
	// RecoveryRetryable exists as a typed decision so that resolvers
	// can express it and the store can reject it with a structured
	// error. It must not be silently accepted.
	if string(RecoveryRetryable) != "RETRYABLE" {
		t.Errorf("RecoveryRetryable = %s, want RETRYABLE", RecoveryRetryable)
	}
}

// ─── TerminalReceipt identity validation ─────────────────────────────

// TestTerminalReceiptIdentityFields verifies that the receipt contains
// the identity fields that must be validated against the database row
// before finalization.
func TestTerminalReceiptIdentityFields(t *testing.T) {
	receipt := TerminalReceipt{
		ExecutionID:   "exec-123",
		Capability:    "test.cap",
		Principal:     "alice",
		RequestDigest: "digest-abc",
	}
	if receipt.ExecutionID != "exec-123" {
		t.Error("ExecutionID not set")
	}
	if receipt.Capability != "test.cap" {
		t.Error("Capability not set")
	}
	if receipt.Principal != "alice" {
		t.Error("Principal not set")
	}
	if receipt.RequestDigest != "digest-abc" {
		t.Error("RequestDigest not set")
	}
}

// ─── DefinitiveFailure contract ──────────────────────────────────────

// TestTerminalReceiptDigestIsSHA256 verifies the digest is a valid
// 64-character lowercase hex SHA-256 digest.
func TestTerminalReceiptDigestIsSHA256(t *testing.T) {
	receipt := TerminalReceipt{
		ExecutionID:    "exec-1",
		TerminalStatus: StateCommitted,
	}
	d, err := receipt.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if len(d) != 64 {
		t.Fatalf("digest length = %d, want 64", len(d))
	}
	for _, c := range d {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("digest contains non-hex character: %c in %s", c, d)
		}
	}
}

// ─── DefaultLeaseConfig ───────────────────────────────────────────────

func TestDefaultLeaseConfig(t *testing.T) {
	if DefaultLeaseConfig.DefaultDuration <= 0 {
		t.Error("DefaultLeaseConfig.DefaultDuration should be positive")
	}
	if DefaultLeaseConfig.MaxDuration <= 0 {
		t.Error("DefaultLeaseConfig.MaxDuration should be positive")
	}
	if DefaultLeaseConfig.MaxDuration < DefaultLeaseConfig.DefaultDuration {
		t.Error("MaxDuration should be >= DefaultDuration")
	}
}

// ─── migrateState ────────────────────────────────────────────────────

func TestMigrateState(t *testing.T) {
	tests := []struct {
		input State
		want  State
	}{
		{"RESERVED", StatePrepared},
		{"DISPATCHING", StateExecuting},
		{"SUCCEEDED", StateCommitted},
		{"RECONCILIATION_REQUIRED", StateUnknown},
		{StatePrepared, StatePrepared},
		{StateInFlight, StateInFlight},
		{StateCommitted, StateCommitted},
	}
	for _, tt := range tests {
		if got := migrateState(tt.input); got != tt.want {
			t.Errorf("migrateState(%s) = %s, want %s", tt.input, got, tt.want)
		}
	}
}

// ─── RecoveryResult ──────────────────────────────────────────────────

func TestRecoveryResultJSON(t *testing.T) {
	result := RecoveryResult{
		Decision:       RecoveryCommitted,
		Result:         json.RawMessage(`{"ok":true}`),
		EvidenceDigest: "abc123",
		ReceiptVersion: 3,
		ProviderID:     "local",
		ProviderRunID:  "run-1",
	}
	b, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "COMMITTED") {
		t.Error("JSON should contain decision")
	}
	if !strings.Contains(string(b), "abc123") {
		t.Error("JSON should contain evidence digest")
	}
}

// TestLegalTransitionMatrix verifies that the Store's transition matrix
// rejects illegal state transitions. This ensures the lifecycle graph
// is enforced inside the Store, not just in callers.
func TestLegalTransitionMatrix(t *testing.T) {
	tests := []struct {
		name  string
		from  State
		to    State
		legal bool
	}{
		// Legal transitions
		{"PREPARED→EXECUTING", StatePrepared, StateExecuting, true},
		{"EXECUTING→IN_FLIGHT", StateExecuting, StateInFlight, true},
		{"EXECUTING→PREPARED", StateExecuting, StatePrepared, true},
		{"IN_FLIGHT→COMMITTED", StateInFlight, StateCommitted, true},
		{"IN_FLIGHT→FAILED", StateInFlight, StateFailed, true},
		{"IN_FLIGHT→UNKNOWN", StateInFlight, StateUnknown, true},
		{"UNKNOWN→COMMITTED", StateUnknown, StateCommitted, true},
		{"UNKNOWN→FAILED", StateUnknown, StateFailed, true},

		// Illegal transitions — DENIED is a wire-level admission status,
		// not a durable store state. It is not reachable via the store.
		{"PREPARED→DENIED", StatePrepared, StateDenied, false},
		{"EXECUTING→DENIED", StateExecuting, StateDenied, false},
		{"PREPARED→COMMITTED", StatePrepared, StateCommitted, false},
		{"PREPARED→IN_FLIGHT", StatePrepared, StateInFlight, false},
		{"PREPARED→UNKNOWN", StatePrepared, StateUnknown, false},
		{"EXECUTING→COMMITTED", StateExecuting, StateCommitted, false},
		{"EXECUTING→UNKNOWN", StateExecuting, StateUnknown, false},
		{"EXECUTING→FAILED", StateExecuting, StateFailed, false},
		{"IN_FLIGHT→PREPARED", StateInFlight, StatePrepared, false},
		{"IN_FLIGHT→EXECUTING", StateInFlight, StateExecuting, false},
		{"IN_FLIGHT→DENIED", StateInFlight, StateDenied, false},
		{"UNKNOWN→IN_FLIGHT", StateUnknown, StateInFlight, false},
		{"UNKNOWN→PREPARED", StateUnknown, StatePrepared, false},
		{"UNKNOWN→EXECUTING", StateUnknown, StateExecuting, false},
		{"UNKNOWN→DENIED", StateUnknown, StateDenied, false},

		// Terminal states are immutable
		{"COMMITTED→EXECUTING", StateCommitted, StateExecuting, false},
		{"COMMITTED→FAILED", StateCommitted, StateFailed, false},
		{"COMMITTED→UNKNOWN", StateCommitted, StateUnknown, false},
		{"FAILED→COMMITTED", StateFailed, StateCommitted, false},
		{"FAILED→UNKNOWN", StateFailed, StateUnknown, false},
		{"DENIED→COMMITTED", StateDenied, StateCommitted, false},
		{"DENIED→IN_FLIGHT", StateDenied, StateInFlight, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLegalTransition(tt.from, tt.to)
			if got != tt.legal {
				t.Errorf("isLegalTransition(%s, %s) = %v, want %v",
					tt.from, tt.to, got, tt.legal)
			}
		})
	}
}

// TestLegalTransitionMatrixExhaustive enumerates EVERY ordered pair of
// states — no hand-picked subset. The legal edge set is the frozen
// contract graph; every other pair must fail closed. A future change
// that adds an edge (e.g. UNKNOWN → PREPARED for "retry") breaks this
// test, which is the point.
func TestLegalTransitionMatrixExhaustive(t *testing.T) {
	states := []State{
		StatePrepared, StateExecuting, StateInFlight,
		StateUnknown, StateCommitted, StateFailed, StateDenied,
	}
	legal := map[State]map[State]bool{
		StatePrepared:  {StateExecuting: true},
		StateExecuting: {StateInFlight: true, StatePrepared: true},
		StateInFlight:  {StateCommitted: true, StateFailed: true, StateUnknown: true},
		StateUnknown:   {StateCommitted: true, StateFailed: true},
	}
	for _, from := range states {
		for _, to := range states {
			want := legal[from][to]
			if got := isLegalTransition(from, to); got != want {
				t.Errorf("isLegalTransition(%s, %s) = %v, want %v", from, to, got, want)
			}
		}
	}
}

// TestGenerateExecutionID verifies that application-side UUID generation
// produces valid UUID v4 format strings.
func TestGenerateExecutionID(t *testing.T) {
	for i := 0; i < 100; i++ {
		id, err := generateExecutionID()
		if err != nil {
			t.Fatalf("generateExecutionID failed: %v", err)
		}
		// UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
		if len(id) != 36 {
			t.Fatalf("execution ID length %d, want 36: %q", len(id), id)
		}
		if id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
			t.Errorf("execution ID missing hyphens: %q", id)
		}
		if id[14] != '4' {
			t.Errorf("execution ID version nibble: got %c, want '4'", id[14])
		}
		variant := id[19]
		if variant != '8' && variant != '9' && variant != 'a' && variant != 'b' {
			t.Errorf("execution ID variant nibble: got %c, want 8/9/a/b", variant)
		}
	}
}

// TestGenerateExecutionIDUniqueness verifies UUIDs are unique.
func TestGenerateExecutionIDUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 10000; i++ {
		id, err := generateExecutionID()
		if err != nil {
			t.Fatal(err)
		}
		if seen[id] {
			t.Fatalf("duplicate execution ID generated: %s", id)
		}
		seen[id] = true
	}
}

// TestIsLegalTransitionNilFrom verifies that zero-value State is rejected.
func TestIsLegalTransitionNilFrom(t *testing.T) {
	if isLegalTransition("", StateCommitted) {
		t.Error("empty state should not transition to COMMITTED")
	}
}

// TestCanonicalizeJSONRejectsTrailingData verifies the strict
// single-value rule: after the first JSON value the decoder must hit
// io.EOF — a second value or a malformed trailing delimiter (which
// Decoder.More treats as end-of-input) is invalid.
func TestCanonicalizeJSONRejectsTrailingData(t *testing.T) {
	valid := []struct{ name, in string }{
		{"object", `{"a":1}`},
		{"array", `[1,2,3]`},
		{"scalar", `1`},
		{"trailing_whitespace", "{\"a\":1}\n \t"},
	}
	for _, tc := range valid {
		t.Run("valid/"+tc.name, func(t *testing.T) {
			out, err := canonicalizeJSON(json.RawMessage(tc.in))
			if err != nil {
				t.Fatalf("canonicalizeJSON(%q) rejected valid input: %v", tc.in, err)
			}
			if len(out) == 0 {
				t.Fatalf("canonicalizeJSON(%q) returned empty output", tc.in)
			}
		})
	}

	invalid := []struct{ name, in string }{
		// These fooled Decoder.More(): it reports "no more elements"
		// at ']' or '}', so trailing garbage after a value was accepted.
		{"extra_closing_brace", `{"a":1}}`},
		{"extra_closing_bracket", `1]`},
		{"object_then_garbage_brace", `{"ok":true}}`},
		// A second complete JSON value must also be rejected.
		{"two_values", `{"a":1} {"b":2}`},
		{"value_then_scalar", `{"a":1} 2`},
		// Non-JSON trailing bytes.
		{"trailing_garbage", `{"a":1} xyz`},
	}
	for _, tc := range invalid {
		t.Run("invalid/"+tc.name, func(t *testing.T) {
			if _, err := canonicalizeJSON(json.RawMessage(tc.in)); err == nil {
				t.Fatalf("canonicalizeJSON(%q) accepted malformed input", tc.in)
			}
		})
	}
}

// TestTerminalReceiptDigestFrozenVector pins the terminal-receipt
// digest ABI: the canonical serialization and the resulting SHA-256
// are frozen — any change to field selection, ordering, or number
// canonicalization inside Digest() changes this value and is a
// deliberate ABI revision, not a silent edit. The fixture exercises
// object-key ordering, number normalization (1.50 → canonical form),
// and precision beyond float64 (9007199254740993).
func TestTerminalReceiptDigestFrozenVector(t *testing.T) {
	receipt := TerminalReceipt{
		ExecutionID:     "exec-frozen-01",
		Capability:      "test.counter.increment",
		Principal:       "alice@example.com",
		RequestDigest:   "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		TerminalStatus:  StateCommitted,
		CanonicalResult: json.RawMessage(`{"b":2,"a":1,"n":1.50,"big":9007199254740993}`),
		ProviderID:      "local",
		ProviderRunID:   "run-42",
		EvidenceDigest:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		ReceiptVersion:  3,
		FinalizedAt:     time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC),
	}
	const want = "11e3560760e61562234822ccc9e006e110e6a2211b3473b36a07ec1cf513c8e3"
	got, err := receipt.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("terminal receipt digest = %s, frozen ABI vector wants %s — deliberate ABI change requires updating this vector and the repair ADR", got, want)
	}
}
