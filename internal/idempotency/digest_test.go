package idempotency

import (
	"encoding/json"
	"testing"
)

func TestCanonicalJSONSortedKeys(t *testing.T) {
	input := map[string]any{
		"b": 1,
		"a": 2,
		"c": 3,
	}
	got, err := CanonicalJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":2,"b":1,"c":3}`
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestCanonicalJSONNested(t *testing.T) {
	input := map[string]any{
		"outer": map[string]any{
			"z": "last",
			"a": "first",
		},
		"inner": []any{3, 1, 2},
	}
	got, err := CanonicalJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	// Keys sorted at every level; arrays preserve order
	want := `{"inner":[3,1,2],"outer":{"a":"first","z":"last"}}`
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestComputeDigestDeterministic(t *testing.T) {
	input1 := DigestInput{
		ProtocolVersion: 1,
		Principal:       "alice@example.com",
		Capability:      "test.counter.increment",
		Arguments:       map[string]any{"counter": "test", "by": 1},
		GrantID:         "grant_123",
		ExecutionClass:  "MUTATION",
	}
	input2 := DigestInput{
		ProtocolVersion: 1,
		Principal:       "alice@example.com",
		Capability:      "test.counter.increment",
		Arguments:       map[string]any{"by": 1, "counter": "test"}, // Reordered
		GrantID:         "grant_123",
		ExecutionClass:  "MUTATION",
	}

	d1, err := ComputeDigest(input1)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := ComputeDigest(input2)
	if err != nil {
		t.Fatal(err)
	}

	if d1 != d2 {
		t.Errorf("reordered keys should produce same digest: %s != %s", d1, d2)
	}
	if len(d1) != 64 {
		t.Errorf("digest should be 64 chars, got %d", len(d1))
	}
}

func TestComputeDigestDifferentGrant(t *testing.T) {
	input1 := DigestInput{
		ProtocolVersion: 1,
		Principal:       "alice@example.com",
		Capability:      "test.counter.increment",
		Arguments:       map[string]any{"counter": "test"},
		GrantID:         "grant_123",
		ExecutionClass:  "MUTATION",
	}
	input2 := DigestInput{
		ProtocolVersion: 1,
		Principal:       "alice@example.com",
		Capability:      "test.counter.increment",
		Arguments:       map[string]any{"counter": "test"},
		GrantID:         "grant_456", // Different grant
		ExecutionClass:  "MUTATION",
	}

	d1, _ := ComputeDigest(input1)
	d2, _ := ComputeDigest(input2)

	if d1 == d2 {
		t.Error("different grant_id should produce different digest")
	}
}

func TestComputeDigestDifferentClass(t *testing.T) {
	input1 := DigestInput{
		ProtocolVersion: 1,
		Principal:       "alice@example.com",
		Capability:      "test.counter.increment",
		Arguments:       map[string]any{"counter": "test"},
		GrantID:         "grant_123",
		ExecutionClass:  "MUTATION",
	}
	input2 := DigestInput{
		ProtocolVersion: 1,
		Principal:       "alice@example.com",
		Capability:      "test.counter.increment",
		Arguments:       map[string]any{"counter": "test"},
		GrantID:         "grant_123",
		ExecutionClass:  "CRITICAL", // Different class
	}

	d1, _ := ComputeDigest(input1)
	d2, _ := ComputeDigest(input2)

	if d1 == d2 {
		t.Error("different execution_class should produce different digest")
	}
}

func TestComputeDigestFromRaw(t *testing.T) {
	args1 := json.RawMessage(`{"counter":"test","by":1}`)
	args2 := json.RawMessage(`{"by":1,"counter":"test"}`)

	d1, err := ComputeDigestFromRaw(1, "alice@example.com", "test.counter.increment", args1, "grant_123", "MUTATION")
	if err != nil {
		t.Fatal(err)
	}
	d2, err := ComputeDigestFromRaw(1, "alice@example.com", "test.counter.increment", args2, "grant_123", "MUTATION")
	if err != nil {
		t.Fatal(err)
	}

	if d1 != d2 {
		t.Errorf("reordered JSON should produce same digest: %s != %s", d1, d2)
	}
}

// TestComputeDigestAuthorityBinding verifies that the immutable
// authority material (generation + grant digest) is bound into the
// request digest: the same grant_id under different authority material
// is a different execution identity, while zero values preserve the
// pre-binding digest bytes exactly.
func TestComputeDigestAuthorityBinding(t *testing.T) {
	args := json.RawMessage(`{"counter":"test","by":1}`)

	base, err := ComputeDigestFromRaw(1, "alice@example.com", "test.counter.increment", args, "grant_123", "MUTATION")
	if err != nil {
		t.Fatal(err)
	}

	// Zero authority material is byte-identical to the unbound digest.
	zero, err := ComputeDigestFromRawWithAuthority(1, "alice@example.com", "test.counter.increment", args, "grant_123", "MUTATION", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if zero != base {
		t.Error("zero authority material must preserve the unbound digest")
	}

	gen1, err := ComputeDigestFromRawWithAuthority(1, "alice@example.com", "test.counter.increment", args, "grant_123", "MUTATION", 1, "digest-a")
	if err != nil {
		t.Fatal(err)
	}
	gen2, err := ComputeDigestFromRawWithAuthority(1, "alice@example.com", "test.counter.increment", args, "grant_123", "MUTATION", 2, "digest-b")
	if err != nil {
		t.Fatal(err)
	}

	if gen1 == base {
		t.Error("bound authority material must change the digest")
	}
	if gen1 == gen2 {
		t.Error("same grant_id at different generations/digests must produce different digests")
	}

	// Generation alone (digest empty) still binds.
	genOnly, err := ComputeDigestFromRawWithAuthority(1, "alice@example.com", "test.counter.increment", args, "grant_123", "MUTATION", 7, "")
	if err != nil {
		t.Fatal(err)
	}
	if genOnly == base || genOnly == gen1 {
		t.Error("generation-only binding must change the digest")
	}
}

func TestStateIsTerminal(t *testing.T) {
	tests := []struct {
		state    State
		terminal bool
	}{
		{StatePrepared, false},
		{StateExecuting, false},
		{StateInFlight, false},
		{StateCommitted, true},
		{StateFailed, true},
		{StateDenied, true},
		{StateUnknown, true},
	}
	for _, tt := range tests {
		if tt.state.IsTerminal() != tt.terminal {
			t.Errorf("%s: IsTerminal() = %v, want %v", tt.state, tt.state.IsTerminal(), tt.terminal)
		}
	}
}

func TestStateCallerTerminal(t *testing.T) {
	tests := []struct {
		state    State
		terminal bool
	}{
		{StatePrepared, false},
		{StateExecuting, false},
		{StateInFlight, false},
		{StateCommitted, true},
		{StateFailed, true},
		{StateDenied, true},
		{StateUnknown, true},
	}
	for _, tt := range tests {
		if got := tt.state.IsCallerTerminal(); got != tt.terminal {
			t.Errorf("%s: IsCallerTerminal() = %v, want %v", tt.state, got, tt.terminal)
		}
	}
}

func TestStateDurablyFinal(t *testing.T) {
	tests := []struct {
		state State
		final bool
	}{
		{StatePrepared, false},
		{StateExecuting, false},
		{StateInFlight, false},
		{StateCommitted, true},
		{StateFailed, true},
		{StateDenied, true},
		{StateUnknown, false},
	}
	for _, tt := range tests {
		if got := tt.state.IsDurablyFinal(); got != tt.final {
			t.Errorf("%s: IsDurablyFinal() = %v, want %v", tt.state, got, tt.final)
		}
	}
}

func TestCanonicalJSONNumber(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"1", "1e0"},
		{"1.0", "1e0"},
		{"1.00", "1e0"},
		{"1e0", "1e0"},
		{"1e+0", "1e0"},
		{"1E0", "1e0"},
		{"1e2", "1e2"},
		{"1.5e3", "1.5e3"},
		{"1.5e-3", "1.5e-3"},
		{"1.50", "1.5e0"},
		{"0.010", "1e-2"},
		{"-0", "0"},
		{"-0.0", "0"},
		{"0e5", "0"},
		{"-1.5", "-1.5e0"},
		{"-0.001", "-1e-3"},
		{"123456789012345678901234567890", "1.2345678901234567890123456789e29"},
		{"9007199254740993", "9.007199254740993e15"},
		{"3.14159", "3.14159e0"},
		{"1e-2", "1e-2"},
		{"2e+1", "2e1"},
		{"10", "1e1"},
		{"100.0", "1e2"},
		{"0.01", "1e-2"},
		{"0.0100", "1e-2"},
		{"12.34", "1.234e1"},
		{"15e-1", "1.5e0"},
	}
	for _, tt := range tests {
		got, err := canonicalJSONNumber(tt.in)
		if err != nil {
			t.Errorf("canonicalJSONNumber(%q) error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("canonicalJSONNumber(%q) = %q, want %q", tt.in, got, tt.want)
		}
		// Canonical output must be a fixed point.
		again, err := canonicalJSONNumber(got)
		if err != nil || again != got {
			t.Errorf("canonicalJSONNumber(%q) = %q is not idempotent (→ %q, %v)", tt.in, got, again, err)
		}
	}
}

// TestCanonicalJSONNumberHostileExponents pins the P0 repair: exponents
// are arbitrary precision, never parsed into int64 (where they wrap
// into collisions), and never expanded into memory. Every case must
// produce a bounded, deterministic canonical form.
func TestCanonicalJSONNumberHostileExponents(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		// Zero collapses before the exponent is ever materialized.
		{"0e999999999999999999999999", "0"},
		{"0e-999999999999999999999999", "0"},
		{"-0e999999999999999999999999", "0"},
		// Beyond int64 — the pre-repair parser wrapped these into
		// arbitrary small exponents, colliding with real values.
		{"1e9223372036854775807", "1e9223372036854775807"},
		{"1e9223372036854775808", "1e9223372036854775808"},
		{"1e18446744073709551615", "1e18446744073709551615"},
		{"1e18446744073709551616", "1e18446744073709551616"},
		{"1e18446744073709551617", "1e18446744073709551617"},
		{"1e-9223372036854775808", "1e-9223372036854775808"},
		{"1e-9223372036854775809", "1e-9223372036854775809"},
		{"1e999999", "1e999999"},
		{"1e-999999", "1e-999999"},
		{"1e99999999999999999999999999", "1e99999999999999999999999999"},
		// Large exponent combined with digit-shift arithmetic.
		{"2.5e18446744073709551616", "2.5e18446744073709551616"},
		{"1.5e-3", "1.5e-3"},
	}
	for _, tt := range tests {
		got, err := canonicalJSONNumber(tt.in)
		if err != nil {
			t.Errorf("canonicalJSONNumber(%q) error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("canonicalJSONNumber(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if len(got) > len(tt.in)+8 {
			t.Errorf("canonicalJSONNumber(%q) expanded to %d bytes — output must stay proportional to input", tt.in, len(got))
		}
	}
}

// TestCanonicalJSONNumberRejectsInvalid verifies the fail-closed API:
// malformed literals are deterministic errors, never panics or partial
// output. json.Decoder only produces valid literals, but constructed
// json.Number values must still fail safely.
func TestCanonicalJSONNumberRejectsInvalid(t *testing.T) {
	invalid := []string{
		"", "-", "+1", ".", ".5", "1.", "1e", "1e+", "1e-", "e5",
		"abc", "1.2.3", "--1", "1ee5", "0x10", "NaN", "Inf", "-Inf",
		"01", "00", "1 ", " 1", "1e1.5",
	}
	for _, in := range invalid {
		if got, err := canonicalJSONNumber(in); err == nil {
			t.Errorf("canonicalJSONNumber(%q) = %q, want error", in, got)
		}
	}
}

// TestComputeDigestHostileNumberEquivalence pins the P0 gate
// assertions: equivalent representations digest identically, and
// exponent-wrapped values do not collide with small numbers.
func TestComputeDigestHostileNumberEquivalence(t *testing.T) {
	digest := func(args string) string {
		d, err := ComputeDigestFromRaw(1, "alice", "cap", []byte(args), "g", "MUTATION")
		if err != nil {
			t.Fatalf("ComputeDigestFromRaw(%s): %v", args, err)
		}
		return d
	}

	one := digest(`{"n":1}`)
	for _, equiv := range []string{`{"n":1.0}`, `{"n":1e0}`, `{"n":1.00}`, `{"n":1e+0}`, `{"n":10e-1}`, `{"n":0.1e1}`} {
		if got := digest(equiv); got != one {
			t.Errorf("args %s digest differs from {\"n\":1}", equiv)
		}
	}

	// int64/uint64-overflowing exponents must not wrap into digest(1).
	for _, hostile := range []string{
		`{"n":1e18446744073709551616}`,
		`{"n":1e9223372036854775808}`,
		`{"n":1e-9223372036854775809}`,
		`{"n":1e999999999999999999999999}`,
	} {
		if got := digest(hostile); got == one {
			t.Errorf("args %s collided with digest({\"n\":1}) — exponent overflow", hostile)
		}
	}

	// Values that differ only beyond int64 must remain distinct.
	if digest(`{"n":1e18446744073709551615}`) == digest(`{"n":1e18446744073709551616}`) {
		t.Error("1e18446744073709551615 and 1e18446744073709551616 produced identical digests")
	}
}

func TestComputeDigestFromRawEquivalentNumbers(t *testing.T) {
	// Semantically equal numbers must digest identically regardless of
	// lexical representation.
	base := func(args string) string {
		d, err := ComputeDigestFromRaw(1, "alice", "cap", []byte(args), "g", "MUTATION")
		if err != nil {
			t.Fatalf("ComputeDigestFromRaw(%s): %v", args, err)
		}
		return d
	}
	variants := []string{
		`{"n": 1}`,
		`{"n": 1.0}`,
		`{"n": 1e0}`,
		`{"n": 1.00}`,
		`{"n": 1e+0}`,
	}
	want := base(variants[0])
	for _, v := range variants[1:] {
		if got := base(v); got != want {
			t.Errorf("args %s digest differs from %s", v, variants[0])
		}
	}
	if base(`{"n": 1.5}`) == want {
		t.Error("distinct values 1 and 1.5 produced identical digests")
	}
}

func TestComputeDigestFromRawLargeIntegersDistinct(t *testing.T) {
	// Integers beyond IEEE-754 precision must not collapse through
	// float64 conversion.
	d1, err := ComputeDigestFromRaw(1, "a", "c", []byte(`{"n":9007199254740992}`), "g", "MUTATION")
	if err != nil {
		t.Fatal(err)
	}
	d2, err := ComputeDigestFromRaw(1, "a", "c", []byte(`{"n":9007199254740993}`), "g", "MUTATION")
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d2 {
		t.Error("9007199254740992 and 9007199254740993 produced identical digests")
	}
}
