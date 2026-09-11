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
