package idempotency

import (
	"encoding/json"
	"testing"
)

// TestCanonicalJSONConformanceCorpus is the conformance corpus for the
// idempotency canonicalization. It is intentionally separate from the
// RunEvidenceV1 cross-language corpus (Go↔TypeScript) because this
// canonicalization is Go-only with different escaping rules.
//
// Each case verifies a specific property that the digest depends on.
func TestCanonicalJSONConformanceCorpus(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected string
	}{
		// Sorted keys at all levels
		{
			name:     "flat object keys sorted",
			input:    map[string]any{"zebra": 1, "apple": 2, "mango": 3},
			expected: `{"apple":2,"mango":3,"zebra":1}`,
		},
		{
			name:     "nested object keys sorted",
			input:    map[string]any{"outer": map[string]any{"z": "last", "a": "first"}},
			expected: `{"outer":{"a":"first","z":"last"}}`,
		},
		// Arrays preserve order (not sorted)
		{
			name:     "array order preserved",
			input:    map[string]any{"list": []any{3, 1, 2}},
			expected: `{"list":[3,1,2]}`,
		},
		// Numbers: json.Number preserves lexical representation
		{
			name:     "json.Number lexical preservation",
			input:    map[string]any{"n": json.Number("9007199254740993")},
			expected: `{"n":9007199254740993}`,
		},
		{
			name:     "json.Number large integer",
			input:    map[string]any{"n": json.Number("18446744073709551615")},
			expected: `{"n":18446744073709551615}`,
		},
		{
			name:     "json.Number decimal",
			input:    map[string]any{"n": json.Number("1.50")},
			expected: `{"n":1.50}`,
		},
		// Numbers: Go native types
		{
			name:     "int",
			input:    map[string]any{"n": 42},
			expected: `{"n":42}`,
		},
		{
			name:     "float64",
			input:    map[string]any{"n": 3.14},
			expected: `{"n":3.14}`,
		},
		// Strings: Unicode preserved
		{
			name:     "unicode string",
			input:    map[string]any{"s": "héllo 世界 🌏"},
			expected: `{"s":"héllo 世界 🌏"}`,
		},
		// Booleans and null
		{
			name:     "boolean true",
			input:    map[string]any{"b": true},
			expected: `{"b":true}`,
		},
		{
			name:     "boolean false",
			input:    map[string]any{"b": false},
			expected: `{"b":false}`,
		},
		{
			name:     "null value",
			input:    map[string]any{"n": nil},
			expected: `{"n":null}`,
		},
		// Empty containers
		{
			name:     "empty object",
			input:    map[string]any{},
			expected: `{}`,
		},
		{
			name:     "empty array",
			input:    map[string]any{"arr": []any{}},
			expected: `{"arr":[]}`,
		},
		// Mixed nested structure
		{
			name: "mixed nesting",
			input: map[string]any{
				"b": []any{map[string]any{"y": 1, "x": 2}, map[string]any{"w": 3}},
				"a": map[string]any{"deep": map[string]any{"z": json.Number("1"), "a": json.Number("2")}},
			},
			expected: `{"a":{"deep":{"a":2,"z":1}},"b":[{"x":2,"y":1},{"w":3}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CanonicalJSON(tt.input)
			if err != nil {
				t.Fatalf("CanonicalJSON error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("CanonicalJSON mismatch:\n  got:      %s\n  expected: %s", got, tt.expected)
			}
		})
	}
}

// TestCanonicalJSONDeterministic verifies that the same value always
// produces the same canonical output regardless of map iteration order.
func TestCanonicalJSONDeterministic(t *testing.T) {
	// Build the same logical value with different insertion orders.
	v1 := map[string]any{
		"a": 1,
		"b": map[string]any{"x": "hello", "y": []any{1, 2, 3}},
		"c": true,
	}
	v2 := map[string]any{
		"c": true,
		"b": map[string]any{"y": []any{1, 2, 3}, "x": "hello"},
		"a": 1,
	}

	s1, err := CanonicalJSON(v1)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := CanonicalJSON(v2)
	if err != nil {
		t.Fatal(err)
	}

	if s1 != s2 {
		t.Errorf("same logical value produced different canonical forms:\n  v1: %s\n  v2: %s", s1, s2)
	}
}

// TestCanonicalJSONDistinctInputs verifies that semantically different
// values always produce different canonical forms (no collisions).
func TestCanonicalJSONDistinctInputs(t *testing.T) {
	pairs := []struct {
		name string
		a, b any
	}{
		{"int vs string", map[string]any{"v": 1}, map[string]any{"v": "1"}},
		{"true vs 1", map[string]any{"v": true}, map[string]any{"v": 1}},
		{"array vs object", map[string]any{"v": []any{1}}, map[string]any{"v": map[string]any{"0": 1}}},
		{"null vs false", map[string]any{"v": nil}, map[string]any{"v": false}},
		{"nested vs flat", map[string]any{"v": map[string]any{"a": 1}}, map[string]any{"v.a": 1}},
	}

	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			s1, err := CanonicalJSON(p.a)
			if err != nil {
				t.Fatal(err)
			}
			s2, err := CanonicalJSON(p.b)
			if err != nil {
				t.Fatal(err)
			}
			if s1 == s2 {
				t.Errorf("distinct values produced identical canonical form: %s", s1)
			}
		})
	}
}
