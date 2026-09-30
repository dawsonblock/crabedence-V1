package capability

import (
	"encoding/json"
	"testing"
)

// Exact-number schema validation: bounds and integer checks must
// never route through float64. These cases cover the boundary values
// where float64 collapses distinct integers (2^53±1), overflows
// int64, or loses decimal precision.

func TestValidateArgumentsExactNumberBounds(t *testing.T) {
	schema := json.RawMessage(`{
		"type": "object",
		"properties": {
			"n": {"type": "number", "minimum": 9007199254740992, "maximum": 9007199254740994}
		},
		"required": ["n"],
		"additionalProperties": false
	}`)

	for _, tc := range []struct {
		name    string
		args    string
		wantErr bool
	}{
		// 2^53+1 is representable exactly in the input — must pass.
		{"2^53+1 in range", `{"n": 9007199254740993}`, false},
		// 2^53+2 exceeds maximum 9007199254740994? No — it equals it.
		{"2^53+2 at max", `{"n": 9007199254740994}`, false},
		// float64 would round 2^53+3 to 2^53+4 — it must fail max.
		{"2^53+3 above max", `{"n": 9007199254740995}`, true},
		// Below minimum.
		{"2^53+1 below min variant", `{"n": 9007199254740991}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateArguments(schema, json.RawMessage(tc.args))
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %s", tc.args)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for %s: %v", tc.args, err)
			}
		})
	}
}

func TestValidateArgumentsExactInteger(t *testing.T) {
	schema := json.RawMessage(`{
		"type": "object",
		"properties": {"n": {"type": "integer"}},
		"required": ["n"],
		"additionalProperties": false
	}`)

	for _, tc := range []struct {
		name    string
		args    string
		wantErr bool
	}{
		{"2^53-1", `{"n": 9007199254740991}`, false},
		{"2^53", `{"n": 9007199254740992}`, false},
		{"2^53+1", `{"n": 9007199254740993}`, false},
		{"int64 max", `{"n": 9223372036854775807}`, false},
		{"int64 max+1", `{"n": 9223372036854775808}`, false},
		{"1e100 whole", `{"n": 1e100}`, false},
		{"integral decimal", `{"n": 12.0}`, false},
		{"non-integer", `{"n": 1.5}`, true},
		{"non-integer big", `{"n": 9007199254740993.5}`, true},
		{"scientific non-integer", `{"n": 1.5e2}`, false}, // 150 — integral
		{"scientific fraction", `{"n": 1.5e-2}`, true},    // 0.015
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateArguments(schema, json.RawMessage(tc.args))
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %s", tc.args)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for %s: %v", tc.args, err)
			}
		})
	}
}

func TestValidateArgumentsMultipleOf(t *testing.T) {
	schema := json.RawMessage(`{
		"type": "object",
		"properties": {"n": {"type": "number", "multipleOf": 0.01}},
		"required": ["n"],
		"additionalProperties": false
	}`)

	for _, tc := range []struct {
		args    string
		wantErr bool
	}{
		{`{"n": 1.23}`, false},
		{`{"n": 0.03}`, false},
		{`{"n": 1.234}`, true},
		{`{"n": 100}`, false},
	} {
		err := ValidateArguments(schema, json.RawMessage(tc.args))
		if tc.wantErr && err == nil {
			t.Fatalf("expected error for %s", tc.args)
		}
		if !tc.wantErr && err != nil {
			t.Fatalf("unexpected error for %s: %v", tc.args, err)
		}
	}
}

func TestValidateArgumentsEnumNumericEquality(t *testing.T) {
	schema := json.RawMessage(`{
		"type": "object",
		"properties": {"n": {"type": "number", "enum": [1, 9007199254740993, 0.5]}},
		"required": ["n"],
		"additionalProperties": false
	}`)

	for _, tc := range []struct {
		args    string
		wantErr bool
	}{
		{`{"n": 1.0}`, false},                // 1.0 == 1 numerically
		{`{"n": 9007199254740993.0}`, false}, // distinct from 9007199254740992
		{`{"n": 0.50}`, false},
		{`{"n": 9007199254740992}`, true},
		{`{"n": 2}`, true},
	} {
		err := ValidateArguments(schema, json.RawMessage(tc.args))
		if tc.wantErr && err == nil {
			t.Fatalf("expected error for %s", tc.args)
		}
		if !tc.wantErr && err != nil {
			t.Fatalf("unexpected error for %s: %v", tc.args, err)
		}
	}
}

func TestValidateArgumentsDecimalPrecision(t *testing.T) {
	schema := json.RawMessage(`{
		"type": "object",
		"properties": {
			"big": {"type": "number", "minimum": 0.000000000000000001},
			"small": {"type": "number", "maximum": 1e-20}
		},
		"additionalProperties": false
	}`)

	// Sub-float64-precision decimals must compare exactly.
	if err := ValidateArguments(schema, json.RawMessage(
		`{"big": 0.000000000000000001, "small": 0.00000000000000000001}`)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := ValidateArguments(schema, json.RawMessage(
		`{"small": 0.000000000000000000011}`)); err == nil {
		t.Fatal("expected maximum violation for 1.1e-20")
	}
}
