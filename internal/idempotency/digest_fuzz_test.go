package idempotency

import (
	"bytes"
	"encoding/json"
	"testing"
)

// FuzzCanonicalJSONNumber drives the number canonicalizer with
// arbitrary input. Required properties (P0-NUM-01/02/04):
//
//   - never panics, whatever the input
//   - malformed input returns a deterministic error, not partial output
//   - canonical output is a fixed point (re-canonicalizing is identity)
//   - output size stays proportional to input size — the exponent is
//     arbitrary precision and is never expanded into memory
func FuzzCanonicalJSONNumber(f *testing.F) {
	seeds := []string{
		"1", "1.0", "1.00", "1e0", "1e+0", "1E0", "-0", "-0.0", "0e5",
		"0e999999999999999999999999", "9007199254740993", "9007199254740993.0",
		"1e9223372036854775807", "1e9223372036854775808",
		"1e18446744073709551616", "1e-9223372036854775808",
		"1e-9223372036854775809", "1e999999", "1e-999999",
		"12.34", "0.0100", "-1.5e-3", "123456789012345678901234567890",
		"", "-", "1.", "1e", "abc", "01", "1e1.5",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := canonicalJSONNumber(s)
		if err != nil {
			return
		}
		// Canonical output must be re-parseable and a fixed point.
		again, err := canonicalJSONNumber(got)
		if err != nil {
			t.Fatalf("canonical output %q (from %q) rejected on re-parse: %v", got, s, err)
		}
		if again != got {
			t.Fatalf("canonicalJSONNumber not idempotent: %q → %q → %q", s, got, again)
		}
		// Output may carry a sign, one point, 'e', and exponent digits —
		// never more than the input plus a small constant.
		if len(got) > len(s)+8 {
			t.Fatalf("canonicalJSONNumber expanded %q (%d bytes) to %q (%d bytes)",
				s, len(s), got, len(got))
		}
	})
}

// FuzzCanonicalJSON drives the full document canonicalizer. Required
// properties: never panics, single-value strictness (trailing data is
// always an error), deterministic output, and canonical output is a
// fixed point of the function.
func FuzzCanonicalJSON(f *testing.F) {
	seeds := [][]byte{
		[]byte(`{"a":1}`),
		[]byte(`{"n":1e999}`),
		[]byte(`{"n":1e18446744073709551616}`),
		[]byte(`{"n":1e-999999999999999999}`),
		[]byte(`[1,2.5,"x",true,null]`),
		[]byte(`"str"`),
		[]byte(`9007199254740993`),
		[]byte(`null`),
		[]byte(`{"x":1}{"x":2}`),
		[]byte(`{"a":1}}`),
		[]byte(``),
		[]byte(`{bad`),
		[]byte(`{"deep":{"a":[true,null,1.50],"b":{"c":0e99}}}`),
		[]byte(`{"big":18446744073709551616,"neg":-9007199254740993}`),
		[]byte(`{"a":1} {"b":2}`),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		canon, err := canonicalizeJSON(json.RawMessage(data))
		if err != nil {
			return
		}
		// nil/empty input canonicalizes to nil (the omitted-field
		// sentinel), not a JSON document.
		if len(canon) == 0 {
			return
		}
		// Deterministic: same input, same output.
		again, err := canonicalizeJSON(json.RawMessage(data))
		if err != nil || !bytes.Equal(again, canon) {
			t.Fatalf("canonicalizeJSON not deterministic for %q", data)
		}
		// Canonical output is a fixed point.
		third, err := canonicalizeJSON(canon)
		if err != nil {
			t.Fatalf("canonical output %q (from %q) rejected on re-parse: %v", canon, data, err)
		}
		if !bytes.Equal(third, canon) {
			t.Fatalf("canonicalizeJSON not idempotent: %q → %q → %q", data, canon, third)
		}
		// Canonical output must remain valid single-value JSON.
		dec := json.NewDecoder(bytes.NewReader(canon))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("canonical output %q does not decode: %v", canon, err)
		}
	})
}

// FuzzRequestDigest drives the full request-digest path. Required
// properties: never panics, deterministic, and stable under
// canonicalization — digest(raw) must equal digest(canonical(raw)).
func FuzzRequestDigest(f *testing.F) {
	seeds := [][]byte{
		[]byte(`{"a":1}`),
		[]byte(`{"n":1e999999999999999999}`),
		[]byte(`{"n":1e-999999999999999999}`),
		[]byte(`{"big":9007199254740993,"bigger":18446744073709551616}`),
		[]byte(`{"s":"x","n":null,"arr":[1,2.5]}`),
		[]byte(`{"x":1} trailing`),
		[]byte(`{"n":0e999999999999}`),
		[]byte(`{"nested":{"n":1.50e2}}`),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		d1, err := ComputeDigestFromRaw(1, "alice", "cap", json.RawMessage(data), "g", "MUTATION")
		if err != nil {
			return
		}
		d2, err := ComputeDigestFromRaw(1, "alice", "cap", json.RawMessage(data), "g", "MUTATION")
		if err != nil {
			t.Fatalf("second digest of %q failed: %v", data, err)
		}
		if d1 != d2 {
			t.Fatalf("digest not deterministic for %q: %s != %s", data, d1, d2)
		}
		// The digest of the canonical form must equal the digest of the
		// raw form — canonicalization is a fixed point by construction.
		canon, err := canonicalizeJSON(json.RawMessage(data))
		if err != nil {
			t.Fatalf("digest succeeded for %q but canonicalize failed: %v", data, err)
		}
		d3, err := ComputeDigestFromRaw(1, "alice", "cap", canon, "g", "MUTATION")
		if err != nil {
			t.Fatalf("digest of canonical %q failed: %v", canon, err)
		}
		if d3 != d1 {
			t.Fatalf("digest not stable under canonicalization: raw %q → %s, canonical %q → %s",
				data, d1, canon, d3)
		}
	})
}
