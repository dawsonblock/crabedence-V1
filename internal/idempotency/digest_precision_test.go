package idempotency

import (
	"encoding/json"
	"testing"
)

// TestComputeDigestFromRawNumericPrecision verifies that distinct large
// integers beyond IEEE-754 float64 exact range produce distinct digests.
//
// Before the UseNumber() fix, json.Unmarshal into map[string]any decoded
// all numbers as float64. This collapsed:
//
//	9007199254740992 (2^53)
//	9007199254740993 (2^53 + 1)
//
// to the same float64 value, causing distinct requests to produce the
// same idempotency digest — a correctness bug that could cause
// IDEMPOTENCY_CONFLICT to not be detected.
func TestComputeDigestFromRawNumericPrecision(t *testing.T) {
	// 2^53 and 2^53+1 are distinct integers that both map to the same
	// float64 (9007199254740992) under IEEE-754.
	args1 := json.RawMessage(`{"transaction_id":9007199254740992}`)
	args2 := json.RawMessage(`{"transaction_id":9007199254740993}`)

	d1, err := ComputeDigestFromRaw(1, "alice@example.com", "payment.create", args1, "grant_123", "CRITICAL")
	if err != nil {
		t.Fatal(err)
	}
	d2, err := ComputeDigestFromRaw(1, "alice@example.com", "payment.create", args2, "grant_123", "CRITICAL")
	if err != nil {
		t.Fatal(err)
	}

	if d1 == d2 {
		t.Errorf("distinct large integers must produce distinct digests:\n  9007199254740992 → %s\n  9007199254740993 → %s\nfloat64 collapse detected — UseNumber() fix regressed", d1, d2)
	}
}

// TestComputeDigestFromRawLargeIntegers verifies multiple large integer
// pairs produce distinct digests.
func TestComputeDigestFromRawLargeIntegers(t *testing.T) {
	pairs := [][2]string{
		{"9007199254740992", "9007199254740993"},         // 2^53, 2^53+1
		{"18446744073709551615", "18446744073709551616"}, // uint64 max, uint64 max+1
		{"-9007199254740993", "-9007199254740992"},       // -(2^53+1), -(2^53)
	}

	for i, pair := range pairs {
		args1 := json.RawMessage(`{"value":` + pair[0] + `}`)
		args2 := json.RawMessage(`{"value":` + pair[1] + `}`)

		d1, err := ComputeDigestFromRaw(1, "test@example.com", "test.cap", args1, "", "MUTATION")
		if err != nil {
			t.Fatal(err)
		}
		d2, err := ComputeDigestFromRaw(1, "test@example.com", "test.cap", args2, "", "MUTATION")
		if err != nil {
			t.Fatal(err)
		}

		if d1 == d2 {
			t.Errorf("pair %d: %s and %s should produce distinct digests (both → %s)", i, pair[0], pair[1], d1)
		}
	}
}

// TestComputeDigestFromRawFloatPreserved verifies that float values
// that ARE representable still work correctly.
func TestComputeDigestFromRawFloatPreserved(t *testing.T) {
	args1 := json.RawMessage(`{"amount":1.5}`)
	args2 := json.RawMessage(`{"amount":2.5}`)

	d1, err := ComputeDigestFromRaw(1, "test@example.com", "test.cap", args1, "", "MUTATION")
	if err != nil {
		t.Fatal(err)
	}
	d2, err := ComputeDigestFromRaw(1, "test@example.com", "test.cap", args2, "", "MUTATION")
	if err != nil {
		t.Fatal(err)
	}

	if d1 == d2 {
		t.Error("distinct float values must produce distinct digests")
	}

	// Same value in different lexical form should produce the same digest
	args3 := json.RawMessage(`{"amount":1.50}`)
	d3, err := ComputeDigestFromRaw(1, "test@example.com", "test.cap", args3, "", "MUTATION")
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d3 {
		t.Errorf("1.5 and 1.50 should produce the same digest: %s != %s", d1, d3)
	}
}
