package idempotency

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"
)

// TestDispatchIdentityDeterminismAndSensitivity proves the execution
// identity contract: the request digest is deterministic for identical
// inputs, canonical over argument key order, unambiguous across bound
// fields, and sensitive to every field the contract binds into
// execution identity — including the authority generation, which is
// what makes reissuing or mutating a grant a new execution rather than
// a silent reinterpretation of an existing one.
func TestDispatchIdentityDeterminismAndSensitivity(t *testing.T) {
	type identity struct {
		protocol          int
		principal         string
		capability        string
		args              string
		authorityRef      string
		class             string
		generation        int64
		authorityDigest   string
		assurance         string
		route             string
		descriptorVersion int
		descriptorDigest  string
	}
	base := identity{
		protocol:          1,
		principal:         "alice@example.com",
		capability:        "test.counter.increment",
		args:              `{"counter":"c","by":1}`,
		authorityRef:      "grant-1",
		class:             "MUTATION",
		generation:        7,
		authorityDigest:   "aa11",
		assurance:         "DURABLE",
		route:             "CRABEDENCE",
		descriptorVersion: 3,
		descriptorDigest:  "dd44",
	}
	digestOf := func(t *testing.T, in identity) string {
		t.Helper()
		d, err := ComputeDigestFromRawWithDescriptor(
			in.protocol, in.principal, in.capability, json.RawMessage(in.args),
			in.authorityRef, in.class, in.generation, in.authorityDigest,
			in.assurance, in.route, in.descriptorVersion, in.descriptorDigest)
		if err != nil {
			t.Fatalf("digest: %v", err)
		}
		return d
	}

	baseDigest := digestOf(t, base)

	// Determinism: identical inputs produce an identical identity.
	for i := 0; i < 20; i++ {
		if got := digestOf(t, base); got != baseDigest {
			t.Fatalf("digest is not deterministic: %s != %s", got, baseDigest)
		}
	}

	// Canonical arguments: key order is not part of the identity.
	reordered := base
	reordered.args = `{"by":1,"counter":"c"}`
	if got := digestOf(t, reordered); got != baseDigest {
		t.Error("argument key order changed the execution identity; the encoding must be canonical")
	}

	// Sensitivity: every bound field changes the identity.
	perturbations := []struct {
		name   string
		mutate func(*identity)
	}{
		{"protocol version", func(in *identity) { in.protocol++ }},
		{"principal", func(in *identity) { in.principal = "bob@example.com" }},
		{"capability", func(in *identity) { in.capability = "system.echo" }},
		{"arguments", func(in *identity) { in.args = `{"counter":"c","by":2}` }},
		{"authority ref", func(in *identity) { in.authorityRef = "grant-2" }},
		{"execution class", func(in *identity) { in.class = "CRITICAL" }},
		{"authority generation", func(in *identity) { in.generation++ }},
		{"authority digest", func(in *identity) { in.authorityDigest = "bb22" }},
		{"assurance profile", func(in *identity) { in.assurance = "HIGH_ASSURANCE" }},
		{"execution route", func(in *identity) { in.route = "DIRECT" }},
		{"descriptor version", func(in *identity) { in.descriptorVersion++ }},
		{"descriptor digest", func(in *identity) { in.descriptorDigest = "ee55" }},
	}
	for _, p := range perturbations {
		in := base
		p.mutate(&in)
		if got := digestOf(t, in); got == baseDigest {
			t.Errorf("changing %s did not change the execution identity", p.name)
		}
	}

	// Unambiguity: moving a value between two fields is a different
	// identity — the canonical encoding must separate fields rather
	// than concatenate them.
	swaps := []struct {
		name   string
		mutate func(*identity)
	}{
		{"principal/capability", func(in *identity) {
			in.principal, in.capability = base.capability, base.principal
		}},
		{"assurance/route", func(in *identity) {
			in.assurance, in.route = base.route, base.assurance
		}},
		{"authority ref/authority digest", func(in *identity) {
			in.authorityRef, in.authorityDigest = base.authorityDigest, base.authorityRef
		}},
		{"authority generation/descriptor version", func(in *identity) {
			in.generation, in.descriptorVersion = int64(base.descriptorVersion), int(base.generation)
		}},
	}
	for _, s := range swaps {
		in := base
		s.mutate(&in)
		if got := digestOf(t, in); got == baseDigest {
			t.Errorf("swapping %s did not change the execution identity", s.name)
		}
	}
}

// TestDispatchIdentityRandomizedDistinctness is the property sweep: over
// randomized identity tuples, the digest is stable for a tuple and
// distinct across tuples.
func TestDispatchIdentityRandomizedDistinctness(t *testing.T) {
	rng := rand.New(rand.NewSource(20260924))
	type tuple struct {
		principal  string
		capability string
		args       string
		generation int64
		authDigest string
		descriptor string
	}
	seen := make(map[string]tuple, 256)
	for i := 0; i < 256; i++ {
		in := tuple{
			principal:  fmt.Sprintf("principal-%d@example.com", rng.Intn(8)),
			capability: fmt.Sprintf("cap.%d", rng.Intn(4)),
			args:       fmt.Sprintf(`{"n":%d}`, rng.Intn(16)),
			generation: int64(rng.Intn(4)),
			authDigest: fmt.Sprintf("ad%02d", rng.Intn(8)),
			descriptor: fmt.Sprintf("dd%02d", rng.Intn(8)),
		}
		digest, err := ComputeDigestFromRawWithDescriptor(
			1, in.principal, in.capability, json.RawMessage(in.args),
			"grant-1", "MUTATION", in.generation, in.authDigest,
			"DURABLE", "CRABEDENCE", 1, in.descriptor)
		if err != nil {
			t.Fatalf("digest: %v", err)
		}
		// Stable for the same tuple.
		again, err := ComputeDigestFromRawWithDescriptor(
			1, in.principal, in.capability, json.RawMessage(in.args),
			"grant-1", "MUTATION", in.generation, in.authDigest,
			"DURABLE", "CRABEDENCE", 1, in.descriptor)
		if err != nil {
			t.Fatalf("digest (repeat): %v", err)
		}
		if digest != again {
			t.Fatalf("digest for %+v is not stable", in)
		}
		// Distinct across distinct tuples.
		if prior, ok := seen[digest]; ok {
			t.Fatalf("distinct tuples collide: %+v and %+v", prior, in)
		}
		seen[digest] = in
	}
}
