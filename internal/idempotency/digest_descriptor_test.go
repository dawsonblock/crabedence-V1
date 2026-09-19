package idempotency

import (
	"encoding/json"
	"testing"
)

// TestDigestBindsDescriptorIdentity pins the descriptor-identity
// binding: the same request under a different capability policy is a
// different execution identity, and zero descriptor inputs reproduce
// the pre-binding digest bytes exactly (the compatibility path).
func TestDigestBindsDescriptorIdentity(t *testing.T) {
	args := json.RawMessage(`{"amount":10}`)

	legacy, err := ComputeDigestFromRawWithAuthority(1,
		"alice@example.com", "billing.charge", args, "grant_1", "MUTATION",
		0, "", "DURABLE", "CRABEDENCE")
	if err != nil {
		t.Fatalf("legacy digest: %v", err)
	}

	// Zero descriptor inputs are omitted from the canonical form, so
	// the descriptor-aware function reproduces the legacy bytes.
	compatible, err := ComputeDigestFromRawWithDescriptor(1,
		"alice@example.com", "billing.charge", args, "grant_1", "MUTATION",
		0, "", "DURABLE", "CRABEDENCE", 0, "")
	if err != nil {
		t.Fatalf("descriptor digest: %v", err)
	}
	if compatible != legacy {
		t.Fatalf("zero descriptor inputs must reproduce the legacy digest:\n%s\n%s", legacy, compatible)
	}

	// A bound descriptor identity changes the digest.
	bound, err := ComputeDigestFromRawWithDescriptor(1,
		"alice@example.com", "billing.charge", args, "grant_1", "MUTATION",
		0, "", "DURABLE", "CRABEDENCE", 1, "aaaa")
	if err != nil {
		t.Fatalf("descriptor digest: %v", err)
	}
	if bound == legacy {
		t.Fatal("binding a descriptor digest must change the request digest")
	}

	// Each descriptor input is independently identity-bearing.
	versionOnly, err := ComputeDigestFromRawWithDescriptor(1,
		"alice@example.com", "billing.charge", args, "grant_1", "MUTATION",
		0, "", "DURABLE", "CRABEDENCE", 2, "")
	if err != nil {
		t.Fatal(err)
	}
	if versionOnly == legacy || versionOnly == bound {
		t.Fatal("a descriptor version alone must be identity-bearing")
	}
	digestOnly, err := ComputeDigestFromRawWithDescriptor(1,
		"alice@example.com", "billing.charge", args, "grant_1", "MUTATION",
		0, "", "DURABLE", "CRABEDENCE", 0, "bbbb")
	if err != nil {
		t.Fatal(err)
	}
	if digestOnly == legacy || digestOnly == versionOnly || digestOnly == bound {
		t.Fatal("a descriptor digest alone must be identity-bearing")
	}
}
