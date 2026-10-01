package idempotency

import (
	"encoding/json"
	"testing"
)

// TestDigestBindsMediation pins the middleware-provenance binding: the
// same request carrying a different mediation claim is a different
// execution identity, and a nil mediation reproduces the pre-binding
// digest bytes exactly (the compatibility path — requests that crossed
// no middleware boundary are unchanged).
func TestDigestBindsMediation(t *testing.T) {
	args := json.RawMessage(`{"amount":10}`)

	// The descriptor-bound digest without mediation is the baseline
	// every mediated request must differ from.
	baseline, err := ComputeDigestFromRawWithDescriptor(1,
		"alice@example.com", "billing.charge", args, "grant_1", "MUTATION",
		0, "", "DURABLE", "CRABEDENCE", 1, "aaaa")
	if err != nil {
		t.Fatalf("baseline digest: %v", err)
	}

	// Nil mediation binds nothing — byte-identical to the baseline, so
	// records created before mediation existed keep their identity.
	compatible, err := ComputeDigestFromRawWithMediation(1,
		"alice@example.com", "billing.charge", args, "grant_1", "MUTATION",
		0, "", "DURABLE", "CRABEDENCE", 1, "aaaa", nil)
	if err != nil {
		t.Fatalf("mediated digest: %v", err)
	}
	if compatible != baseline {
		t.Fatalf("nil mediation must reproduce the baseline digest:\n%s\n%s", baseline, compatible)
	}

	mediation := &MediationBinding{
		MiddlewareSetDigest:    "aa55",
		OriginalArgsDigest:     "bb66",
		ReleaseRootDigest:      "cc77",
		PluginManifestSHA256:   "dd99",
		PluginLibrarySHA256:    "ee11",
		ActivationConfigSHA256: "ff22",
	}
	bound, err := ComputeDigestFromRawWithMediation(1,
		"alice@example.com", "billing.charge", args, "grant_1", "MUTATION",
		0, "", "DURABLE", "CRABEDENCE", 1, "aaaa", mediation)
	if err != nil {
		t.Fatalf("mediated digest: %v", err)
	}
	if bound == baseline {
		t.Fatal("carrying mediation must change the request digest")
	}

	// Each mediation input is independently identity-bearing.
	setOnly := &MediationBinding{MiddlewareSetDigest: "aa55", OriginalArgsDigest: "bb66"}
	setOnlyDigest, err := ComputeDigestFromRawWithMediation(1,
		"alice@example.com", "billing.charge", args, "grant_1", "MUTATION",
		0, "", "DURABLE", "CRABEDENCE", 1, "aaaa", setOnly)
	if err != nil {
		t.Fatal(err)
	}
	if setOnlyDigest == baseline || setOnlyDigest == bound {
		t.Fatal("mediation without a release root must be identity-bearing and distinct")
	}

	differentSet := &MediationBinding{
		MiddlewareSetDigest: "dd88",
		OriginalArgsDigest:  "bb66",
		ReleaseRootDigest:   "cc77",
	}
	differentSetDigest, err := ComputeDigestFromRawWithMediation(1,
		"alice@example.com", "billing.charge", args, "grant_1", "MUTATION",
		0, "", "DURABLE", "CRABEDENCE", 1, "aaaa", differentSet)
	if err != nil {
		t.Fatal(err)
	}
	if differentSetDigest == bound {
		t.Fatal("a different middleware set digest must change the request digest")
	}

	for name, mutate := range map[string]func(*MediationBinding){
		"plugin manifest":   func(value *MediationBinding) { value.PluginManifestSHA256 = "changed" },
		"plugin library":    func(value *MediationBinding) { value.PluginLibrarySHA256 = "changed" },
		"activation config": func(value *MediationBinding) { value.ActivationConfigSHA256 = "changed" },
	} {
		changed := *mediation
		mutate(&changed)
		changedDigest, err := ComputeDigestFromRawWithMediation(1,
			"alice@example.com", "billing.charge", args, "grant_1", "MUTATION",
			0, "", "DURABLE", "CRABEDENCE", 1, "aaaa", &changed)
		if err != nil {
			t.Fatalf("%s digest: %v", name, err)
		}
		if changedDigest == bound {
			t.Fatalf("changing %s must change the request digest", name)
		}
	}
}

// TestDigestMediationDeterminism pins the canonical encoding: field
// emission order in the canonical form is fixed, so the same mediation
// digests identically regardless of how the caller populated the
// binding.
func TestDigestMediationDeterminism(t *testing.T) {
	args := json.RawMessage(`{"amount":10}`)
	mediation := &MediationBinding{
		MiddlewareSetDigest: "aa55",
		OriginalArgsDigest:  "bb66",
	}
	a, err := ComputeDigestFromRawWithMediation(1,
		"alice@example.com", "billing.charge", args, "grant_1", "MUTATION",
		0, "", "DURABLE", "CRABEDENCE", 1, "aaaa", mediation)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ComputeDigestFromRawWithMediation(1,
		"alice@example.com", "billing.charge", args, "grant_1", "MUTATION",
		0, "", "DURABLE", "CRABEDENCE", 1, "aaaa", mediation)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("the mediation binding must digest deterministically")
	}
}
