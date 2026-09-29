package capability

import (
	"testing"
	"time"
)

// TestVerifyGrantDigest pins the authority-material identity rule: a
// grant must PROVE its identity from the material it carries, so a
// missing digest or a digest that disagrees with the material is
// unverified — the store must refuse it rather than resolve the
// (possibly degraded) material it decoded.
func TestVerifyGrantDigest(t *testing.T) {
	grant := &Grant{
		ID:           "g1",
		Generation:   3,
		Principal:    "alice@example.com",
		Capabilities: []string{"cap.a"},
		Constraints:  map[string][]string{"repo": {"acme/one"}},
		IssuedAt:     time.UnixMilli(1_700_000_000_000).UTC(),
		ExpiresAt:    time.UnixMilli(1_700_003_600_000).UTC(),
	}
	grant.Digest = ComputeGrantDigest(grant)
	if !VerifyGrantDigest(grant) {
		t.Fatal("a grant whose digest matches its material must verify")
	}

	widened := *grant
	widened.Capabilities = []string{"cap.a", "cap.evil"}
	if VerifyGrantDigest(&widened) {
		t.Fatal("widened capabilities must not verify against the stored digest")
	}

	unconstrained := *grant
	unconstrained.Constraints = nil
	if VerifyGrantDigest(&unconstrained) {
		t.Fatal("dropped constraints must not verify against the stored digest")
	}

	empty := *grant
	empty.Digest = ""
	if VerifyGrantDigest(&empty) {
		t.Fatal("a grant without a stored digest must not verify")
	}

	if VerifyGrantDigest(nil) {
		t.Fatal("nil must not verify")
	}
}

// TestComputeGrantDigestIsCanonicalOverConstraints proves the digest is
// stable under constraint ordering and duplication, so a reissued
// equivalent grant keeps the same identity.
func TestComputeGrantDigestIsCanonicalOverConstraints(t *testing.T) {
	base := &Grant{
		ID:           "g1",
		Generation:   1,
		Principal:    "alice@example.com",
		Capabilities: []string{"cap.b", "cap.a"},
		Constraints:  map[string][]string{"repo": {"acme/two", "acme/one", "acme/one"}},
	}
	reordered := &Grant{
		ID:           "g1",
		Generation:   1,
		Principal:    "alice@example.com",
		Capabilities: []string{"cap.a", "cap.b"},
		Constraints:  map[string][]string{"repo": {"acme/one", "acme/two"}},
	}
	if ComputeGrantDigest(base) != ComputeGrantDigest(reordered) {
		t.Fatal("logically identical grant material must produce the same digest")
	}
}
