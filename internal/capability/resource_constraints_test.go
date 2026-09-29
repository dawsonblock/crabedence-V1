package capability

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// Resource-scoped authority: grants carry constraint dimensions
// (e.g. repo) bound into their immutable material, and capabilities
// bind dimensions to request arguments. A github.issue.create grant
// constrained to repo=[a/b] must not cover c/d.

func TestGrantAllowsResource(t *testing.T) {
	g := &Grant{Constraints: map[string][]string{
		"repo": {"example-org/my-app", "example-org/other"},
		"env":  {"*"},
		"none": {},
	}}
	for _, tc := range []struct {
		dimension, value string
		want             bool
	}{
		{"repo", "example-org/my-app", true},
		{"repo", "example-org/other", true},
		{"repo", "other-org/repo", false},
		{"env", "anything", true},     // "*" admits any value
		{"unbound", "anything", true}, // absent dimension is unconstrained
		{"none", "anything", false},   // present-but-empty admits nothing
	} {
		if got := g.AllowsResource(tc.dimension, tc.value); got != tc.want {
			t.Errorf("AllowsResource(%q, %q) = %v, want %v", tc.dimension, tc.value, got, tc.want)
		}
	}
}

func TestGrantAllowsResourceUnconstrainedGrant(t *testing.T) {
	g := &Grant{}
	if !g.AllowsResource("repo", "any/repo") {
		t.Fatal("a grant without constraints must admit every resource value")
	}
}

// Constrained grants are different authority: the digest must bind the
// constraint material, stay stable across input ordering, and leave
// unconstrained grants on their pre-constraints digest.
func TestGrantDigestBindsConstraints(t *testing.T) {
	base := &Grant{ID: "g", Principal: "alice", Capabilities: []string{"cap.a"}}
	constrained := &Grant{ID: "g", Principal: "alice", Capabilities: []string{"cap.a"},
		Constraints: map[string][]string{"repo": {"a/b", "c/d"}}}
	reordered := &Grant{ID: "g", Principal: "alice", Capabilities: []string{"cap.a"},
		Constraints: map[string][]string{"repo": {"c/d", "a/b", "a/b"}}}
	different := &Grant{ID: "g", Principal: "alice", Capabilities: []string{"cap.a"},
		Constraints: map[string][]string{"repo": {"a/b"}}}

	if ComputeGrantDigest(constrained) == ComputeGrantDigest(base) {
		t.Fatal("constraints must change the grant digest")
	}
	if ComputeGrantDigest(constrained) != ComputeGrantDigest(reordered) {
		t.Fatal("digest must be insensitive to constraint ordering and duplicates")
	}
	if ComputeGrantDigest(constrained) == ComputeGrantDigest(different) {
		t.Fatal("different constraint values must produce different digests")
	}
	if ComputeGrantDigest(base) != ComputeGrantDigest(&Grant{ID: "g", Principal: "alice",
		Capabilities: []string{"cap.a"}, Constraints: map[string][]string{}}) {
		t.Fatal("an explicitly empty constraint map must digest like an absent one")
	}
}

// VerifyAuthority enforces the resource scope end to end: the
// descriptor binds the repo dimension to the "repo" argument, the
// grant lists the admitted repositories, and everything else denies.
func TestVerifyAuthorityResourceConstraints(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(Descriptor{
		ID:             "test.issue.create",
		ExecutionClass: ClassMutation,
		AdapterID:      "test",
		AuthorityPolicy: AuthorityPolicy{
			ID:            "test.issue",
			GrantRequired: true,
			ResourceArguments: map[string]string{
				"repo": "repo",
			},
		},
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	resolver := NewInMemoryGrantResolver()
	resolver.AddGrant(&Grant{
		ID:           "grant_scoped",
		Principal:    "alice@example.com",
		Capabilities: []string{"test.issue.create"},
		Constraints:  map[string][]string{"repo": {"example-org/my-app"}},
	})
	resolver.AddGrant(&Grant{
		ID:           "grant_wide",
		Principal:    "alice@example.com",
		Capabilities: []string{"test.issue.create"},
	})

	req := func(repo, grantID string) AdmissionRequest {
		args, _ := json.Marshal(map[string]string{"repo": repo, "title": "t"})
		return AdmissionRequest{
			Capability: "test.issue.create",
			Arguments:  args,
			Principal:  "alice@example.com",
			GrantID:    grantID,
		}
	}

	if _, fc, reason := r.VerifyAuthority(context.Background(), req("example-org/my-app", "grant_scoped"), resolver); fc != "" {
		t.Fatalf("in-scope repo must be admitted, got %s: %s", fc, reason)
	}
	if _, fc, _ := r.VerifyAuthority(context.Background(), req("other-org/repo", "grant_scoped"), resolver); fc != FailureUnauthorized {
		t.Fatalf("out-of-scope repo must deny, got %s", fc)
	}
	if _, fc, _ := r.VerifyAuthority(context.Background(), req("other-org/repo", "grant_wide"), resolver); fc != "" {
		t.Fatalf("an unconstrained grant must admit any repo, got %s", fc)
	}

	// The bound argument must be present and a string — anything else
	// fails closed rather than silently skipping the check.
	missing, _ := json.Marshal(map[string]string{"title": "t"})
	if _, fc, _ := r.VerifyAuthority(context.Background(), AdmissionRequest{
		Capability: "test.issue.create", Arguments: missing,
		Principal: "alice@example.com", GrantID: "grant_wide",
	}, resolver); fc != FailureUnauthorized {
		t.Fatalf("missing resource argument must deny, got %s", fc)
	}
	nonString, _ := json.Marshal(map[string]any{"repo": 42})
	if _, fc, _ := r.VerifyAuthority(context.Background(), AdmissionRequest{
		Capability: "test.issue.create", Arguments: nonString,
		Principal: "alice@example.com", GrantID: "grant_wide",
	}, resolver); fc != FailureUnauthorized {
		t.Fatalf("non-string resource argument must deny, got %s", fc)
	}
}

// A resource binding without a grant requirement is dead policy —
// constraints could never be evaluated — so the registry scan rejects it.
func TestRegistryRejectsResourceArgumentsWithoutGrant(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(Descriptor{
		ID:             "test.bad.binding",
		ExecutionClass: ClassRead,
		AdapterID:      "test",
		AuthorityPolicy: AuthorityPolicy{
			ID:            "test.bad",
			GrantRequired: false,
			ResourceArguments: map[string]string{
				"repo": "repo",
			},
		},
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	err := r.Validate()
	if err == nil || !strings.Contains(err.Error(), "resource arguments require GrantRequired") {
		t.Fatalf("registry scan must reject resource binding without GrantRequired, got %v", err)
	}
}
