package capability

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
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

// The brokered path answers "what does this principal's store admit for
// this request" when the caller names no reference: exactly one live
// grant that covers the capability and admits the bound arguments
// resolves; zero denies; two deny as ambiguous, because an execution
// must be attributable to exactly one authority's material.
func TestVerifyAuthorityBrokered(t *testing.T) {
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
	resolver.AddGrant(&Grant{
		ID:           "grant_revoked",
		Principal:    "alice@example.com",
		Capabilities: []string{"test.issue.create"},
		Revoked:      true,
	})
	resolver.AddGrant(&Grant{
		ID:           "grant_expired",
		Principal:    "alice@example.com",
		Capabilities: []string{"test.issue.create"},
		ExpiresAt:    time.Now().Add(-time.Hour),
	})
	resolver.AddGrant(&Grant{
		ID:           "grant_other_capability",
		Principal:    "alice@example.com",
		Capabilities: []string{"some.other.capability"},
	})
	// Mallory holds a covering grant — she is legitimately authorized,
	// and her grant must never appear in alice's candidacy.
	resolver.AddGrant(&Grant{
		ID:           "grant_other_principal",
		Principal:    "mallory@example.com",
		Capabilities: []string{"test.issue.create"},
	})

	req := func(repo string) AdmissionRequest {
		args, _ := json.Marshal(map[string]string{"repo": repo, "title": "t"})
		return AdmissionRequest{
			Capability: "test.issue.create",
			Arguments:  args,
			Principal:  "alice@example.com",
			// No GrantID — the store answers.
		}
	}

	// Two grants admit in-scope: ambiguous — the durable record could not
	// name which authority admitted the execution.
	if _, fc, reason := r.VerifyAuthority(context.Background(), req("example-org/my-app"), resolver); fc != FailureUnauthorized {
		t.Fatalf("two admitting grants must refuse as ambiguous, got %s", fc)
	} else if !strings.Contains(reason, "ambiguous") {
		t.Fatalf("the refusal should name the ambiguity, got: %s", reason)
	}

	// Constraints are part of candidacy: for a repo only the wide grant
	// admits, the scoped grant is not a candidate and the answer is one.
	grant, fc, reason := r.VerifyAuthority(context.Background(), req("other-org/repo"), resolver)
	if fc != "" {
		t.Fatalf("exactly one admitting grant must resolve, got %s: %s", fc, reason)
	}
	if grant.ID != "grant_wide" {
		t.Fatalf("the admitting grant is grant_wide, got %s", grant.ID)
	}

	// Mallory resolves through her own grant — the enumeration scopes to
	// the authenticated principal, so her grant is not alice's candidacy
	// and alice's are not hers.
	grant, fc, _ = r.VerifyAuthority(context.Background(), AdmissionRequest{
		Capability: "test.issue.create",
		Arguments:  req("other-org/repo").Arguments,
		Principal:  "mallory@example.com",
	}, resolver)
	if fc != "" {
		t.Fatalf("mallory's own grant must admit her, got %s", fc)
	}
	if grant.ID != "grant_other_principal" {
		t.Fatalf("mallory must resolve her own grant, got %s", grant.ID)
	}

	// A principal holding no grants at all is denied.
	if _, fc, _ := r.VerifyAuthority(context.Background(), AdmissionRequest{
		Capability: "test.issue.create",
		Arguments:  req("other-org/repo").Arguments,
		Principal:  "nobody@example.com",
	}, resolver); fc != FailureUnauthorized {
		t.Fatalf("a grantless principal must deny, got %s", fc)
	}
}

// A resolver that cannot enumerate a principal's grants cannot broker:
// the named-reference path still works, the reference-less one denies.
func TestVerifyAuthorityBrokeredRequiresEnumeration(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(Descriptor{
		ID:             "test.nogrant",
		ExecutionClass: ClassMutation,
		AdapterID:      "test",
		AuthorityPolicy: AuthorityPolicy{
			ID:            "test.nogrant",
			GrantRequired: true,
		},
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	if _, fc, _ := r.VerifyAuthority(context.Background(), AdmissionRequest{
		Capability: "test.nogrant", Principal: "alice@example.com",
	}, NoopGrantResolver{}); fc != FailureUnauthorized {
		t.Fatalf("a non-enumerating resolver must deny the brokered path, got %s", fc)
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
