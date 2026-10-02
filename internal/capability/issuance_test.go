package capability

import (
	"reflect"
	"strings"
	"testing"
)

// issuanceTestRegistry builds a small catalog covering the cases the issuance
// policy has to distinguish: a two-dimension capability, a single-dimension
// one, and one declaring no resource dimensions at all.
func issuanceTestRegistry(t *testing.T) *Registry {
	t.Helper()
	registry := NewRegistry()
	for _, descriptor := range []CapabilityDescriptor{
		{
			ID:             "test.mutation.scoped",
			ExecutionClass: ClassMutation,
			AuthorityPolicy: AuthorityPolicy{
				ID:                "test.mutation.scoped",
				GrantRequired:     true,
				ResourceArguments: map[string]string{"repo": "repo", "base": "base"},
			},
		},
		{
			ID:             "test.mutation.repo",
			ExecutionClass: ClassMutation,
			AuthorityPolicy: AuthorityPolicy{
				ID:                "test.mutation.repo",
				GrantRequired:     true,
				ResourceArguments: map[string]string{"repo": "repo"},
			},
		},
		{
			ID:             "test.plain",
			ExecutionClass: ClassPure,
			AuthorityPolicy: AuthorityPolicy{
				ID: "test.plain",
			},
		},
	} {
		if err := registry.Register(descriptor); err != nil {
			t.Fatalf("register %s: %v", descriptor.ID, err)
		}
	}
	return registry
}

func TestRequiredResourceDimensionsUnionsTheSelection(t *testing.T) {
	registry := issuanceTestRegistry(t)

	got, err := registry.RequiredResourceDimensions([]string{"test.mutation.scoped", "test.mutation.repo"})
	if err != nil {
		t.Fatalf("RequiredResourceDimensions: %v", err)
	}
	if want := []string{"base", "repo"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("dimensions: got %v, want %v", got, want)
	}

	got, err = registry.RequiredResourceDimensions([]string{"test.plain"})
	if err != nil {
		t.Fatalf("RequiredResourceDimensions: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("a capability declaring no dimensions must require none, got %v", got)
	}
}

func TestRequiredResourceDimensionsWildcardCoversTheWholeCatalog(t *testing.T) {
	registry := issuanceTestRegistry(t)
	got, err := registry.RequiredResourceDimensions([]string{"*"})
	if err != nil {
		t.Fatalf("RequiredResourceDimensions: %v", err)
	}
	if want := []string{"base", "repo"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("wildcard dimensions: got %v, want %v", got, want)
	}
}

// The previously dangerous case: a capability that declares a resource
// dimension, issued with no scope declaration at all, used to mint a grant
// covering every resource the service credential could reach. It must now be a
// named rejection.
func TestValidateIssuanceScopeOmittedDimensionIsRejection(t *testing.T) {
	registry := issuanceTestRegistry(t)
	_, err := registry.ValidateIssuanceScope([]string{"test.mutation.repo"}, nil, nil)
	if err == nil {
		t.Fatal("omitting a declared dimension must reject")
	}
	if want := `resource dimension "repo" requires either a constraint or an explicit unconstrained acknowledgement`; !strings.Contains(err.Error(), want) {
		t.Fatalf("error should carry %q, got %q", want, err.Error())
	}
}

func TestValidateIssuanceScopeConcreteAndAcknowledged(t *testing.T) {
	registry := issuanceTestRegistry(t)

	effective, err := registry.ValidateIssuanceScope(
		[]string{"test.mutation.repo"},
		map[string][]string{"repo": {"example-org/my-app"}},
		nil,
	)
	if err != nil {
		t.Fatalf("constrained dimension: %v", err)
	}
	if want := map[string][]string{"repo": {"example-org/my-app"}}; !reflect.DeepEqual(effective, want) {
		t.Fatalf("effective constraints: got %v, want %v", effective, want)
	}

	// An explicit acknowledgement materializes as the wildcard value, so the
	// grant records that its breadth was a choice rather than an omission.
	effective, err = registry.ValidateIssuanceScope(
		[]string{"test.mutation.repo"},
		nil,
		[]string{"repo"},
	)
	if err != nil {
		t.Fatalf("acknowledged dimension: %v", err)
	}
	if want := map[string][]string{"repo": {"*"}}; !reflect.DeepEqual(effective, want) {
		t.Fatalf("acknowledged constraints: got %v, want %v", effective, want)
	}
}

// Every declared dimension is enforced, not just the first one the issuer
// remembered: repo alone must not satisfy a capability that also binds base.
func TestValidateIssuanceScopeMultipleDimensionsAllEnforced(t *testing.T) {
	registry := issuanceTestRegistry(t)

	_, err := registry.ValidateIssuanceScope(
		[]string{"test.mutation.scoped"},
		map[string][]string{"repo": {"example-org/my-app"}},
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), `"base"`) {
		t.Fatalf("a grant covering repo but not base must name base, got %v", err)
	}

	effective, err := registry.ValidateIssuanceScope(
		[]string{"test.mutation.scoped"},
		map[string][]string{"repo": {"example-org/my-app"}},
		[]string{"base"},
	)
	if err != nil {
		t.Fatalf("repo constrained plus base acknowledged: %v", err)
	}
	want := map[string][]string{"repo": {"example-org/my-app"}, "base": {"*"}}
	if !reflect.DeepEqual(effective, want) {
		t.Fatalf("effective constraints: got %v, want %v", effective, want)
	}
}

func TestValidateIssuanceScopeRejections(t *testing.T) {
	registry := issuanceTestRegistry(t)
	for _, tc := range []struct {
		name          string
		capabilities  []string
		constraints   map[string][]string
		unconstrained []string
		want          string
	}{
		{
			name:         "conflicting constrained and unconstrained",
			capabilities: []string{"test.mutation.repo"},
			constraints:  map[string][]string{"repo": {"a/b"}},
			unconstrained: []string{
				"repo",
			},
			want: `resource dimension "repo" declared both constrained and unconstrained`,
		},
		{
			name:         "unknown constrained dimension",
			capabilities: []string{"test.mutation.repo"},
			constraints:  map[string][]string{"repo": {"a/b"}, "tenant": {"t1"}},
			want:         `unknown resource dimension "tenant"`,
		},
		{
			name:         "unknown acknowledged dimension",
			capabilities: []string{"test.mutation.repo"},
			constraints:  map[string][]string{"repo": {"a/b"}},
			unconstrained: []string{
				"tenant",
			},
			want: `unknown resource dimension "tenant"`,
		},
		{
			name:         "wildcard value smuggled through a constraint",
			capabilities: []string{"test.mutation.repo"},
			constraints:  map[string][]string{"repo": {"*"}},
			want:         "wildcard shorthand",
		},
		{
			name:         "duplicate constraint value",
			capabilities: []string{"test.mutation.repo"},
			constraints:  map[string][]string{"repo": {"a/b", "a/b"}},
			want:         "declared twice",
		},
		{
			name:         "duplicate acknowledgement",
			capabilities: []string{"test.mutation.repo"},
			unconstrained: []string{
				"repo",
				"repo",
			},
			want: "acknowledged unconstrained twice",
		},
		{
			name:         "empty constraint value",
			capabilities: []string{"test.mutation.repo"},
			constraints:  map[string][]string{"repo": {""}},
			want:         "empty constraint value",
		},
		{
			name:         "empty constraint list",
			capabilities: []string{"test.mutation.repo"},
			constraints:  map[string][]string{"repo": {}},
			want:         "empty constraint list",
		},
		{
			name:         "unknown capability",
			capabilities: []string{"test.nonexistent"},
			constraints:  map[string][]string{"repo": {"a/b"}},
			want:         "not in the issuance catalog",
		},
		{
			name:         "wildcard mixed with named capabilities",
			capabilities: []string{"*", "test.mutation.repo"},
			constraints:  map[string][]string{"repo": {"a/b"}},
			want:         "cannot be combined with named capabilities",
		},
		{
			name:         "dimension a capability does not declare",
			capabilities: []string{"test.plain"},
			constraints:  map[string][]string{"repo": {"a/b"}},
			want:         `unknown resource dimension "repo"`,
		},
		{
			name:         "empty capability list",
			capabilities: nil,
			want:         "capability list is empty",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := registry.ValidateIssuanceScope(tc.capabilities, tc.constraints, tc.unconstrained)
			if err == nil {
				t.Fatalf("expected rejection containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("rejection: got %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

// A wildcard-all grant is a deliberate act: it must still address every
// dimension the whole catalog declares, so it cannot be produced by leaving
// fields empty.
func TestValidateIssuanceScopeWildcardAllRequiresExplicitScope(t *testing.T) {
	registry := issuanceTestRegistry(t)

	if _, err := registry.ValidateIssuanceScope([]string{"*"}, nil, nil); err == nil {
		t.Fatal("a wildcard grant with no scope declarations must reject")
	}

	effective, err := registry.ValidateIssuanceScope(
		[]string{"*"},
		nil,
		[]string{"repo", "base"},
	)
	if err != nil {
		t.Fatalf("wildcard grant acknowledging every dimension: %v", err)
	}
	want := map[string][]string{"repo": {"*"}, "base": {"*"}}
	if !reflect.DeepEqual(effective, want) {
		t.Fatalf("wildcard effective constraints: got %v, want %v", effective, want)
	}
}

// The acknowledgement changes what the grant carries, but not what the
// evaluator does with it: "*" still means unconstrained, and compatibility
// for grants that carry no dimension at all is untouched.
func TestAcknowledgedUnconstrainedGrantEvaluatesUnchanged(t *testing.T) {
	grant := Grant{
		Capabilities: []string{"test.mutation.repo"},
		Constraints:  map[string][]string{"repo": {"*"}},
	}
	if !grant.AllowsResource("repo", "anything/at-all") {
		t.Fatal("an acknowledged wildcard must still admit every value")
	}

	historical := Grant{
		Capabilities: []string{"test.mutation.repo"},
	}
	if !historical.AllowsResource("repo", "anything/at-all") {
		t.Fatal("a historical grant with the dimension absent must still verify")
	}
}
