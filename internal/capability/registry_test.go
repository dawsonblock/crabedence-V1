package capability

import (
	"encoding/json"
	"testing"
)

func TestRegistryRegisterAndLookup(t *testing.T) {
	r := NewRegistry()

	desc := Descriptor{
		ID:             "test.echo",
		ExecutionClass: ClassPure,
		AdapterID:      "test",
		AuthorityPolicy: AuthorityPolicy{
			ID:            "test.echo",
			GrantRequired: false,
		},
	}

	if err := r.Register(desc); err != nil {
		t.Fatal(err)
	}

	got, ok := r.Lookup("test.echo")
	if !ok {
		t.Fatal("expected to find test.echo")
	}
	if got.ID != "test.echo" {
		t.Errorf("expected ID=test.echo, got %s", got.ID)
	}
	if got.ExecutionClass != ClassPure {
		t.Errorf("expected ClassPure, got %s", got.ExecutionClass)
	}
}

func TestRegistryDuplicateRegister(t *testing.T) {
	r := NewRegistry()

	desc := Descriptor{
		ID:             "test.dup",
		ExecutionClass: ClassPure,
		AdapterID:      "test",
	}

	if err := r.Register(desc); err != nil {
		t.Fatal(err)
	}

	// Duplicate should fail
	err := r.Register(desc)
	if err == nil {
		t.Fatal("expected error for duplicate registration")
	}
}

func TestRegistryLookupMissing(t *testing.T) {
	r := NewRegistry()

	_, ok := r.Lookup("nonexistent")
	if ok {
		t.Fatal("expected not found for nonexistent capability")
	}
}

func TestRegistryList(t *testing.T) {
	r := NewRegistry()

	r.Register(Descriptor{ID: "a", ExecutionClass: ClassPure, AdapterID: "test"})
	r.Register(Descriptor{ID: "b", ExecutionClass: ClassRead, AdapterID: "test"})
	r.Register(Descriptor{ID: "c", ExecutionClass: ClassMutation, AdapterID: "test"})

	ids := r.List()
	if len(ids) != 3 {
		t.Fatalf("expected 3 capabilities, got %d", len(ids))
	}
	if r.Count() != 3 {
		t.Fatalf("expected count=3, got %d", r.Count())
	}
}

func TestExecutionClassValid(t *testing.T) {
	tests := []struct {
		class ExecutionClass
		valid bool
	}{
		{ClassPure, true},
		{ClassRead, true},
		{ClassMutation, true},
		{ClassCritical, true},
		{"BANANA", false},
		{"", false},
	}
	for _, tt := range tests {
		if tt.class.Valid() != tt.valid {
			t.Errorf("%s: Valid() = %v, want %v", tt.class, tt.class.Valid(), tt.valid)
		}
	}
}

func TestExecutionClassRequiresIdempotencyKey(t *testing.T) {
	tests := []struct {
		class    ExecutionClass
		required bool
	}{
		{ClassPure, false},
		{ClassRead, false},
		{ClassMutation, true},
		{ClassCritical, true},
	}
	for _, tt := range tests {
		if tt.class.RequiresIdempotencyKey() != tt.required {
			t.Errorf("%s: RequiresIdempotencyKey() = %v, want %v", tt.class, tt.class.RequiresIdempotencyKey(), tt.required)
		}
	}
}

func TestExecutionClassRequiresEvidence(t *testing.T) {
	if !ClassCritical.RequiresEvidence() {
		t.Error("CRITICAL should require evidence")
	}
	if ClassPure.RequiresEvidence() {
		t.Error("PURE should not require evidence")
	}
}

func TestAdmitCapabilityNotFound(t *testing.T) {
	r := NewRegistry()
	decision := r.Admit(AdmissionRequest{
		Capability: "nonexistent",
		Principal:  "alice@example.com",
	})
	if decision.Allowed {
		t.Fatal("expected not allowed for nonexistent capability")
	}
	if decision.FailureCode != FailureCapabilityNotFound {
		t.Errorf("expected CAPABILITY_NOT_FOUND, got %s", decision.FailureCode)
	}
}

func TestAdmitCapabilityUnimplemented(t *testing.T) {
	r := NewRegistry()
	r.Register(Descriptor{
		ID:             "test.unimpl",
		ExecutionClass: ClassPure,
		AdapterID:      "", // No adapter
	})
	decision := r.Admit(AdmissionRequest{
		Capability: "test.unimpl",
		Principal:  "alice@example.com",
	})
	if decision.Allowed {
		t.Fatal("expected not allowed for unimplemented capability")
	}
	if decision.FailureCode != FailureCapabilityUnimplemented {
		t.Errorf("expected CAPABILITY_UNIMPLEMENTED, got %s", decision.FailureCode)
	}
}

func TestAdmitExecutionClassMismatch(t *testing.T) {
	r := NewRegistry()
	r.Register(Descriptor{
		ID:             "test.mismatch",
		ExecutionClass: ClassMutation,
		AdapterID:      "test",
		AuthorityPolicy: AuthorityPolicy{
			ID:            "test.mismatch",
			GrantRequired: true,
		},
	})

	// Caller asserts READ but registry pins MUTATION
	decision := r.Admit(AdmissionRequest{
		Capability:     "test.mismatch",
		Principal:      "alice@example.com",
		GrantID:        "grant_123",
		IdempotencyKey: "key_001",
		ExecutionClass: "READ",
	})
	if decision.Allowed {
		t.Fatal("expected not allowed for class mismatch")
	}
	if decision.FailureCode != FailureAdmissionDenied {
		t.Errorf("expected ADMISSION_DENIED, got %s", decision.FailureCode)
	}
}

func TestAdmitMissingPrincipal(t *testing.T) {
	r := NewRegistry()
	r.Register(Descriptor{
		ID:             "test.noprincipal",
		ExecutionClass: ClassPure,
		AdapterID:      "test",
	})

	decision := r.Admit(AdmissionRequest{
		Capability: "test.noprincipal",
		// Missing Principal
	})
	if decision.Allowed {
		t.Fatal("expected not allowed for missing principal")
	}
	if decision.FailureCode != FailureUnauthorized {
		t.Errorf("expected UNAUTHORIZED, got %s", decision.FailureCode)
	}
}

func TestAdmitMissingGrantID(t *testing.T) {
	r := NewRegistry()
	r.Register(Descriptor{
		ID:             "test.nogrant",
		ExecutionClass: ClassPure,
		AdapterID:      "test",
		AuthorityPolicy: AuthorityPolicy{
			ID:            "test.nogrant",
			GrantRequired: true,
		},
	})

	decision := r.Admit(AdmissionRequest{
		Capability: "test.nogrant",
		Principal:  "alice@example.com",
		// Missing GrantID
	})
	if decision.Allowed {
		t.Fatal("expected not allowed for missing grant_id")
	}
	if decision.FailureCode != FailureUnauthorized {
		t.Errorf("expected UNAUTHORIZED, got %s", decision.FailureCode)
	}
}

func TestAdmitMissingIdempotencyKey(t *testing.T) {
	r := NewRegistry()
	r.Register(Descriptor{
		ID:             "test.nokey",
		ExecutionClass: ClassMutation,
		AdapterID:      "test",
		AuthorityPolicy: AuthorityPolicy{
			ID:            "test.nokey",
			GrantRequired: true,
		},
	})

	decision := r.Admit(AdmissionRequest{
		Capability: "test.nokey",
		Principal:  "alice@example.com",
		GrantID:    "grant_123",
		// Missing IdempotencyKey
	})
	if decision.Allowed {
		t.Fatal("expected not allowed for missing idempotency key")
	}
	if decision.FailureCode != FailureAdmissionDenied {
		t.Errorf("expected ADMISSION_DENIED, got %s", decision.FailureCode)
	}
}

func TestAdmitValid(t *testing.T) {
	r := NewRegistry()
	r.Register(Descriptor{
		ID:             "test.valid",
		ExecutionClass: ClassMutation,
		AdapterID:      "test",
		AuthorityPolicy: AuthorityPolicy{
			ID:            "test.valid",
			GrantRequired: true,
		},
		Schema: json.RawMessage(`{"type":"object"}`),
	})

	decision := r.Admit(AdmissionRequest{
		Capability:     "test.valid",
		Principal:      "alice@example.com",
		GrantID:        "grant_123",
		IdempotencyKey: "key_001",
	})
	if !decision.Allowed {
		t.Fatalf("expected allowed, got %s: %s", decision.FailureCode, decision.Reason)
	}
	if decision.Descriptor.ID != "test.valid" {
		t.Errorf("expected descriptor ID=test.valid, got %s", decision.Descriptor.ID)
	}
}

func TestThreeDimensionalRouting(t *testing.T) {
	tests := []struct {
		name          string
		class         ExecutionClass
		assurance     AssuranceProfile
		route         ExecutionRoute
		wantAssurance AssuranceProfile
		wantRoute     ExecutionRoute
	}{
		{
			name:          "PURE defaults to NONE/LOCAL",
			class:         ClassPure,
			wantAssurance: AssuranceNone,
			wantRoute:     RouteLocal,
		},
		{
			name:          "READ defaults to STANDARD/DIRECT",
			class:         ClassRead,
			wantAssurance: AssuranceStandard,
			wantRoute:     RouteDirect,
		},
		{
			name:          "MUTATION defaults to DURABLE/CRABEDENCE",
			class:         ClassMutation,
			wantAssurance: AssuranceDurable,
			wantRoute:     RouteCrabedence,
		},
		{
			name:          "CRITICAL defaults to HIGH_ASSURANCE/CRABEDENCE",
			class:         ClassCritical,
			wantAssurance: AssuranceHighAssurance,
			wantRoute:     RouteCrabedence,
		},
		{
			name:          "READ with HIGH_ASSURANCE overrides to CRABEDENCE",
			class:         ClassRead,
			assurance:     AssuranceHighAssurance,
			wantAssurance: AssuranceHighAssurance,
			wantRoute:     RouteCrabedence,
		},
		{
			name:          "READ with explicit DIRECT route",
			class:         ClassRead,
			route:         RouteDirect,
			wantAssurance: AssuranceStandard,
			wantRoute:     RouteDirect,
		},
		{
			name:          "PURE with explicit CRABEDENCE route (unusual but allowed)",
			class:         ClassPure,
			route:         RouteCrabedence,
			wantAssurance: AssuranceNone,
			wantRoute:     RouteCrabedence,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := Descriptor{
				ID:               "test.cap",
				ExecutionClass:   tt.class,
				AssuranceProfile: tt.assurance,
				ExecutionRoute:   tt.route,
				AdapterID:        "test",
			}
			if got := d.EffectiveAssuranceProfile(); got != tt.wantAssurance {
				t.Errorf("assurance: got %s, want %s", got, tt.wantAssurance)
			}
			if got := d.EffectiveExecutionRoute(); got != tt.wantRoute {
				t.Errorf("route: got %s, want %s", got, tt.wantRoute)
			}
		})
	}
}

func TestExecutionRouteValid(t *testing.T) {
	valid := []ExecutionRoute{RouteLocal, RouteDirect, RouteCrabedence}
	for _, r := range valid {
		if !r.Valid() {
			t.Errorf("expected %s to be valid", r)
		}
	}
	invalid := []ExecutionRoute{"", "FAST", "SLOW", "remote"}
	for _, r := range invalid {
		if r.Valid() {
			t.Errorf("expected %q to be invalid", r)
		}
	}
}

func TestDefaultExecutionRoute(t *testing.T) {
	tests := []struct {
		profile AssuranceProfile
		want    ExecutionRoute
	}{
		{AssuranceNone, RouteLocal},
		{AssuranceStandard, RouteDirect},
		{AssuranceDurable, RouteCrabedence},
		{AssuranceHighAssurance, RouteCrabedence},
	}
	for _, tt := range tests {
		if got := DefaultExecutionRoute(tt.profile); got != tt.want {
			t.Errorf("DefaultExecutionRoute(%s) = %s, want %s", tt.profile, got, tt.want)
		}
	}
}
