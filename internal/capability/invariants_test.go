package capability

import "testing"

// Architectural laws, as first-class named tests. Each test asserts one
// law from the capability trust model
// (docs/architecture/capability-trust-model.md); the law ID is the test
// name, so a violation is unambiguous in CI output.

// INV-001: A MUTATION can never execute through LOCAL (or any other
// non-durable route).
func TestINV001MutationCannotUseLocalRoute(t *testing.T) {
	if _, err := Resolve(CapabilityDescriptor{ID: "inv.mut", ExecutionClass: ClassMutation, ExecutionRoute: RouteLocal, AdapterID: "adapter"}); err == nil {
		t.Fatal("INV-001 violated: a MUTATION registered on the LOCAL route")
	}
	if _, err := Resolve(CapabilityDescriptor{ID: "inv.mut", ExecutionClass: ClassMutation, ExecutionRoute: RouteDirect, AdapterID: "adapter"}); err == nil {
		t.Fatal("INV-001 violated: a MUTATION registered on the DIRECT route")
	}
	if _, err := Resolve(CapabilityDescriptor{ID: "inv.mut", ExecutionClass: ClassMutation, AdapterID: "adapter"}); err != nil {
		t.Fatalf("MUTATION with the default durable route must resolve: %v", err)
	}
}

// INV-002: A CRITICAL operation can never execute without
// HIGH_ASSURANCE.
func TestINV002CriticalRequiresHighAssurance(t *testing.T) {
	for _, assurance := range []AssuranceProfile{AssuranceNone, AssuranceStandard, AssuranceDurable} {
		if _, err := Resolve(CapabilityDescriptor{
			ID: "inv.crit", ExecutionClass: ClassCritical, AssuranceProfile: assurance,
			ExecutionRoute: RouteCrabedence, AdapterID: "adapter",
		}); err == nil {
			t.Fatalf("INV-002 violated: CRITICAL registered with assurance %s", assurance)
		}
	}
	resolved, err := Resolve(CapabilityDescriptor{ID: "inv.crit", ExecutionClass: ClassCritical, AdapterID: "adapter"})
	if err != nil {
		t.Fatalf("CRITICAL with the default HIGH_ASSURANCE must resolve: %v", err)
	}
	if resolved.AssuranceProfile != AssuranceHighAssurance {
		t.Fatalf("CRITICAL default assurance = %s, want HIGH_ASSURANCE", resolved.AssuranceProfile)
	}
}

// INV-003: An unrecognized capability can never reach a provider.
func TestINV003UnknownCapabilityIsDeniedAtAdmission(t *testing.T) {
	registry := NewRegistry()
	decision := registry.Admit(AdmissionRequest{Capability: "inv.unknown", Principal: "alice@example.com"})
	if decision.Allowed || decision.FailureCode != FailureCapabilityNotFound {
		t.Fatalf("INV-003 violated: unknown capability admitted: %+v", decision)
	}
}

// INV-004: Caller-supplied execution class cannot influence routing.
func TestINV004CallerClassAssertionCannotDowngrade(t *testing.T) {
	registry := NewRegistry()
	registerForTest(t, registry, CapabilityDescriptor{ID: "inv.crit", ExecutionClass: ClassCritical, AdapterID: "adapter"})

	downgrade := registry.Admit(AdmissionRequest{
		Capability: "inv.crit", Principal: "alice@example.com", GrantID: "g",
		IdempotencyKey: "k", ExecutionClass: "READ",
	})
	if downgrade.Allowed {
		t.Fatal("INV-004 violated: a caller class assertion was accepted")
	}

	// With no assertion, the registry's pinned class is what executes.
	admitted := registry.Admit(AdmissionRequest{
		Capability: "inv.crit", Principal: "alice@example.com", GrantID: "g", IdempotencyKey: "k",
	})
	if !admitted.Allowed || admitted.Descriptor.ExecutionClass != ClassCritical {
		t.Fatalf("the registry class must be authoritative: %+v", admitted)
	}
	if admitted.Descriptor.ExecutionRoute != RouteCrabedence {
		t.Fatalf("INV-004 violated: routing followed a caller value (%s)", admitted.Descriptor.ExecutionRoute)
	}
}
