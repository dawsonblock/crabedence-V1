package capability

import (
	"reflect"
	"strings"
	"testing"
)

// Architectural laws, as first-class named tests. Each test asserts one
// law from the capability trust model
// (docs/architecture/capability-trust-model.md); the law ID is the test
// name, so a violation is unambiguous in CI output.

// INV-013: A LOCAL capability can never require a grant — LOCAL
// execution never reaches the authority resolver, so a grant
// requirement would be silently unenforced.
func TestINV013LocalCannotRequireAGrant(t *testing.T) {
	_, err := Resolve(CapabilityDescriptor{
		ID: "inv.local", ExecutionClass: ClassPure, ExecutionRoute: RouteLocal,
		AdapterID:       "adapter",
		AuthorityPolicy: AuthorityPolicy{ID: "inv.local", GrantRequired: true},
	})
	if err == nil {
		t.Fatal("INV-013 violated: a LOCAL capability required a grant")
	}
	if !strings.Contains(err.Error(), "LOCAL route cannot require a grant") {
		t.Fatalf("unexpected error: %v", err)
	}

	// The whole-registry scan rejects it too, so a descriptor that
	// bypassed Resolve cannot enter a validated registry.
	registry := NewRegistry()
	if err := registry.RegisterResolved(ResolvedDescriptor{
		ID: "inv.local.scan", DescriptorVersion: 1, ExecutionClass: ClassPure,
		AssuranceProfile: AssuranceNone, ExecutionRoute: RouteLocal, AdapterID: "adapter",
		AuthorityPolicy: AuthorityPolicy{ID: "inv.local.scan", GrantRequired: true},
	}); err != nil {
		t.Fatalf("RegisterResolved: %v", err)
	}
	if err := registry.Validate(); err == nil {
		t.Fatal("INV-013 violated: the registry scan accepted LOCAL + grant-required")
	}
}

// INV-014: Provider availability cannot modify capability security
// classification. Availability is runtime state: it never changes a
// descriptor, its digest, or the registry digest, and an unavailable
// adapter never becomes a routing or class fallback.
func TestINV014AvailabilityCannotModifyPolicy(t *testing.T) {
	registry := NewRegistry()
	registerForTest(t, registry, CapabilityDescriptor{ID: "inv.github", ExecutionClass: ClassMutation, AdapterID: "github"})
	registerForTest(t, registry, CapabilityDescriptor{ID: "inv.echo", ExecutionClass: ClassPure, AdapterID: "system"})

	before, ok := registry.Lookup("inv.github")
	if !ok {
		t.Fatal("inv.github must be registered")
	}
	digestBefore, err := registry.Digest()
	if err != nil {
		t.Fatal(err)
	}

	// GitHub is not configured in this deployment; system is.
	availability := registry.Availability(AdapterAvailability{
		"system": {Status: AvailabilityAvailable},
	})
	byID := make(map[string]CapabilityAvailability, len(availability))
	for _, entry := range availability {
		byID[entry.CapabilityID] = entry
	}
	if got := byID["inv.github"].Status; got != AvailabilityAdapterNotConfigured {
		t.Fatalf("unconfigured adapter must be ADAPTER_NOT_CONFIGURED, got %s", got)
	}
	if got := byID["inv.echo"].Status; got != AvailabilityAvailable {
		t.Fatalf("wired adapter must be AVAILABLE, got %s", got)
	}

	// The policy is untouched: same descriptor, same digests, same route.
	after, ok := registry.Lookup("inv.github")
	if !ok {
		t.Fatal("inv.github disappeared from the registry")
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("INV-014 violated: availability changed the descriptor:\nbefore=%+v\nafter=%+v", before, after)
	}
	if after.ExecutionClass != ClassMutation || after.AssuranceProfile != AssuranceDurable || after.ExecutionRoute != RouteCrabedence {
		t.Fatalf("INV-014 violated: classification changed to %s/%s/%s",
			after.ExecutionClass, after.AssuranceProfile, after.ExecutionRoute)
	}
	digestAfter, err := registry.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if digestBefore != digestAfter {
		t.Fatalf("INV-014 violated: availability changed the registry digest (%s -> %s)", digestBefore, digestAfter)
	}

	// Admission is policy and does not consult availability: the request
	// is admitted, then fails closed at dispatch as CAPABILITY_UNAVAILABLE
	// (covered end to end in the execution package). It never becomes an
	// unknown capability.
	decision := registry.Admit(AdmissionRequest{Capability: "inv.github", Principal: "alice@example.com", GrantID: "g", IdempotencyKey: "k"})
	if !decision.Allowed {
		t.Fatalf("admission must not consult availability: %+v", decision)
	}
	if decision.Descriptor.ExecutionRoute != RouteCrabedence {
		t.Fatalf("INV-014 violated: routing changed to %s", decision.Descriptor.ExecutionRoute)
	}
}

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
