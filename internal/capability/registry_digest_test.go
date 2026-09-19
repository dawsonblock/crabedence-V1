package capability

import (
	"encoding/json"
	"strings"
	"testing"
)

func registerForTest(t *testing.T, registry *Registry, descriptor CapabilityDescriptor) {
	t.Helper()
	if err := registry.Register(descriptor); err != nil {
		t.Fatalf("register %s: %v", descriptor.ID, err)
	}
}

func TestRegistryDigestIsStableAndPolicySensitive(t *testing.T) {
	build := func(t *testing.T, schema json.RawMessage, mutateClass ExecutionClass) *Registry {
		t.Helper()
		registry := NewRegistry()
		registerForTest(t, registry, CapabilityDescriptor{ID: "a.read", ExecutionClass: ClassRead, AdapterID: "adapter", Schema: schema})
		registerForTest(t, registry, CapabilityDescriptor{ID: "b.mutate", ExecutionClass: mutateClass, AdapterID: "adapter"})
		return registry
	}

	schema := json.RawMessage(`{"type":"object","properties":{"x":{"type":"number","minimum":1}}}`)
	base, err := build(t, schema, ClassMutation).Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}

	// Key order and numeric spelling are canonicalized away.
	reordered, err := build(t, json.RawMessage(`{"properties":{"x":{"minimum":1.0,"type":"number"}},"type":"object"}`), ClassMutation).Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if reordered != base {
		t.Fatalf("schema key order/number spelling must not change the registry digest:\n%s\n%s", base, reordered)
	}

	// A classification change is a policy change.
	changedClass, err := build(t, schema, ClassRead).Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if changedClass == base {
		t.Fatal("changing a capability's execution class must change the registry digest")
	}

	// Adding a capability is a policy change.
	added := build(t, schema, ClassMutation)
	registerForTest(t, added, CapabilityDescriptor{ID: "c.read", ExecutionClass: ClassRead, AdapterID: "adapter"})
	addedDigest, err := added.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if addedDigest == base {
		t.Fatal("adding a capability must change the registry digest")
	}

	// Rebuilding the same policy reproduces the digest exactly.
	rebuilt, err := build(t, schema, ClassMutation).Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if rebuilt != base {
		t.Fatal("the same registry policy must reproduce the same digest")
	}
}

func TestRegistryReportCounts(t *testing.T) {
	registry := NewRegistry()
	registerForTest(t, registry, CapabilityDescriptor{ID: "a.pure", ExecutionClass: ClassPure, AdapterID: "adapter"})
	registerForTest(t, registry, CapabilityDescriptor{ID: "b.read", ExecutionClass: ClassRead, AdapterID: "adapter"})
	registerForTest(t, registry, CapabilityDescriptor{ID: "c.mutate", ExecutionClass: ClassMutation, AdapterID: "adapter"})
	registerForTest(t, registry, CapabilityDescriptor{ID: "d.critical", ExecutionClass: ClassCritical, AdapterID: "adapter"})

	report, err := registry.Report()
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if report.Total != 4 {
		t.Fatalf("total = %d, want 4", report.Total)
	}
	if report.ByClass[ClassPure] != 1 || report.ByClass[ClassRead] != 1 || report.ByClass[ClassMutation] != 1 || report.ByClass[ClassCritical] != 1 {
		t.Fatalf("class counts = %+v", report.ByClass)
	}
	if report.ByRoute[RouteLocal] != 1 || report.ByRoute[RouteDirect] != 1 || report.ByRoute[RouteCrabedence] != 2 {
		t.Fatalf("route counts = %+v", report.ByRoute)
	}
	if report.ByAssurance[AssuranceNone] != 1 || report.ByAssurance[AssuranceStandard] != 1 || report.ByAssurance[AssuranceDurable] != 1 || report.ByAssurance[AssuranceHighAssurance] != 1 {
		t.Fatalf("assurance counts = %+v", report.ByAssurance)
	}
	rendered := report.String()
	for _, want := range []string{"Capability Registry", "Descriptors: 4", "Registry SHA-256: " + report.Digest} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("report missing %q:\n%s", want, rendered)
		}
	}
}

func TestRegistryValidateRejectsMalformedSchema(t *testing.T) {
	registry := NewRegistry()
	// Registration itself stays permissive — the whole-registry scan is
	// what fails the registry.
	registerForTest(t, registry, CapabilityDescriptor{
		ID: "x.read", ExecutionClass: ClassRead, AdapterID: "adapter",
		Schema: json.RawMessage(`{"type":`),
	})
	err := registry.Validate()
	if err == nil {
		t.Fatal("Validate must reject a malformed argument schema")
	}
	if !strings.Contains(err.Error(), "not valid JSON") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRegistryValidateRejectsUnsupportedSchemaKeyword(t *testing.T) {
	registry := NewRegistry()
	registerForTest(t, registry, CapabilityDescriptor{
		ID: "x.read", ExecutionClass: ClassRead, AdapterID: "adapter",
		Schema: json.RawMessage(`{"type":"object","properties":{"x":{"type":"string","pattern":"^a"}}}`),
	})
	err := registry.Validate()
	if err == nil {
		t.Fatal("Validate must reject schema keywords the validator does not implement")
	}
	if !strings.Contains(err.Error(), `unsupported keyword "pattern"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRegistryValidateRejectsMissingAdapterBinding(t *testing.T) {
	registry := NewRegistry()
	registerForTest(t, registry, CapabilityDescriptor{ID: "x.read", ExecutionClass: ClassRead})
	err := registry.Validate()
	if err == nil {
		t.Fatal("Validate must reject a capability with no adapter binding")
	}
	if !strings.Contains(err.Error(), "no adapter binding") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRegistryValidateAcceptsSupportedSchemaShapes(t *testing.T) {
	registry := NewRegistry()
	registerForTest(t, registry, CapabilityDescriptor{
		ID: "x.read", ExecutionClass: ClassRead, AdapterID: "adapter",
		Schema: json.RawMessage(`{
			"type": "object",
			"required": ["items"],
			"additionalProperties": false,
			"properties": {
				"items": {
					"type": "array",
					"items": {"type": "object", "properties": {"name": {"type": "string", "maxLength": 64}}}
				},
				"mode": {"type": "string", "enum": ["fast", "safe"]},
				"count": {"type": "integer", "minimum": 0, "maximum": 10, "multipleOf": 1}
			}
		}`),
	})
	if err := registry.Validate(); err != nil {
		t.Fatalf("supported schema shapes must pass the registry scan: %v", err)
	}
}

func TestValidateAdaptersRejectsUnwiredAdapter(t *testing.T) {
	registry := NewRegistry()
	registerForTest(t, registry, CapabilityDescriptor{ID: "a.read", ExecutionClass: ClassRead, AdapterID: "wired"})
	registerForTest(t, registry, CapabilityDescriptor{ID: "b.read", ExecutionClass: ClassRead, AdapterID: "orphan"})

	if err := registry.ValidateAdapters(map[string]bool{"wired": true}); err == nil {
		t.Fatal("ValidateAdapters must reject a capability whose adapter is not wired")
	} else if !strings.Contains(err.Error(), `adapter "orphan" is not wired`) {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := registry.ValidateAdapters(map[string]bool{"wired": true, "orphan": true}); err != nil {
		t.Fatalf("wired adapters must pass: %v", err)
	}
}
