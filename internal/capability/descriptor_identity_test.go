package capability

import (
	"encoding/json"
	"testing"
)

func resolvedForDigest(t *testing.T, descriptor CapabilityDescriptor) ResolvedDescriptor {
	t.Helper()
	resolved, err := Resolve(descriptor)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	return resolved
}

func TestDescriptorDigestBindsPolicy(t *testing.T) {
	base := resolvedForDigest(t, CapabilityDescriptor{
		ID:             "example.read",
		ExecutionClass: ClassRead,
		AdapterID:      "adapter",
		Schema:         json.RawMessage(`{"type":"object","properties":{"x":{"type":"integer"}}}`),
	})
	baseDigest, err := base.DescriptorDigest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}

	// Same policy reproduces the same digest.
	again := resolvedForDigest(t, CapabilityDescriptor{
		ID:             "example.read",
		ExecutionClass: ClassRead,
		AdapterID:      "adapter",
		Schema:         json.RawMessage(`{"properties":{"x":{"type":"integer"}},"type":"object"}`),
	})
	againDigest, err := again.DescriptorDigest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if againDigest != baseDigest {
		t.Fatalf("schema key order must not change the descriptor digest:\n%s\n%s", baseDigest, againDigest)
	}

	cases := map[string]CapabilityDescriptor{
		"declared version": {
			ID: "example.read", ExecutionClass: ClassRead, AdapterID: "adapter",
			DescriptorVersion: 2,
		},
		"policy revision": {
			ID: "example.read", ExecutionClass: ClassRead, AdapterID: "adapter",
			PolicyRevision: "ticket-1234",
		},
		"schema change": {
			ID: "example.read", ExecutionClass: ClassRead, AdapterID: "adapter",
			Schema: json.RawMessage(`{"type":"object","properties":{"x":{"type":"string"}}}`),
		},
		"authority policy change": {
			ID: "example.read", ExecutionClass: ClassRead, AdapterID: "adapter",
			AuthorityPolicy: AuthorityPolicy{ID: "example.read", GrantRequired: true},
		},
		"adapter change": {
			ID: "example.read", ExecutionClass: ClassRead, AdapterID: "other-adapter",
		},
		"route change": {
			ID: "example.read", ExecutionClass: ClassRead, AdapterID: "adapter",
			ExecutionRoute: RouteCrabedence,
		},
	}
	for name, descriptor := range cases {
		t.Run(name, func(t *testing.T) {
			resolved := resolvedForDigest(t, descriptor)
			digest, err := resolved.DescriptorDigest()
			if err != nil {
				t.Fatalf("digest: %v", err)
			}
			if digest == baseDigest {
				t.Fatalf("%s must change the descriptor digest", name)
			}
		})
	}
}

func TestRegistrySnapshotRoundTrips(t *testing.T) {
	registry := NewRegistry()
	registerForTest(t, registry, CapabilityDescriptor{ID: "b.read", ExecutionClass: ClassRead, AdapterID: "adapter"})
	registerForTest(t, registry, CapabilityDescriptor{
		ID: "a.mutate", ExecutionClass: ClassMutation, AdapterID: "adapter",
		DescriptorVersion: 2, PolicyRevision: "ticket-1",
	})

	snapshot, err := registry.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	digest, err := registry.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.RegistrySHA256 != digest {
		t.Fatalf("snapshot digest %s != registry digest %s", snapshot.RegistrySHA256, digest)
	}
	if len(snapshot.Descriptors) != 2 || snapshot.Descriptors[0].ID != "a.mutate" {
		t.Fatalf("descriptors must be sorted by ID: %+v", snapshot.Descriptors)
	}
	if snapshot.Descriptors[0].DescriptorVersion != 2 || snapshot.Descriptors[0].PolicyRevision != "ticket-1" {
		t.Fatalf("descriptor identity missing from the snapshot: %+v", snapshot.Descriptors[0])
	}

	first, err := snapshot.JSON()
	if err != nil {
		t.Fatal(err)
	}
	second, err := registry.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := second.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(secondJSON) {
		t.Fatal("the snapshot bytes must be deterministic")
	}
}

func TestResolveDefaultsAndValidatesDescriptorVersion(t *testing.T) {
	resolved := resolvedForDigest(t, CapabilityDescriptor{ID: "a.read", ExecutionClass: ClassRead, AdapterID: "adapter"})
	if resolved.DescriptorVersion != 1 {
		t.Fatalf("descriptor version default = %d, want 1", resolved.DescriptorVersion)
	}

	if _, err := Resolve(CapabilityDescriptor{ID: "a.read", ExecutionClass: ClassRead, AdapterID: "adapter", DescriptorVersion: -1}); err == nil {
		t.Fatal("a negative descriptor version must be rejected")
	}

	// A declared version flows through resolution and the registry digest.
	declared := resolvedForDigest(t, CapabilityDescriptor{ID: "a.read", ExecutionClass: ClassRead, AdapterID: "adapter", DescriptorVersion: 3})
	if declared.DescriptorVersion != 3 {
		t.Fatalf("descriptor version = %d, want 3", declared.DescriptorVersion)
	}

	base := NewRegistry()
	registerForTest(t, base, CapabilityDescriptor{ID: "a.read", ExecutionClass: ClassRead, AdapterID: "adapter"})
	baseDigest, err := base.Digest()
	if err != nil {
		t.Fatal(err)
	}
	bumped := NewRegistry()
	registerForTest(t, bumped, CapabilityDescriptor{ID: "a.read", ExecutionClass: ClassRead, AdapterID: "adapter", DescriptorVersion: 2})
	bumpedDigest, err := bumped.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if bumpedDigest == baseDigest {
		t.Fatal("a descriptor version bump must change the registry digest")
	}
}
