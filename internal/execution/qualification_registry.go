package execution

import (
	"fmt"

	"github.com/openclaw/crabbox/internal/capability"
)

// QualificationRegistryExtensionID is the test-only capability the
// external CRITICAL qualification harness exercises. It is deliberately
// NOT part of RegisterBuiltinCapabilities: the release's security-policy
// identity must never advertise a capability that exists solely to test
// the implementation.
const QualificationRegistryExtensionID = "qualification.critical.commit"

// RegisterQualificationCapabilities registers the explicit qualification
// extensions on top of an already-built release registry.
//
// The qualification registry is constructed under one rule:
//
//	exact release registry + explicit qualification descriptors
//	  = qualification registry
//
// It refuses to overwrite an existing descriptor, so a qualification
// build can never silently replace or modify production policy.
func RegisterQualificationCapabilities(registry *capability.Registry) error {
	if _, exists := registry.Lookup(QualificationRegistryExtensionID); exists {
		return fmt.Errorf("qualification extension %s would replace a release descriptor", QualificationRegistryExtensionID)
	}
	descriptor, err := capability.Resolve(capability.CapabilityDescriptor{
		ID:             QualificationRegistryExtensionID,
		ExecutionClass: capability.ClassCritical,
		AdapterID:      "qualification",
		AuthorityPolicy: capability.AuthorityPolicy{
			ID:            QualificationRegistryExtensionID,
			GrantRequired: true,
		},
	})
	if err != nil {
		return fmt.Errorf("resolve qualification extension: %w", err)
	}
	return registry.RegisterResolved(descriptor)
}

// QualificationRegistryExtensions returns the extension record for a
// registry that was built as release + extensions: the descriptor digest
// of every qualification-only capability it added.
func QualificationRegistryExtensions(registry *capability.Registry) ([]RegistryExtension, error) {
	descriptor, ok := registry.Lookup(QualificationRegistryExtensionID)
	if !ok {
		return nil, nil
	}
	digest, err := descriptor.DescriptorDigest()
	if err != nil {
		return nil, err
	}
	return []RegistryExtension{{CapabilityID: QualificationRegistryExtensionID, DescriptorSHA256: digest}}, nil
}

// RegistryExtension names one qualification-only capability and the
// digest of the exact descriptor that was added.
type RegistryExtension struct {
	CapabilityID     string `json:"capability_id"`
	DescriptorSHA256 string `json:"descriptor_sha256"`
}

// RegistryExtensionRecord binds the two registry identities together:
// what the release ships, what the qualification build actually loaded,
// and exactly which descriptors separate them.
type RegistryExtensionRecord struct {
	BaseRegistrySHA256          string              `json:"base_registry_sha256"`
	QualificationRegistrySHA256 string              `json:"qualification_registry_sha256"`
	QualificationExtensions     []RegistryExtension `json:"qualification_extensions"`
}
