// Signer policy qualification: production mode, a cluster topology, and
// multi-replica deployments must refuse to auto-generate a signing
// identity. The trust root is provisioned, never silently created per
// host — otherwise each instance would mint receipts its peers cannot
// verify against a shared key ring.

package execution

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProductionModeParsing(t *testing.T) {
	t.Setenv("CRABBOX_MODE", "")
	if productionMode() {
		t.Fatal("unset CRABBOX_MODE must not be production")
	}
	t.Setenv("CRABBOX_MODE", "development")
	if productionMode() {
		t.Fatal("development must not be production")
	}
	t.Setenv("CRABBOX_MODE", "production")
	if !productionMode() {
		t.Fatal("CRABBOX_MODE=production must be production")
	}
	t.Setenv("CRABBOX_MODE", " Production ")
	if !productionMode() {
		t.Fatal("production parsing must be case/space-insensitive")
	}
}

func TestEvidenceKeyPolicyDevelopmentAllowsGeneration(t *testing.T) {
	t.Setenv("CRABBOX_MODE", "development")
	t.Setenv("CRABBOX_REPLICAS", "")
	// Missing env var path: development may fall back to a default
	// host-local key path and generate it crash-durably.
	if err := validateEvidenceKeyPolicy(TopologySingle, ""); err != nil {
		t.Fatalf("development must allow missing key path, got %v", err)
	}
	if err := validateEvidenceKeyPolicy(TopologySingle, filepath.Join(t.TempDir(), "does-not-exist.pem")); err != nil {
		t.Fatalf("development must allow nonexistent key path, got %v", err)
	}
}

func TestEvidenceKeyPolicyProductionRequiresProvisionedKey(t *testing.T) {
	t.Setenv("CRABBOX_MODE", "production")
	t.Setenv("CRABBOX_REPLICAS", "")
	if err := validateEvidenceKeyPolicy(TopologySingle, ""); err == nil {
		t.Fatal("production must refuse a missing CRABBOX_EVIDENCE_KEY")
	}
	missing := filepath.Join(t.TempDir(), "no-such.pem")
	if err := validateEvidenceKeyPolicy(TopologySingle, missing); err == nil {
		t.Fatal("production must refuse a nonexistent key file")
	}
	existing := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(existing, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateEvidenceKeyPolicy(TopologySingle, existing); err != nil {
		t.Fatalf("production must accept an existing provisioned key, got %v", err)
	}
}

func TestEvidenceKeyPolicyReplicasRequireSharedKey(t *testing.T) {
	t.Setenv("CRABBOX_MODE", "")
	t.Setenv("CRABBOX_REPLICAS", "3")
	if err := validateEvidenceKeyPolicy(TopologySingle, ""); err == nil {
		t.Fatal("multi-replica must refuse a missing CRABBOX_EVIDENCE_KEY")
	}
	missing := filepath.Join(t.TempDir(), "no-such.pem")
	if err := validateEvidenceKeyPolicy(TopologySingle, missing); err == nil {
		t.Fatal("multi-replica must refuse a nonexistent key file")
	}
	existing := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(existing, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateEvidenceKeyPolicy(TopologySingle, existing); err != nil {
		t.Fatalf("multi-replica must accept an existing provisioned key, got %v", err)
	}
}

// TestEvidenceKeyPolicyClusterRequiresProvisionedKey proves the cluster
// topology requires a provisioned key even when the declared replica
// count is one: the topology declares a replicated deployment, so a
// host-local key would become a divergent cluster identity the moment a
// second replica appears.
func TestEvidenceKeyPolicyClusterRequiresProvisionedKey(t *testing.T) {
	t.Setenv("CRABBOX_MODE", "")
	t.Setenv("CRABBOX_REPLICAS", "")
	if err := validateEvidenceKeyPolicy(TopologyCluster, ""); err == nil {
		t.Fatal("cluster topology must refuse a missing CRABBOX_EVIDENCE_KEY")
	}
	missing := filepath.Join(t.TempDir(), "no-such.pem")
	if err := validateEvidenceKeyPolicy(TopologyCluster, missing); err == nil {
		t.Fatal("cluster topology must refuse a nonexistent key file")
	}
	existing := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(existing, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateEvidenceKeyPolicy(TopologyCluster, existing); err != nil {
		t.Fatalf("cluster topology must accept an existing provisioned key, got %v", err)
	}
}
