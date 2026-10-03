// Signer policy qualification: production mode, a cluster topology, and
// multi-replica deployments must refuse to auto-generate a signing
// identity. The trust root is provisioned, never silently created per
// host — otherwise each instance would mint receipts its peers cannot
// verify against a shared key ring.

package execution

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeploymentModeParsing(t *testing.T) {
	t.Setenv("CRABBOX_MODE", "")
	if _, err := resolveDeploymentMode(); err == nil ||
		!strings.Contains(err.Error(), "must be declared") {
		t.Fatal("unset CRABBOX_MODE must fail closed, never assume a mode")
	}
	t.Setenv("CRABBOX_MODE", "development")
	if mode, err := resolveDeploymentMode(); err != nil || mode != "development" {
		t.Fatalf("development must resolve, got %q, %v", mode, err)
	}
	t.Setenv("CRABBOX_MODE", "production")
	if mode, err := resolveDeploymentMode(); err != nil || mode != "production" {
		t.Fatalf("CRABBOX_MODE=production must resolve, got %q, %v", mode, err)
	}
	t.Setenv("CRABBOX_MODE", " Production ")
	if mode, err := resolveDeploymentMode(); err != nil || mode != "production" {
		t.Fatalf("production parsing must be case/space-insensitive, got %q, %v", mode, err)
	}
	t.Setenv("CRABBOX_MODE", "staging")
	if _, err := resolveDeploymentMode(); err == nil ||
		!strings.Contains(err.Error(), "unknown CRABBOX_MODE") {
		t.Fatal("an unknown mode must fail closed, never map to a weaker one")
	}
}

func TestEvidenceKeyPolicyDevelopmentAllowsGeneration(t *testing.T) {
	// Missing env var path: development may fall back to a default
	// host-local key path and generate it crash-durably.
	cfg := &ServiceConfig{Topology: TopologySingle, Replicas: 1}
	if err := validateEvidenceKeyPolicy(cfg); err != nil {
		t.Fatalf("development must allow missing key path, got %v", err)
	}
	cfg.EvidenceKeyPath = filepath.Join(t.TempDir(), "does-not-exist.pem")
	if err := validateEvidenceKeyPolicy(cfg); err != nil {
		t.Fatalf("development must allow nonexistent key path, got %v", err)
	}
}

func TestEvidenceKeyPolicyProductionRequiresProvisionedKey(t *testing.T) {
	cfg := &ServiceConfig{Topology: TopologySingle, Replicas: 1, production: true}
	if err := validateEvidenceKeyPolicy(cfg); err == nil {
		t.Fatal("production must refuse a missing CRABBOX_EVIDENCE_KEY")
	}
	cfg.EvidenceKeyPath = filepath.Join(t.TempDir(), "no-such.pem")
	if err := validateEvidenceKeyPolicy(cfg); err == nil {
		t.Fatal("production must refuse a nonexistent key file")
	}
	existing := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(existing, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.EvidenceKeyPath = existing
	if err := validateEvidenceKeyPolicy(cfg); err != nil {
		t.Fatalf("production must accept an existing provisioned key, got %v", err)
	}
}

func TestEvidenceKeyPolicyReplicasRequireSharedKey(t *testing.T) {
	cfg := &ServiceConfig{Topology: TopologySingle, Replicas: 3}
	if err := validateEvidenceKeyPolicy(cfg); err == nil {
		t.Fatal("multi-replica must refuse a missing CRABBOX_EVIDENCE_KEY")
	}
	cfg.EvidenceKeyPath = filepath.Join(t.TempDir(), "no-such.pem")
	if err := validateEvidenceKeyPolicy(cfg); err == nil {
		t.Fatal("multi-replica must refuse a nonexistent key file")
	}
	existing := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(existing, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.EvidenceKeyPath = existing
	if err := validateEvidenceKeyPolicy(cfg); err != nil {
		t.Fatalf("multi-replica must accept an existing provisioned key, got %v", err)
	}
}

// TestEvidenceKeyPolicyClusterRequiresProvisionedKey proves the cluster
// topology requires a provisioned key even when the declared replica
// count is one: the topology declares a replicated deployment, so a
// host-local key would become a divergent cluster identity the moment a
// second replica appears.
func TestEvidenceKeyPolicyClusterRequiresProvisionedKey(t *testing.T) {
	cfg := &ServiceConfig{Topology: TopologyCluster, Replicas: 1}
	if err := validateEvidenceKeyPolicy(cfg); err == nil {
		t.Fatal("cluster topology must refuse a missing CRABBOX_EVIDENCE_KEY")
	}
	cfg.EvidenceKeyPath = filepath.Join(t.TempDir(), "no-such.pem")
	if err := validateEvidenceKeyPolicy(cfg); err == nil {
		t.Fatal("cluster topology must refuse a nonexistent key file")
	}
	existing := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(existing, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.EvidenceKeyPath = existing
	if err := validateEvidenceKeyPolicy(cfg); err != nil {
		t.Fatalf("cluster topology must accept an existing provisioned key, got %v", err)
	}
}
