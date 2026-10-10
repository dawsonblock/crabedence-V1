package execution

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The validated deployment-mode snapshot: CRABBOX_MODE is resolved
// exactly once, inside LoadServiceConfig, and every security decision
// that depends on it consumes the ServiceConfig. These tests mutate
// the process environment after load and prove the service keeps
// applying the posture it validated — the split-brain regression
// where the execution path re-read CRABBOX_MODE and quietly adopted
// development semantics under a production deployment.

// loadProductionConfig builds a fully declared production ServiceConfig.
func loadProductionConfig(t *testing.T, extra func(t *testing.T)) *ServiceConfig {
	t.Helper()
	clearServiceEnv(t)
	t.Setenv("CRABBOX_MODE", "production")
	t.Setenv("CRABBOX_TOPOLOGY", "single")
	t.Setenv("CRABEDENCE_PEER_PRINCIPALS", "1000:alice@example.com")
	t.Setenv("CRABEDENCE_ATTESTATION_REQUIRED", "true")
	t.Setenv("CRABEDENCE_APPROVED_RUNTIME_KEYS", testApprovedRuntimeKey(t))
	if extra != nil {
		extra(t)
	}
	cfg, err := LoadServiceConfig(ServeOptions{})
	if err != nil {
		t.Fatalf("production load: %v", err)
	}
	if !cfg.Production() {
		t.Fatal("the config must report production mode")
	}
	return cfg
}

// TestGitHubOriginPolicyUsesValidatedModeSnapshot loads production,
// arms the plaintext-loopback exception, then flips the environment
// to development. The transport must still refuse the insecure
// origin: the decision reads cfg.Production(), the snapshot.
func TestGitHubOriginPolicyUsesValidatedModeSnapshot(t *testing.T) {
	cfg := loadProductionConfig(t, func(t *testing.T) {
		t.Setenv("CRABBOX_GITHUB_TOKEN", "ghp_snapshot")
		t.Setenv("CRABBOX_GITHUB_API_URL", "http://127.0.0.1:8080")
		t.Setenv(insecureTestProviderOriginEnv, "true")
	})
	t.Setenv("CRABBOX_MODE", "development")

	if _, err := newGitHubTransportForService(cfg, nil); err == nil ||
		!strings.Contains(err.Error(), "unavailable in production mode") {
		t.Fatalf("the production snapshot must keep refusing plaintext origins after the environment is mutated: %v", err)
	}

	// Counter-proof: a config validated as development keeps the
	// exception even when the environment is flipped to production —
	// the decision really is bound to the validated mode, either way.
	clearServiceEnv(t)
	t.Setenv("CRABBOX_GITHUB_TOKEN", "ghp_snapshot")
	t.Setenv("CRABBOX_GITHUB_API_URL", "http://127.0.0.1:8080")
	t.Setenv(insecureTestProviderOriginEnv, "true")
	dev, err := LoadServiceConfig(ServeOptions{})
	if err != nil {
		t.Fatalf("development load: %v", err)
	}
	t.Setenv("CRABBOX_MODE", "production")
	if _, err := newGitHubTransportForService(dev, nil); err != nil {
		t.Fatalf("the development snapshot keeps the exception it validated: %v", err)
	}
}

// TestEvidenceKeyPolicyUsesValidatedModeSnapshot proves the key-policy
// gate — which runs at serve time, after load — applies the validated
// mode, not a post-load environment.
func TestEvidenceKeyPolicyUsesValidatedModeSnapshot(t *testing.T) {
	cfg := loadProductionConfig(t, nil)
	t.Setenv("CRABBOX_MODE", "development")

	err := validateEvidenceKeyPolicy(cfg)
	if err == nil || !strings.Contains(err.Error(), "requires CRABBOX_EVIDENCE_KEY") {
		t.Fatalf("the production snapshot must keep requiring a provisioned key after env mutation: %v", err)
	}

	clearServiceEnv(t)
	dev, err := LoadServiceConfig(ServeOptions{})
	if err != nil {
		t.Fatalf("development load: %v", err)
	}
	t.Setenv("CRABBOX_MODE", "production")
	if err := validateEvidenceKeyPolicy(dev); err != nil {
		t.Fatalf("the development snapshot keeps auto-provisioning it validated: %v", err)
	}
}

// TestValidatedModeSnapshotCoversEveryModeDecision mutates every input
// the loader resolved and proves the loaded config — the only source
// of truth downstream — is unaffected.
func TestValidatedModeSnapshotCoversEveryModeDecision(t *testing.T) {
	cfg := loadProductionConfig(t, nil)

	t.Setenv("CRABBOX_MODE", "development")
	t.Setenv("CRABBOX_TOPOLOGY", "")
	t.Setenv("CRABBOX_REPLICAS", "8")
	t.Setenv("CRABEDENCE_ATTESTATION_REQUIRED", "")
	t.Setenv("CRABEDENCE_ATTESTATION_RELAXED", "true")
	t.Setenv("CRABEDENCE_PEER_PRINCIPALS", "")

	if !cfg.Production() {
		t.Fatal("Production() must keep reporting the validated mode")
	}
	if cfg.Topology != TopologySingle || cfg.Replicas != 1 {
		t.Fatalf("topology/replicas = %s/%d, want the validated single/1", cfg.Topology, cfg.Replicas)
	}
	if cfg.Attestation == nil || !cfg.Attestation.Required || cfg.Attestation.Relaxed {
		t.Fatalf("attestation = %+v, want the validated required-not-relaxed policy", cfg.Attestation)
	}
	if len(cfg.PeerPrincipals) != 1 || cfg.PeerPrincipals[1000] != "alice@example.com" {
		t.Fatalf("peer principals = %v, want the validated mapping", cfg.PeerPrincipals)
	}
}

// TestDeploymentModeIsResolvedOnce scans this package's non-test
// sources and proves CRABBOX_MODE has exactly one environment reader:
// resolveDeploymentMode inside LoadServiceConfig. After startup
// configuration exists the only source of truth is cfg.Production().
func TestDeploymentModeIsResolvedOnce(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var readers []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, `os.Getenv("CRABBOX_MODE")`) {
				readers = append(readers, name+":"+strconv.Itoa(i+1))
			}
		}
	}
	if len(readers) != 1 || !strings.HasPrefix(readers[0], "serve.go:") {
		t.Fatalf(`os.Getenv("CRABBOX_MODE") must be read once, inside resolveDeploymentMode; found readers %v`, readers)
	}
}
