package execution

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// clearServiceEnv resets every environment variable the configuration
// loader reads, so a test observes the loader's own defaults rather
// than whatever the developer's shell provides.
func clearServiceEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"CRABBOX_MODE", "CRABBOX_TOPOLOGY", "CRABBOX_REPLICAS",
		"CRABEDENCE_STORE_BACKEND", "CRABEDENCE_STORE_PATH", "CRABEDENCE_DATABASE_URL",
		"CRABBOX_GITHUB_TOKEN", "GITHUB_TOKEN", "CRABBOX_GITHUB_ENABLED", "CRABBOX_GITHUB_API_URL",
		"CRABEDENCE_QUAL_PROVIDER_URL",
		"CRABBOX_EVIDENCE_KEY", "CRABBOX_EVIDENCE_TRUSTED_SIGNERS",
		"CRABEDENCE_PEER_PRINCIPALS", "CRABEDENCE_TRUSTED_PROXY_UIDS",
		"CRABEDENCE_PROVIDER_EXECUTION_MAX",
		"CRABEDENCE_PROVIDER_MAX_CONCURRENT", "CRABEDENCE_PROVIDER_DEGRADED_AFTER",
		"CRABEDENCE_PROVIDER_OPEN_AFTER", "CRABEDENCE_PROVIDER_OPEN_COOLDOWN",
		"CRABEDENCE_ATTESTATION_REQUIRED", "CRABEDENCE_ATTESTATION_RELAXED",
		"CRABEDENCE_ATTESTATION_SESSION_TTL", "CRABEDENCE_APPROVED_RUNTIME_KEYS",
		"CRABEDENCE_APPROVED_RELEASES", "CRABEDENCE_APPROVED_PLUGIN_MANIFESTS",
		"CRABEDENCE_APPROVED_ABI",
	} {
		t.Setenv(name, "")
	}
	// LoadServiceConfig requires an explicitly declared deployment
	// mode — tests exercise development defaults, so declare it.
	t.Setenv("CRABBOX_MODE", "development")
}

// testApprovedRuntimeKey returns a valid
// <fingerprint>:<base64-key> entry for CRABEDENCE_APPROVED_RUNTIME_KEYS.
func testApprovedRuntimeKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:]) + ":" + base64.StdEncoding.EncodeToString(pub)
}

func TestLoadServiceConfigDevelopmentDefaults(t *testing.T) {
	clearServiceEnv(t)
	cfg, err := LoadServiceConfig(ServeOptions{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Topology != TopologySingle || cfg.Replicas != 1 {
		t.Fatalf("topology/replicas = %s/%d, want single/1", cfg.Topology, cfg.Replicas)
	}
	if cfg.Backend != "sqlite" {
		t.Fatalf("backend = %s, want sqlite (no DSN configured)", cfg.Backend)
	}
	if cfg.GitHubEnabled || cfg.QualProviderURL != "" || cfg.EvidenceKeyPath != "" || cfg.PeerPrincipals != nil {
		t.Fatalf("adapters/trust root should be unconfigured by default: %+v", cfg)
	}
	if cfg.ExecutorTimeouts.ProviderExecution != DefaultExecutorTimeouts().ProviderExecution {
		t.Fatalf("provider ceiling = %s, want the default %s", cfg.ExecutorTimeouts.ProviderExecution, DefaultExecutorTimeouts().ProviderExecution)
	}
	if cfg.ProviderGate != DefaultProviderGateConfig() {
		t.Fatalf("provider gate = %+v, want the production defaults", cfg.ProviderGate)
	}
}

func TestLoadServiceConfigResolvesOverrides(t *testing.T) {
	clearServiceEnv(t)
	t.Setenv("CRABEDENCE_STORE_BACKEND", "sqlite")
	t.Setenv("CRABEDENCE_STORE_PATH", "/tmp/explicit.db")
	t.Setenv("CRABEDENCE_PROVIDER_EXECUTION_MAX", "90s")
	t.Setenv("CRABEDENCE_PROVIDER_MAX_CONCURRENT", "8")
	t.Setenv("CRABEDENCE_PROVIDER_OPEN_COOLDOWN", "2m")
	cfg, err := LoadServiceConfig(ServeOptions{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.StorePath != "/tmp/explicit.db" {
		t.Fatalf("store path = %q", cfg.StorePath)
	}
	if cfg.ExecutorTimeouts.ProviderExecution != 90*time.Second {
		t.Fatalf("provider ceiling = %s, want 90s", cfg.ExecutorTimeouts.ProviderExecution)
	}
	if cfg.ProviderGate.MaxConcurrent != 8 || cfg.ProviderGate.OpenCooldown != 2*time.Minute {
		t.Fatalf("provider gate = %+v, want the overrides applied", cfg.ProviderGate)
	}
	// A DSN resolves "auto" to postgres.
	t.Setenv("CRABEDENCE_STORE_BACKEND", "auto")
	cfg, err = LoadServiceConfig(ServeOptions{DatabaseURL: "postgres://example/db"})
	if err != nil {
		t.Fatalf("load with DSN: %v", err)
	}
	if cfg.Backend != "postgres" {
		t.Fatalf("backend with DSN = %s, want postgres", cfg.Backend)
	}
}

func TestLoadServiceConfigFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T)
		wantErr string
	}{
		{"mode undeclared", func(t *testing.T) { t.Setenv("CRABBOX_MODE", "") }, "CRABBOX_MODE must be declared"},
		{"unknown mode", func(t *testing.T) { t.Setenv("CRABBOX_MODE", "staging") }, "unknown CRABBOX_MODE"},
		{"unknown backend", func(t *testing.T) { t.Setenv("CRABEDENCE_STORE_BACKEND", "mysql") }, "unknown CRABEDENCE_STORE_BACKEND"},
		{"malformed replica count", func(t *testing.T) { t.Setenv("CRABBOX_REPLICAS", "2x") }, "not a positive integer"},
		{"unknown topology", func(t *testing.T) { t.Setenv("CRABBOX_TOPOLOGY", "sharded") }, "unknown CRABBOX_TOPOLOGY"},
		{"production without topology", func(t *testing.T) { t.Setenv("CRABBOX_MODE", "production") }, "must be explicitly declared in production"},
		{"production without peer authentication", func(t *testing.T) {
			t.Setenv("CRABBOX_MODE", "production")
			t.Setenv("CRABBOX_TOPOLOGY", "single")
		}, "requires CRABEDENCE_PEER_PRINCIPALS"},
		{"cluster with sqlite", func(t *testing.T) { t.Setenv("CRABBOX_TOPOLOGY", "cluster") }, "cluster requires the shared postgres store backend"},
		{"single with replicas", func(t *testing.T) {
			t.Setenv("CRABBOX_TOPOLOGY", "single")
			t.Setenv("CRABBOX_REPLICAS", "3")
		}, "contradicts CRABBOX_REPLICAS"},
		{"malformed executor ceiling", func(t *testing.T) { t.Setenv("CRABEDENCE_PROVIDER_EXECUTION_MAX", "soon") }, "not a positive Go duration"},
		{"malformed max concurrent", func(t *testing.T) { t.Setenv("CRABEDENCE_PROVIDER_MAX_CONCURRENT", "many") }, "not a positive integer"},
		{"contradictory gate thresholds", func(t *testing.T) {
			t.Setenv("CRABEDENCE_PROVIDER_DEGRADED_AFTER", "9")
			t.Setenv("CRABEDENCE_PROVIDER_OPEN_AFTER", "3")
		}, "cannot exceed CRABEDENCE_PROVIDER_OPEN_AFTER"},
		{"malformed trusted signer", func(t *testing.T) { t.Setenv("CRABBOX_EVIDENCE_TRUSTED_SIGNERS", "not-a-fingerprint") }, "is not a SHA-256 fingerprint"},
		{"malformed peer principals", func(t *testing.T) { t.Setenv("CRABEDENCE_PEER_PRINCIPALS", "not-a-uid:alice") }, "CRABEDENCE_PEER_PRINCIPALS"},
		{"malformed trusted proxies", func(t *testing.T) { t.Setenv("CRABEDENCE_TRUSTED_PROXY_UIDS", "not-a-uid") }, "CRABEDENCE_TRUSTED_PROXY_UIDS"},
		{"production wildcard without trusted proxy", func(t *testing.T) {
			t.Setenv("CRABBOX_MODE", "production")
			t.Setenv("CRABBOX_TOPOLOGY", "single")
			t.Setenv("CRABEDENCE_PEER_PRINCIPALS", "0:*")
		}, "CRABEDENCE_TRUSTED_PROXY_UIDS"},
		{"github enabled without token", func(t *testing.T) { t.Setenv("CRABBOX_GITHUB_ENABLED", "true") }, "no CRABBOX_GITHUB_TOKEN or GITHUB_TOKEN"},
		{"production without attestation", func(t *testing.T) {
			t.Setenv("CRABBOX_MODE", "production")
			t.Setenv("CRABBOX_TOPOLOGY", "single")
			t.Setenv("CRABEDENCE_PEER_PRINCIPALS", "1000:alice@example.com")
		}, "requires runtime attestation"},
		{"production with relaxed attestation", func(t *testing.T) {
			t.Setenv("CRABBOX_MODE", "production")
			t.Setenv("CRABBOX_TOPOLOGY", "single")
			t.Setenv("CRABEDENCE_PEER_PRINCIPALS", "1000:alice@example.com")
			t.Setenv("CRABEDENCE_ATTESTATION_REQUIRED", "true")
			t.Setenv("CRABEDENCE_ATTESTATION_RELAXED", "true")
		}, "RELAXED is development-only"},
		{"required attestation without keys", func(t *testing.T) {
			t.Setenv("CRABEDENCE_ATTESTATION_REQUIRED", "true")
		}, "CRABEDENCE_APPROVED_RUNTIME_KEYS"},
		{"identity allowlist without keys", func(t *testing.T) {
			t.Setenv("CRABEDENCE_APPROVED_RELEASES", strings.Repeat("a", 64))
		}, "require CRABEDENCE_APPROVED_RUNTIME_KEYS or CRABEDENCE_ATTESTATION_RELAXED"},
		{"malformed runtime key", func(t *testing.T) {
			t.Setenv("CRABEDENCE_APPROVED_RUNTIME_KEYS", "not-an-entry")
		}, "CRABEDENCE_APPROVED_RUNTIME_KEYS"},
		{"malformed session ttl", func(t *testing.T) {
			t.Setenv("CRABEDENCE_ATTESTATION_RELAXED", "true")
			t.Setenv("CRABEDENCE_ATTESTATION_SESSION_TTL", "soon")
		}, "CRABEDENCE_ATTESTATION_SESSION_TTL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearServiceEnv(t)
			tc.setup(t)
			_, err := LoadServiceConfig(ServeOptions{})
			if err == nil {
				t.Fatal("load must fail closed")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want substring %q", err, tc.wantErr)
			}
		})
	}
}

// TestProductionRequiresAuthenticatedPrincipals proves the loader
// refuses production without a peer map and admits it with one — the
// declaration the staging unit carries.
func TestProductionRequiresAuthenticatedPrincipals(t *testing.T) {
	clearServiceEnv(t)
	t.Setenv("CRABBOX_MODE", "production")
	t.Setenv("CRABBOX_TOPOLOGY", "single")

	if _, err := LoadServiceConfig(ServeOptions{}); err == nil || !strings.Contains(err.Error(), "CRABEDENCE_PEER_PRINCIPALS") {
		t.Fatalf("production without a peer map must fail closed, got %v", err)
	}

	t.Setenv("CRABEDENCE_PEER_PRINCIPALS", "1000:alice@example.com")
	t.Setenv("CRABEDENCE_ATTESTATION_REQUIRED", "true")
	t.Setenv("CRABEDENCE_APPROVED_RUNTIME_KEYS", testApprovedRuntimeKey(t))
	cfg, err := LoadServiceConfig(ServeOptions{})
	if err != nil {
		t.Fatalf("production with a peer map and attestation must load: %v", err)
	}
	if cfg.Attestation == nil || !cfg.Attestation.Required || len(cfg.Attestation.ApprovedKeys) != 1 {
		t.Fatalf("attestation policy = %+v, want required with one approved key", cfg.Attestation)
	}
	if !cfg.Production() {
		t.Fatal("the config must report production mode")
	}
	if len(cfg.PeerPrincipals) != 1 || cfg.PeerPrincipals[1000] != "alice@example.com" {
		t.Fatalf("peer principals = %v, want the declared mapping", cfg.PeerPrincipals)
	}
}

// TestServiceConfigReportExcludesSecrets proves the startup report is
// built from non-secret characteristics only: a token, a DSN with a
// password, and the key path never appear in it.
func TestServiceConfigReportExcludesSecrets(t *testing.T) {
	clearServiceEnv(t)
	const dsn = "postgres://user:hunter2@db.example.com/crab"
	t.Setenv("CRABBOX_GITHUB_TOKEN", "ghp_supersecret_value")
	t.Setenv("CRABBOX_EVIDENCE_KEY", "/run/secrets/evidence.pem")
	t.Setenv("CRABEDENCE_PROVIDER_EXECUTION_MAX", "45s")
	cfg, err := LoadServiceConfig(ServeOptions{DatabaseURL: dsn})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	report := cfg.Report()
	for _, secret := range []string{"ghp_supersecret_value", "hunter2", "/run/secrets/evidence.pem"} {
		if strings.Contains(report, secret) {
			t.Errorf("startup report leaked %q:\n%s", secret, report)
		}
	}
	for _, want := range []string{
		"topology:         single",
		"effect store:     postgres",
		"evidence key:     provisioned",
		"github adapter:   enabled",
		"provider ceiling: 45s",
		"provider gate:    max 64 concurrent",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("startup report is missing %q:\n%s", want, report)
		}
	}
}

// TestLoadServiceConfigAmbientGitHubTokenDoesNotEnable proves an
// ambient GITHUB_TOKEN — present in many shells and CI environments
// without intent — cannot switch on the adapter by itself: capability
// availability is configuration, not credential discovery. The
// service-specific CRABBOX_GITHUB_TOKEN is itself a declaration and
// still enables implicitly; CRABBOX_GITHUB_ENABLED=true makes an
// ambient token usable.
func TestLoadServiceConfigAmbientGitHubTokenDoesNotEnable(t *testing.T) {
	clearServiceEnv(t)
	t.Setenv("GITHUB_TOKEN", "ghp_ambient_only")
	cfg, err := LoadServiceConfig(ServeOptions{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.GitHubEnabled {
		t.Fatal("ambient GITHUB_TOKEN must not enable the github adapter")
	}

	// Explicit opt-in admits the ambient token as the credential.
	t.Setenv("CRABBOX_GITHUB_ENABLED", "true")
	cfg, err = LoadServiceConfig(ServeOptions{})
	if err != nil {
		t.Fatalf("load with explicit enable: %v", err)
	}
	if !cfg.GitHubEnabled || cfg.GitHubToken != "ghp_ambient_only" {
		t.Fatalf("explicit enable must admit the ambient token: enabled=%v", cfg.GitHubEnabled)
	}

	// The service-specific variable is itself a declaration.
	t.Setenv("CRABBOX_GITHUB_ENABLED", "")
	t.Setenv("CRABBOX_GITHUB_TOKEN", "ghp_declared")
	cfg, err = LoadServiceConfig(ServeOptions{})
	if err != nil {
		t.Fatalf("load with CRABBOX_GITHUB_TOKEN: %v", err)
	}
	if !cfg.GitHubEnabled || cfg.GitHubToken != "ghp_declared" {
		t.Fatalf("CRABBOX_GITHUB_TOKEN must enable the adapter and win the credential: enabled=%v", cfg.GitHubEnabled)
	}
}
