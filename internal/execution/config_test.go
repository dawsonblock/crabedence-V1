package execution

import (
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
		"CRABEDENCE_PEER_PRINCIPALS",
		"CRABEDENCE_PROVIDER_EXECUTION_MAX",
		"CRABEDENCE_PROVIDER_MAX_CONCURRENT", "CRABEDENCE_PROVIDER_DEGRADED_AFTER",
		"CRABEDENCE_PROVIDER_OPEN_AFTER", "CRABEDENCE_PROVIDER_OPEN_COOLDOWN",
	} {
		t.Setenv(name, "")
	}
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
		{"unknown backend", func(t *testing.T) { t.Setenv("CRABEDENCE_STORE_BACKEND", "mysql") }, "unknown CRABEDENCE_STORE_BACKEND"},
		{"malformed replica count", func(t *testing.T) { t.Setenv("CRABBOX_REPLICAS", "2x") }, "not a positive integer"},
		{"unknown topology", func(t *testing.T) { t.Setenv("CRABBOX_TOPOLOGY", "sharded") }, "unknown CRABBOX_TOPOLOGY"},
		{"production without topology", func(t *testing.T) { t.Setenv("CRABBOX_MODE", "production") }, "must be explicitly declared in production"},
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
		{"github enabled without token", func(t *testing.T) { t.Setenv("CRABBOX_GITHUB_ENABLED", "true") }, "no CRABBOX_GITHUB_TOKEN or GITHUB_TOKEN"},
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
