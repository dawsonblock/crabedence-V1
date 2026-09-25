package execution

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// ServiceConfig is the validated deployment configuration of the
// execution service. Every environment read on the startup path is
// resolved here, once, before any resource is opened: malformed or
// contradictory values fail closed at load time, and the non-secret
// resolved characteristics are printable (Report) so a misdeployment
// is visible before traffic arrives.
type ServiceConfig struct {
	// Topology, replica count, and the effect-store backend.
	Topology    Topology
	Replicas    int
	Backend     string
	StorePath   string
	DatabaseURL string

	// Adapters.
	GitHubEnabled   bool
	GitHubToken     string
	GitHubAPIURL    string
	QualProviderURL string

	// Evidence trust root.
	EvidenceKeyPath        string
	EvidenceTrustedSigners []string

	// Peer authentication and execution budgets.
	PeerPrincipals   PeerPrincipalMap
	ExecutorTimeouts ExecutorTimeouts
	ProviderGate     ProviderGateConfig
}

// LoadServiceConfig resolves and validates the deployment configuration.
// Development defaults are explicit here; production requirements are
// enforced (topology must be declared, cluster requires PostgreSQL and
// a provisioned key) rather than assumed.
func LoadServiceConfig(opts ServeOptions) (*ServiceConfig, error) {
	cfg := &ServiceConfig{
		DatabaseURL:      opts.DatabaseURL,
		ExecutorTimeouts: DefaultExecutorTimeouts(),
	}

	topology, err := resolveTopology()
	if err != nil {
		return nil, err
	}
	cfg.Topology = topology

	replicas, err := replicaCount()
	if err != nil {
		return nil, err
	}
	cfg.Replicas = replicas

	backend, err := resolveStoreBackend(opts.DatabaseURL)
	if err != nil {
		return nil, err
	}
	cfg.Backend = backend

	// Topology, replica count, and store backend must be consistent: a
	// contradictory declaration is a startup error, never a silent
	// reinterpretation of what the deployment asked for.
	if cfg.Topology == TopologySingle && cfg.Replicas > 1 {
		return nil, fmt.Errorf("CRABBOX_TOPOLOGY=single contradicts CRABBOX_REPLICAS=%d: a single-replica topology cannot declare multiple replicas", cfg.Replicas)
	}
	if cfg.Replicas > 1 && cfg.Backend != "postgres" {
		return nil, fmt.Errorf("multi-replica deployment (CRABBOX_REPLICAS=%d) requires the shared postgres store backend (CRABEDENCE_STORE_BACKEND=postgres with CRABEDENCE_DATABASE_URL); backend %q gives each replica an independent ledger", cfg.Replicas, cfg.Backend)
	}
	if cfg.Topology == TopologyCluster && cfg.Backend != "postgres" {
		return nil, fmt.Errorf("CRABBOX_TOPOLOGY=cluster requires the shared postgres store backend (CRABEDENCE_STORE_BACKEND=postgres with CRABEDENCE_DATABASE_URL); backend %q gives each replica an independent ledger", cfg.Backend)
	}
	cfg.StorePath = os.Getenv("CRABEDENCE_STORE_PATH")

	// Adapter wiring: CRABBOX_GITHUB_ENABLED forces the adapter on, a
	// token enables it implicitly, and enabling without a token still
	// fails closed at startup. GITHUB_TOKEN is ambient in many dev
	// shells and CI environments, so an explicit
	// CRABBOX_GITHUB_ENABLED=false/0/no must disable the adapter even
	// when a token is present.
	githubToken := os.Getenv("CRABBOX_GITHUB_TOKEN")
	if githubToken == "" {
		githubToken = os.Getenv("GITHUB_TOKEN")
	}
	githubEnabled := githubToken != ""
	switch strings.ToLower(strings.TrimSpace(os.Getenv("CRABBOX_GITHUB_ENABLED"))) {
	case "true", "1", "yes":
		githubEnabled = true
	case "false", "0", "no":
		githubEnabled = false
	}
	if githubEnabled && githubToken == "" {
		return nil, fmt.Errorf("github adapter enabled (CRABBOX_GITHUB_ENABLED) but no CRABBOX_GITHUB_TOKEN or GITHUB_TOKEN configured")
	}
	cfg.GitHubEnabled = githubEnabled
	cfg.GitHubToken = githubToken
	cfg.GitHubAPIURL = os.Getenv("CRABBOX_GITHUB_API_URL")
	if cfg.GitHubAPIURL == "" {
		cfg.GitHubAPIURL = "https://api.github.com"
	}
	// The qualification provider URL is configuration, not a secret;
	// the adapter enforces the loopback-only contract when it is
	// constructed.
	cfg.QualProviderURL = strings.TrimSpace(os.Getenv("CRABEDENCE_QUAL_PROVIDER_URL"))

	cfg.EvidenceKeyPath = os.Getenv("CRABBOX_EVIDENCE_KEY")
	trusted, err := parseTrustedEvidenceSigners(os.Getenv("CRABBOX_EVIDENCE_TRUSTED_SIGNERS"))
	if err != nil {
		return nil, err
	}
	cfg.EvidenceTrustedSigners = trusted

	peerMap, err := ParsePeerPrincipalMap(os.Getenv("CRABEDENCE_PEER_PRINCIPALS"))
	if err != nil {
		return nil, fmt.Errorf("CRABEDENCE_PEER_PRINCIPALS: %w", err)
	}
	cfg.PeerPrincipals = peerMap

	// The executor-owned provider ceiling applies on top of any caller
	// deadline: a provider that exceeds it — including one that ignores
	// cancellation entirely — converges the record to UNKNOWN +
	// reconciliation instead of heartbeating the lease forever.
	if raw := strings.TrimSpace(os.Getenv("CRABEDENCE_PROVIDER_EXECUTION_MAX")); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("CRABEDENCE_PROVIDER_EXECUTION_MAX %q is not a positive Go duration (e.g. 90s, 5m)", raw)
		}
		cfg.ExecutorTimeouts.ProviderExecution = d
	}

	gateCfg, err := providerGateConfigFromEnv()
	if err != nil {
		return nil, err
	}
	cfg.ProviderGate = gateCfg

	return cfg, nil
}

// Production reports whether the deployment declared production mode.
func (c *ServiceConfig) Production() bool { return productionMode() }

// EvidenceKeySource describes where the signing identity comes from
// without revealing the path: a provisioned key is a deployment
// decision, a host-local key is a development convenience.
func (c *ServiceConfig) EvidenceKeySource() string {
	if strings.TrimSpace(c.EvidenceKeyPath) != "" {
		return "provisioned (CRABBOX_EVIDENCE_KEY)"
	}
	return "host-local default (development only)"
}

// Report renders the resolved, non-secret operating characteristics.
// Secrets — tokens, DSNs, credentials — are excluded by construction:
// the structure has no field for them.
func (c *ServiceConfig) Report() string {
	mode := "development"
	if c.Production() {
		mode = "production"
	}
	github := "disabled"
	if c.GitHubEnabled {
		github = "enabled"
	}
	qualification := "not configured"
	if c.QualProviderURL != "" {
		qualification = "external provider configured"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Service configuration:\n")
	fmt.Fprintf(&b, "  mode:             %s\n", mode)
	fmt.Fprintf(&b, "  topology:         %s (declared replicas: %d)\n", c.Topology, c.Replicas)
	fmt.Fprintf(&b, "  effect store:     %s\n", c.Backend)
	fmt.Fprintf(&b, "  evidence key:     %s\n", c.EvidenceKeySource())
	fmt.Fprintf(&b, "  github adapter:   %s\n", github)
	fmt.Fprintf(&b, "  qualification:    %s\n", qualification)
	fmt.Fprintf(&b, "  peer auth:        %d mapped UIDs\n", len(c.PeerPrincipals))
	fmt.Fprintf(&b, "  provider ceiling: %s\n", c.ExecutorTimeouts.ProviderExecution)
	fmt.Fprintf(&b, "  provider gate:    max %d concurrent; degraded after %d consecutive ambiguous outcomes; circuit opens after %d (cooldown %s)\n",
		c.ProviderGate.MaxConcurrent, c.ProviderGate.DegradedAfter, c.ProviderGate.OpenAfter, c.ProviderGate.OpenCooldown)
	return b.String()
}

// resolveStoreBackend resolves CRABEDENCE_STORE_BACKEND. "auto"/unset
// resolves to postgres when a DSN is configured and sqlite otherwise;
// an unknown value is a startup error.
func resolveStoreBackend(databaseURL string) (string, error) {
	backend := strings.ToLower(strings.TrimSpace(os.Getenv("CRABEDENCE_STORE_BACKEND")))
	switch backend {
	case "", "auto":
		if databaseURL != "" {
			return "postgres", nil
		}
		return "sqlite", nil
	case "sqlite", "postgres", "none":
		return backend, nil
	default:
		return "", fmt.Errorf("unknown CRABEDENCE_STORE_BACKEND %q (want sqlite, postgres, none, or auto)", backend)
	}
}

// parseTrustedEvidenceSigners parses CRABBOX_EVIDENCE_TRUSTED_SIGNERS:
// a comma-separated list of additional signer fingerprints. A malformed
// fingerprint is never a plausible signer — silently dropping it would
// quietly shrink the trusted set, so it refuses startup.
func parseTrustedEvidenceSigners(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var trusted []string
	for _, fp := range strings.Split(raw, ",") {
		fp = strings.TrimSpace(fp)
		if fp == "" {
			continue
		}
		if !isSHA256Hex(fp) {
			return nil, fmt.Errorf("CRABBOX_EVIDENCE_TRUSTED_SIGNERS entry %q is not a SHA-256 fingerprint (64 lowercase hex chars)", fp)
		}
		trusted = append(trusted, fp)
	}
	return trusted, nil
}
