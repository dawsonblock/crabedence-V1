package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/openclaw/crabbox/internal/authority"
	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/idempotency"
	"github.com/openclaw/crabbox/internal/reconcile"
)

// ServeOptions configures the execution service.
type ServeOptions struct {
	SocketPath        string
	DatabaseURL       string // PostgreSQL DSN — used when the postgres store backend is selected (see CRABEDENCE_STORE_BACKEND)
	ReconcileInterval int64  // Reconciliation interval in seconds (0 = disable)
	Release           string // Release identity for the runtime configuration digest (e.g. "0.52.0-rc.1"); empty for dev builds
}

// Serve starts the persistent execution service.
// It registers built-in capabilities, connects to PostgreSQL for durable
// idempotency, and listens on the Unix socket until the context is
// cancelled or a signal is received.
func Serve(ctx context.Context, opts ServeOptions) error {
	// Deployment configuration is resolved and validated before any
	// resource is opened: a malformed or contradictory declaration
	// fails closed here, never later.
	cfg, err := LoadServiceConfig(opts)
	if err != nil {
		return err
	}

	registry := capability.NewRegistry()

	// The capability registry is STATIC for a release: every built-in
	// capability is registered regardless of deployment configuration,
	// so the registry digest identifies the security policy this build
	// ships rather than the environment it runs in. Adapter availability
	// is a runtime property — an unwired adapter fails closed at dispatch
	// (known capability, unavailable adapter), never as an unknown
	// capability and never as a routing change. Registration goes through
	// the single built-in catalog (RegisterBuiltinCapabilities), the same
	// one cmd/registry-digest and the qualification harness use.
	if err := RegisterBuiltinCapabilities(registry); err != nil {
		return err
	}

	// Adapter wiring is deployment configuration, resolved by the
	// loader: CRABBOX_GITHUB_ENABLED forces the adapter on, a token
	// enables it implicitly, and enabling without a token fails closed
	// before this point.
	var githubHandler *GitHubIssueHandler
	var githubReads *GitHubReads
	if cfg.GitHubEnabled {
		githubHandler = NewGitHubIssueHandler(cfg.GitHubAPIURL, cfg.GitHubToken)
		// The observational read shares the provider identity and
		// configuration with the mutation adapter.
		githubReads = NewGitHubReads(cfg.GitHubAPIURL, cfg.GitHubToken)
	}

	// Qualification extension: CRABEDENCE_QUAL_PROVIDER_URL wires the
	// external CRITICAL qualification provider — a separate process with
	// its own durable ledger — as a deployed adapter. Setting it registers
	// qualification.critical.commit as an explicit extension of the
	// release registry (the registry digest and the runtime
	// configuration identity change to reflect the extension, exactly as
	// the qualification harness binds it). Unset, the service serves the
	// unmodified release registry.
	//
	// The URL is configuration, not a secret: the qualification
	// provider is loopback-bound and unauthenticated. The adapter
	// enforces that contract — a URL targeting anything but the local
	// host is a startup error, not a best-effort connection.
	var qualAdapter *QualificationAdapter
	if cfg.QualProviderURL != "" {
		qualAdapter, err = NewQualificationAdapter(cfg.QualProviderURL)
		if err != nil {
			return err
		}
		desc, err := QualificationDescriptor()
		if err != nil {
			return fmt.Errorf("qualification capability descriptor: %w", err)
		}
		if err := registry.RegisterResolved(desc); err != nil {
			return fmt.Errorf("register qualification capability: %w", err)
		}
		// Fail closed: a configured-but-unreachable provider must not
		// start a service that would mint UNKNOWN records it cannot
		// reconcile. The provider serves /stats without side effects.
		if err := qualAdapter.ping(ctx); err != nil {
			return fmt.Errorf("qualification provider at %s is not reachable: %w", cfg.QualProviderURL, err)
		}
	}

	// Create handlers
	echoHandler := NewEchoHandler()
	counterHandler := NewCounterHandler()
	infoHandler := NewSystemInfoHandler()

	// Durable store backend. Both engines implement the same
	// idempotency.EffectStore contract — same state graph, fencing,
	// monotonic observations, and terminal proof policy.
	//
	// The backend, topology, and replica count were resolved and
	// cross-checked by the configuration loader (CRABEDENCE_STORE_BACKEND
	// selects the engine; CRABEDENCE_STORE_PATH locates the SQLite file).
	// Exactly-once is a cluster-wide property: every replica must
	// contend on one ledger. Each SQLite file mints its own execution
	// IDs, and the provider idempotency token is derived from them, so
	// two replicas on independent ledgers derive different provider
	// tokens for the same idempotency key and can dispatch the same
	// effect twice — which is why a cluster topology, and any declared
	// replica count above one, requires postgres.

	var store idempotency.EffectStore
	var authorityStore capability.GrantResolver
	switch cfg.Backend {
	case "postgres":
		if cfg.DatabaseURL == "" {
			return fmt.Errorf("CRABEDENCE_STORE_BACKEND=postgres requires CRABEDENCE_DATABASE_URL")
		}
		db, err := sql.Open("pgx", cfg.DatabaseURL)
		if err != nil {
			return fmt.Errorf("failed to open database: %w", err)
		}
		defer db.Close()

		if err := db.PingContext(ctx); err != nil {
			return fmt.Errorf("failed to connect to database: %w", err)
		}

		store, err = idempotency.NewStore(db)
		if err != nil {
			return fmt.Errorf("failed to create idempotency store: %w", err)
		}

		authorityStore, err = authority.NewStore(db)
		if err != nil {
			return fmt.Errorf("failed to create authority store: %w", err)
		}
	case "sqlite":
		path := cfg.StorePath
		if path == "" {
			base, err := os.UserConfigDir()
			if err != nil {
				return fmt.Errorf("failed to resolve config dir for embedded store: %w", err)
			}
			path = filepath.Join(base, "crabbox", "crabedence.db")
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return fmt.Errorf("failed to create store directory: %w", err)
		}
		db, err := idempotency.OpenSQLiteDB(path)
		if err != nil {
			return fmt.Errorf("failed to open embedded store %s: %w", path, err)
		}
		defer db.Close()

		if err := db.PingContext(ctx); err != nil {
			return fmt.Errorf("failed to connect to embedded store: %w", err)
		}

		store, err = idempotency.NewSQLiteStore(db)
		if err != nil {
			return fmt.Errorf("failed to create idempotency store: %w", err)
		}

		authorityStore, err = authority.NewSQLiteStore(db)
		if err != nil {
			return fmt.Errorf("failed to create authority store: %w", err)
		}
	}

	// Evidence signer: the execution service attests CRITICAL terminal
	// outcomes with an Ed25519-signed effect receipt.
	//
	// Deployment configuration (multi-replica safe):
	//   CRABBOX_EVIDENCE_KEY — path to the Ed25519 signing key PEM.
	//     Replicas MUST share the same key material (mounted secret)
	//     or receipts signed by one replica will be rejected by another.
	//     Default: the CLI attest key path (~/.config/crabbox/attest/).
	//   CRABBOX_EVIDENCE_TRUSTED_SIGNERS — comma-separated additional
	//     signer fingerprints the store trusts, for key rotation or
	//     distinct signing identities across replicas.
	//   CRABBOX_TOPOLOGY — declared deployment topology (single or
	//     cluster). Cluster refuses to start without an existing,
	//     provisioned CRABBOX_EVIDENCE_KEY, regardless of the declared
	//     replica count.
	//   CRABBOX_REPLICAS — declared replica count. When > 1 the service
	//     refuses to start without an explicitly configured, existing
	//     CRABBOX_EVIDENCE_KEY: auto-generating a host-local key per
	//     replica would give each replica a distinct cluster identity
	//     and produce evidence receipts its peers cannot verify.
	//   CRABBOX_MODE — set to "production" to forbid key
	//     auto-generation on single-node deployments too: the trust
	//     root must be provisioned (mounted key, KMS/HSM signer, or
	//     an explicitly configured secret), never created silently.
	var signer *evidence.Signer
	if store != nil {
		keyPath := cfg.EvidenceKeyPath
		if err := validateEvidenceKeyPolicy(cfg.Topology, keyPath); err != nil {
			return err
		}
		if keyPath == "" {
			var err error
			keyPath, err = evidenceKeyPath()
			if err != nil {
				return fmt.Errorf("failed to resolve evidence key path: %w", err)
			}
			if _, statErr := os.Stat(keyPath); os.IsNotExist(statErr) {
				fmt.Fprintf(os.Stderr, "evidence signer: no key at %s — generating a host-local signing identity; for multi-replica deployments set CRABBOX_EVIDENCE_KEY to a provisioned shared key\n", keyPath)
			}
		}
		var err error
		signer, err = evidence.LoadOrCreateSigner(keyPath)
		if err != nil {
			return fmt.Errorf("failed to load evidence signer: %w", err)
		}
		// The local signer is always trusted; additional fingerprints
		// (rotation, distinct replica identities) were validated by the
		// configuration loader, so a malformed entry can never quietly
		// shrink the trusted set.
		trusted := append([]string{signer.Fingerprint()}, cfg.EvidenceTrustedSigners...)
		store.SetTrustedEvidenceSigners(trusted...)
	}

	// Create a multi-handler that dispatches based on adapter ID
	// If we have a durable store, wrap it in a DispatchExecutor
	var handler Handler
	var durable Handler
	var providerGate *ProviderGate
	handlers := map[string]Handler{
		"system":       echoHandler,
		"test-counter": counterHandler,
		"system-info":  infoHandler,
	}
	if githubHandler != nil {
		handlers["github"] = githubHandler
	}
	if qualAdapter != nil {
		handlers[QualificationAdapterID] = qualAdapter
	}
	multiHandler := NewMultiHandler(handlers)

	// Registry invariant scan and startup report. The registry fails
	// closed as a whole: a capability with an invalid dimension
	// combination, no adapter binding, a malformed argument schema, or
	// an unsupported schema keyword refuses service startup instead of
	// surfacing at execution time. The registry digest is the stable
	// identity of the exact capability policy set this process serves.
	if err := registry.Validate(); err != nil {
		return fmt.Errorf("capability registry invariant scan failed: %w", err)
	}
	// Unwired adapters are legitimate deployment state, not a registry
	// defect: the capability stays registered (static policy) and fails
	// closed as CAPABILITY_UNAVAILABLE at the deployment boundary
	// (dynamic availability). Report exactly what this deployment cannot
	// execute, with the policy it still carries.
	adapterStates := make(capability.AdapterAvailability, len(handlers))
	for adapterID := range handlers {
		adapterStates[adapterID] = capability.AdapterState{Status: capability.AvailabilityAvailable}
	}
	reportCapabilityAvailability(registry, registry.CheckAdapterAvailability(adapterStates))
	report, err := registry.Report()
	if err != nil {
		return fmt.Errorf("capability registry report failed: %w", err)
	}
	fmt.Fprint(os.Stderr, report.String())

	if store != nil {
		// Use DispatchExecutor for durable idempotency. The
		// provider-invocation ceiling and the provider gate policy were
		// resolved and validated by the configuration loader; the gate
		// bounds simultaneous provider calls and opens a circuit after
		// consecutive ambiguous outcomes, so a wedged provider cannot
		// accumulate goroutines without limit. Reconciliation never
		// acquires it.
		executor := NewDispatchExecutor(multiHandler, store)
		executor.SetEvidenceSigner(signer)
		executor.SetTimeouts(cfg.ExecutorTimeouts)
		providerGate = NewProviderGate(cfg.ProviderGate)
		executor.SetProviderGate(providerGate)
		durable = executor
	} else {
		// No store — fail closed for MUTATION/CRITICAL
		durable = NewFailClosedHandler(multiHandler)
	}

	// LOCAL leg — Function Hooks. PURE capabilities resolve to the
	// LOCAL route (PURE + NONE assurance) and execute in-process under
	// the hook runtime: validated arguments in, bounded JSON out, audit
	// record written, no effect-fabric dependency injected. The DIRECT
	// leg lands with the first observational adapter and fails closed
	// until then.
	hooks := NewFunctionHookRegistry()
	if err := RegisterSystemEchoHook(hooks); err != nil {
		return fmt.Errorf("failed to register system.echo function hook: %w", err)
	}
	directReads := NewDirectReadRegistry()
	if err := RegisterSystemInfoRead(directReads, infoHandler); err != nil {
		return fmt.Errorf("failed to register system.info direct read: %w", err)
	}
	if githubReads != nil {
		if err := RegisterGitHubReads(directReads, githubReads); err != nil {
			return fmt.Errorf("failed to register github.issue.get direct read: %w", err)
		}
	}
	dispatcher := NewRouteDispatcher(durable)
	dispatcher.SetLocal(hooks)
	dispatcher.SetDirect(directReads)
	handler = dispatcher

	service := NewService(registry, handler, opts.SocketPath)
	// The deployment boundary owns availability: the service refuses a
	// known capability whose adapter this deployment did not wire, with
	// CAPABILITY_UNAVAILABLE (never CAPABILITY_NOT_FOUND, never a
	// routing change).
	service.SetAdapterAvailability(adapterStates)

	// Wire production authority: PostgreSQL-backed grant resolution.
	// Without this, the service defaults to NoopGrantResolver which
	// denies all grant-required capabilities in production.
	if authorityStore != nil {
		service.SetGrantResolver(authorityStore)
	}

	// Peer authentication was parsed and validated by the configuration
	// loader: when set, every request's principal claim is verified
	// against the kernel-supplied peer UID — unmapped UIDs, missing
	// credentials, and mismatched claims are denied, and the
	// authenticated principal replaces the claim in the execution
	// identity. Unset, the service keeps the bearer model's claimed
	// principal (the socket is already owner-only).
	if cfg.PeerPrincipals != nil {
		service.SetPeerAuth(cfg.PeerPrincipals)
		fmt.Fprintf(os.Stderr, "Peer authentication: strict UID→principal map (%d entries)\n", len(cfg.PeerPrincipals))
	}

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start reconciliation worker if enabled.
	// Register capability-specific resolvers for each provider that
	// supports recovery. The default resolver is NoopResolver (fail-
	// closed: UNKNOWN stays UNKNOWN unless a resolver proves otherwise).
	if store != nil && opts.ReconcileInterval > 0 {
		worker := reconcile.NewWorker(store, reconcile.NoopResolver{})
		// Reconciliation resolvers are wrapped so lookup outcomes are
		// counted on the provider gate. The wrapper never acquires
		// dispatch capacity: the provider failure that strands a
		// record in UNKNOWN must not also block the lookup that
		// resolves it.
		worker.RegisterResolver("test.counter.increment", providerGate.ObserveResolver("test-counter", counterHandler))
		if githubHandler != nil {
			worker.RegisterResolver("github.issue.create", providerGate.ObserveResolver("github", githubHandler))
		}
		if qualAdapter != nil {
			worker.RegisterResolver(QualificationCapabilityID, providerGate.ObserveResolver(QualificationAdapterID, qualAdapter))
		}
		worker.SetEvidenceSigner(signer)
		// Reconciliation runs under a supervisor with an explicit
		// readiness policy: cycle timing, consecutive failures, and the
		// UNKNOWN backlog age are observable, and readiness transitions
		// are logged.
		supervisor := reconcile.NewSupervisor(worker, store, reconcile.SupervisorConfig{
			Interval:               durationSeconds(opts.ReconcileInterval),
			MaxConsecutiveFailures: 5,
			MaxUnknownAge:          time.Hour,
		})
		// Readiness surface: the supervisor's health escapes the Go
		// object graph into a file next to the socket, so an
		// orchestrator (systemd, Kubernetes, a watchdog) can observe
		// reconciliation health without reading logs.
		statusPath := filepath.Join(filepath.Dir(opts.SocketPath), "reconciler-status.json")
		supervisor.SetStatusWriter(func(health reconcile.Health) {
			payload, err := json.Marshal(health)
			if err != nil {
				fmt.Fprintf(os.Stderr, "reconciliation readiness: cannot marshal status: %v\n", err)
				return
			}
			if err := writeFileAtomic(statusPath, append(payload, '\n'), 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "reconciliation readiness: cannot write status file %s: %v\n", statusPath, err)
			}
		})
		go func() {
			if err := supervisor.Run(ctx); err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "reconciliation supervisor stopped: %v\n", err)
			}
		}()
	}

	// Start service
	if err := service.Start(ctx); err != nil {
		return fmt.Errorf("failed to start execution service: %w", err)
	}
	defer service.Stop()

	// Export the verifiable registry envelope next to the socket so
	// planner-side runtimes (NEMO) route on trusted descriptors instead
	// of maintaining their own capability catalog. The envelope carries
	// the registry digest AND the exact canonical bytes it covers, so a
	// consumer verifies SHA-256 over the bytes it was given and only
	// then parses them — no cross-language canonicalization is required
	// for the verification to be sound. It is written AFTER the service
	// starts: Service.Start creates and verifies the socket directory,
	// so the envelope lands in a secured directory (and startup fails
	// closed rather than writing somewhere else).
	envelope, err := registry.Envelope()
	if err != nil {
		return fmt.Errorf("capability registry envelope failed: %w", err)
	}
	payload, err := envelope.JSON()
	if err != nil {
		return fmt.Errorf("capability registry envelope failed: %w", err)
	}
	catalogPath := filepath.Join(filepath.Dir(opts.SocketPath), "capabilities.json")
	if err := writeFileAtomic(catalogPath, payload, 0o600); err != nil {
		return fmt.Errorf("failed to write capability registry envelope: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Capability registry snapshot: %s (sha256 %s)\n", catalogPath, envelope.RegistrySHA256)

	// Runtime configuration identity: the deployment state this process
	// runs in — deliberately separate from the registry digest, and
	// built only from normalized, non-secret configuration.
	runtimeCfg := RuntimeConfiguration{
		Release:         opts.Release,
		RegistrySHA256:  report.Digest,
		EffectStore:     cfg.Backend,
		EnabledAdapters: adapterIDs(handlers),
	}
	runtimeEnvelope, err := RuntimeIdentityEnvelopeFor(runtimeCfg)
	if err != nil {
		return fmt.Errorf("runtime configuration identity failed: %w", err)
	}
	runtimePayload, err := runtimeEnvelope.JSON()
	if err != nil {
		return fmt.Errorf("runtime configuration identity failed: %w", err)
	}
	identityPath := filepath.Join(filepath.Dir(opts.SocketPath), "runtime-identity.json")
	if err := writeFileAtomic(identityPath, runtimePayload, 0o600); err != nil {
		return fmt.Errorf("failed to write runtime identity envelope: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Runtime configuration digest: %s (%s)\n", runtimeEnvelope.RuntimeConfigurationSHA256, identityPath)

	fmt.Fprintf(os.Stderr, "Crabedence execution service listening on %s\n", opts.SocketPath)
	fmt.Fprintf(os.Stderr, "Registered capabilities: %v\n", registry.List())
	if store != nil {
		fmt.Fprintf(os.Stderr, "Durable idempotency: enabled (%s)\n", cfg.Backend)
	} else {
		fmt.Fprintf(os.Stderr, "Durable idempotency: disabled (MUTATION/CRITICAL will fail closed)\n")
	}
	// Startup configuration report: the resolved, non-secret operating
	// characteristics of this process, so a misdeployment is visible
	// before traffic arrives. Secrets are excluded by construction.
	fmt.Fprint(os.Stderr, cfg.Report())
	if providerGate != nil {
		cfg := providerGate.Config()
		fmt.Fprintf(os.Stderr, "Provider gate: max %d concurrent per provider; degraded after %d consecutive ambiguous outcomes; circuit opens after %d (cooldown %s)\n",
			cfg.MaxConcurrent, cfg.DegradedAfter, cfg.OpenAfter, cfg.OpenCooldown)
	}

	// Wait for signal or context cancellation
	select {
	case <-sigCh:
		fmt.Fprintln(os.Stderr, "Shutting down...")
	case <-ctx.Done():
	}

	return nil
}

// adapterIDs returns the adapter IDs wired into this deployment.
func adapterIDs(handlers map[string]Handler) []string {
	ids := make([]string, 0, len(handlers))
	for id := range handlers {
		ids = append(ids, id)
	}
	return ids
}

// reportCapabilityAvailability prints the deployment's runtime
// availability view: which registered capabilities this deployment
// cannot currently execute, and why. Availability is derived state — it
// never modifies the registry, its descriptors, or its digest (INV-014).
func reportCapabilityAvailability(registry *capability.Registry, report capability.AdapterAvailabilityReport) {
	if len(report.Unavailable) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "Capability availability: %d of %d registered capabilities are not executable in this deployment\n",
		len(report.Unavailable), report.Total)
	for _, entry := range report.Unavailable {
		fmt.Fprintf(os.Stderr, "  %s\n", entry.CapabilityID)
		fmt.Fprintln(os.Stderr, "    KNOWN:     yes")
		if desc, ok := registry.Lookup(entry.CapabilityID); ok {
			fmt.Fprintf(os.Stderr, "    POLICY:    %s / %s / %s\n", desc.ExecutionClass, desc.AssuranceProfile, desc.ExecutionRoute)
		}
		fmt.Fprintf(os.Stderr, "    ADAPTER:   %s\n", entry.AdapterID)
		fmt.Fprintln(os.Stderr, "    AVAILABLE: no")
		fmt.Fprintf(os.Stderr, "    REASON:    %s (%s)\n", entry.Status, entry.Reason)
	}
}

// FailClosedHandler wraps a handler and rejects MUTATION/CRITICAL
// operations when durable idempotency is unavailable. This prevents
// a configuration error from silently converting guarded mutations
// into unguarded ones.
type FailClosedHandler struct {
	inner Handler
}

// NewFailClosedHandler creates a handler that fails closed for
// MUTATION/CRITICAL when no durable store is available.
func NewFailClosedHandler(inner Handler) *FailClosedHandler {
	return &FailClosedHandler{inner: inner}
}

// durationSeconds converts an int64 to a time.Duration.
func durationSeconds(s int64) time.Duration {
	return time.Duration(s) * time.Second
}

// writeFileAtomic writes a file crash-durably: temp file in the same
// directory, file fsync, rename, then directory fsync. A partially
// written registry snapshot must never be observable.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".capabilities-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName) // no-op after a successful rename
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tempName, mode); err != nil {
		return err
	}
	if err := os.Rename(tempName, path); err != nil {
		return err
	}
	// Commit the directory entry so the file survives a power loss.
	// This is a hard failure, not a best-effort sync: a write that may
	// not survive a crash must not be reported as durable.
	dirHandle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open %s for durability commit: %w", dir, err)
	}
	syncErr := dirHandle.Sync()
	closeErr := dirHandle.Close()
	if syncErr != nil {
		return fmt.Errorf("directory fsync failed — %s durability not guaranteed: %w", filepath.Base(path), syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("directory close failed after fsync: %w", closeErr)
	}
	return nil
}

// providerGateConfigFromEnv applies the deployment's provider-gate
// overrides to the production defaults. Malformed or contradictory
// values are startup errors, never a silent fallback.
func providerGateConfigFromEnv() (ProviderGateConfig, error) {
	cfg := DefaultProviderGateConfig()
	positive := func(name string) (int, bool, error) {
		raw := strings.TrimSpace(os.Getenv(name))
		if raw == "" {
			return 0, false, nil
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			return 0, false, fmt.Errorf("%s %q is not a positive integer", name, raw)
		}
		return n, true, nil
	}
	if n, ok, err := positive("CRABEDENCE_PROVIDER_MAX_CONCURRENT"); err != nil {
		return cfg, err
	} else if ok {
		cfg.MaxConcurrent = n
	}
	if n, ok, err := positive("CRABEDENCE_PROVIDER_DEGRADED_AFTER"); err != nil {
		return cfg, err
	} else if ok {
		cfg.DegradedAfter = n
	}
	if n, ok, err := positive("CRABEDENCE_PROVIDER_OPEN_AFTER"); err != nil {
		return cfg, err
	} else if ok {
		cfg.OpenAfter = n
	}
	if raw := strings.TrimSpace(os.Getenv("CRABEDENCE_PROVIDER_OPEN_COOLDOWN")); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			return cfg, fmt.Errorf("CRABEDENCE_PROVIDER_OPEN_COOLDOWN %q is not a positive Go duration (e.g. 30s, 2m)", raw)
		}
		cfg.OpenCooldown = d
	}
	if cfg.DegradedAfter > cfg.OpenAfter {
		return cfg, fmt.Errorf("CRABEDENCE_PROVIDER_DEGRADED_AFTER (%d) cannot exceed CRABEDENCE_PROVIDER_OPEN_AFTER (%d)", cfg.DegradedAfter, cfg.OpenAfter)
	}
	return cfg, nil
}

// Topology is the declared deployment topology. It is explicit in
// production: a missing CRABBOX_TOPOLOGY aborts startup rather than
// assuming that an unset replica count means one production replica.
type Topology string

const (
	// TopologySingle is one service instance: a local (SQLite) ledger
	// and a host-local evidence key are valid.
	TopologySingle Topology = "single"
	// TopologyCluster is a replicated service: every replica must
	// contend on one shared PostgreSQL ledger and share one
	// provisioned evidence key.
	TopologyCluster Topology = "cluster"
)

// resolveTopology parses CRABBOX_TOPOLOGY. Outside production an unset
// value resolves to single; production must declare the topology
// explicitly. CRABBOX_REPLICAS remains a declared replica count and a
// consistency check — never the source of truth.
func resolveTopology() (Topology, error) {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("CRABBOX_TOPOLOGY")))
	switch raw {
	case "":
		if productionMode() {
			return "", fmt.Errorf("CRABBOX_TOPOLOGY must be explicitly declared in production (single or cluster): a missing topology is never assumed to mean one production replica")
		}
		return TopologySingle, nil
	case string(TopologySingle):
		return TopologySingle, nil
	case string(TopologyCluster):
		return TopologyCluster, nil
	default:
		return "", fmt.Errorf("unknown CRABBOX_TOPOLOGY %q (want single or cluster)", os.Getenv("CRABBOX_TOPOLOGY"))
	}
}

// replicaCount parses CRABBOX_REPLICAS into the declared replica
// count; unset/empty means a single replica. The parse fails closed:
// a malformed value like "2x" is a startup error, never a silent
// single-replica downgrade of replicated-mode protections.
func replicaCount() (int, error) {
	raw := strings.TrimSpace(os.Getenv("CRABBOX_REPLICAS"))
	if raw == "" {
		return 1, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("CRABBOX_REPLICAS %q is not a positive integer", os.Getenv("CRABBOX_REPLICAS"))
	}
	return n, nil
}

// replicatedDeployment reports whether the operator declared a
// multi-replica topology via CRABBOX_REPLICAS > 1. Replicated mode
// tightens evidence-key requirements — a cryptographic cluster
// identity must never be accidentally host-local. A malformed
// CRABBOX_REPLICAS counts as replicated here (fail closed); Serve
// rejects it outright via replicaCount before this runs.
func replicatedDeployment() bool {
	n, err := replicaCount()
	return err != nil || n > 1
}

// productionMode reports whether the operator declared production
// via CRABBOX_MODE=production. Production forbids auto-generating a
// signing identity — the trust root must be provisioned (mounted
// Ed25519 key, KMS/HSM signer, or an explicitly configured secret),
// never silently created per host.
func productionMode() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("CRABBOX_MODE")), "production")
}

// validateEvidenceKeyPolicy enforces the provisioned-key requirement
// for deployment modes that must never auto-generate a signer: a
// cluster topology (CRABBOX_TOPOLOGY=cluster), multi-replica
// (CRABBOX_REPLICAS > 1), and production (CRABBOX_MODE=production).
// All require CRABBOX_EVIDENCE_KEY to point at an existing provisioned
// key; auto-creation remains available only in single-node development
// mode.
func validateEvidenceKeyPolicy(topology Topology, keyPath string) error {
	if topology == TopologyCluster {
		if keyPath == "" {
			return fmt.Errorf("cluster topology (CRABBOX_TOPOLOGY=cluster) requires CRABBOX_EVIDENCE_KEY pointing to a provisioned key shared across replicas")
		}
		if _, err := os.Stat(keyPath); err != nil {
			return fmt.Errorf("cluster topology requires an existing evidence key at CRABBOX_EVIDENCE_KEY=%s (key auto-creation is disabled for cluster deployments): %w", keyPath, err)
		}
		return nil
	}
	if replicatedDeployment() {
		if keyPath == "" {
			return fmt.Errorf("multi-replica deployment (CRABBOX_REPLICAS=%s) requires CRABBOX_EVIDENCE_KEY pointing to a provisioned key shared across replicas", os.Getenv("CRABBOX_REPLICAS"))
		}
		if _, err := os.Stat(keyPath); err != nil {
			return fmt.Errorf("multi-replica deployment requires an existing evidence key at CRABBOX_EVIDENCE_KEY=%s (key auto-creation is disabled for replicas): %w", keyPath, err)
		}
		return nil
	}
	if productionMode() {
		if keyPath == "" {
			return fmt.Errorf("production mode (CRABBOX_MODE=production) requires CRABBOX_EVIDENCE_KEY pointing to a provisioned signing key — key auto-generation is development-only")
		}
		if _, err := os.Stat(keyPath); err != nil {
			return fmt.Errorf("production mode requires an existing evidence key at CRABBOX_EVIDENCE_KEY=%s: %w", keyPath, err)
		}
	}
	return nil
}

// evidenceKeyPath returns the shared attest key location
// (~/.config/crabbox/attest/id_ed25519.pem) — the same key the CLI uses
// for terminal run receipts gives the deployment a single signer
// identity for both run receipts and effect-fabric evidence receipts.
func evidenceKeyPath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "crabbox", "attest", "id_ed25519.pem"), nil
}

// isSHA256Hex reports whether s is a 64-character lowercase hex
// SHA-256 fingerprint — the only form the evidence-trust list accepts.
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
