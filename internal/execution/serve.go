package execution

import (
	"context"
	"database/sql"
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
}

// DefaultServeOptions returns sensible defaults.
func DefaultServeOptions() ServeOptions {
	return ServeOptions{
		SocketPath:        defaultSocketPath(),
		ReconcileInterval: 30,
	}
}

// defaultSocketPath returns a secure socket location.
// Uses XDG_RUNTIME_DIR if available, falls back to a private
// per-user directory under /tmp. The directory is created and
// verified fail-closed by Service.Start.
func defaultSocketPath() string {
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		return xdg + "/crabedence/execution.sock"
	}
	return "/tmp/crabedence-" + os.Getenv("USER") + "/execution.sock"
}

// Serve starts the persistent execution service.
// It registers built-in capabilities, connects to PostgreSQL for durable
// idempotency, and listens on the Unix socket until the context is
// cancelled or a signal is received.
func Serve(ctx context.Context, opts ServeOptions) error {
	registry := capability.NewRegistry()

	// Register built-in capabilities
	if err := RegisterEchoCapability(registry); err != nil {
		return fmt.Errorf("failed to register system.echo: %w", err)
	}
	if err := RegisterCounterCapability(registry); err != nil {
		return fmt.Errorf("failed to register test.counter.increment: %w", err)
	}
	if err := RegisterSystemInfoCapability(registry); err != nil {
		return fmt.Errorf("failed to register system.info: %w", err)
	}

	// github.issue.create is opt-in: it is registered only when
	// explicitly configured via CRABBOX_GITHUB_TOKEN (or GITHUB_TOKEN)
	// or CRABBOX_GITHUB_ENABLED. Enabling without a token fails closed
	// at startup rather than registering a capability that cannot run.
	githubToken := os.Getenv("CRABBOX_GITHUB_TOKEN")
	if githubToken == "" {
		githubToken = os.Getenv("GITHUB_TOKEN")
	}
	// GITHUB_TOKEN is ambient in many dev shells and CI environments —
	// an explicit CRABBOX_GITHUB_ENABLED=false/0/no must disable the
	// capability even when a token is present.
	githubEnabled := githubToken != ""
	switch strings.ToLower(strings.TrimSpace(os.Getenv("CRABBOX_GITHUB_ENABLED"))) {
	case "true", "1", "yes":
		githubEnabled = true
	case "false", "0", "no":
		githubEnabled = false
	}
	var githubHandler *GitHubIssueHandler
	var githubReads *GitHubReads
	if githubEnabled {
		if githubToken == "" {
			return fmt.Errorf("github.issue.create enabled (CRABBOX_GITHUB_ENABLED) but no CRABBOX_GITHUB_TOKEN or GITHUB_TOKEN configured")
		}
		baseURL := os.Getenv("CRABBOX_GITHUB_API_URL")
		if baseURL == "" {
			baseURL = "https://api.github.com"
		}
		githubHandler = NewGitHubIssueHandler(baseURL, githubToken)
		if err := RegisterGitHubIssueCapability(registry); err != nil {
			return fmt.Errorf("failed to register github.issue.create: %w", err)
		}
		// The observational read shares the provider identity and
		// configuration with the mutation adapter.
		githubReads = NewGitHubReads(baseURL, githubToken)
		if err := RegisterGitHubReadCapabilities(registry); err != nil {
			return fmt.Errorf("failed to register github.issue.get: %w", err)
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
	//   CRABEDENCE_STORE_BACKEND — "sqlite" (default for local/
	//     single-host deployments), "postgres" (clustered/multi-host),
	//     "none" (durable store explicitly disabled — MUTATION/CRITICAL
	//     fail closed), or "auto"/unset (postgres when
	//     CRABEDENCE_DATABASE_URL is configured, sqlite otherwise).
	//   CRABEDENCE_STORE_PATH — SQLite file location.
	//     Default: ~/.config/crabbox/crabedence.db
	//   CRABEDENCE_DATABASE_URL — PostgreSQL DSN (postgres backend).
	backend := strings.ToLower(strings.TrimSpace(os.Getenv("CRABEDENCE_STORE_BACKEND")))
	switch backend {
	case "", "auto":
		if opts.DatabaseURL != "" {
			backend = "postgres"
		} else {
			backend = "sqlite"
		}
	case "sqlite", "postgres", "none":
	default:
		return fmt.Errorf("unknown CRABEDENCE_STORE_BACKEND %q (want sqlite, postgres, none, or auto)", backend)
	}

	var store idempotency.EffectStore
	var authorityStore capability.GrantResolver
	switch backend {
	case "postgres":
		if opts.DatabaseURL == "" {
			return fmt.Errorf("CRABEDENCE_STORE_BACKEND=postgres requires CRABEDENCE_DATABASE_URL")
		}
		db, err := sql.Open("pgx", opts.DatabaseURL)
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
		path := os.Getenv("CRABEDENCE_STORE_PATH")
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
		keyPath := os.Getenv("CRABBOX_EVIDENCE_KEY")
		if err := validateEvidenceKeyPolicy(keyPath); err != nil {
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
		trusted := []string{signer.Fingerprint()}
		if extra := os.Getenv("CRABBOX_EVIDENCE_TRUSTED_SIGNERS"); extra != "" {
			for _, fp := range strings.Split(extra, ",") {
				fp = strings.TrimSpace(fp)
				if fp == "" {
					continue
				}
				// A malformed fingerprint is never a plausible signer —
				// silently dropping it would quietly shrink the trusted
				// set, so refuse to start instead.
				if !isSHA256Hex(fp) {
					return fmt.Errorf("CRABBOX_EVIDENCE_TRUSTED_SIGNERS entry %q is not a SHA-256 fingerprint (64 lowercase hex chars)", fp)
				}
				trusted = append(trusted, fp)
			}
		}
		store.SetTrustedEvidenceSigners(trusted...)
	}

	// Create a multi-handler that dispatches based on adapter ID
	// If we have a durable store, wrap it in a DispatchExecutor
	var handler Handler
	var durable Handler
	handlers := map[string]Handler{
		"system":       echoHandler,
		"test-counter": counterHandler,
		"system-info":  infoHandler,
	}
	if githubHandler != nil {
		handlers["github"] = githubHandler
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
	knownAdapters := make(map[string]bool, len(handlers))
	for adapterID := range handlers {
		knownAdapters[adapterID] = true
	}
	if err := registry.ValidateAdapters(knownAdapters); err != nil {
		return err
	}
	report, err := registry.Report()
	if err != nil {
		return fmt.Errorf("capability registry report failed: %w", err)
	}
	fmt.Fprint(os.Stderr, report.String())

	if store != nil {
		// Use DispatchExecutor for durable idempotency
		executor := NewDispatchExecutor(multiHandler, store)
		executor.SetEvidenceSigner(signer)
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

	// Wire production authority: PostgreSQL-backed grant resolution.
	// Without this, the service defaults to NoopGrantResolver which
	// denies all grant-required capabilities in production.
	if authorityStore != nil {
		service.SetGrantResolver(authorityStore)
	}

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start reconciliation worker if enabled.
	// Register capability-specific resolvers for each provider that
	// supports recovery. The default resolver is NoopResolver (fail-
	// closed: UNKNOWN stays UNKNOWN unless a resolver proves otherwise).
	if store != nil && opts.ReconcileInterval > 0 {
		worker := reconcile.NewWorker(store, reconcile.NoopResolver{}, durationSeconds(opts.ReconcileInterval))
		worker.RegisterResolver("test.counter.increment", counterHandler)
		if githubHandler != nil {
			worker.RegisterResolver("github.issue.create", githubHandler)
		}
		worker.SetEvidenceSigner(signer)
		go worker.Run(ctx)
	}

	// Start service
	if err := service.Start(ctx); err != nil {
		return fmt.Errorf("failed to start execution service: %w", err)
	}
	defer service.Stop()

	fmt.Fprintf(os.Stderr, "Crabedence execution service listening on %s\n", opts.SocketPath)
	fmt.Fprintf(os.Stderr, "Registered capabilities: %v\n", registry.List())
	if store != nil {
		fmt.Fprintf(os.Stderr, "Durable idempotency: enabled (%s)\n", backend)
	} else {
		fmt.Fprintf(os.Stderr, "Durable idempotency: disabled (MUTATION/CRITICAL will fail closed)\n")
	}

	// Wait for signal or context cancellation
	select {
	case <-sigCh:
		fmt.Fprintln(os.Stderr, "Shutting down...")
	case <-ctx.Done():
	}

	return nil
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

// replicatedDeployment reports whether the operator declared a
// multi-replica topology via CRABBOX_REPLICAS > 1. Replicated mode
// tightens evidence-key requirements — a cryptographic cluster
// identity must never be accidentally host-local.
func replicatedDeployment() bool {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("CRABBOX_REPLICAS")))
	return err == nil && n > 1
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
// for deployment modes that must never auto-generate a signer:
// multi-replica (CRABBOX_REPLICAS > 1) and production
// (CRABBOX_MODE=production). Both require CRABBOX_EVIDENCE_KEY to
// point at an existing provisioned key; auto-creation remains
// available in single-node development mode.
func validateEvidenceKeyPolicy(keyPath string) error {
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
