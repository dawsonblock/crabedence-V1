package execution

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
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
	DatabaseURL       string // PostgreSQL connection string for durable idempotency
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
// Uses XDG_RUNTIME_DIR if available, falls back to a 0700 directory.
func defaultSocketPath() string {
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		dir := xdg + "/crabedence"
		os.MkdirAll(dir, 0o700)
		return dir + "/execution.sock"
	}
	// Fallback: create a private directory in /tmp with 0700 permissions
	dir := "/tmp/crabedence-" + os.Getenv("USER")
	os.MkdirAll(dir, 0o700)
	return dir + "/execution.sock"
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
	githubEnabled := os.Getenv("CRABBOX_GITHUB_ENABLED") == "true" || githubToken != ""
	var githubHandler *GitHubIssueHandler
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
	}

	// Create handlers
	echoHandler := NewEchoHandler()
	counterHandler := NewCounterHandler()
	infoHandler := NewSystemInfoHandler()

	// Connect to PostgreSQL for durable idempotency and authority
	var store *idempotency.Store
	var authorityStore *authority.Store
	if opts.DatabaseURL != "" {
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
	var signer *evidence.Signer
	if store != nil {
		keyPath := os.Getenv("CRABBOX_EVIDENCE_KEY")
		if keyPath == "" {
			var err error
			keyPath, err = evidenceKeyPath()
			if err != nil {
				return fmt.Errorf("failed to resolve evidence key path: %w", err)
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
				if fp = strings.TrimSpace(fp); fp != "" {
					trusted = append(trusted, fp)
				}
			}
		}
		store.SetTrustedEvidenceSigners(trusted...)
	}

	// Create a multi-handler that dispatches based on adapter ID
	// If we have a durable store, wrap it in a DispatchExecutor
	var handler Handler
	handlers := map[string]Handler{
		"system":       echoHandler,
		"test-counter": counterHandler,
		"system-info":  infoHandler,
	}
	if githubHandler != nil {
		handlers["github"] = githubHandler
	}
	multiHandler := NewMultiHandler(handlers)

	if store != nil {
		// Use DispatchExecutor for durable idempotency
		executor := NewDispatchExecutor(multiHandler, store)
		executor.SetEvidenceSigner(signer)
		handler = executor
	} else {
		// No store — fail closed for MUTATION/CRITICAL
		handler = NewFailClosedHandler(multiHandler)
	}

	service := NewService(registry, handler, opts.SocketPath)

	// Wire production authority: PostgreSQL-backed grant resolution.
	// Without this, the service defaults to NoopGrantResolver which
	// denies all grant-required capabilities in production.
	if authorityStore != nil {
		service.SetGrantResolver(authorityStore)
	}

	// Ensure socket directory has restrictive permissions
	if dir := filepath.Dir(opts.SocketPath); dir != "" && dir != "." {
		os.MkdirAll(dir, 0o700)
		os.Chmod(dir, 0o700)
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
		fmt.Fprintf(os.Stderr, "Durable idempotency: enabled (PostgreSQL)\n")
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
