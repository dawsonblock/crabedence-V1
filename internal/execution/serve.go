package execution

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
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

	// Create handlers
	echoHandler := NewEchoHandler()
	counterHandler := NewCounterHandler()
	infoHandler := NewSystemInfoHandler()

	// Connect to PostgreSQL for durable idempotency
	var store *idempotency.Store
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
	}

	// Create a multi-handler that dispatches based on adapter ID
	// If we have a durable store, wrap it in a DispatchExecutor
	var handler Handler
	multiHandler := NewMultiHandler(map[string]Handler{
		"system":       echoHandler,
		"test-counter": counterHandler,
		"system-info":  infoHandler,
	})

	if store != nil {
		// Use DispatchExecutor for durable idempotency
		handler = NewDispatchExecutor(multiHandler, store)
	} else {
		// No store — fail closed for MUTATION/CRITICAL
		handler = NewFailClosedHandler(multiHandler)
	}

	service := NewService(registry, handler, opts.SocketPath)

	// Ensure socket directory has restrictive permissions
	if dir := filepathDir(opts.SocketPath); dir != "" {
		os.Chmod(dir, 0o700)
	}

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start reconciliation worker if enabled
	if store != nil && opts.ReconcileInterval > 0 {
		worker := reconcile.NewWorker(store, reconcile.NoopResolver{}, durationSeconds(opts.ReconcileInterval))
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

// filepathDir returns the directory portion of a path.
func filepathDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			if i == 0 {
				return "/"
			}
			return path[:i]
		}
	}
	return "."
}

// durationSeconds converts an int64 to a time.Duration.
func durationSeconds(s int64) time.Duration {
	return time.Duration(s) * time.Second
}
