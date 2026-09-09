package execution

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/openclaw/crabbox/internal/capability"
)

// ServeOptions configures the execution service.
type ServeOptions struct {
	SocketPath string
}

// DefaultServeOptions returns sensible defaults.
func DefaultServeOptions() ServeOptions {
	return ServeOptions{
		SocketPath: "/tmp/crabedence-exec.sock",
	}
}

// Serve starts the persistent execution service.
// It registers built-in capabilities and listens on the Unix socket
// until the context is cancelled or a signal is received.
func Serve(ctx context.Context, opts ServeOptions) error {
	registry := capability.NewRegistry()

	// Register built-in capabilities
	if err := RegisterEchoCapability(registry); err != nil {
		return fmt.Errorf("failed to register system.echo: %w", err)
	}
	if err := RegisterCounterCapability(registry); err != nil {
		return fmt.Errorf("failed to register test.counter.increment: %w", err)
	}

	// Create a multi-handler that dispatches based on adapter ID
	handler := NewMultiHandler(map[string]Handler{
		"system":       NewEchoHandler(),
		"test-counter": NewCounterHandler(),
	})

	service := NewService(registry, handler, opts.SocketPath)

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start service
	if err := service.Start(ctx); err != nil {
		return fmt.Errorf("failed to start execution service: %w", err)
	}
	defer service.Stop()

	fmt.Fprintf(os.Stderr, "Crabedence execution service listening on %s\n", opts.SocketPath)
	fmt.Fprintf(os.Stderr, "Registered capabilities: %v\n", registry.List())

	// Wait for signal or context cancellation
	select {
	case <-sigCh:
		fmt.Fprintln(os.Stderr, "Shutting down...")
	case <-ctx.Done():
	}

	return nil
}

// MultiHandler dispatches to the appropriate handler based on adapter ID.
type MultiHandler struct {
	handlers map[string]Handler
}

// NewMultiHandler creates a handler that dispatches based on adapter ID.
func NewMultiHandler(handlers map[string]Handler) *MultiHandler {
	return &MultiHandler{handlers: handlers}
}

// Execute dispatches to the handler matching the descriptor's AdapterID.
func (m *MultiHandler) Execute(ctx context.Context, req Request, desc capability.Descriptor) Response {
	handler, ok := m.handlers[desc.AdapterID]
	if !ok {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureCapabilityUnimplemented),
			Error:       fmt.Sprintf("no handler for adapter: %s", desc.AdapterID),
		}
	}
	return handler.Execute(ctx, req, desc)
}
