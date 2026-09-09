package cli

import (
	"context"
	"os"

	"github.com/openclaw/crabbox/internal/execution"
)

// serveExecCommand implements `crabbox serve-execution`: starts the
// persistent Go execution service on a Unix socket.
//
// The database URL for durable idempotency is read from the
// CRABEDENCE_DATABASE_URL environment variable. If unset,
// MUTATION/CRITICAL operations fail closed (no unguarded mutations).
func (a App) serveExecCommand(ctx context.Context, socketPath string) error {
	return execution.Serve(ctx, execution.ServeOptions{
		SocketPath:        socketPath,
		DatabaseURL:       os.Getenv("CRABEDENCE_DATABASE_URL"),
		ReconcileInterval: 30,
	})
}
