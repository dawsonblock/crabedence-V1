package cli

import (
	"context"
	"os"

	"github.com/openclaw/crabbox/internal/execution"
)

// serveExecCommand implements `crabbox serve-execution`: starts the
// persistent Go execution service on a Unix socket.
//
// The durable store backend is selected by CRABEDENCE_STORE_BACKEND
// (sqlite|postgres|none|auto; default auto). SQLite — the default
// local backend — stores at CRABEDENCE_STORE_PATH (or the platform
// config dir). PostgreSQL uses CRABEDENCE_DATABASE_URL. With no store
// configured, MUTATION/CRITICAL operations fail closed (no unguarded
// mutations).
func (a App) serveExecCommand(ctx context.Context, socketPath string) error {
	return execution.Serve(ctx, execution.ServeOptions{
		SocketPath:        socketPath,
		DatabaseURL:       os.Getenv("CRABEDENCE_DATABASE_URL"),
		ReconcileInterval: 30,
		Release:           currentVersion(),
	})
}
