package cli

import (
	"context"

	"github.com/openclaw/crabbox/internal/execution"
)

// serveExecCommand implements `crabbox serve-execution`: starts the
// persistent Go execution service on a Unix socket.
func (a App) serveExecCommand(ctx context.Context, socketPath string) error {
	return execution.Serve(ctx, execution.ServeOptions{
		SocketPath: socketPath,
	})
}
