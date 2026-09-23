// Command qual-provider runs the external CRITICAL qualification
// provider as a real process — the deployed-provider tier of the
// staging proofs (proof 09). It serves the same HTTP API the test
// harness uses (internal/qualprovider): POST /operations, operation
// lookup, immutable artifacts, stats — with its own durable ledger in
// the state directory, so executor death cannot erase provider truth.
//
// It is a qualification component, not a production capability: deploy
// it only on staging/qualification hosts, loopback-bound.
//
// Usage:
//
//	qual-provider --dir /var/lib/crabedence-qual --listen 127.0.0.1:9100
//	qual-provider --dir <dir> --addr-file <path>   # publish bound addr
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openclaw/crabbox/internal/qualprovider"
)

func main() {
	var (
		dir      = flag.String("dir", "", "state directory for the durable ledger and artifacts (required)")
		listen   = flag.String("listen", "127.0.0.1:0", "listen address (loopback by default; never expose this service off-host)")
		addrFile = flag.String("addr-file", "", "if set, write the bound address to this file (0600) once listening")
	)
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "qual-provider: --dir is required")
		flag.Usage()
		os.Exit(2)
	}

	srv, err := qualprovider.New(*dir, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "qual-provider: %v\n", err)
		os.Exit(1)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "qual-provider: listen %s: %v\n", *listen, err)
		os.Exit(1)
	}
	if *addrFile != "" {
		if err := os.WriteFile(*addrFile, []byte(ln.Addr().String()), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "qual-provider: write addr file: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Fprintf(os.Stderr, "qual-provider: serving %s (state dir %s)\n", ln.Addr(), *dir)

	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpSrv.Shutdown(shutdownCtx)
	}()
	if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "qual-provider: serve: %v\n", err)
		os.Exit(1)
	}
}
