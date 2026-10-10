// Command qual-provider runs the external CRITICAL qualification
// provider as a real process — the deployed-provider tier of the
// staging proofs (proof 09). It serves the same HTTP API the test
// harness uses (internal/qualprovider): POST /operations, operation
// lookup, immutable artifacts, stats — with its own durable ledger in
// the state directory, so executor death cannot erase provider truth.
//
// It is a qualification component, not a production capability: it is
// unauthenticated by design and refuses to start on anything but a
// loopback listen address.
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
	"sync"
	"syscall"
	"time"

	"github.com/openclaw/crabbox/internal/qualprovider"
)

// DefaultMaxConnections bounds the simultaneously served connections.
// Further connections are refused (closed) rather than queued without
// limit.
const DefaultMaxConnections = 64

func main() {
	var (
		dir      = flag.String("dir", "", "state directory for the durable ledger and artifacts (required)")
		listen   = flag.String("listen", "127.0.0.1:0", "listen address; must be loopback — the provider refuses anything else")
		addrFile = flag.String("addr-file", "", "if set, write the bound address to this file (0600) once listening")
		maxConns = flag.Int("max-connections", DefaultMaxConnections, "maximum simultaneously served connections; further connections are refused")
	)
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "qual-provider: --dir is required")
		flag.Usage()
		os.Exit(2)
	}
	if *maxConns < 1 {
		fmt.Fprintf(os.Stderr, "qual-provider: --max-connections must be at least 1, got %d\n", *maxConns)
		os.Exit(2)
	}
	if err := validateListenAddress(*listen); err != nil {
		fmt.Fprintf(os.Stderr, "qual-provider: %v\n", err)
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
	if err := verifyLoopbackListener(ln); err != nil {
		ln.Close()
		fmt.Fprintf(os.Stderr, "qual-provider: %v\n", err)
		os.Exit(1)
	}
	ln = &boundedListener{Listener: ln, slots: make(chan struct{}, *maxConns)}
	if *addrFile != "" {
		if err := os.WriteFile(*addrFile, []byte(ln.Addr().String()), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "qual-provider: write addr file: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Fprintf(os.Stderr, "qual-provider: serving %s (state dir %s, max %d connections)\n", ln.Addr(), *dir, *maxConns)

	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
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

// validateListenAddress refuses any --listen value that could expose the
// provider off-host. The provider is unauthenticated by design, so a
// non-loopback bind is a misdeployment, not a preference.
func validateListenAddress(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("--listen %q: %v (want host:port with a loopback host)", addr, err)
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return fmt.Errorf("--listen %q: invalid port %q", addr, port)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("--listen %q: host %q is not a loopback IP or localhost", addr, host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("--listen %q: %s is not a loopback address — the qualification provider must never be exposed off-host", addr, ip)
	}
	return nil
}

// verifyLoopbackListener double-checks the address actually bound, so a
// host-name resolution or platform quirk cannot smuggle a non-loopback
// bind past the flag check.
func verifyLoopbackListener(ln net.Listener) error {
	tcp, ok := ln.Addr().(*net.TCPAddr)
	if !ok || tcp.IP == nil || !tcp.IP.IsLoopback() {
		return fmt.Errorf("refusing to serve on non-loopback address %s", ln.Addr())
	}
	return nil
}

// boundedListener caps simultaneously served connections. A connection
// accepted at the ceiling is closed immediately — an explicit refusal
// rather than unbounded work — and the accept loop backs off briefly so
// a connection flood cannot spin a core.
type boundedListener struct {
	net.Listener
	slots chan struct{}
}

func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &slottedConn{Conn: conn, release: func() { <-l.slots }}, nil
		default:
			conn.Close()
			time.Sleep(5 * time.Millisecond)
		}
	}
}

// slottedConn releases its listener slot exactly once, when the
// connection closes.
type slottedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *slottedConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}
