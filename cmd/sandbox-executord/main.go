// Command sandbox-executord is the isolated execution sidecar: a
// bounded Unix socket that accepts job submissions only from
// kernel-verified peer identities carrying the shared submission
// token. It runs as a dedicated unprivileged identity with an isolated
// HOME and no ambient credentials — and holds no authority keys, so
// compromising it cannot mint admissions or rewrite evidence.
//
// Flags:
//
//	-socket-dir   owner-only directory for executor.sock (required)
//	-peer-uids    comma-separated uid:submitter allowlist (required)
//	-token-file   shared-secret file (0600, owner-only; optional —
//	              its absence is reported, not silent)
//
// The daemon logs every admission decision to stderr. PR-03 accepts
// and records submissions; the signed job contract (PR-04) and the
// actual execution backend (PR-05) are later gates.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/openclaw/crabbox/internal/sandboxexecutor"
)

func main() {
	socketDir := flag.String("socket-dir", os.Getenv("SANDBOX_EXECUTOR_SOCKET_DIR"), "owner-only directory for executor.sock (or SANDBOX_EXECUTOR_SOCKET_DIR)")
	peerUIDs := flag.String("peer-uids", os.Getenv("SANDBOX_EXECUTOR_PEER_UIDS"), "comma-separated uid:submitter allowlist (or SANDBOX_EXECUTOR_PEER_UIDS)")
	tokenFile := flag.String("token-file", os.Getenv("SANDBOX_EXECUTOR_TOKEN_FILE"), "0600 owner-only shared-secret file (or SANDBOX_EXECUTOR_TOKEN_FILE)")
	flag.Parse()

	peers, err := sandboxexecutor.ParsePeerAllowlist(*peerUIDs)
	if err != nil {
		log.Fatalf("sandbox-executord: %v", err)
	}
	var token *sandboxexecutor.SubmissionToken
	if *tokenFile != "" {
		token, err = sandboxexecutor.LoadSubmissionToken(*tokenFile)
		if err != nil {
			log.Fatalf("sandbox-executord: %v", err)
		}
	}

	srv, err := sandboxexecutor.NewServer(sandboxexecutor.Config{
		SocketDir: *socketDir,
		Peers:     peers,
		Token:     token,
		Audit:     func(format string, args ...any) { log.Printf(format, args...) },
	})
	if err != nil {
		log.Fatalf("sandbox-executord: %v", err)
	}
	if err := srv.Start(); err != nil {
		log.Fatalf("sandbox-executord: %v", err)
	}
	fmt.Fprintf(os.Stderr, "sandbox-executord ready on %s\n", srv.SocketPath())

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sig:
	case <-srv.Done():
	}
	if err := srv.Stop(); err != nil {
		log.Fatalf("sandbox-executord: stop: %v", err)
	}
}
