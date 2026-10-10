// Command sandbox-executord is the isolated execution sidecar: a
// bounded Unix socket that accepts job submissions only from
// kernel-verified peer identities carrying the shared submission
// token — and, when authority keys are configured, a valid
// Ed25519-signed SandboxJobV1 contract. It runs as a dedicated
// unprivileged identity with an isolated HOME and no ambient
// credentials — and holds no signing keys, so compromising it cannot
// mint admissions or rewrite evidence.
//
// Every admitted job is persisted to a fenced SQLite ledger before
// dispatch: a crash cannot erase an acknowledged job identity, and an
// uncertain dispatch is reconciled as ambiguous — never re-launched
// blind.
//
// Flags:
//
//	-socket-dir      owner-only directory for executor.sock (required)
//	-peer-uids       comma-separated uid:submitter allowlist (required)
//	-token-file      shared-secret file (0600, owner-only; optional —
//	                 its absence is reported, not silent)
//	-job-pubkey-file authority public-key trust file (0600; each line
//	                 "fingerprint:base64-pubkey" or bare base64 key —
//	                 configuring it makes signed contracts mandatory)
//	-backend         execution backend: "" (record only) or
//	                 "microsandbox" (requires -job-pubkey-file)
//	-msb-bin         path to the msb binary (microsandbox backend)
//	-state-dir       artifact directory for captured output (defaults
//	                 to <socket-dir>/artifacts)
//	-ledger          durable job ledger path (defaults to
//	                 <socket-dir>/executor-ledger.db)
//	-max-conns       simultaneous connection bound (default 64)
//	-dispatch-timeout bound on one backend launch call (default 45s)
//	-contract-max-ttl bound on contract validity window (default 1h,
//	                 negative disables)
//	-ceil-cpus/-ceil-memory-mb/-ceil-timeout-secs
//	                 operator resource ceilings for contracts
//
// The daemon logs every admission decision to stderr.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/openclaw/crabbox/internal/sandboxexecutor"
)

func main() {
	socketDir := flag.String("socket-dir", os.Getenv("SANDBOX_EXECUTOR_SOCKET_DIR"), "owner-only directory for executor.sock (or SANDBOX_EXECUTOR_SOCKET_DIR)")
	peerUIDs := flag.String("peer-uids", os.Getenv("SANDBOX_EXECUTOR_PEER_UIDS"), "comma-separated uid:submitter allowlist (or SANDBOX_EXECUTOR_PEER_UIDS)")
	tokenFile := flag.String("token-file", os.Getenv("SANDBOX_EXECUTOR_TOKEN_FILE"), "0600 owner-only shared-secret file (or SANDBOX_EXECUTOR_TOKEN_FILE)")
	pubkeyFile := flag.String("job-pubkey-file", os.Getenv("SANDBOX_EXECUTOR_JOB_PUBKEY_FILE"), "0600 owner-only authority public-key trust file (or SANDBOX_EXECUTOR_JOB_PUBKEY_FILE)")
	backendName := flag.String("backend", os.Getenv("SANDBOX_EXECUTOR_BACKEND"), "execution backend: \"\" or \"microsandbox\" (or SANDBOX_EXECUTOR_BACKEND)")
	msbBin := flag.String("msb-bin", os.Getenv("SANDBOX_EXECUTOR_MSB_BIN"), "path to the msb binary (or SANDBOX_EXECUTOR_MSB_BIN)")
	stateDir := flag.String("state-dir", os.Getenv("SANDBOX_EXECUTOR_STATE_DIR"), "artifact directory for captured output (or SANDBOX_EXECUTOR_STATE_DIR)")
	ledgerPath := flag.String("ledger", os.Getenv("SANDBOX_EXECUTOR_LEDGER"), "durable job ledger path (or SANDBOX_EXECUTOR_LEDGER)")
	maxConns := flag.Int("max-conns", 0, "simultaneous connection bound (default 64)")
	dispatchTimeout := flag.Duration("dispatch-timeout", 0, "bound on one backend launch call (default 45s)")
	contractMaxTTL := flag.Duration("contract-max-ttl", 0, "bound on contract validity window (default 1h; negative disables)")
	ceilCPUs := flag.Float64("ceil-cpus", 0, "contract cpus ceiling (0 = no operator ceiling)")
	ceilMemMB := flag.Uint64("ceil-memory-mb", 0, "contract memory_mb ceiling (0 = no operator ceiling)")
	ceilTimeout := flag.Uint("ceil-timeout-secs", 0, "contract timeout_seconds ceiling (0 = no operator ceiling)")
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
	var keys sandboxexecutor.AuthorityKeys
	if *pubkeyFile != "" {
		keys, err = sandboxexecutor.LoadAuthorityKeys(*pubkeyFile)
		if err != nil {
			log.Fatalf("sandbox-executord: %v", err)
		}
	}

	// The dependency chain is mandatory: a real backend executes only
	// what a signed contract authorizes. Configuring a backend with
	// no trust set is refused here and again inside NewServer.
	var backend sandboxexecutor.Backend
	switch *backendName {
	case "":
	case "microsandbox":
		if len(keys) == 0 {
			log.Fatalf("sandbox-executord: -backend=microsandbox requires -job-pubkey-file — unsigned jobs must never reach execution")
		}
		bin := *msbBin
		if bin == "" {
			bin = filepath.Join(os.Getenv("HOME"), ".microsandbox", "bin", "msb")
		}
		if st, err := os.Stat(bin); err != nil || st.IsDir() {
			log.Fatalf("sandbox-executord: msb binary not found at %s — pass -msb-bin", bin)
		}
		artifacts := *stateDir
		if artifacts == "" {
			artifacts = filepath.Join(*socketDir, "artifacts")
		}
		backend = &sandboxexecutor.MSBBackend{Bin: bin, StateDir: artifacts}
	default:
		log.Fatalf("sandbox-executord: unknown backend %q (want \"\" or \"microsandbox\")", *backendName)
	}

	var ceiling *sandboxexecutor.ResourceBudget
	if *ceilCPUs > 0 || *ceilMemMB > 0 || *ceilTimeout > 0 {
		ceiling = &sandboxexecutor.ResourceBudget{
			CPUs:           *ceilCPUs,
			MemoryMB:       *ceilMemMB,
			TimeoutSeconds: uint32(*ceilTimeout),
		}
	}

	srv, err := sandboxexecutor.NewServer(sandboxexecutor.Config{
		SocketDir:       *socketDir,
		Peers:           peers,
		Token:           token,
		AuthorityKeys:   keys,
		Backend:         backend,
		LedgerPath:      *ledgerPath,
		MaxConns:        *maxConns,
		DispatchTimeout: *dispatchTimeout,
		MaxContractTTL:  *contractMaxTTL,
		ResourceCeiling: ceiling,
		Audit:           func(format string, args ...any) { log.Printf(format, args...) },
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
