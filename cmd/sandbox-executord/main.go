// Command sandbox-executord is the isolated execution sidecar: a
// bounded Unix socket that accepts job submissions only from
// kernel-verified peer identities carrying the shared submission
// token — and, when authority keys are configured, a valid
// Ed25519-signed SandboxJobV2 contract. It runs as a dedicated
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
//	-msb-version     pinned Microsandbox runtime version the adapter
//	                 is qualified against (default 0.7.8); a runtime
//	                 that is not the pinned version refuses startup —
//	                 the runtime-owned job protocol is what makes a
//	                 guest exit event observable independently of any
//	                 CLI process exit code, and that semantics is
//	                 version-qualified, never assumed
//	-msb-deployment-profile
//	                 host-runtime isolation profile every sandbox
//	                 boots under (default single-tenant); the booted
//	                 configuration must carry exactly this profile,
//	                 and the host's own prerequisite check (msb
//	                 doctor) must pass — an executor that cannot
//	                 prove its host is supported refuses to run
//	                 rather than downgrading the isolation it was
//	                 configured for
//	-msb-pull        image fetch policy: never (default — the pinned
//	                 image must be present locally, and a missing one
//	                 refuses fast instead of fetching mid-dispatch) or
//	                 if-missing
//	-state-dir       artifact directory for captured output (defaults
//	                 to <socket-dir>/artifacts)
//	-ledger          durable job ledger path (defaults to
//	                 <socket-dir>/executor-ledger.db)
//	-max-conns       simultaneous connection bound (default 64)
//	-dispatch-timeout bound on one backend launch call (default 45s)
//	-contract-max-ttl bound on contract validity window (default 1h,
//	                 negative disables)
//	-ceil-cpus/-ceil-memory-mb/-ceil-disk-mb/-ceil-output-bytes/-ceil-timeout-secs
//	                 operator resource ceilings for contracts
//	-pool-vms/-pool-submitter-vms/-pool-cpus/-pool-memory-mb/-pool-disk-mb/-pool-output-bytes
//	                 aggregate bounds across all in-flight jobs; a
//	                 configured dimension requires every contract to
//	                 declare it (undeclared refuses rather than
//	                 counting as free)
//	-evidence-dir    execution-evidence chain directory: receipts,
//	                 signed checkpoints and the evidence signer key
//	                 (defaults to <socket-dir>/evidence). Every
//	                 terminal job emits a signed receipt before its
//	                 ledger transition; checkpoints commit to the
//	                 durable terminal enumeration so deletion, rewrite
//	                 or rollback is independently detectable.
//	-evidence-key    evidence signer PKCS8 PEM (defaults to
//	                 <evidence-dir>/executor-evidence.pem, created
//	                 durably if absent). It attests outcomes — it can
//	                 never authorize jobs.
//
// The daemon logs every admission decision to stderr, including the
// evidence signer fingerprint an operator should pin for verifiers.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/openclaw/crabbox/internal/sandboxexecutor"
)

// lastLine returns the final non-empty line of a diagnostic block —
// the startup report wants the verdict, not the whole checklist.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if line := strings.TrimSpace(lines[i]); line != "" {
			return line
		}
	}
	return ""
}

func main() {
	socketDir := flag.String("socket-dir", os.Getenv("SANDBOX_EXECUTOR_SOCKET_DIR"), "owner-only directory for executor.sock (or SANDBOX_EXECUTOR_SOCKET_DIR)")
	peerUIDs := flag.String("peer-uids", os.Getenv("SANDBOX_EXECUTOR_PEER_UIDS"), "comma-separated uid:submitter allowlist (or SANDBOX_EXECUTOR_PEER_UIDS)")
	tokenFile := flag.String("token-file", os.Getenv("SANDBOX_EXECUTOR_TOKEN_FILE"), "0600 owner-only shared-secret file (or SANDBOX_EXECUTOR_TOKEN_FILE)")
	pubkeyFile := flag.String("job-pubkey-file", os.Getenv("SANDBOX_EXECUTOR_JOB_PUBKEY_FILE"), "0600 owner-only authority public-key trust file (or SANDBOX_EXECUTOR_JOB_PUBKEY_FILE)")
	backendName := flag.String("backend", os.Getenv("SANDBOX_EXECUTOR_BACKEND"), "execution backend: \"\" or \"microsandbox\" (or SANDBOX_EXECUTOR_BACKEND)")
	msbBin := flag.String("msb-bin", os.Getenv("SANDBOX_EXECUTOR_MSB_BIN"), "path to the msb binary (or SANDBOX_EXECUTOR_MSB_BIN)")
	msbVersion := flag.String("msb-version", sandboxexecutor.PinnedMSBVersion, "pinned Microsandbox runtime version the adapter is qualified against")
	msbProfile := flag.String("msb-deployment-profile", sandboxexecutor.DeploymentSingleTenant, "host-runtime isolation profile every sandbox boots under (single-tenant or multi-tenant)")
	msbPull := flag.String("msb-pull", "never", "image fetch policy for the microsandbox backend: never (require the pinned image locally) or if-missing")
	stateDir := flag.String("state-dir", os.Getenv("SANDBOX_EXECUTOR_STATE_DIR"), "artifact directory for captured output (or SANDBOX_EXECUTOR_STATE_DIR)")
	ledgerPath := flag.String("ledger", os.Getenv("SANDBOX_EXECUTOR_LEDGER"), "durable job ledger path (or SANDBOX_EXECUTOR_LEDGER)")
	maxConns := flag.Int("max-conns", 0, "simultaneous connection bound (default 64)")
	dispatchTimeout := flag.Duration("dispatch-timeout", 0, "bound on one backend launch call (default 45s)")
	contractMaxTTL := flag.Duration("contract-max-ttl", 0, "bound on contract validity window (default 1h; negative disables)")
	ceilCPUs := flag.Float64("ceil-cpus", 0, "contract cpus ceiling (0 = no operator ceiling)")
	ceilMemMB := flag.Uint64("ceil-memory-mb", 0, "contract memory_mb ceiling (0 = no operator ceiling)")
	ceilDiskMB := flag.Uint64("ceil-disk-mb", 0, "contract disk_mb ceiling (0 = no operator ceiling)")
	ceilOutput := flag.Uint64("ceil-output-bytes", 0, "contract max_output_bytes ceiling (0 = no operator ceiling)")
	ceilTimeout := flag.Uint("ceil-timeout-secs", 0, "contract timeout_seconds ceiling (0 = no operator ceiling)")
	poolVMs := flag.Int("pool-vms", 0, "aggregate bound on concurrent VMs (0 = unbounded)")
	poolSubmitterVMs := flag.Int("pool-submitter-vms", 0, "aggregate bound on concurrent VMs per submitter (0 = unbounded)")
	poolCPUs := flag.Float64("pool-cpus", 0, "aggregate bound on declared cpus (0 = unbounded)")
	poolMemMB := flag.Uint64("pool-memory-mb", 0, "aggregate bound on declared memory in MiB (0 = unbounded)")
	poolDiskMB := flag.Uint64("pool-disk-mb", 0, "aggregate bound on declared disk in MiB (0 = unbounded)")
	poolOutput := flag.Uint64("pool-output-bytes", 0, "aggregate bound on declared output in bytes (0 = unbounded)")
	evidenceDir := flag.String("evidence-dir", os.Getenv("SANDBOX_EXECUTOR_EVIDENCE_DIR"), "execution-evidence chain directory (or SANDBOX_EXECUTOR_EVIDENCE_DIR)")
	evidenceKey := flag.String("evidence-key", os.Getenv("SANDBOX_EXECUTOR_EVIDENCE_KEY"), "evidence signer PKCS8 PEM path (or SANDBOX_EXECUTOR_EVIDENCE_KEY)")
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
		if *msbPull != sandboxexecutor.PullNever && *msbPull != sandboxexecutor.PullIfMissing {
			log.Fatalf("sandbox-executord: -msb-pull must be %q or %q, got %q",
				sandboxexecutor.PullNever, sandboxexecutor.PullIfMissing, *msbPull)
		}
		artifacts := *stateDir
		if artifacts == "" {
			artifacts = filepath.Join(*socketDir, "artifacts")
		}
		mb := &sandboxexecutor.MSBBackend{
			Bin: bin, StateDir: artifacts, PullPolicy: *msbPull,
			RequiredVersion: *msbVersion, DeploymentProfile: *msbProfile,
		}
		// The pinned runtime is part of the execution policy: the
		// adapter's structured-observation semantics are qualified
		// against one runtime version, so a different one refuses
		// startup instead of silently degrading how results are
		// observed.
		verifyCtx, verifyCancel := context.WithTimeout(context.Background(), 30*time.Second)
		got, verr := mb.VerifyRuntime(verifyCtx)
		verifyCancel()
		if verr != nil {
			log.Fatalf("sandbox-executord: %v", verr)
		}
		log.Printf("sandbox-executord: microsandbox runtime %s verified at %s", got, bin)
		// The host confinement profile is the other half of the
		// policy: an unsupported host refuses startup rather than
		// running without the isolation the executor promises.
		hostCtx, hostCancel := context.WithTimeout(context.Background(), 60*time.Second)
		hostOut, herr := mb.VerifyHost(hostCtx)
		hostCancel()
		if herr != nil {
			log.Fatalf("sandbox-executord: %v", herr)
		}
		log.Printf("sandbox-executord: host confinement verified (%s; profile %s)", lastLine(hostOut), *msbProfile)
		backend = mb
	default:
		log.Fatalf("sandbox-executord: unknown backend %q (want \"\" or \"microsandbox\")", *backendName)
	}

	var ceiling *sandboxexecutor.ResourceBudget
	if *ceilCPUs > 0 || *ceilMemMB > 0 || *ceilDiskMB > 0 || *ceilOutput > 0 || *ceilTimeout > 0 {
		ceiling = &sandboxexecutor.ResourceBudget{
			CPUs:           *ceilCPUs,
			MemoryMB:       *ceilMemMB,
			DiskMB:         *ceilDiskMB,
			MaxOutputBytes: *ceilOutput,
			TimeoutSeconds: uint32(*ceilTimeout),
		}
	}

	// The aggregate pool bounds what all in-flight jobs may consume
	// together; a configured dimension also requires every contract
	// to declare it, so an agent can never consume more than its
	// authorization names.
	var pool *sandboxexecutor.ResourcePool
	if *poolVMs > 0 || *poolSubmitterVMs > 0 || *poolCPUs > 0 || *poolMemMB > 0 || *poolDiskMB > 0 || *poolOutput > 0 {
		pool = &sandboxexecutor.ResourcePool{
			MaxConcurrentVMs: *poolVMs,
			MaxSubmitterVMs:  *poolSubmitterVMs,
			TotalCPUs:        *poolCPUs,
			TotalMemoryMB:    *poolMemMB,
			TotalDiskMB:      *poolDiskMB,
			TotalOutputBytes: *poolOutput,
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
		ResourcePool:    pool,
		EvidenceDir:     *evidenceDir,
		EvidenceKeyPath: *evidenceKey,
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
