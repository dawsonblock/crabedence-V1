// sandbox-custodyd is the external evidence-custody witness. It holds
// archive-segment payloads the executor releases its operational rows
// only after custody, and acknowledges each witnessed segment with a
// signature under the witness's own key in an append-only chain.
//
// Flags:
//
//	-socket-dir <dir>     owner-only directory for custody.sock
//	                      (or SANDBOX_CUSTODY_SOCKET_DIR)
//	-custody-dir <dir>    custody store: payloads + ack chain
//	                      (or SANDBOX_CUSTODY_DIR)
//	-key <path>           witness signer PKCS8 PEM, created if absent
//	                      (or SANDBOX_CUSTODY_KEY)
//	-token-file <path>    optional shared-secret file the executor must
//	                      present (or SANDBOX_CUSTODY_TOKEN_FILE)
//	-verify               audit the custody dir and exit (no daemon)
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/openclaw/crabbox/internal/sandboxcustody"
)

func main() {
	socketDir := flag.String("socket-dir", os.Getenv("SANDBOX_CUSTODY_SOCKET_DIR"), "owner-only directory for custody.sock (or SANDBOX_CUSTODY_SOCKET_DIR)")
	custodyDir := flag.String("custody-dir", os.Getenv("SANDBOX_CUSTODY_DIR"), "custody store directory (or SANDBOX_CUSTODY_DIR)")
	keyPath := flag.String("key", os.Getenv("SANDBOX_CUSTODY_KEY"), "witness signer PKCS8 PEM path (or SANDBOX_CUSTODY_KEY)")
	tokenFile := flag.String("token-file", os.Getenv("SANDBOX_CUSTODY_TOKEN_FILE"), "optional shared-secret file (or SANDBOX_CUSTODY_TOKEN_FILE)")
	trustFile := flag.String("trust-file", os.Getenv("SANDBOX_CUSTODY_TRUST_FILE"), "with -verify: custody trust root (JSON) — acknowledgements by unapproved witnesses are findings (or SANDBOX_CUSTODY_TRUST_FILE)")
	verify := flag.Bool("verify", false, "audit the custody dir and exit instead of running the daemon")
	flag.Parse()

	if *verify {
		if *custodyDir == "" {
			log.Fatalf("sandbox-custodyd: -verify requires -custody-dir")
		}
		var findings []string
		if *trustFile != "" {
			trust, terr := sandboxcustody.LoadTrustRoot(*trustFile)
			if terr != nil {
				log.Fatalf("sandbox-custodyd: %v", terr)
			}
			findings = sandboxcustody.VerifyCustodyDirTrusted(*custodyDir, trust)
		} else {
			findings = sandboxcustody.VerifyCustodyDir(*custodyDir)
		}
		if len(findings) > 0 {
			for _, f := range findings {
				fmt.Fprintf(os.Stderr, "custody finding: %s\n", f)
			}
			log.Fatalf("sandbox-custodyd: custody verification found %d problem(s)", len(findings))
		}
		fmt.Fprintf(os.Stderr, "custody verification: clean\n")
		return
	}

	var token string
	if *tokenFile != "" {
		raw, err := os.ReadFile(*tokenFile)
		if err != nil {
			log.Fatalf("sandbox-custodyd: %v", err)
		}
		token = strings.TrimSpace(string(raw))
	}

	srv, err := sandboxcustody.NewServer(sandboxcustody.Config{
		SocketDir:  *socketDir,
		CustodyDir: *custodyDir,
		KeyPath:    *keyPath,
		Token:      token,
		Audit:      func(format string, args ...any) { log.Printf(format, args...) },
	})
	if err != nil {
		log.Fatalf("sandbox-custodyd: %v", err)
	}
	if err := srv.Start(); err != nil {
		log.Fatalf("sandbox-custodyd: %v", err)
	}
	fmt.Fprintf(os.Stderr, "sandbox-custodyd ready on %s\n", srv.SocketPath())

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sig:
	case <-srv.Done():
	}
	if err := srv.Stop(); err != nil {
		log.Fatalf("sandbox-custodyd: stop: %v", err)
	}
}
