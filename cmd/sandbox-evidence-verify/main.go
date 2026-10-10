// sandbox-evidence-verify independently verifies a sandbox-executord
// execution-evidence chain against its ledger — the check an operator
// (or anyone holding the checkpoint files) runs OFF the executor host:
//
//	sandbox-evidence-verify -ledger /path/executor-ledger.db \
//	    -evidence-dir /path/evidence -trusted-signer <fingerprint>
//
// What it proves:
//   - every receipt parses strictly, is signed by a trusted evidence
//     signer, and binds exactly the ledger row it describes;
//   - every terminal ledger row has a receipt and every receipt a
//     terminal row — evidence gaps and orphan attestations are both
//     loud;
//   - the latest signed checkpoint still covers the terminal
//     enumeration — deleted, rewritten, reordered or rolled-back
//     records break the chain digest;
//   - every recorded artifact digest still matches the bytes on disk.
//
// The tool opens the ledger READ-ONLY: no flock, no epoch bump, no
// reconcile — a verifier must never mutate the store it checks.
// A nonzero exit is a finding, not a crash.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	sx "github.com/openclaw/crabbox/internal/sandboxexecutor"
)

func main() {
	var (
		ledgerPath    = flag.String("ledger", "", "executor ledger path (opened read-only)")
		evidenceDir   = flag.String("evidence-dir", "", "evidence directory holding receipts.jsonl and checkpoints/")
		trustedSigner = flag.String("trusted-signer", "", "comma-separated evidence signer fingerprints to trust (required)")
		checkpoint    = flag.String("checkpoint", "", "specific checkpoint file (default: the highest record_count)")
	)
	flag.Parse()

	if *ledgerPath == "" || *evidenceDir == "" || *trustedSigner == "" {
		fmt.Fprintln(os.Stderr, "usage: -ledger, -evidence-dir and -trusted-signer are required")
		os.Exit(2)
	}
	trusted := map[string]bool{}
	for _, fp := range strings.Split(*trustedSigner, ",") {
		if fp = strings.TrimSpace(fp); fp != "" {
			trusted[fp] = true
		}
	}

	rep := sx.VerifyEvidenceDir(*ledgerPath, *evidenceDir, *checkpoint, trusted)
	if len(rep.Failures) == 0 {
		fmt.Printf("OK: %d receipts verified, %d terminal records covered by checkpoint %d, %d artifacts re-hashed\n",
			rep.Receipts, rep.TerminalRows, rep.CheckpointCount, rep.Artifacts)
		return
	}
	for _, f := range rep.Failures {
		fmt.Fprintln(os.Stderr, "  FAIL", f)
	}
	fmt.Fprintf(os.Stderr, "FAILED: %d evidence problem(s) found\n", len(rep.Failures))
	os.Exit(1)
}
