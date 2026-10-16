// sandbox-history is the unified-memory operator tool: it ingests
// the system's development record — git history, executor ledgers,
// evidence directories, custody stores, test streams, documents —
// into the append-only, hash-chained event store, and queries and
// verifies what it holds.
//
//	sandbox-history -db /path/history.db ingest-git /path/repo [range]
//	sandbox-history -db /path/history.db ingest-ledger /path/ledger.db
//	sandbox-history -db /path/history.db ingest-evidence /path/evidence [-trusted-signer fp,...]
//	sandbox-history -db /path/history.db ingest-custody /path/custody [-trusted-signer fp,...]
//	sandbox-history -db /path/history.db ingest-doc FILE...
//	sandbox-history -db /path/history.db ingest-teststream FILE [-label NAME]
//	sandbox-history -db /path/history.db ingest-conversations PATH
//	sandbox-history -db /path/history.db ingest-traces PATH
//	sandbox-history -db /path/history.db ingest-archive FILE
//	sandbox-history -db /path/history.db ingest-experiments PATH
//	sandbox-history -db /path/history.db ingest-recovery /path/ledger.db
//	sandbox-history -db /path/history.db query [-kind K] [-correlation C] [-limit N]
//	sandbox-history -db /path/history.db stats
//	sandbox-history -db /path/history.db verify
//	sandbox-history -db /path/history.db checkpoint DIR -witness-key KEY.pem
//	sandbox-history -db /path/history.db verify-checkpoint DIR [-trusted-signer fp,...]
//
// checkpoint asks an independent witness (its own key, held outside
// this store) to sign the current chain head into DIR; verify-checkpoint
// fetches the latest checkpoint from outside the database and fails
// when the store has rolled back below — or diverged from — the
// witnessed head. Witnessing proves what was committed; it cannot
// prove records nobody witnessed.
// Ingest commands are idempotent: every record carries a dedupe key
// derived from its source identity, so re-running an ingest appends
// only what is new. verify re-derives the entire event chain; a
// nonzero exit is a finding, not a crash.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/history"
	sx "github.com/openclaw/crabbox/internal/sandboxexecutor"
)

func main() {
	dbPath := flag.String("db", "", "history store path (required)")
	trusted := flag.String("trusted-signer", "", "comma-separated signer fingerprints to trust (ingest-evidence, ingest-custody)")
	ledger := flag.String("ledger", "", "ingest-evidence: executor ledger for full checkpoint verification")
	witnessKey := flag.String("witness-key", "", "checkpoint: witness signer key file (created if absent)")
	contentDir := flag.String("content-dir", "", "content-addressed object dir for source bytes (default <db>.content)")
	label := flag.String("label", "", "label for ingest-teststream")
	kind := flag.String("kind", "", "query/append: event kind filter")
	subject := flag.String("subject", "", "append: event subject")
	payload := flag.String("payload", "", "append: event payload (JSON)")
	dedupe := flag.String("dedupe", "", "append: explicit dedupe key")
	correlation := flag.String("correlation", "", "query/append: correlation key filter")
	limit := flag.Int("limit", 20, "query: max events")
	flag.Parse()

	args := flag.Args()
	if *dbPath == "" || len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sandbox-history -db PATH <ingest-git|ingest-ledger|ingest-evidence|ingest-custody|ingest-doc|ingest-teststream|query|stats|verify> [args]")
		os.Exit(2)
	}
	trustedSet := map[string]bool{}
	for _, fp := range strings.Split(*trusted, ",") {
		if fp = strings.TrimSpace(fp); fp != "" {
			trustedSet[fp] = true
		}
	}

	op := args[0]
	rest := args[1:]
	var s *history.Store
	var err error
	if op == "verify" || op == "query" || op == "stats" ||
		op == "verify-checkpoint" || op == "checkpoint" {
		s, err = history.OpenReadOnly(*dbPath)
	} else {
		s, err = history.OpenStore(*dbPath)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "open history:", err)
		os.Exit(1)
	}
	defer s.Close()

	switch op {
	case "ingest-git":
		if len(rest) < 1 {
			usage("ingest-git REPO_DIR [range]")
		}
		spec := ""
		if len(rest) > 1 {
			spec = rest[1]
		}
		n, err := s.IngestGit(context.Background(), rest[0], spec)
		done(n, err, "commits")

	case "ingest-ledger":
		if len(rest) != 1 {
			usage("ingest-ledger LEDGER.db")
		}
		l, err := sx.InspectLedger(rest[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "open ledger:", err)
			os.Exit(1)
		}
		defer l.Close()
		n, err := s.IngestJobs(l)
		done(n, err, "jobs")

	case "ingest-evidence":
		if len(rest) != 1 {
			usage("ingest-evidence EVIDENCE_DIR")
		}
		var refs []evidence.TerminalRef
		if *ledger != "" {
			l, err := sx.InspectLedger(*ledger)
			if err != nil {
				fmt.Fprintln(os.Stderr, "open ledger:", err)
				os.Exit(1)
			}
			defer l.Close()
			refs, err = l.TerminalRefs()
			if err != nil {
				fmt.Fprintln(os.Stderr, "terminal refs:", err)
				os.Exit(1)
			}
		}
		n, err := s.IngestEvidenceDir(rest[0], trustedSet, refs)
		done(n, err, "evidence records")

	case "ingest-custody":
		if len(rest) != 1 {
			usage("ingest-custody CUSTODY_DIR")
		}
		n, err := s.IngestCustodyDir(rest[0], trustedSet)
		done(n, err, "custody acks")

	case "ingest-doc":
		if len(rest) < 1 {
			usage("ingest-doc FILE...")
		}
		n, err := s.IngestDocuments(rest...)
		done(n, err, "documents")

	case "ingest-teststream":
		if len(rest) != 1 {
			usage("ingest-teststream FILE")
		}
		f, err := os.Open(rest[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "open stream:", err)
			os.Exit(1)
		}
		defer f.Close()
		n, err := s.IngestTestStream(f, *label)
		done(n, err, "test records")

	case "ingest-conversations", "ingest-traces", "ingest-experiments", "ingest-archive":
		if len(rest) != 1 {
			usage(op + " PATH")
		}
		cs, err := openContentStore(*dbPath, *contentDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "content store:", err)
			os.Exit(1)
		}
		var n int
		switch op {
		case "ingest-conversations":
			n, err = s.IngestConversations(rest[0], cs)
		case "ingest-traces":
			n, err = s.IngestTraces(rest[0], cs)
		case "ingest-experiments":
			n, err = s.IngestExperiments(rest[0], cs)
		case "ingest-archive":
			n, err = s.IngestArchive(rest[0], cs)
		}
		done(n, err, "records")

	case "ingest-recovery":
		if len(rest) != 1 {
			usage("ingest-recovery LEDGER.db")
		}
		l, err := sx.InspectLedger(rest[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "open ledger:", err)
			os.Exit(1)
		}
		defer l.Close()
		n, err := s.IngestRecovery(l, rest[0])
		done(n, err, "recovery events")

	case "append":
		// Ad-hoc records: experiments, failed attempts, observations —
		// anything an operator wants in memory that no dedicated
		// ingester covers. The dedupe key defaults to the record's
		// content digest, so an identical re-append is idempotent.
		kind := *kind
		if kind == "" {
			kind = "experiment"
		}
		if *subject == "" || *payload == "" {
			usage("append -subject S -payload JSON [-kind K] [-correlation C] [-dedupe D]")
		}
		dk := *dedupe
		if dk == "" {
			sum := sha256.Sum256([]byte(kind + "\x00" + *subject + "\x00" + *correlation + "\x00" + *payload))
			dk = "manual:" + hex.EncodeToString(sum[:])
		}
		appended, err := s.Append(&history.Event{
			DedupeKey: dk, Kind: kind, Subject: *subject,
			Correlation: *correlation, Source: "manual",
			Payload: json.RawMessage(*payload),
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "append:", err)
			os.Exit(1)
		}
		fmt.Printf("appended %d events\n", len(appended))

	case "query":
		kinds := []string{}
		if *kind != "" {
			kinds = strings.Split(*kind, ",")
		}
		events, err := s.Query(history.QueryOpts{
			Kinds: kinds, Correlation: *correlation, Limit: *limit,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "query:", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(events, "", "  ")
		fmt.Println(string(out))

	case "stats":
		total, perKind, head, err := s.Stats()
		if err != nil {
			fmt.Fprintln(os.Stderr, "stats:", err)
			os.Exit(1)
		}
		fmt.Printf("%d events, head %s\n", total, head)
		for k, n := range perKind {
			fmt.Printf("  %-12s %d\n", k, n)
		}

	case "verify":
		findings := s.Verify()
		if len(findings) == 0 {
			total, _, head, _ := s.Stats()
			fmt.Printf("OK: %d events, chain head %s\n", total, head)
			return
		}
		for _, f := range findings {
			fmt.Fprintln(os.Stderr, "  FAIL", f)
		}
		fmt.Fprintf(os.Stderr, "FAILED: %d chain problem(s)\n", len(findings))
		os.Exit(1)

	case "checkpoint":
		if len(rest) != 1 {
			usage("checkpoint CHECKPOINT_DIR -witness-key KEY.pem")
		}
		if *witnessKey == "" {
			fmt.Fprintln(os.Stderr, "checkpoint requires -witness-key — the witness is an independent key, not the store's own")
			os.Exit(2)
		}
		witness, err := evidence.LoadOrCreateSigner(*witnessKey)
		if err != nil {
			fmt.Fprintln(os.Stderr, "witness key:", err)
			os.Exit(1)
		}
		cp, err := s.WriteCheckpoint(rest[0], witness)
		if err != nil {
			fmt.Fprintln(os.Stderr, "checkpoint:", err)
			os.Exit(1)
		}
		fmt.Printf("checkpoint %d: store %s head %s witnessed by %s\n",
			cp.Sequence, cp.StoreID, cp.ChainHead[:16], cp.Signer)

	case "verify-checkpoint":
		if len(rest) != 1 {
			usage("verify-checkpoint CHECKPOINT_DIR [-trusted-signer fp,...]")
		}
		cps, err := history.LoadCheckpoints(rest[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "load checkpoints:", err)
			os.Exit(1)
		}
		if len(cps) == 0 {
			fmt.Fprintln(os.Stderr, "no checkpoints in", rest[0], "— nothing witnessed; the store is unanchored")
			os.Exit(1)
		}
		var failed bool
		for _, f := range history.VerifyCheckpointChain(cps) {
			fmt.Fprintln(os.Stderr, "  FAIL", f)
			failed = true
		}
		latest := cps[len(cps)-1].Checkpoint()
		if err := history.VerifyCheckpointFile(latest, trustedSet); err != nil {
			fmt.Fprintln(os.Stderr, "  FAIL", err)
			failed = true
		}
		if !failed {
			for _, f := range s.VerifyAgainstCheckpoint(latest) {
				fmt.Fprintln(os.Stderr, "  FAIL", f)
				failed = true
			}
		}
		if failed {
			fmt.Fprintln(os.Stderr, "FAILED: store disagrees with the witnessed record")
			os.Exit(1)
		}
		fmt.Printf("OK: witnessed seq %d head %s holds (witness %s)\n",
			latest.Sequence, latest.ChainHead[:16], latest.Signer)

	default:
		fmt.Fprintln(os.Stderr, "unknown op:", op)
		os.Exit(2)
	}
}

// openContentStore resolves the object dir: explicit -content-dir,
// else a sibling of the database so memory and its held evidence
// travel together.
func openContentStore(dbPath, dir string) (*history.ContentStore, error) {
	if dir == "" {
		dir = dbPath + ".content"
	}
	return history.OpenContentStore(dir)
}

func usage(s string) {
	fmt.Fprintln(os.Stderr, "usage: "+s)
	os.Exit(2)
}

func done(n int, err error, what string) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "ingest:", err)
		os.Exit(1)
	}
	fmt.Printf("ingested %d %s\n", n, what)
}
