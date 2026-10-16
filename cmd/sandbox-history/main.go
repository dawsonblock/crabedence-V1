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
//	sandbox-history -db /path/history.db query [-kind K] [-correlation C] [-limit N]
//	sandbox-history -db /path/history.db stats
//	sandbox-history -db /path/history.db verify
//
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
	if op == "verify" || op == "query" || op == "stats" {
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

	default:
		fmt.Fprintln(os.Stderr, "unknown op:", op)
		os.Exit(2)
	}
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
