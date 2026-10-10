// evidence-checkpoint is the independent verifier for the service's
// signed evidence checkpoints.
//
// The service emits a checkpoint periodically when
// CRABEDENCE_CHECKPOINT_PATH is configured, retaining every emission in
// an append-only log beside the latest file and mirroring both onto
// CRABEDENCE_CHECKPOINT_CUSTODY_PATH when set — custody that counts as
// independent only when that storage lives outside the service host's
// failure domain. This tool re-enumerates the
// store's terminal evidence and proves a held checkpoint still covers
// it: the signature verifies under a trusted signer fingerprint, the
// store still holds at least the covered records, and the covered
// prefix recomputes to the checkpoint's chain digest — a deleted,
// rewritten, reordered or rolled-back covered record fails. Any
// emission from the retained log may be verified the same way.
//
// Usage:
//
//	evidence-checkpoint -store /path/to/crabedence.db -checkpoint cp.json \
//	    -trusted <signer-fingerprint>[,<fingerprint>...]
//	evidence-checkpoint -store postgres://... -checkpoint cp.json -trusted ...
//	evidence-checkpoint -store ... -checkpoint cp.json.jsonl -trusted ...
//	    [-chains]
//
// When -checkpoint names a retained journal (*.jsonl) the whole history
// is verified — signature, contiguous sequence, monotonic coverage and
// a single signing identity per stream — and the final entry's chain is
// checked against the store. -chains additionally verifies every
// entry's chain against the store prefix, not just the head's.
//
// Exit status: 0 when the checkpoint verifies, 1 when it does not, 2 on
// a usage or store error.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/idempotency"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("evidence-checkpoint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	storeSpec := fs.String("store", "", "effect store: a SQLite database file or a postgres:// DSN")
	cpPath := fs.String("checkpoint", "", "the held checkpoint file or retained journal (*.jsonl) to verify")
	trusted := fs.String("trusted", "", "comma-separated trusted signer fingerprints")
	chains := fs.Bool("chains", false, "journal mode: verify every entry's chain against the store, not only the head's")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *storeSpec == "" || *cpPath == "" || strings.TrimSpace(*trusted) == "" {
		fs.Usage()
		fmt.Fprintf(stderr, "-store, -checkpoint and -trusted are all required\n")
		return 2
	}
	trustedSet := map[string]bool{}
	for _, fp := range strings.Split(*trusted, ",") {
		if fp = strings.TrimSpace(fp); fp != "" {
			trustedSet[fp] = true
		}
	}
	if len(trustedSet) == 0 {
		fmt.Fprintf(stderr, "-trusted carries no fingerprints\n")
		return 2
	}
	store, closer, err := openStore(*storeSpec)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	defer closer.Close()
	refs, err := store.TerminalEvidence(context.Background())
	if err != nil {
		fmt.Fprintf(stderr, "cannot enumerate terminal evidence: %v\n", err)
		return 2
	}
	if strings.HasSuffix(*cpPath, ".jsonl") {
		return verifyJournal(*cpPath, refs, trustedSet, *chains, stdout, stderr)
	}
	data, err := os.ReadFile(*cpPath)
	if err != nil {
		fmt.Fprintf(stderr, "read checkpoint: %v\n", err)
		return 2
	}
	var cp evidence.Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		fmt.Fprintf(stderr, "checkpoint %s is not parseable: %v\n", *cpPath, err)
		return 2
	}
	if err := evidence.VerifyCheckpoint(&cp, refs, trustedSet); err != nil {
		fmt.Fprintf(stderr, "INVALID: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "OK: checkpoint %d (issued %s) covers %d terminal records; chain %s verified under signer %s\n",
		cp.Sequence, cp.IssuedAt, cp.RecordCount, cp.ChainDigest, cp.Signer)
	return 0
}

// verifyJournal verifies a whole retained checkpoint log: every entry's
// signature and the stream's continuity invariants, plus each entry's
// chain against the store's covered prefix when chains is set — and
// always for the head entry, so the journal's claimed coverage is
// proven against the live store, not merely self-consistent.
func verifyJournal(path string, refs []evidence.TerminalRef, trusted map[string]bool, chains bool, stdout, stderr io.Writer) int {
	fh, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(stderr, "read journal: %v\n", err)
		return 2
	}
	defer fh.Close()
	opts := evidence.CheckpointHistoryOptions{TrustedSigners: trusted}
	if chains {
		opts.Current = refs
	}
	summary, err := evidence.VerifyCheckpointHistory(fh, opts)
	if err != nil {
		fmt.Fprintf(stderr, "INVALID: %v\n", err)
		return 1
	}
	if summary.Entries == 0 {
		fmt.Fprintf(stderr, "INVALID: journal %s holds no checkpoint entries\n", path)
		return 1
	}
	if !chains {
		if err := evidence.VerifyCheckpoint(summary.Last, refs, trusted); err != nil {
			fmt.Fprintf(stderr, "INVALID: head entry: %v\n", err)
			return 1
		}
	}
	fmt.Fprintf(stdout, "OK: journal %s holds %d verified entries; head sequence %d (issued %s) covers %d terminal records under signer %s\n",
		path, summary.Entries, summary.LastSequence, summary.LastIssuedAt, summary.LastRecordCount, summary.Signer)
	return 0
}

// openStore opens the effect store named by spec: a postgres:// or
// postgresql:// DSN for the shared engine, anything else as a SQLite
// database path — the same two engines the service selects.
func openStore(spec string) (idempotency.EffectStore, io.Closer, error) {
	ctx := context.Background()
	if strings.HasPrefix(spec, "postgres://") || strings.HasPrefix(spec, "postgresql://") {
		db, err := sql.Open("pgx", spec)
		if err != nil {
			return nil, nil, fmt.Errorf("open postgres store: %w", err)
		}
		if err := db.PingContext(ctx); err != nil {
			db.Close()
			return nil, nil, fmt.Errorf("connect postgres store: %w", err)
		}
		st, err := idempotency.NewStore(db)
		if err != nil {
			db.Close()
			return nil, nil, fmt.Errorf("create postgres store: %w", err)
		}
		return st, db, nil
	}
	db, err := idempotency.OpenSQLiteDB(spec)
	if err != nil {
		return nil, nil, fmt.Errorf("open sqlite store %s: %w", spec, err)
	}
	st, err := idempotency.NewSQLiteStore(db)
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("create sqlite store: %w", err)
	}
	return st, db, nil
}
