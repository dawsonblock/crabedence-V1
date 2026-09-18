package idempotency

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLitePragmasApplied(t *testing.T) {
	db, err := OpenSQLiteDB(filepath.Join(t.TempDir(), "db", "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	want := map[string]any{
		"journal_mode": "wal",
		"synchronous":  int64(2), // FULL
		"foreign_keys": int64(1),
		"busy_timeout": int64(5000),
		"temp_store":   int64(2), // MEMORY
	}
	for p, w := range want {
		var v any
		if err := db.QueryRow("PRAGMA " + p).Scan(&v); err != nil {
			t.Fatalf("pragma %s: %v", p, err)
		}
		if v != w {
			t.Errorf("pragma %s = %v, want %v", p, v, w)
		}
	}
}

// TestSQLiteRestartIntegrity exercises the machine-restart path at
// process granularity: commit records in several states, close the
// database, reopen it fresh, run integrity_check, and verify the
// durable records survive intact. WAL + synchronous=FULL (asserted in
// TestSQLitePragmasApplied) are what make this safe.
func TestSQLiteRestartIntegrity(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "db", "restart.db")
	ctx := context.Background()

	write := func() {
		db, err := OpenSQLiteDB(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		s, err := NewSQLiteStore(db)
		if err != nil {
			t.Fatal(err)
		}
		// Committed record.
		acq, err := s.Acquire(ctx, "k1", "p", "cap", "d1", "g", "MUTATION", time.Second)
		if err != nil || !acq.Acquired() {
			t.Fatalf("acquire k1: %v", err)
		}
		if err := s.BeginExecution(ctx, acq.Record.ExecutionID, acq.LeaseToken, acq.Generation); err != nil {
			t.Fatal(err)
		}
		if err := s.MarkInFlight(ctx, acq.Record.ExecutionID, acq.LeaseToken, acq.Generation, "prov", []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		if err := s.Finalize(ctx, acq.Record.ExecutionID, acq.LeaseToken, acq.Generation, StateInFlight, TerminalReceipt{
			ExecutionID: acq.Record.ExecutionID, Capability: "cap", Principal: "p",
			RequestDigest: "d1", TerminalStatus: StateCommitted,
			CanonicalResult: []byte(`{"ok":1}`),
		}); err != nil {
			t.Fatal(err)
		}
		// In-flight record with provider observation.
		acq2, err := s.Acquire(ctx, "k2", "p", "cap", "d2", "g", "MUTATION", time.Second)
		if err != nil || !acq2.Acquired() {
			t.Fatalf("acquire k2: %v", err)
		}
		if err := s.BeginExecution(ctx, acq2.Record.ExecutionID, acq2.LeaseToken, acq2.Generation); err != nil {
			t.Fatal(err)
		}
		if err := s.MarkInFlight(ctx, acq2.Record.ExecutionID, acq2.LeaseToken, acq2.Generation, "prov", []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		if err := s.RecordProviderObservation(ctx, acq2.Record.ExecutionID, acq2.LeaseToken, acq2.Generation, ProviderObservation{
			ProviderID: "prov", ProviderStatus: "SUCCEEDED", Result: []byte(`{"ok":2}`),
		}); err != nil {
			t.Fatal(err)
		}
	}
	write()

	// Restart: reopen the same file and verify integrity + contents.
	db, err := OpenSQLiteDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var ic string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&ic); err != nil {
		t.Fatal(err)
	}
	if ic != "ok" {
		t.Fatalf("integrity_check = %q", ic)
	}
	var jm string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&jm); err != nil {
		t.Fatal(err)
	}
	if jm != "wal" {
		t.Fatalf("journal_mode = %q after reopen, want wal", jm)
	}

	s, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatal(err)
	}
	r1, err := s.LookupByKey(ctx, "p", "cap", "k1")
	if err != nil {
		t.Fatal(err)
	}
	if r1.State != StateCommitted {
		t.Fatalf("k1 state = %s after restart, want COMMITTED", r1.State)
	}
	r2, err := s.LookupByKey(ctx, "p", "cap", "k2")
	if err != nil {
		t.Fatal(err)
	}
	if r2.State != StateInFlight {
		t.Fatalf("k2 state = %s after restart, want IN_FLIGHT", r2.State)
	}
	if r2.ProviderStatus != "SUCCEEDED" || string(r2.ProviderResult) != `{"ok":2}` {
		t.Fatalf("k2 observation lost across restart: status=%q result=%s", r2.ProviderStatus, r2.ProviderResult)
	}
}
