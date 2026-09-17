package idempotency

import (
	"path/filepath"
	"testing"
)

func TestSQLitePragmasApplied(t *testing.T) {
	db, err := OpenSQLiteDB(filepath.Join(t.TempDir(), "p.db"))
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
