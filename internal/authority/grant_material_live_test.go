package authority

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
)

// TestLiveGrantMaterialFailsClosed is the PostgreSQL half of the
// authority fail-open regression: material that cannot be verified must
// deny, and the derived-data migrations must abort rather than normalize
// corrupted material into a digest.
func TestLiveGrantMaterialFailsClosed(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live authority material test")
	}
	ctx := context.Background()

	open := func(t *testing.T) (*sql.DB, *Store) {
		t.Helper()
		db, err := openTestDB(dbURL)
		if err != nil {
			t.Fatalf("open test db: %v", err)
		}
		t.Cleanup(func() { db.Close() })
		// The store creates and migrates the schema; clear it after.
		store, err := NewStore(db)
		if err != nil {
			t.Fatalf("NewStore: %v", err)
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM authority_grants`); err != nil {
			t.Fatalf("clear grants: %v", err)
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM authority_heads`); err != nil {
			t.Fatalf("clear heads: %v", err)
		}
		return db, store
	}

	t.Run("verified material resolves", func(t *testing.T) {
		_, store := open(t)
		issued, err := store.IssueGrantWithConstraints(ctx, "g-live-ok", "alice",
			[]string{"cap.a"}, map[string][]string{"repo": {"acme/one"}}, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		resolved, err := store.Resolve(ctx, "g-live-ok", "alice")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if resolved == nil || !capability.VerifyGrantDigest(resolved) {
			t.Fatalf("verified material must resolve and verify: %+v", resolved)
		}
		if resolved.Digest != issued.Digest {
			t.Fatalf("resolved digest %s != issued digest %s", resolved.Digest, issued.Digest)
		}
	})

	cases := []struct {
		name    string
		corrupt string
	}{
		{"capabilities widened", `UPDATE authority_grants SET capabilities = '{cap.a,cap.evil}' WHERE grant_id = 'g-live-bad'`},
		{"constraints widened", `UPDATE authority_grants SET constraints = '{}'::jsonb WHERE grant_id = 'g-live-bad'`},
		{"digest erased", `UPDATE authority_grants SET grant_digest = '' WHERE grant_id = 'g-live-bad'`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, store := open(t)
			if _, err := store.IssueGrantWithConstraints(ctx, "g-live-bad", "alice",
				[]string{"cap.a"}, map[string][]string{"repo": {"acme/one"}}, time.Now().Add(time.Hour)); err != nil {
				t.Fatalf("issue: %v", err)
			}
			if _, err := db.ExecContext(ctx, tc.corrupt); err != nil {
				t.Fatalf("corrupt: %v", err)
			}
			resolved, err := store.Resolve(ctx, "g-live-bad", "alice")
			if err == nil {
				t.Fatalf("resolve returned %+v for unverifiable material; want an error", resolved)
			}
			if !errors.Is(err, ErrGrantMaterialUnverified) {
				t.Fatalf("error = %v, want ErrGrantMaterialUnverified", err)
			}
			if resolved != nil {
				t.Fatalf("resolve returned a grant alongside an error: %+v", resolved)
			}
		})
	}

	t.Run("undecodable material cannot be stored at all", func(t *testing.T) {
		db, store := open(t)
		if _, err := store.IssueGrant(ctx, "g-live-mig", "alice", []string{"cap.a"}, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("issue: %v", err)
		}
		// PostgreSQL validates TEXT[] and JSONB at the storage boundary, so
		// the decode-abort path in the digest migrations is unreachable on
		// this engine — malformed material cannot get into the table. The
		// reachable gate is digest verification, covered above; this
		// asserts the storage boundary that makes the abort defensive only.
		if _, err := db.ExecContext(ctx, `UPDATE authority_grants SET capabilities = '{' WHERE grant_id = 'g-live-mig'`); err == nil {
			t.Fatal("PostgreSQL must reject a malformed text[] literal")
		}
		if _, err := db.ExecContext(ctx, `UPDATE authority_grants SET constraints = '['::jsonb WHERE grant_id = 'g-live-mig'`); err == nil {
			t.Fatal("PostgreSQL must reject malformed JSONB")
		}
		// The material is untouched, so the grant still resolves.
		resolved, err := store.Resolve(ctx, "g-live-mig", "alice")
		if err != nil || resolved == nil {
			t.Fatalf("untouched grant must resolve: %+v, %v", resolved, err)
		}
	})
}
