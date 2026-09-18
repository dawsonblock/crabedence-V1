package authority

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/openclaw/crabbox/internal/capability"
)

func openSQLite(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestSQLiteIssueGrantImmutableGenerations verifies that reissuing a
// grant_id appends a new immutable generation rather than mutating the
// issued grant: generation 1's material stays in the table unchanged
// and Resolve returns the new latest generation.
func TestSQLiteIssueGrantImmutableGenerations(t *testing.T) {
	db := openSQLite(t)
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	ctx := context.Background()

	gen1, err := store.IssueGrant(ctx, "g1", "alice", []string{"cap.a"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("issue gen1: %v", err)
	}
	if gen1.Generation != 1 || gen1.Digest == "" {
		t.Fatalf("expected generation 1 with digest, got %+v", gen1)
	}

	gen2, err := store.IssueGrant(ctx, "g1", "alice", []string{"cap.a", "cap.b"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("issue gen2: %v", err)
	}
	if gen2.Generation != 2 {
		t.Fatalf("expected generation 2, got %d", gen2.Generation)
	}
	if gen2.Digest == gen1.Digest {
		t.Fatal("expected different digest for different grant material")
	}

	// The immutable generation-1 row must still exist unchanged.
	var caps string
	var digest string
	if err := db.QueryRowContext(ctx, `
		SELECT capabilities, grant_digest FROM authority_grants
		WHERE grant_id = 'g1' AND generation = 1
	`).Scan(&caps, &digest); err != nil {
		t.Fatalf("generation 1 row missing or unreadable: %v", err)
	}
	if digest != gen1.Digest {
		t.Errorf("generation 1 digest mutated: stored %s, issued %s", digest, gen1.Digest)
	}
	if caps != `["cap.a"]` {
		t.Errorf("generation 1 capabilities mutated: %s", caps)
	}

	// Resolve returns the latest generation with its own digest.
	got, err := store.Resolve(ctx, "g1", "alice")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got == nil || got.Generation != 2 || got.Digest != gen2.Digest {
		t.Fatalf("expected gen2 snapshot, got %+v", got)
	}
	if len(got.Capabilities) != 2 {
		t.Errorf("expected gen2 capabilities, got %v", got.Capabilities)
	}
}

// TestSQLiteReissueSupersedes verifies that an older still-valid
// generation cannot resurface after a reissue — even when the newer
// generation is narrower or already expired.
func TestSQLiteReissueSupersedes(t *testing.T) {
	db := openSQLite(t)
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	ctx := context.Background()

	// gen1: valid for an hour. gen2: already expired.
	if _, err := store.IssueGrant(ctx, "g1", "alice", []string{"cap.a"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("issue gen1: %v", err)
	}
	if _, err := store.IssueGrant(ctx, "g1", "alice", []string{"cap.a"}, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("issue gen2: %v", err)
	}

	got, err := store.Resolve(ctx, "g1", "alice")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil — latest generation is expired and supersedes gen1; got %+v", got)
	}
}

// TestSQLiteResolveReissuePrincipalChange verifies that reissuing a
// grant_id to a different principal revokes the original holder's
// access: the latest generation supersedes globally, not per-principal.
func TestSQLiteResolveReissuePrincipalChange(t *testing.T) {
	db := openSQLite(t)
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	ctx := context.Background()

	if _, err := store.IssueGrant(ctx, "g1", "alice", []string{"cap.a"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := store.IssueGrant(ctx, "g1", "bob", []string{"cap.a"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("reissue: %v", err)
	}

	if got, _ := store.Resolve(ctx, "g1", "alice"); got != nil {
		t.Error("expected nil for alice — grant superseded by bob's generation")
	}
	if got, _ := store.Resolve(ctx, "g1", "bob"); got == nil {
		t.Error("expected bob's generation to resolve")
	}
}

// TestSQLiteExpiredGrantNotResolved verifies expiry is evaluated by
// the database clock inside Resolve — an already-expired grant is
// invisible to admission.
func TestSQLiteExpiredGrantNotResolved(t *testing.T) {
	db := openSQLite(t)
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	ctx := context.Background()

	if _, err := store.IssueGrant(ctx, "g1", "alice", []string{"cap.a"}, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := store.Resolve(ctx, "g1", "alice")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != nil {
		t.Error("expected nil grant — database-time expiry filters it at Resolve")
	}
}

// TestSQLiteRevokeAllGenerations verifies revocation covers every
// generation and preserves the immutable rows.
func TestSQLiteRevokeAllGenerations(t *testing.T) {
	db := openSQLite(t)
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	ctx := context.Background()

	if _, err := store.IssueGrant(ctx, "g1", "alice", []string{"cap.a"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("issue gen1: %v", err)
	}
	if _, err := store.IssueGrant(ctx, "g1", "alice", []string{"cap.a"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("issue gen2: %v", err)
	}
	if err := store.RevokeGrant(ctx, "g1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if got, _ := store.Resolve(ctx, "g1", "alice"); got != nil {
		t.Error("expected nil grant after revocation")
	}

	// Revocation must not delete the forensic snapshots.
	var revokedCount int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM authority_grants WHERE grant_id = 'g1' AND revoked = 1 AND revoked_at IS NOT NULL
	`).Scan(&revokedCount); err != nil {
		t.Fatalf("count revoked: %v", err)
	}
	if revokedCount != 2 {
		t.Errorf("expected both generations revoked and preserved, got %d", revokedCount)
	}
}

// TestSQLiteLegacySchemaMigration verifies that a pre-generation
// authority_grants table is upgraded: existing rows become generation 1
// with a backfilled digest and remain resolvable.
func TestSQLiteLegacySchemaMigration(t *testing.T) {
	db := openSQLite(t)
	ctx := context.Background()

	// Create the legacy single-generation schema and seed it.
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE authority_grants (
			grant_id TEXT PRIMARY KEY,
			principal TEXT NOT NULL,
			capabilities TEXT NOT NULL DEFAULT '[]',
			expires_at INTEGER,
			revoked INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)
	`); err != nil {
		t.Fatalf("create legacy table: %v", err)
	}
	futureMs := time.Now().Add(time.Hour).UnixMilli()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO authority_grants (grant_id, principal, capabilities, expires_at, created_at, updated_at)
		VALUES ('legacy-g', 'alice', '["cap.a"]', ?1, 1, 1)
	`, futureMs); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}

	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore migration: %v", err)
	}

	got, err := store.Resolve(ctx, "legacy-g", "alice")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got == nil {
		t.Fatal("expected migrated row to resolve as generation 1")
	}
	if got.Generation != 1 || got.Digest == "" {
		t.Fatalf("expected generation 1 with backfilled digest, got %+v", got)
	}

	// A reissue after migration must continue the generation sequence.
	gen2, err := store.IssueGrant(ctx, "legacy-g", "alice", []string{"cap.a"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("reissue: %v", err)
	}
	if gen2.Generation != 2 {
		t.Errorf("expected generation 2 after migration, got %d", gen2.Generation)
	}
}

// TestGrantDigestDeterminism verifies the grant digest is stable for
// identical material and changes on any mutation — including the
// capability order being canonicalized away.
func TestGrantDigestDeterminism(t *testing.T) {
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	g1 := &capability.Grant{ID: "g", Generation: 3, Principal: "alice", Capabilities: []string{"cap.a", "cap.b"}, ExpiresAt: exp}
	g2 := &capability.Grant{ID: "g", Generation: 3, Principal: "alice", Capabilities: []string{"cap.b", "cap.a"}, ExpiresAt: exp}
	if capability.ComputeGrantDigest(g1) != capability.ComputeGrantDigest(g2) {
		t.Error("expected capability order to be canonicalized")
	}

	g3 := &capability.Grant{ID: "g", Generation: 4, Principal: "alice", Capabilities: []string{"cap.a", "cap.b"}, ExpiresAt: exp}
	if capability.ComputeGrantDigest(g1) == capability.ComputeGrantDigest(g3) {
		t.Error("expected generation change to alter digest")
	}
	g4 := &capability.Grant{ID: "g", Generation: 3, Principal: "alice", Capabilities: []string{"cap.a"}, ExpiresAt: exp}
	if capability.ComputeGrantDigest(g1) == capability.ComputeGrantDigest(g4) {
		t.Error("expected capability change to alter digest")
	}
}
