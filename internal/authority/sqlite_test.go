package authority

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
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

// openSQLiteFile opens a file-backed SQLite database with the same
// transaction semantics as the production store: WAL, busy timeout,
// and BEGIN IMMEDIATE — required for real multi-connection concurrency.
func openSQLiteFile(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authority.db")
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)"+
		"&_pragma=synchronous(FULL)&_pragma=busy_timeout(10000)"+
		"&_txlock=immediate", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open sqlite file: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestSQLiteIssueConcurrentSerialized hammers one grant_id with 50
// concurrent IssueGrant calls. The authority-head lock must serialize
// them into exactly generations 1..50 — no duplicates, no primary-key
// failures, no skipped generations.
func TestSQLiteIssueConcurrentSerialized(t *testing.T) {
	db := openSQLiteFile(t)
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	ctx := context.Background()

	const workers = 50
	gens := make(chan int64, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g, err := store.IssueGrant(ctx, "g-conc", "alice", []string{"cap.a"}, time.Now().Add(time.Hour))
			if err != nil {
				errs <- err
				return
			}
			gens <- g.Generation
		}()
	}
	wg.Wait()
	close(gens)
	close(errs)

	for err := range errs {
		t.Fatalf("concurrent issue failed: %v", err)
	}
	seen := map[int64]bool{}
	for g := range gens {
		if seen[g] {
			t.Fatalf("duplicate generation issued: %d", g)
		}
		seen[g] = true
	}
	for want := int64(1); want <= workers; want++ {
		if !seen[want] {
			t.Fatalf("generation %d missing from issued set %v", want, seen)
		}
	}
}

// TestSQLiteRevokeGeneration verifies generation-scoped revocation:
// only the named immutable generation is revoked, under the same
// authority-head lock as issuance.
func TestSQLiteRevokeGeneration(t *testing.T) {
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

	if err := store.RevokeGeneration(ctx, "g1", 1); err != nil {
		t.Fatalf("revoke gen1: %v", err)
	}
	var g1Revoked, g2Revoked int
	if err := db.QueryRowContext(ctx, `SELECT revoked FROM authority_grants WHERE grant_id='g1' AND generation=1`).Scan(&g1Revoked); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT revoked FROM authority_grants WHERE grant_id='g1' AND generation=2`).Scan(&g2Revoked); err != nil {
		t.Fatal(err)
	}
	if g1Revoked != 1 {
		t.Error("generation 1 was not revoked")
	}
	if g2Revoked != 0 {
		t.Error("generation 2 must not be revoked by a generation-1 revocation")
	}

	// Latest generation still resolves; revoking it kills the grant.
	if got, _ := store.Resolve(ctx, "g1", "alice"); got == nil {
		t.Fatal("generation 2 should still resolve after gen1 revocation")
	}
	if err := store.RevokeGeneration(ctx, "g1", 2); err != nil {
		t.Fatalf("revoke gen2: %v", err)
	}
	if got, _ := store.Resolve(ctx, "g1", "alice"); got != nil {
		t.Fatal("latest generation revoked — grant must not resolve")
	}

	if err := store.RevokeGeneration(ctx, "g1", 99); err == nil {
		t.Error("revoking a nonexistent generation must fail")
	}
}

// TestSQLiteCloseAuthorityRef verifies closure blocks all future
// issuance under the reference — including on an authority ref that
// never existed — while leaving issued generations resolvable.
func TestSQLiteCloseAuthorityRef(t *testing.T) {
	db := openSQLite(t)
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	ctx := context.Background()

	issued, err := store.IssueGrant(ctx, "g1", "alice", []string{"cap.a"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := store.CloseAuthorityRef(ctx, "g1"); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := store.IssueGrant(ctx, "g1", "alice", []string{"cap.a"}, time.Now().Add(time.Hour)); !errors.Is(err, ErrAuthorityClosed) {
		t.Fatalf("issue under closed ref = %v, want ErrAuthorityClosed", err)
	}
	// Closure does not revoke the already-issued material.
	got, err := store.Resolve(ctx, "g1", "alice")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got == nil || got.Generation != issued.Generation || got.Digest != issued.Digest {
		t.Fatalf("closed ref's issued grant must remain resolvable, got %+v", got)
	}

	// Closing a never-issued ref creates a closed head — no generation
	// can ever be minted under it.
	if err := store.CloseAuthorityRef(ctx, "never-issued"); err != nil {
		t.Fatalf("close unknown ref: %v", err)
	}
	if _, err := store.IssueGrant(ctx, "never-issued", "alice", []string{"cap.a"}, time.Now().Add(time.Hour)); !errors.Is(err, ErrAuthorityClosed) {
		t.Fatalf("issue under never-issued closed ref = %v, want ErrAuthorityClosed", err)
	}
}

// TestSQLiteResolvedDigestRecomputable is the shared conformance
// invariant: a resolved grant always reproduces its stored digest —
// issued_at/expires_at are bound as the exact Unix-millisecond
// integers the store persisted, so sub-millisecond input precision
// cannot break the invariant on either backend.
func TestSQLiteResolvedDigestRecomputable(t *testing.T) {
	db := openSQLite(t)
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	ctx := context.Background()

	// Nanosecond-precision expiry — the pre-repair digest bound
	// RFC3339Nano while the store persisted milliseconds, so a
	// resolved grant could never reproduce its stored digest.
	expires := time.Date(2030, 6, 15, 10, 30, 0, 123456789, time.UTC)
	issued, err := store.IssueGrant(ctx, "g1", "alice", []string{"cap.a"}, expires)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if issued.IssuedAt.IsZero() {
		t.Error("issued grant must carry issued_at material")
	}

	got, err := store.Resolve(ctx, "g1", "alice")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got == nil {
		t.Fatal("grant did not resolve")
	}
	if got.Digest != issued.Digest {
		t.Errorf("resolved digest %s != issued digest %s", got.Digest, issued.Digest)
	}
	if want := capability.ComputeGrantDigest(got); got.Digest != want {
		t.Errorf("resolved digest %s does not recompute to %s", got.Digest, want)
	}
}
