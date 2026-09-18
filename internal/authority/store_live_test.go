package authority

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/testutil"
)

// openTestDB opens a PostgreSQL connection for live authority tests,
// scoped to a package-private schema so parallel package test binaries
// cannot interfere.
func openTestDB(dbURL string) (*sql.DB, error) {
	return testutil.OpenLiveDB(dbURL, "crabbox_test_authority")
}

// TestLiveAuthorityGrantLookup tests that a valid grant can be resolved.
func TestLiveAuthorityGrantLookup(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create authority store: %v", err)
	}

	ctx := context.Background()
	grantID := fmt.Sprintf("test-grant-lookup-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	capabilities := []string{"test.counter.increment"}
	expiresAt := time.Now().Add(1 * time.Hour)

	defer db.ExecContext(ctx, `DELETE FROM authority_grants WHERE grant_id = $1`, grantID)

	issued, err := store.IssueGrant(ctx, grantID, principal, capabilities, expiresAt)
	if err != nil {
		t.Fatalf("failed to issue grant: %v", err)
	}
	if issued.Generation != 1 {
		t.Errorf("expected first issue to be generation 1, got %d", issued.Generation)
	}
	if issued.Digest == "" {
		t.Error("expected issued grant to carry a grant digest")
	}

	grant, err := store.Resolve(ctx, grantID, principal)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if grant == nil {
		t.Fatal("expected grant to be found")
	}
	if grant.ID != grantID {
		t.Errorf("expected grant ID %s, got %s", grantID, grant.ID)
	}
	if grant.Principal != principal {
		t.Errorf("expected principal %s, got %s", principal, grant.Principal)
	}
	if len(grant.Capabilities) != 1 || grant.Capabilities[0] != "test.counter.increment" {
		t.Errorf("expected capabilities [test.counter.increment], got %v", grant.Capabilities)
	}
	if grant.Generation != 1 || grant.Digest != issued.Digest {
		t.Errorf("expected resolved grant to be the issued snapshot (gen=%d digest=%s), got gen=%d digest=%s",
			1, issued.Digest, grant.Generation, grant.Digest)
	}
}

// TestLiveAuthorityPrincipalMismatch tests that a grant is not resolved
// when the principal does not match.
func TestLiveAuthorityPrincipalMismatch(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create authority store: %v", err)
	}

	ctx := context.Background()
	grantID := fmt.Sprintf("test-grant-pm-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	wrongPrincipal := "bob@example.com"
	capabilities := []string{"test.counter.increment"}
	expiresAt := time.Now().Add(1 * time.Hour)

	defer db.ExecContext(ctx, `DELETE FROM authority_grants WHERE grant_id = $1`, grantID)

	if _, err := store.IssueGrant(ctx, grantID, principal, capabilities, expiresAt); err != nil {
		t.Fatalf("failed to issue grant: %v", err)
	}

	grant, err := store.Resolve(ctx, grantID, wrongPrincipal)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if grant != nil {
		t.Error("expected nil grant for principal mismatch")
	}
}

// TestLiveAuthorityCapabilityMismatch tests that a grant with the wrong
// capability is not valid for the requested capability.
func TestLiveAuthorityCapabilityMismatch(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create authority store: %v", err)
	}

	ctx := context.Background()
	grantID := fmt.Sprintf("test-grant-cm-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	capabilities := []string{"test.counter.increment"}
	expiresAt := time.Now().Add(1 * time.Hour)

	defer db.ExecContext(ctx, `DELETE FROM authority_grants WHERE grant_id = $1`, grantID)

	if _, err := store.IssueGrant(ctx, grantID, principal, capabilities, expiresAt); err != nil {
		t.Fatalf("failed to issue grant: %v", err)
	}

	grant, err := store.Resolve(ctx, grantID, principal)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if grant == nil {
		t.Fatal("expected grant to be found")
	}

	if !grant.IsValid("test.counter.increment", time.Now()) {
		t.Error("expected grant to be valid for test.counter.increment")
	}
	if grant.IsValid("test.counter.decrement", time.Now()) {
		t.Error("expected grant to be INVALID for test.counter.decrement")
	}
}

// TestLiveAuthorityExpiry tests that an expired grant is not resolved:
// expiry is evaluated against the database clock in Resolve, so an
// already-expired grant is invisible to admission.
func TestLiveAuthorityExpiry(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create authority store: %v", err)
	}

	ctx := context.Background()
	grantID := fmt.Sprintf("test-grant-exp-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	capabilities := []string{"test.counter.increment"}
	expiresAt := time.Now().Add(-1 * time.Hour)

	defer db.ExecContext(ctx, `DELETE FROM authority_grants WHERE grant_id = $1`, grantID)

	if _, err := store.IssueGrant(ctx, grantID, principal, capabilities, expiresAt); err != nil {
		t.Fatalf("failed to issue grant: %v", err)
	}

	grant, err := store.Resolve(ctx, grantID, principal)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if grant != nil {
		t.Error("expected nil grant — database-time expiry filters it at Resolve")
	}
}

// TestLiveAuthorityRevocation tests that a revoked grant is not resolved.
func TestLiveAuthorityRevocation(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create authority store: %v", err)
	}

	ctx := context.Background()
	grantID := fmt.Sprintf("test-grant-rev-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	capabilities := []string{"test.counter.increment"}
	expiresAt := time.Now().Add(1 * time.Hour)

	defer db.ExecContext(ctx, `DELETE FROM authority_grants WHERE grant_id = $1`, grantID)

	if _, err := store.IssueGrant(ctx, grantID, principal, capabilities, expiresAt); err != nil {
		t.Fatalf("failed to issue grant: %v", err)
	}

	grant, err := store.Resolve(ctx, grantID, principal)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if grant == nil {
		t.Fatal("expected grant to be found before revocation")
	}

	if err := store.RevokeGrant(ctx, grantID); err != nil {
		t.Fatalf("failed to revoke grant: %v", err)
	}

	grant, err = store.Resolve(ctx, grantID, principal)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if grant != nil {
		t.Error("expected nil grant after revocation")
	}
}

// TestLiveAuthorityDatabaseError tests that the store handles database
// errors gracefully (returns an error, not a nil grant).
func TestLiveAuthorityDatabaseError(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create authority store: %v", err)
	}

	db.Close()

	ctx := context.Background()
	_, err = store.Resolve(ctx, "any-grant-id", "alice@example.com")
	if err == nil {
		t.Error("expected error when database is unavailable")
	}
}

// TestLiveAuthorityIssueConcurrentSerialized hammers one grant_id with
// 50 concurrent IssueGrant calls on separate pooled connections. The
// authority-head FOR UPDATE lock must serialize them into exactly
// generations 1..50 — no primary-key collisions, no duplicates.
func TestLiveAuthorityIssueConcurrentSerialized(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create authority store: %v", err)
	}

	ctx := context.Background()
	grantID := fmt.Sprintf("test-grant-conc-%d", time.Now().UnixNano())
	defer db.ExecContext(ctx, `DELETE FROM authority_grants WHERE grant_id = $1`, grantID)
	defer db.ExecContext(ctx, `DELETE FROM authority_heads WHERE grant_id = $1`, grantID)

	const workers = 50
	gens := make(chan int64, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g, err := store.IssueGrant(ctx, grantID, "alice@example.com",
				[]string{"test.counter.increment"}, time.Now().Add(time.Hour))
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

// TestLiveAuthorityRevokeGeneration verifies generation-scoped
// revocation under the authority-head lock on PostgreSQL.
func TestLiveAuthorityRevokeGeneration(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create authority store: %v", err)
	}

	ctx := context.Background()
	grantID := fmt.Sprintf("test-grant-revgen-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	defer db.ExecContext(ctx, `DELETE FROM authority_grants WHERE grant_id = $1`, grantID)
	defer db.ExecContext(ctx, `DELETE FROM authority_heads WHERE grant_id = $1`, grantID)

	if _, err := store.IssueGrant(ctx, grantID, principal, []string{"cap.a"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("issue gen1: %v", err)
	}
	if _, err := store.IssueGrant(ctx, grantID, principal, []string{"cap.a"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("issue gen2: %v", err)
	}

	if err := store.RevokeGeneration(ctx, grantID, 1); err != nil {
		t.Fatalf("revoke gen1: %v", err)
	}
	var g1Revoked, g2Revoked bool
	if err := db.QueryRowContext(ctx, `SELECT revoked FROM authority_grants WHERE grant_id=$1 AND generation=1`, grantID).Scan(&g1Revoked); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT revoked FROM authority_grants WHERE grant_id=$1 AND generation=2`, grantID).Scan(&g2Revoked); err != nil {
		t.Fatal(err)
	}
	if !g1Revoked {
		t.Error("generation 1 was not revoked")
	}
	if g2Revoked {
		t.Error("generation 2 must not be revoked by a generation-1 revocation")
	}
	if err := store.RevokeGeneration(ctx, grantID, 99); err == nil {
		t.Error("revoking a nonexistent generation must fail")
	}
}

// TestLiveAuthorityCloseRef verifies CloseAuthorityRef blocks all
// future issuance on PostgreSQL while leaving issued generations
// resolvable — including closing a never-issued reference.
func TestLiveAuthorityCloseRef(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create authority store: %v", err)
	}

	ctx := context.Background()
	grantID := fmt.Sprintf("test-grant-close-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	defer db.ExecContext(ctx, `DELETE FROM authority_grants WHERE grant_id = $1`, grantID)
	defer db.ExecContext(ctx, `DELETE FROM authority_heads WHERE grant_id = $1`, grantID)

	issued, err := store.IssueGrant(ctx, grantID, principal, []string{"cap.a"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := store.CloseAuthorityRef(ctx, grantID); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := store.IssueGrant(ctx, grantID, principal, []string{"cap.a"}, time.Now().Add(time.Hour)); !errors.Is(err, ErrAuthorityClosed) {
		t.Fatalf("issue under closed ref = %v, want ErrAuthorityClosed", err)
	}
	got, err := store.Resolve(ctx, grantID, principal)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got == nil || got.Generation != issued.Generation || got.Digest != issued.Digest {
		t.Fatalf("closed ref's issued grant must remain resolvable, got %+v", got)
	}

	neverID := grantID + "-never"
	defer db.ExecContext(ctx, `DELETE FROM authority_heads WHERE grant_id = $1`, neverID)
	if err := store.CloseAuthorityRef(ctx, neverID); err != nil {
		t.Fatalf("close unknown ref: %v", err)
	}
	if _, err := store.IssueGrant(ctx, neverID, principal, []string{"cap.a"}, time.Now().Add(time.Hour)); !errors.Is(err, ErrAuthorityClosed) {
		t.Fatalf("issue under never-issued closed ref = %v, want ErrAuthorityClosed", err)
	}
}

// TestLiveAuthorityResolvedDigestRecomputable is the shared
// conformance invariant on PostgreSQL: a resolved grant always
// reproduces its stored digest — issued_at/expires_at are bound as
// the exact Unix-millisecond integers persisted.
func TestLiveAuthorityResolvedDigestRecomputable(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create authority store: %v", err)
	}

	ctx := context.Background()
	grantID := fmt.Sprintf("test-grant-digest-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	defer db.ExecContext(ctx, `DELETE FROM authority_grants WHERE grant_id = $1`, grantID)
	defer db.ExecContext(ctx, `DELETE FROM authority_heads WHERE grant_id = $1`, grantID)

	expires := time.Date(2030, 6, 15, 10, 30, 0, 123456789, time.UTC)
	issued, err := store.IssueGrant(ctx, grantID, principal, []string{"cap.a"}, expires)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if issued.IssuedAt.IsZero() {
		t.Error("issued grant must carry issued_at material")
	}

	got, err := store.Resolve(ctx, grantID, principal)
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
