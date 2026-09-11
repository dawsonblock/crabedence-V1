package authority

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// openTestDB opens a PostgreSQL connection for live authority tests.
func openTestDB(dbURL string) (*sql.DB, error) {
	return sql.Open("pgx", dbURL)
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

	if err := store.IssueGrant(ctx, grantID, principal, capabilities, expiresAt); err != nil {
		t.Fatalf("failed to issue grant: %v", err)
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

	if err := store.IssueGrant(ctx, grantID, principal, capabilities, expiresAt); err != nil {
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

	if err := store.IssueGrant(ctx, grantID, principal, capabilities, expiresAt); err != nil {
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

// TestLiveAuthorityExpiry tests that an expired grant is not valid.
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

	if err := store.IssueGrant(ctx, grantID, principal, capabilities, expiresAt); err != nil {
		t.Fatalf("failed to issue grant: %v", err)
	}

	grant, err := store.Resolve(ctx, grantID, principal)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if grant == nil {
		t.Fatal("expected grant to be found (not revoked, just expired)")
	}

	if grant.IsValid("test.counter.increment", time.Now()) {
		t.Error("expected expired grant to be INVALID")
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

	if err := store.IssueGrant(ctx, grantID, principal, capabilities, expiresAt); err != nil {
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
