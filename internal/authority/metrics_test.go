package authority

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
)

// metricStore is the lifecycle surface both authority engines expose —
// the counter contract below runs identically against each.
type metricStore interface {
	Resolve(ctx context.Context, grantID, principal string) (*capability.Grant, error)
	IssueGrant(ctx context.Context, grantID, principal string, capabilities []string, expiresAt time.Time) (*capability.Grant, error)
	RevokeGeneration(ctx context.Context, grantID string, generation int64) error
	CloseAuthorityRef(ctx context.Context, grantID string) error
	RevokeGrant(ctx context.Context, grantID string) error
	Metrics() *Metrics
}

func checkAuthorityMetrics(t *testing.T, s metricStore, p string) {
	t.Helper()
	ctx := context.Background()

	want := func(key string, v int64) {
		t.Helper()
		if got := s.Metrics().Snapshot()[key]; got != v {
			t.Fatalf("%s = %d, want %d", key, got, v)
		}
	}

	// A resolve against missing material counts the consultation and
	// the denial — the two operands of the admission-refusal signal.
	if g, err := s.Resolve(ctx, p+"-absent", "alice"); err != nil || g != nil {
		t.Fatalf("absent resolve: g=%v err=%v", g, err)
	}
	want("authority_resolves_total", 1)
	want("authority_resolve_denials_total", 1)

	if _, err := s.IssueGrant(ctx, p+"-g1", "alice", []string{"cap.a"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if g, err := s.Resolve(ctx, p+"-g1", "alice"); err != nil || g == nil {
		t.Fatalf("resolve: g=%v err=%v", g, err)
	}
	if g, err := s.Resolve(ctx, p+"-g1", "bob"); err != nil || g != nil {
		t.Fatalf("wrong-principal resolve: g=%v err=%v", g, err)
	}
	want("authority_grants_issued_total", 1)
	want("authority_resolves_total", 3)
	want("authority_resolve_denials_total", 2)

	// Revoking the live generation denies subsequent resolves.
	if err := s.RevokeGeneration(ctx, p+"-g1", 1); err != nil {
		t.Fatalf("revoke generation: %v", err)
	}
	if g, err := s.Resolve(ctx, p+"-g1", "alice"); err != nil || g != nil {
		t.Fatalf("post-revoke resolve: g=%v err=%v", g, err)
	}
	want("authority_generations_revoked_total", 1)
	want("authority_resolve_denials_total", 3)

	// Reissue mints a new generation; whole-grant revocation and
	// reference closure count separately.
	if _, err := s.IssueGrant(ctx, p+"-g1", "alice", []string{"cap.a"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("reissue: %v", err)
	}
	if err := s.RevokeGrant(ctx, p+"-g1"); err != nil {
		t.Fatalf("revoke grant: %v", err)
	}
	if _, err := s.IssueGrant(ctx, p+"-g2", "alice", []string{"cap.b"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("issue g2: %v", err)
	}
	if err := s.CloseAuthorityRef(ctx, p+"-g2"); err != nil {
		t.Fatalf("close: %v", err)
	}
	want("authority_grants_issued_total", 3)
	want("authority_generations_revoked_total", 1)
	want("authority_grants_revoked_total", 1)
	want("authority_refs_closed_total", 1)
}

// TestAuthorityMetricsLifecycle exercises every counter on the SQLite
// engine always and on PostgreSQL when the live database is
// configured — same names, same semantics.
func TestAuthorityMetricsLifecycle(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		s, err := NewSQLiteStore(openSQLite(t))
		if err != nil {
			t.Fatalf("NewSQLiteStore: %v", err)
		}
		checkAuthorityMetrics(t, s, "m")
	})
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		return
	}
	t.Run("postgres", func(t *testing.T) {
		db, err := openTestDB(dbURL)
		if err != nil {
			t.Fatalf("open test db: %v", err)
		}
		t.Cleanup(func() { db.Close() })
		s, err := NewStore(db)
		if err != nil {
			t.Fatalf("NewStore: %v", err)
		}
		checkAuthorityMetrics(t, s, fmt.Sprintf("m-%d", time.Now().UnixNano()))
	})
}
