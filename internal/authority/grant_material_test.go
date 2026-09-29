package authority

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
)

func mustExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

// TestSQLiteResolveFailsClosedOnUnverifiableMaterial is the regression
// for the authority fail-open defect: corrupted capability or constraint
// material must deny, never resolve as a wildcard or unconstrained
// grant, and a stored digest that disagrees with the material it covers
// must be refused. Before the fix, a decode failure became an empty
// capability list — which is the wildcard — so corrupt bytes authorized
// everything.
func TestSQLiteResolveFailsClosedOnUnverifiableMaterial(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		corrupt func(t *testing.T, db *sql.DB, grantID string)
	}{
		{
			name: "corrupt capabilities JSON",
			corrupt: func(t *testing.T, db *sql.DB, grantID string) {
				mustExec(t, db, `UPDATE authority_grants SET capabilities = ? WHERE grant_id = ?`, `{"not":"a list"}`, grantID)
			},
		},
		{
			name: "corrupt constraints JSON",
			corrupt: func(t *testing.T, db *sql.DB, grantID string) {
				mustExec(t, db, `UPDATE authority_grants SET constraints = ? WHERE grant_id = ?`, `[`, grantID)
			},
		},
		{
			name: "capabilities widened without reissuing the digest",
			corrupt: func(t *testing.T, db *sql.DB, grantID string) {
				mustExec(t, db, `UPDATE authority_grants SET capabilities = ? WHERE grant_id = ?`, `["cap.a","cap.evil"]`, grantID)
			},
		},
		{
			name: "constraints widened without reissuing the digest",
			corrupt: func(t *testing.T, db *sql.DB, grantID string) {
				mustExec(t, db, `UPDATE authority_grants SET constraints = ? WHERE grant_id = ?`, `{}`, grantID)
			},
		},
		{
			name: "digest erased",
			corrupt: func(t *testing.T, db *sql.DB, grantID string) {
				mustExec(t, db, `UPDATE authority_grants SET grant_digest = '' WHERE grant_id = ?`, grantID)
			},
		},
		{
			name: "blank capabilities",
			corrupt: func(t *testing.T, db *sql.DB, grantID string) {
				mustExec(t, db, `UPDATE authority_grants SET capabilities = '' WHERE grant_id = ?`, grantID)
			},
		},
		{
			name: "whitespace capabilities",
			corrupt: func(t *testing.T, db *sql.DB, grantID string) {
				mustExec(t, db, `UPDATE authority_grants SET capabilities = '   ' WHERE grant_id = ?`, grantID)
			},
		},
		{
			name: "blank constraints",
			corrupt: func(t *testing.T, db *sql.DB, grantID string) {
				mustExec(t, db, `UPDATE authority_grants SET constraints = '' WHERE grant_id = ?`, grantID)
			},
		},
		{
			name: "non-canonical capabilities",
			corrupt: func(t *testing.T, db *sql.DB, grantID string) {
				mustExec(t, db, `UPDATE authority_grants SET capabilities = '[ "cap.a" ]' WHERE grant_id = ?`, grantID)
			},
		},
		{
			// `null` is how the issuer encodes an empty (wildcard) list, so
			// the decoder accepts it — the digest is what catches material
			// rewritten to null without a reissue.
			name: "capabilities rewritten to null",
			corrupt: func(t *testing.T, db *sql.DB, grantID string) {
				mustExec(t, db, `UPDATE authority_grants SET capabilities = 'null' WHERE grant_id = ?`, grantID)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := openSQLite(t)
			store, err := NewSQLiteStore(db)
			if err != nil {
				t.Fatalf("NewSQLiteStore: %v", err)
			}
			if _, err := store.IssueGrantWithConstraints(ctx, "g1", "alice",
				[]string{"cap.a"}, map[string][]string{"repo": {"acme/one"}}, time.Now().Add(time.Hour)); err != nil {
				t.Fatalf("issue grant: %v", err)
			}
			tc.corrupt(t, db, "g1")

			resolved, err := store.Resolve(ctx, "g1", "alice")
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
}

// TestSQLiteResolveAcceptsVerifiedMaterial is the positive direction: an
// untouched grant resolves, and its digest verifies against its material.
func TestSQLiteResolveAcceptsVerifiedMaterial(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	issued, err := store.IssueGrantWithConstraints(ctx, "g1", "alice",
		[]string{"cap.a"}, map[string][]string{"repo": {"acme/one"}}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("issue grant: %v", err)
	}
	resolved, err := store.Resolve(ctx, "g1", "alice")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved == nil {
		t.Fatal("verified material must resolve")
	}
	if resolved.Digest != issued.Digest {
		t.Fatalf("resolved digest %s != issued digest %s", resolved.Digest, issued.Digest)
	}
	if !capability.VerifyGrantDigest(resolved) {
		t.Fatal("resolved grant digest does not verify against its material")
	}
	if !resolved.HasCapability("cap.a") || resolved.HasCapability("cap.evil") {
		t.Fatalf("capability set changed: %v", resolved.Capabilities)
	}
	if !resolved.AllowsResource("repo", "acme/one") || resolved.AllowsResource("repo", "acme/two") {
		t.Fatalf("constraint scope changed: %v", resolved.Constraints)
	}
}

// TestSQLiteDigestMigrationsAbortOnUnverifiableMaterial proves the
// derived-data migrations refuse to normalize corrupted material into a
// digest: recomputing a digest over a degraded interpretation would
// legitimize it.
func TestSQLiteDigestMigrationsAbortOnUnverifiableMaterial(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		run  func(ctx context.Context, tx *sql.Tx) error
	}{
		{"recompute", recomputeSQLiteGrantDigests},
		{"backfill", backfillSQLiteGrantDigests},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := openSQLite(t)
			store, err := NewSQLiteStore(db)
			if err != nil {
				t.Fatalf("NewSQLiteStore: %v", err)
			}
			if _, err := store.IssueGrant(ctx, "g1", "alice", []string{"cap.a"}, time.Now().Add(time.Hour)); err != nil {
				t.Fatalf("issue grant: %v", err)
			}
			// Corrupt the material AND leave the digest unset, so both
			// migration paths must decode this row.
			mustExec(t, db, `UPDATE authority_grants SET capabilities = ?, grant_digest = '' WHERE grant_id = ?`, `{`, "g1")

			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer tx.Rollback()
			err = tc.run(ctx, tx)
			if err == nil {
				t.Fatal("a digest migration must abort on unverifiable material")
			}
			if !errors.Is(err, ErrGrantMaterialUnverified) {
				t.Fatalf("error = %v, want it to wrap ErrGrantMaterialUnverified", err)
			}
		})
	}
}

// TestSQLiteMigrationRefusesBroadeningRepresentations is the migration
// half of the authority fail-open regression: blank, whitespace, and
// non-canonical material must ABORT the digest migrations rather than be
// minted into a cryptographically verified wildcard grant.
func TestSQLiteMigrationRefusesBroadeningRepresentations(t *testing.T) {
	ctx := context.Background()
	representations := []struct {
		name  string
		value string
	}{
		{"blank", `''`},
		{"whitespace", `'   '`},
		{"non-canonical array", `'[ "cap.a" ]'`},
		{"non-canonical object", `'{ "repo": [ "acme/one" ] }'`},
	}
	for _, representation := range representations {
		t.Run(representation.name, func(t *testing.T) {
			db := openSQLite(t)
			store, err := NewSQLiteStore(db)
			if err != nil {
				t.Fatalf("NewSQLiteStore: %v", err)
			}
			if _, err := store.IssueGrantWithConstraints(ctx, "g1", "alice",
				[]string{"cap.a"}, map[string][]string{"repo": {"acme/one"}}, time.Now().Add(time.Hour)); err != nil {
				t.Fatalf("issue grant: %v", err)
			}
			mustExec(t, db,
				`UPDATE authority_grants SET capabilities = `+representation.value+`, constraints = `+representation.value+`, grant_digest = '' WHERE grant_id = ?`,
				"g1")

			// An in-memory SQLite database is per-connection, so pin one
			// connection for the migrations and the readback.
			conn, err := db.Conn(ctx)
			if err != nil {
				t.Fatalf("pin connection: %v", err)
			}
			defer conn.Close()
			tx, err := conn.BeginTx(ctx, nil)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			if err := recomputeSQLiteGrantDigests(ctx, tx); err == nil {
				t.Fatal("recompute must abort on broadening material")
			}
			if err := backfillSQLiteGrantDigests(ctx, tx); err == nil {
				t.Fatal("backfill must abort on broadening material")
			}
			if err := tx.Rollback(); err != nil {
				t.Fatalf("rollback: %v", err)
			}
			// Nothing was minted: the row still has no digest.
			var digest string
			if err := conn.QueryRowContext(ctx,
				`SELECT grant_digest FROM authority_grants WHERE grant_id = ?`, "g1").Scan(&digest); err != nil {
				t.Fatalf("read digest: %v", err)
			}
			if digest != "" {
				t.Fatalf("migration minted a digest (%q) for unverifiable material", digest)
			}
		})
	}
}

// TestSQLiteWildcardGrantStillResolves proves the strictness does not
// break a legitimately issued wildcard, and pins BOTH stored
// representations: json.Marshal encodes a nil slice as `null` and an
// allocated empty slice as `[]`. Both mean "no capabilities" — the
// wildcard — so a later cleanup that normalizes the two would silently
// change authority semantics, and this test fails if that happens.
func TestSQLiteWildcardGrantStillResolves(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name         string
		capabilities []string
		stored       string
	}{
		{"nil slice marshals to null", nil, "null"},
		{"empty slice marshals to []", []string{}, "[]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := openSQLite(t)
			store, err := NewSQLiteStore(db)
			if err != nil {
				t.Fatalf("NewSQLiteStore: %v", err)
			}
			if _, err := store.IssueGrant(ctx, "g-wild", "alice", tc.capabilities, time.Now().Add(time.Hour)); err != nil {
				t.Fatalf("issue wildcard grant: %v", err)
			}
			var stored string
			if err := db.QueryRowContext(ctx,
				`SELECT capabilities FROM authority_grants WHERE grant_id = ?`, "g-wild").Scan(&stored); err != nil {
				t.Fatalf("read stored capabilities: %v", err)
			}
			if stored != tc.stored {
				t.Fatalf("stored capabilities = %q, want %q", stored, tc.stored)
			}
			resolved, err := store.Resolve(ctx, "g-wild", "alice")
			if err != nil {
				t.Fatalf("wildcard grant must resolve: %v", err)
			}
			if resolved == nil || !resolved.HasCapability("anything.at.all") {
				t.Fatalf("wildcard grant must permit any capability: %+v", resolved)
			}
			if !capability.VerifyGrantDigest(resolved) {
				t.Fatal("wildcard grant digest must verify")
			}
		})
	}
}
