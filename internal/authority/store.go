// Package authority provides PostgreSQL-backed authority verification
// for the Crabedence execution service.
//
// Grants are stored in the authority_grants table and resolved by
// the execution service before dispatching MUTATION/CRITICAL
// capabilities. This replaces the NoopGrantResolver default so
// that production serve-execution actually enforces authority.
//
// Grants are immutable: reissuing a grant_id appends a new generation
// row rather than mutating the issued material, and the latest
// generation supersedes all earlier ones for admission. Each row
// carries a grant_digest over its material so a durable execution can
// prove exactly which authority snapshot admitted it. Expiry and
// revocation decisions use the database's own clock, not the
// application clock.
package authority

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
)

// Store is a PostgreSQL-backed GrantResolver.
type Store struct {
	db *sql.DB
}

// NewStore creates a new PostgreSQL-backed authority store.
// It ensures the authority_grants table exists and migrates legacy
// single-generation tables to the generation-keyed schema.
func NewStore(db *sql.DB) (*Store, error) {
	s := &Store{db: db}
	if err := s.ensureSchema(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to ensure authority schema: %w", err)
	}
	return s, nil
}

// ensureSchema creates the generation-keyed authority_grants table if
// it doesn't exist, then upgrades legacy single-generation tables.
func (s *Store) ensureSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS authority_grants (
			grant_id TEXT NOT NULL,
			generation INTEGER NOT NULL,
			principal TEXT NOT NULL,
			capabilities TEXT[] NOT NULL DEFAULT '{}',
			grant_digest TEXT NOT NULL DEFAULT '',
			expires_at TIMESTAMPTZ,
			revoked BOOLEAN NOT NULL DEFAULT FALSE,
			revoked_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (grant_id, generation)
		)
	`); err != nil {
		return err
	}
	return s.migrateLegacySchema(ctx)
}

// migrateLegacySchema upgrades a pre-generation authority_grants table
// (primary key on grant_id alone, in-place updates) to the immutable
// generation-keyed schema. Existing rows become generation 1 and get
// their grant_digest backfilled.
func (s *Store) migrateLegacySchema(ctx context.Context) error {
	var hasGeneration bool
	if err := s.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_name = 'authority_grants'
			  AND column_name = 'generation'
		)
	`).Scan(&hasGeneration); err != nil {
		return fmt.Errorf("failed to inspect authority schema: %w", err)
	}
	if hasGeneration {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmts := []string{
		`ALTER TABLE authority_grants ADD COLUMN generation INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE authority_grants ADD COLUMN grant_digest TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE authority_grants ADD COLUMN revoked_at TIMESTAMPTZ`,
		`ALTER TABLE authority_grants DROP CONSTRAINT authority_grants_pkey`,
		`ALTER TABLE authority_grants ADD PRIMARY KEY (grant_id, generation)`,
	}
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("authority schema migration failed: %w", err)
		}
	}
	if err := backfillGrantDigests(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// backfillGrantDigests computes and stores the grant_digest for rows
// migrated from the legacy schema (digest column empty).
func backfillGrantDigests(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT grant_id, generation, principal, capabilities, expires_at
		FROM authority_grants
		WHERE grant_digest = ''
	`)
	if err != nil {
		return fmt.Errorf("failed to scan grants for digest backfill: %w", err)
	}
	defer rows.Close()

	type legacyRow struct {
		grantID    string
		generation int64
		principal  string
		caps       []string
		expiresAt  time.Time
	}
	var pending []legacyRow
	for rows.Next() {
		var r legacyRow
		var capsRaw []byte
		var expiresAt sql.NullTime
		if err := rows.Scan(&r.grantID, &r.generation, &r.principal, &capsRaw, &expiresAt); err != nil {
			return fmt.Errorf("failed to scan grant row for digest backfill: %w", err)
		}
		r.caps = parsePostgresArray(string(capsRaw))
		if expiresAt.Valid {
			r.expiresAt = expiresAt.Time
		}
		pending = append(pending, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, r := range pending {
		digest := capability.ComputeGrantDigest(&capability.Grant{
			ID:           r.grantID,
			Generation:   r.generation,
			Principal:    r.principal,
			Capabilities: r.caps,
			ExpiresAt:    r.expiresAt,
		})
		if _, err := tx.ExecContext(ctx, `
			UPDATE authority_grants SET grant_digest = $3
			WHERE grant_id = $1 AND generation = $2
		`, r.grantID, r.generation, digest); err != nil {
			return fmt.Errorf("failed to backfill grant digest: %w", err)
		}
	}
	return nil
}

// Resolve implements capability.GrantResolver.
//
// It returns the LATEST generation of the grant_id — generations
// supersede globally, so an older still-valid generation cannot resurface
// after a reissue. Expiry is evaluated against the database clock
// (expires_at > NOW()), not the application clock. A revoked,
// DB-expired, or principal-mismatched latest generation resolves to
// nil: the grant no longer admits anyone.
func (s *Store) Resolve(ctx context.Context, grantID string, principal string) (*capability.Grant, error) {
	if grantID == "" {
		return nil, nil
	}

	var g capability.Grant
	var capabilities []byte
	var expiresAt sql.NullTime
	var unexpired bool
	err := s.db.QueryRowContext(ctx, `
		SELECT grant_id, generation, principal, capabilities, grant_digest,
		       expires_at, revoked,
		       (expires_at IS NULL OR expires_at > NOW()) AS unexpired
		FROM authority_grants
		WHERE grant_id = $1
		ORDER BY generation DESC
		LIMIT 1
	`, grantID).Scan(
		&g.ID, &g.Generation, &g.Principal, &capabilities, &g.Digest,
		&expiresAt, &g.Revoked, &unexpired,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("authority lookup failed: %w", err)
	}

	if g.Principal != principal || g.Revoked || !unexpired {
		return nil, nil
	}
	if expiresAt.Valid {
		g.ExpiresAt = expiresAt.Time
	}

	// Parse capabilities array from PostgreSQL text[] format.
	// pgx returns it as a string like {cap1,cap2} or {cap1,cap2,cap3}
	if len(capabilities) > 0 {
		g.Capabilities = parsePostgresArray(string(capabilities))
	}

	return &g, nil
}

// ExpiryIsAuthoritative reports that Resolve already evaluates expiry
// against the database clock — VerifyAuthority skips its application
// clock expiry check for this resolver.
func (s *Store) ExpiryIsAuthoritative() bool { return true }

// IssueGrant appends a new immutable generation for grant_id and
// returns the issued snapshot — never updates an existing row in
// place. The generation is max+1 under a transaction so concurrent
// issues serialize instead of colliding on the primary key. The
// returned grant's Digest is bound into execution request digests so
// that the same grant_id under different material is a different
// authority.
func (s *Store) IssueGrant(ctx context.Context, grantID, principal string, capabilities []string, expiresAt time.Time) (*capability.Grant, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var generation int64
	if err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(generation), 0) + 1
		FROM authority_grants
		WHERE grant_id = $1
	`, grantID).Scan(&generation); err != nil {
		return nil, fmt.Errorf("failed to allocate grant generation: %w", err)
	}

	grant := &capability.Grant{
		ID:           grantID,
		Generation:   generation,
		Principal:    principal,
		Capabilities: append([]string(nil), capabilities...),
		ExpiresAt:    expiresAt,
	}
	grant.Digest = capability.ComputeGrantDigest(grant)

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO authority_grants
			(grant_id, generation, principal, capabilities, grant_digest, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, grantID, generation, principal, capabilities, grant.Digest, nullableTime(expiresAt)); err != nil {
		return nil, fmt.Errorf("failed to issue grant: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return grant, nil
}

// RevokeGrant marks every generation of a grant_id as revoked, stamping
// the database-clock revocation time. Existing generations are never
// deleted — they remain as immutable forensic snapshots.
func (s *Store) RevokeGrant(ctx context.Context, grantID string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE authority_grants
		SET revoked = TRUE, revoked_at = COALESCE(revoked_at, NOW())
		WHERE grant_id = $1
	`, grantID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("grant not found: %s", grantID)
	}
	return nil
}

// parsePostgresArray parses a PostgreSQL text[] representation like
// {cap1,cap2} into a Go []string.
func parsePostgresArray(s string) []string {
	if len(s) < 2 || s[0] != '{' || s[len(s)-1] != '}' {
		return nil
	}
	inner := s[1 : len(s)-1]
	if inner == "" {
		return nil
	}
	// Simple split — assumes no commas or braces inside capability IDs
	var result []string
	current := ""
	for _, c := range inner {
		if c == ',' {
			result = append(result, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	result = append(result, current)
	return result
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
