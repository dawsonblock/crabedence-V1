// Package authority provides PostgreSQL-backed authority verification
// for the Crabedence execution service.
//
// Grants are stored in the authority_grants table and resolved by
// the execution service before dispatching MUTATION/CRITICAL
// capabilities. This replaces the NoopGrantResolver default so
// that production serve-execution actually enforces authority.
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
// It ensures the authority_grants table exists.
func NewStore(db *sql.DB) (*Store, error) {
	s := &Store{db: db}
	if err := s.ensureSchema(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to ensure authority schema: %w", err)
	}
	return s, nil
}

// ensureSchema creates the authority_grants table if it doesn't exist.
func (s *Store) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS authority_grants (
			grant_id TEXT PRIMARY KEY,
			principal TEXT NOT NULL,
			capabilities TEXT[] NOT NULL DEFAULT '{}',
			expires_at TIMESTAMPTZ,
			revoked BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	return err
}

// Resolve implements capability.GrantResolver.
// It looks up the grant by ID and principal, and returns it if found.
// The caller (VerifyAuthority) checks validity (expiry, revocation).
func (s *Store) Resolve(ctx context.Context, grantID string, principal string) (*capability.Grant, error) {
	if grantID == "" {
		return nil, nil
	}

	var g capability.Grant
	var capabilities []byte
	var expiresAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT grant_id, principal, capabilities, expires_at, revoked
		FROM authority_grants
		WHERE grant_id = $1 AND principal = $2 AND revoked = FALSE
	`, grantID, principal).Scan(
		&g.ID, &g.Principal, &capabilities, &expiresAt, &g.Revoked,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("authority lookup failed: %w", err)
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

// IssueGrant inserts a new grant.
func (s *Store) IssueGrant(ctx context.Context, grantID, principal string, capabilities []string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO authority_grants (grant_id, principal, capabilities, expires_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (grant_id) DO UPDATE
		SET principal = $2, capabilities = $3, expires_at = $4,
		    revoked = FALSE, updated_at = NOW()
	`, grantID, principal, capabilities, nullableTime(expiresAt))
	return err
}

// RevokeGrant marks a grant as revoked.
func (s *Store) RevokeGrant(ctx context.Context, grantID string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE authority_grants SET revoked = TRUE, updated_at = NOW()
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
