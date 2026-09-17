package authority

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
)

// SQLiteStore is the embedded GrantResolver counterpart of the
// PostgreSQL Store — same table semantics, JSON-array capabilities and
// INTEGER unix-millisecond timestamps instead of text[]/TIMESTAMPTZ.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore creates an embedded authority store on db.
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	s := &SQLiteStore{db: db}
	if err := s.ensureSchema(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to ensure authority schema: %w", err)
	}
	return s, nil
}

func (s *SQLiteStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS authority_grants (
			grant_id TEXT PRIMARY KEY,
			principal TEXT NOT NULL,
			capabilities TEXT NOT NULL DEFAULT '[]',
			expires_at INTEGER,
			revoked INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)
	`)
	return err
}

// sqliteNow is the DB-owned unix-millisecond clock — the same time
// authority the idempotency SQLite store uses.
const sqliteNow = `CAST(unixepoch('subsec') * 1000 AS INTEGER)`

// Resolve implements capability.GrantResolver.
func (s *SQLiteStore) Resolve(ctx context.Context, grantID string, principal string) (*capability.Grant, error) {
	if grantID == "" {
		return nil, nil
	}

	var g capability.Grant
	var capabilitiesJSON string
	var expiresAt sql.NullInt64
	var revoked int
	err := s.db.QueryRowContext(ctx, `
		SELECT grant_id, principal, capabilities, expires_at, revoked
		FROM authority_grants
		WHERE grant_id = ?1 AND principal = ?2 AND revoked = 0
	`, grantID, principal).Scan(
		&g.ID, &g.Principal, &capabilitiesJSON, &expiresAt, &revoked,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("authority lookup failed: %w", err)
	}

	if expiresAt.Valid {
		g.ExpiresAt = time.UnixMilli(expiresAt.Int64).UTC()
	}
	if capabilitiesJSON != "" {
		_ = json.Unmarshal([]byte(capabilitiesJSON), &g.Capabilities)
	}
	return &g, nil
}

// IssueGrant inserts a new grant.
func (s *SQLiteStore) IssueGrant(ctx context.Context, grantID, principal string, capabilities []string, expiresAt time.Time) error {
	caps, err := json.Marshal(capabilities)
	if err != nil {
		return err
	}
	var expMs any
	if !expiresAt.IsZero() {
		expMs = expiresAt.UnixMilli()
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO authority_grants (grant_id, principal, capabilities, expires_at, created_at, updated_at)
		VALUES (?1, ?2, ?3, ?4, `+sqliteNow+`, `+sqliteNow+`)
		ON CONFLICT (grant_id) DO UPDATE
		SET principal = ?2, capabilities = ?3, expires_at = ?4,
		    revoked = 0, updated_at = `+sqliteNow+`
	`, grantID, principal, string(caps), expMs)
	return err
}

// RevokeGrant marks a grant as revoked.
func (s *SQLiteStore) RevokeGrant(ctx context.Context, grantID string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE authority_grants SET revoked = 1, updated_at = `+sqliteNow+`
		WHERE grant_id = ?1
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
