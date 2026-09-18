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
// PostgreSQL Store — same immutable-generation semantics, JSON-array
// capabilities and INTEGER unix-millisecond timestamps instead of
// text[]/TIMESTAMPTZ. Expiry decisions use SQLite's own clock so
// authority validity never depends on the application clock.
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
	if _, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS authority_grants (
			grant_id TEXT NOT NULL,
			generation INTEGER NOT NULL,
			principal TEXT NOT NULL,
			capabilities TEXT NOT NULL DEFAULT '[]',
			grant_digest TEXT NOT NULL DEFAULT '',
			expires_at INTEGER,
			revoked INTEGER NOT NULL DEFAULT 0,
			revoked_at INTEGER,
			created_at INTEGER NOT NULL DEFAULT 0,
			updated_at INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (grant_id, generation)
		)
	`); err != nil {
		return err
	}
	return s.migrateLegacySchema(ctx)
}

// migrateLegacySchema upgrades a pre-generation authority_grants table
// (primary key on grant_id alone, in-place updates) by rebuilding it
// under the generation-keyed schema. Existing rows become generation 1
// and get their grant_digest backfilled.
func (s *SQLiteStore) migrateLegacySchema(ctx context.Context) error {
	var hasGeneration bool
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(authority_grants)`)
	if err != nil {
		return fmt.Errorf("failed to inspect authority schema: %w", err)
	}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == "generation" {
			hasGeneration = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
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
		`CREATE TABLE authority_grants_v2 (
			grant_id TEXT NOT NULL,
			generation INTEGER NOT NULL,
			principal TEXT NOT NULL,
			capabilities TEXT NOT NULL DEFAULT '[]',
			grant_digest TEXT NOT NULL DEFAULT '',
			expires_at INTEGER,
			revoked INTEGER NOT NULL DEFAULT 0,
			revoked_at INTEGER,
			created_at INTEGER NOT NULL DEFAULT 0,
			updated_at INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (grant_id, generation)
		)`,
		`INSERT INTO authority_grants_v2
			(grant_id, generation, principal, capabilities, expires_at, revoked, created_at, updated_at)
		 SELECT grant_id, 1, principal, capabilities, expires_at, revoked, created_at, updated_at
		 FROM authority_grants`,
		`DROP TABLE authority_grants`,
		`ALTER TABLE authority_grants_v2 RENAME TO authority_grants`,
	}
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("authority schema migration failed: %w", err)
		}
	}
	if err := backfillSQLiteGrantDigests(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// backfillSQLiteGrantDigests computes and stores grant_digest for rows
// migrated from the legacy schema (digest column empty).
func backfillSQLiteGrantDigests(ctx context.Context, tx *sql.Tx) error {
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
		var capsJSON string
		var expiresAt sql.NullInt64
		if err := rows.Scan(&r.grantID, &r.generation, &r.principal, &capsJSON, &expiresAt); err != nil {
			return fmt.Errorf("failed to scan grant row for digest backfill: %w", err)
		}
		_ = json.Unmarshal([]byte(capsJSON), &r.caps)
		if expiresAt.Valid {
			r.expiresAt = time.UnixMilli(expiresAt.Int64).UTC()
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
			UPDATE authority_grants SET grant_digest = ?3
			WHERE grant_id = ?1 AND generation = ?2
		`, r.grantID, r.generation, digest); err != nil {
			return fmt.Errorf("failed to backfill grant digest: %w", err)
		}
	}
	return nil
}

// sqliteNow is the DB-owned unix-millisecond clock — the same time
// authority the idempotency SQLite store uses.
const sqliteNow = `CAST(unixepoch('subsec') * 1000 AS INTEGER)`

// Resolve implements capability.GrantResolver.
//
// It returns the LATEST generation of the grant_id — generations
// supersede globally, so an older still-valid generation cannot resurface
// after a reissue. Expiry is evaluated against SQLite's own clock, not
// the application clock. A revoked, DB-expired, or principal-mismatched
// latest generation resolves to nil.
func (s *SQLiteStore) Resolve(ctx context.Context, grantID string, principal string) (*capability.Grant, error) {
	if grantID == "" {
		return nil, nil
	}

	var g capability.Grant
	var capabilitiesJSON string
	var expiresAt sql.NullInt64
	var revoked, unexpired int
	err := s.db.QueryRowContext(ctx, `
		SELECT grant_id, generation, principal, capabilities, grant_digest,
		       expires_at, revoked,
		       (expires_at IS NULL OR expires_at > `+sqliteNow+`) AS unexpired
		FROM authority_grants
		WHERE grant_id = ?1
		ORDER BY generation DESC
		LIMIT 1
	`, grantID).Scan(
		&g.ID, &g.Generation, &g.Principal, &capabilitiesJSON, &g.Digest,
		&expiresAt, &revoked, &unexpired,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("authority lookup failed: %w", err)
	}

	g.Revoked = revoked != 0
	if g.Principal != principal || g.Revoked || unexpired == 0 {
		return nil, nil
	}
	if expiresAt.Valid {
		g.ExpiresAt = time.UnixMilli(expiresAt.Int64).UTC()
	}
	if capabilitiesJSON != "" {
		_ = json.Unmarshal([]byte(capabilitiesJSON), &g.Capabilities)
	}
	return &g, nil
}

// ExpiryIsAuthoritative reports that Resolve already evaluates expiry
// against the database clock — VerifyAuthority skips its application
// clock expiry check for this resolver.
func (s *SQLiteStore) ExpiryIsAuthoritative() bool { return true }

// IssueGrant appends a new immutable generation for grant_id and
// returns the issued snapshot — never updates an existing row in
// place. The generation is max+1 under a transaction so concurrent
// issues serialize instead of colliding on the primary key.
func (s *SQLiteStore) IssueGrant(ctx context.Context, grantID, principal string, capabilities []string, expiresAt time.Time) (*capability.Grant, error) {
	caps, err := json.Marshal(capabilities)
	if err != nil {
		return nil, err
	}
	var expMs any
	if !expiresAt.IsZero() {
		expMs = expiresAt.UnixMilli()
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var generation int64
	if err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(generation), 0) + 1
		FROM authority_grants
		WHERE grant_id = ?1
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
			(grant_id, generation, principal, capabilities, grant_digest, expires_at, created_at, updated_at)
		VALUES (?1, ?2, ?3, ?4, ?5, ?6, `+sqliteNow+`, `+sqliteNow+`)
	`, grantID, generation, principal, string(caps), grant.Digest, expMs); err != nil {
		return nil, fmt.Errorf("failed to issue grant: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return grant, nil
}

// RevokeGrant marks every generation of a grant_id as revoked, stamping
// the database-clock revocation time. Generations are never deleted.
func (s *SQLiteStore) RevokeGrant(ctx context.Context, grantID string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE authority_grants
		SET revoked = 1,
		    revoked_at = COALESCE(revoked_at, `+sqliteNow+`),
		    updated_at = `+sqliteNow+`
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
