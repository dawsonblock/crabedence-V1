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
	if err := s.migrateLegacySchema(ctx); err != nil {
		return err
	}
	return s.ensureAuthorityHeads(ctx)
}

// sqliteHasColumn reports whether table has a column, via PRAGMA
// table_info — SQLite has no ADD COLUMN IF NOT EXISTS.
func sqliteHasColumn(ctx context.Context, db *sql.DB, table, column string) (bool, error) {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// ensureAuthorityHeads performs the r13 authority upgrade atomically:
// the issued_at material column, the authority_heads serialization
// table seeded from existing grants, and a digest recompute under the
// normalized millisecond ABI. All-or-nothing: a crash mid-upgrade
// retries cleanly on next startup.
func (s *SQLiteStore) ensureAuthorityHeads(ctx context.Context) error {
	var exists int
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM sqlite_master
		WHERE type = 'table' AND name = 'authority_heads'
	`).Scan(&exists); err != nil {
		return fmt.Errorf("failed to inspect authority_heads: %w", err)
	}
	if exists > 0 {
		return nil
	}

	hasIssuedAt, err := sqliteHasColumn(ctx, s.db, "authority_grants", "issued_at")
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if !hasIssuedAt {
		if _, err := tx.ExecContext(ctx, `
			ALTER TABLE authority_grants ADD COLUMN issued_at INTEGER
		`); err != nil {
			return fmt.Errorf("authority_heads upgrade failed: %w", err)
		}
	}
	stmts := []string{
		`UPDATE authority_grants SET issued_at = created_at WHERE issued_at IS NULL`,
		`CREATE TABLE authority_heads (
			grant_id        TEXT PRIMARY KEY,
			next_generation INTEGER NOT NULL,
			closed          INTEGER NOT NULL DEFAULT 0,
			version         INTEGER NOT NULL DEFAULT 1
		)`,
		`INSERT INTO authority_heads (grant_id, next_generation)
		 SELECT grant_id, MAX(generation) + 1 FROM authority_grants GROUP BY grant_id`,
	}
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("authority_heads upgrade failed: %w", err)
		}
	}
	if err := recomputeSQLiteGrantDigests(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// recomputeSQLiteGrantDigests rewrites every stored grant_digest under
// the current digest algorithm — derived data brought onto the
// millisecond-time ABI a resolved grant reproduces.
func recomputeSQLiteGrantDigests(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT grant_id, generation, principal, capabilities, issued_at, expires_at
		FROM authority_grants
	`)
	if err != nil {
		return fmt.Errorf("failed to scan grants for digest recompute: %w", err)
	}
	defer rows.Close()

	type grantRow struct {
		grantID    string
		generation int64
		principal  string
		caps       []string
		issuedAt   time.Time
		expiresAt  time.Time
	}
	var pending []grantRow
	for rows.Next() {
		var r grantRow
		var capsJSON string
		var issuedAt, expiresAt sql.NullInt64
		if err := rows.Scan(&r.grantID, &r.generation, &r.principal, &capsJSON, &issuedAt, &expiresAt); err != nil {
			return fmt.Errorf("failed to scan grant row for digest recompute: %w", err)
		}
		_ = json.Unmarshal([]byte(capsJSON), &r.caps)
		if issuedAt.Valid {
			r.issuedAt = time.UnixMilli(issuedAt.Int64).UTC()
		}
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
			IssuedAt:     r.issuedAt,
			ExpiresAt:    r.expiresAt,
		})
		if _, err := tx.ExecContext(ctx, `
			UPDATE authority_grants SET grant_digest = ?3
			WHERE grant_id = ?1 AND generation = ?2 AND grant_digest <> ?3
		`, r.grantID, r.generation, digest); err != nil {
			return fmt.Errorf("failed to recompute grant digest: %w", err)
		}
	}
	return nil
}

// lockAuthorityHead creates the head row for grantID if absent and
// returns its next generation and closed flag. SQLite serializes
// writers at the database level through the surrounding BEGIN
// IMMEDIATE transaction, so the head row is the logical lock point —
// identical semantics to the PostgreSQL FOR UPDATE path.
func (s *SQLiteStore) lockAuthorityHead(ctx context.Context, tx *sql.Tx, grantID string) (nextGeneration int64, closed bool, err error) {
	if _, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO authority_heads (grant_id, next_generation)
		SELECT ?1, COALESCE(MAX(generation), 0) + 1
		FROM authority_grants WHERE grant_id = ?1
	`, grantID); err != nil {
		return 0, false, fmt.Errorf("failed to ensure authority head: %w", err)
	}
	var closedInt int
	if err := tx.QueryRowContext(ctx, `
		SELECT next_generation, closed FROM authority_heads WHERE grant_id = ?1
	`, grantID).Scan(&nextGeneration, &closedInt); err != nil {
		return 0, false, fmt.Errorf("failed to lock authority head: %w", err)
	}
	return nextGeneration, closedInt != 0, nil
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
	var issuedAt, expiresAt sql.NullInt64
	var revoked, unexpired int
	err := s.db.QueryRowContext(ctx, `
		SELECT grant_id, generation, principal, capabilities, grant_digest,
		       issued_at, expires_at, revoked,
		       (expires_at IS NULL OR expires_at > `+sqliteNow+`) AS unexpired
		FROM authority_grants
		WHERE grant_id = ?1
		ORDER BY generation DESC
		LIMIT 1
	`, grantID).Scan(
		&g.ID, &g.Generation, &g.Principal, &capabilitiesJSON, &g.Digest,
		&issuedAt, &expiresAt, &revoked, &unexpired,
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
	// issued_at/expires_at are already Unix-millisecond integers — the
	// exact values the digest binds, so a resolved grant reproduces
	// its stored digest identically.
	if issuedAt.Valid {
		g.IssuedAt = time.UnixMilli(issuedAt.Int64).UTC()
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
// place. The generation is allocated from the authority_heads row
// inside a BEGIN IMMEDIATE transaction, so concurrent issuers
// serialize into strictly increasing generations instead of racing
// MAX(generation)+1 into a primary-key collision. A closed authority
// reference rejects issuance with ErrAuthorityClosed.
func (s *SQLiteStore) IssueGrant(ctx context.Context, grantID, principal string, capabilities []string, expiresAt time.Time) (*capability.Grant, error) {
	caps, err := json.Marshal(capabilities)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	generation, closed, err := s.lockAuthorityHead(ctx, tx, grantID)
	if err != nil {
		return nil, err
	}
	if closed {
		return nil, fmt.Errorf("%w: %s", ErrAuthorityClosed, grantID)
	}

	var expMs any
	var normalizedExpiry time.Time
	if !expiresAt.IsZero() {
		normalizedExpiry = time.UnixMilli(expiresAt.UTC().UnixMilli()).UTC()
		expMs = normalizedExpiry.UnixMilli()
	}
	grant := &capability.Grant{
		ID:           grantID,
		Generation:   generation,
		Principal:    principal,
		Capabilities: append([]string(nil), capabilities...),
		IssuedAt:     time.UnixMilli(time.Now().UTC().UnixMilli()).UTC(),
		ExpiresAt:    normalizedExpiry,
	}
	grant.Digest = capability.ComputeGrantDigest(grant)

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO authority_grants
			(grant_id, generation, principal, capabilities, grant_digest, issued_at, expires_at, created_at, updated_at)
		VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, `+sqliteNow+`, `+sqliteNow+`)
	`, grantID, generation, principal, string(caps), grant.Digest,
		grant.IssuedAt.UnixMilli(), expMs); err != nil {
		return nil, fmt.Errorf("failed to issue grant: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE authority_heads
		SET next_generation = next_generation + 1, version = version + 1
		WHERE grant_id = ?1
	`, grantID); err != nil {
		return nil, fmt.Errorf("failed to advance authority head: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return grant, nil
}

// RevokeGeneration revokes one immutable generation of grant_id under
// the authority-head lock — identical semantics to the PostgreSQL
// FOR UPDATE path through BEGIN IMMEDIATE serialization.
func (s *SQLiteStore) RevokeGeneration(ctx context.Context, grantID string, generation int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, _, err := s.lockAuthorityHead(ctx, tx, grantID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE authority_grants
		SET revoked = 1,
		    revoked_at = COALESCE(revoked_at, `+sqliteNow+`),
		    updated_at = `+sqliteNow+`
		WHERE grant_id = ?1 AND generation = ?2
	`, grantID, generation)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("grant generation not found: %s#%d", grantID, generation)
	}
	return tx.Commit()
}

// CloseAuthorityRef permanently prevents future issuance under
// grant_id. Existing generations are untouched — an already-issued,
// unexpired, unrevoked generation remains resolvable and bound to any
// durable execution it admitted.
func (s *SQLiteStore) CloseAuthorityRef(ctx context.Context, grantID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, _, err := s.lockAuthorityHead(ctx, tx, grantID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE authority_heads SET closed = 1, version = version + 1
		WHERE grant_id = ?1
	`, grantID); err != nil {
		return err
	}
	return tx.Commit()
}

// RevokeGrant marks every generation of a grant_id as revoked, stamping
// the database-clock revocation time. Generations are never deleted.
// The update runs under the authority-head lock so it serializes with
// concurrent issuance; the reference itself stays open for reissue —
// call CloseAuthorityRef when it must die.
func (s *SQLiteStore) RevokeGrant(ctx context.Context, grantID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, _, err := s.lockAuthorityHead(ctx, tx, grantID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
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
	return tx.Commit()
}
