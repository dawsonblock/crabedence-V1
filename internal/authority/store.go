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
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
)

// ErrAuthorityClosed is returned when issuance is attempted under an
// authority reference that has been closed by CloseAuthorityRef —
// no further generations can ever be minted for it.
var ErrAuthorityClosed = errors.New("authority reference is closed")

// Store is a PostgreSQL-backed GrantResolver.
type Store struct {
	db      *sql.DB
	metrics Metrics
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
			constraints JSONB NOT NULL DEFAULT '{}',
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
	// Resource-constraint material: added after CREATE so existing
	// pre-constraints tables gain the column too. '{}' (unconstrained)
	// digests identically to an absent field, so no stored digest
	// changes under this upgrade.
	if _, err := s.db.ExecContext(ctx, `
		ALTER TABLE authority_grants
		ADD COLUMN IF NOT EXISTS constraints JSONB NOT NULL DEFAULT '{}'
	`); err != nil {
		return fmt.Errorf("failed to add constraints column: %w", err)
	}
	if err := s.migrateLegacySchema(ctx); err != nil {
		return err
	}
	return s.ensureAuthorityHeads(ctx)
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
		SELECT grant_id, generation, principal, capabilities, constraints, expires_at
		FROM authority_grants
		WHERE grant_digest = ''
	`)
	if err != nil {
		return fmt.Errorf("failed to scan grants for digest backfill: %w", err)
	}
	defer rows.Close()

	type legacyRow struct {
		grantID     string
		generation  int64
		principal   string
		caps        []string
		constraints map[string][]string
		expiresAt   time.Time
	}
	var pending []legacyRow
	for rows.Next() {
		var r legacyRow
		var capsRaw, constraintsRaw []byte
		var expiresAt sql.NullTime
		if err := rows.Scan(&r.grantID, &r.generation, &r.principal, &capsRaw, &constraintsRaw, &expiresAt); err != nil {
			return fmt.Errorf("failed to scan grant row for digest backfill: %w", err)
		}
		caps, constraints, err := decodePostgresGrantMaterial(capsRaw, constraintsRaw)
		if err != nil {
			return fmt.Errorf("%w: grant %s generation %d has unverifiable authority material; refusing to backfill its digest: %v", ErrGrantMaterialUnverified, r.grantID, r.generation, err)
		}
		r.caps = caps
		r.constraints = constraints
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
			Constraints:  r.constraints,
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

// ensureAuthorityHeads performs the r13 authority upgrade atomically:
// it adds the issued_at material column, creates the authority_heads
// serialization table, seeds one head per existing grant_id, and
// recomputes every stored grant_digest under the normalized
// millisecond ABI. The whole upgrade commits or none of it does, so a
// crash mid-upgrade retries cleanly on next startup.
func (s *Store) ensureAuthorityHeads(ctx context.Context) error {
	var exists bool
	if err := s.db.QueryRowContext(ctx, `
		SELECT to_regclass('authority_heads') IS NOT NULL
	`).Scan(&exists); err != nil {
		return fmt.Errorf("failed to inspect authority_heads: %w", err)
	}
	if exists {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmts := []string{
		`ALTER TABLE authority_grants ADD COLUMN IF NOT EXISTS issued_at TIMESTAMPTZ`,
		`UPDATE authority_grants SET issued_at = created_at WHERE issued_at IS NULL`,
		`CREATE TABLE authority_heads (
			grant_id        TEXT PRIMARY KEY,
			next_generation BIGINT NOT NULL,
			closed          BOOLEAN NOT NULL DEFAULT FALSE,
			version         BIGINT NOT NULL DEFAULT 1
		)`,
		`INSERT INTO authority_heads (grant_id, next_generation)
		 SELECT grant_id, MAX(generation) + 1 FROM authority_grants GROUP BY grant_id`,
	}
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("authority_heads upgrade failed: %w", err)
		}
	}
	if err := recomputeGrantDigests(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// recomputeGrantDigests rewrites every stored grant_digest under the
// current digest algorithm. Digests are derived data: rows issued
// before the millisecond-time ABI carry stale digests that must be
// brought onto the ABI a resolved grant reproduces.
func recomputeGrantDigests(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT grant_id, generation, principal, capabilities, constraints, issued_at, expires_at
		FROM authority_grants
	`)
	if err != nil {
		return fmt.Errorf("failed to scan grants for digest recompute: %w", err)
	}
	defer rows.Close()

	type grantRow struct {
		grantID     string
		generation  int64
		principal   string
		caps        []string
		constraints map[string][]string
		issuedAt    time.Time
		expiresAt   time.Time
	}
	var pending []grantRow
	for rows.Next() {
		var r grantRow
		var capsRaw, constraintsRaw []byte
		var issuedAt, expiresAt sql.NullTime
		if err := rows.Scan(&r.grantID, &r.generation, &r.principal, &capsRaw, &constraintsRaw, &issuedAt, &expiresAt); err != nil {
			return fmt.Errorf("failed to scan grant row for digest recompute: %w", err)
		}
		caps, constraints, err := decodePostgresGrantMaterial(capsRaw, constraintsRaw)
		if err != nil {
			return fmt.Errorf("%w: grant %s generation %d has unverifiable authority material; refusing to recompute its digest: %v", ErrGrantMaterialUnverified, r.grantID, r.generation, err)
		}
		r.caps = caps
		r.constraints = constraints
		if issuedAt.Valid {
			r.issuedAt = time.UnixMilli(issuedAt.Time.UTC().UnixMilli()).UTC()
		}
		if expiresAt.Valid {
			r.expiresAt = time.UnixMilli(expiresAt.Time.UTC().UnixMilli()).UTC()
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
			Constraints:  r.constraints,
			IssuedAt:     r.issuedAt,
			ExpiresAt:    r.expiresAt,
		})
		if _, err := tx.ExecContext(ctx, `
			UPDATE authority_grants SET grant_digest = $3
			WHERE grant_id = $1 AND generation = $2 AND grant_digest <> $3
		`, r.grantID, r.generation, digest); err != nil {
			return fmt.Errorf("failed to recompute grant digest: %w", err)
		}
	}
	return nil
}

// lockAuthorityHead creates the head row for grantID if absent (seeded
// from existing grants) and locks it FOR UPDATE, returning the next
// generation and closed flag. Every mutation of an authority
// reference — issuance, generation revocation, closure — takes this
// same lock, so issue/revoke/close races serialize on one row instead
// of depending on transaction timing.
func (s *Store) lockAuthorityHead(ctx context.Context, tx *sql.Tx, grantID string) (nextGeneration int64, closed bool, err error) {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO authority_heads (grant_id, next_generation)
		SELECT $1, COALESCE(MAX(generation), 0) + 1
		FROM authority_grants WHERE grant_id = $1
		ON CONFLICT (grant_id) DO NOTHING
	`, grantID); err != nil {
		return 0, false, fmt.Errorf("failed to ensure authority head: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `
		SELECT next_generation, closed FROM authority_heads
		WHERE grant_id = $1 FOR UPDATE
	`, grantID).Scan(&nextGeneration, &closed); err != nil {
		return 0, false, fmt.Errorf("failed to lock authority head: %w", err)
	}
	return nextGeneration, closed, nil
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
	var capabilities, constraints []byte
	var issuedAt, expiresAt sql.NullTime
	var unexpired bool
	s.metrics.resolves.Add(1)
	err := s.db.QueryRowContext(ctx, `
		SELECT grant_id, generation, principal, capabilities, constraints, grant_digest,
		       issued_at, expires_at, revoked,
		       (expires_at IS NULL OR expires_at > NOW()) AS unexpired
		FROM authority_grants
		WHERE grant_id = $1
		ORDER BY generation DESC
		LIMIT 1
	`, grantID).Scan(
		&g.ID, &g.Generation, &g.Principal, &capabilities, &constraints, &g.Digest,
		&issuedAt, &expiresAt, &g.Revoked, &unexpired,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			s.metrics.resolveDenied.Add(1)
			return nil, nil
		}
		return nil, fmt.Errorf("authority lookup failed: %w", err)
	}

	if g.Principal != principal || g.Revoked || !unexpired {
		s.metrics.resolveDenied.Add(1)
		return nil, nil
	}
	// Resolve normalizes to Unix milliseconds — the same integer the
	// digest binds — so ComputeGrantDigest(resolved) reproduces the
	// stored digest exactly even when the stored TIMESTAMPTZ carries
	// sub-millisecond precision.
	if issuedAt.Valid {
		g.IssuedAt = time.UnixMilli(issuedAt.Time.UTC().UnixMilli()).UTC()
	}
	if expiresAt.Valid {
		g.ExpiresAt = time.UnixMilli(expiresAt.Time.UTC().UnixMilli()).UTC()
	}

	// Strict decode + digest verification: corrupted authority material
	// must deny, never broaden. An empty capability list is the wildcard
	// and a nil constraint map is unconstrained, so a decode failure must
	// never be allowed to produce either.
	caps, err := parsePostgresTextArray(string(capabilities))
	if err != nil {
		s.metrics.resolveDenied.Add(1)
		return nil, fmt.Errorf("%w: grant %s generation %d: %v", ErrGrantMaterialUnverified, g.ID, g.Generation, err)
	}
	constraintMap, err := decodeConstraintsJSON(string(constraints))
	if err != nil {
		s.metrics.resolveDenied.Add(1)
		return nil, fmt.Errorf("%w: grant %s generation %d: %v", ErrGrantMaterialUnverified, g.ID, g.Generation, err)
	}
	g.Capabilities = caps
	g.Constraints = constraintMap
	if !capability.VerifyGrantDigest(&g) {
		s.metrics.resolveDenied.Add(1)
		return nil, fmt.Errorf("%w: grant %s generation %d stored digest does not match its material", ErrGrantMaterialUnverified, g.ID, g.Generation)
	}

	return &g, nil
}

// ExpiryIsAuthoritative reports that Resolve already evaluates expiry
// against the database clock — VerifyAuthority skips its application
// clock expiry check for this resolver.
func (s *Store) ExpiryIsAuthoritative() bool { return true }

// IssueGrant appends a new immutable generation for grant_id and
// returns the issued snapshot — never updates an existing row in
// place. The generation is allocated from the authority_heads row
// locked FOR UPDATE inside the transaction, so concurrent issuers
// serialize into strictly increasing generations (7, 8, ...) instead
// of racing MAX(generation)+1 into a primary-key collision. The
// returned grant's Digest is bound into execution request digests so
// that the same grant_id under different material is a different
// authority.
//
// A closed authority reference rejects issuance with
// ErrAuthorityClosed. Revocation of a grant that has already admitted
// a durable execution never invalidates that execution's mandatory
// completion, persistence, or reconciliation — admission-time
// authority material is immutable and digest-bound.
func (s *Store) IssueGrant(ctx context.Context, grantID, principal string, capabilities []string, expiresAt time.Time) (*capability.Grant, error) {
	return s.IssueGrantWithConstraints(ctx, grantID, principal, capabilities, nil, expiresAt)
}

// IssueGrantWithConstraints is IssueGrant with resource constraints:
// dimension → admitted values (e.g. "repo" → ["openclaw/crabbox"]).
// Constraints are immutable grant material — they are stored on the
// generation row and bound into grant_digest, so an execution can
// prove exactly which resource scope admitted it.
func (s *Store) IssueGrantWithConstraints(ctx context.Context, grantID, principal string, capabilities []string, constraints map[string][]string, expiresAt time.Time) (*capability.Grant, error) {
	// Store '{}' rather than JSONB null for an unconstrained grant so
	// the column always holds an object matching its declared default.
	if len(constraints) == 0 {
		constraints = map[string][]string{}
	}
	constraintsJSON, err := json.Marshal(constraints)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal grant constraints: %w", err)
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

	var normalizedExpiry time.Time
	if !expiresAt.IsZero() {
		normalizedExpiry = time.UnixMilli(expiresAt.UTC().UnixMilli()).UTC()
	}
	grant := &capability.Grant{
		ID:           grantID,
		Generation:   generation,
		Principal:    principal,
		Capabilities: append([]string(nil), capabilities...),
		Constraints:  constraints,
		IssuedAt:     time.UnixMilli(time.Now().UTC().UnixMilli()).UTC(),
		ExpiresAt:    normalizedExpiry,
	}
	grant.Digest = capability.ComputeGrantDigest(grant)

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO authority_grants
			(grant_id, generation, principal, capabilities, constraints, grant_digest, issued_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, grantID, generation, principal, capabilities, string(constraintsJSON), grant.Digest,
		nullableTime(grant.IssuedAt), nullableTime(grant.ExpiresAt)); err != nil {
		return nil, fmt.Errorf("failed to issue grant: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE authority_heads
		SET next_generation = next_generation + 1, version = version + 1
		WHERE grant_id = $1
	`, grantID); err != nil {
		return nil, fmt.Errorf("failed to advance authority head: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.metrics.issued.Add(1)
	return grant, nil
}

// RevokeGeneration revokes one immutable generation of grant_id,
// stamping the database-clock revocation time. It acquires the same
// authority-head lock as issuance, so a revoke can never interleave
// ambiguously with a concurrent issue: either the generation already
// existed (and is revoked) or it had not been issued when the lock was
// taken.
func (s *Store) RevokeGeneration(ctx context.Context, grantID string, generation int64) error {
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
		SET revoked = TRUE, revoked_at = COALESCE(revoked_at, NOW())
		WHERE grant_id = $1 AND generation = $2
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
	if err := tx.Commit(); err != nil {
		return err
	}
	s.metrics.generationsRevoked.Add(1)
	return nil
}

// CloseAuthorityRef permanently prevents any future generations from
// being issued under grant_id. It takes the same authority-head lock
// as issuance. Closing does not revoke existing generations — an
// already-issued, unexpired, unrevoked generation remains resolvable
// (and remains bound to any durable execution it admitted); use
// RevokeGrant or RevokeGeneration to kill issued material.
func (s *Store) CloseAuthorityRef(ctx context.Context, grantID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, _, err := s.lockAuthorityHead(ctx, tx, grantID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE authority_heads SET closed = TRUE, version = version + 1
		WHERE grant_id = $1
	`, grantID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.metrics.refsClosed.Add(1)
	return nil
}

// RevokeGrant marks every generation of a grant_id as revoked, stamping
// the database-clock revocation time. Existing generations are never
// deleted — they remain as immutable forensic snapshots. The update
// runs under the authority-head lock so it serializes with concurrent
// issuance rather than racing it. RevokeGrant does not close the
// reference: a later IssueGrant mints a new (unrevoked) generation —
// call CloseAuthorityRef when the reference itself must die.
func (s *Store) RevokeGrant(ctx context.Context, grantID string) error {
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
	if err := tx.Commit(); err != nil {
		return err
	}
	s.metrics.grantsRevoked.Add(1)
	return nil
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
