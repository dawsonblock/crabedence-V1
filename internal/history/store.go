package history

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	_ "modernc.org/sqlite"
)

// schemaVersion is bumped only by a migration that knows how to carry
// every existing row forward — the store's history is itself history,
// never silently rebuilt.
//
// v2 adds the trust layer: store_meta carries the store's stable
// identity (bound into witnessed checkpoints so a replaced database
// cannot inherit witnessed history), and assessments carries
// versioned verification verdicts kept apart from the immutable
// observations they describe.
const schemaVersion = 2

// Store is the append-only event chain. One process owns the writer
// at a time (the writer mutex serializes appends; the chain's seq
// assignment requires it), and readers always see a chain-consistent
// snapshot.
type Store struct {
	db *sql.DB
	wr sync.Mutex
}

// OpenStore opens (creating if needed) the history store at path.
// Unlike the executor ledger it holds no flock — memory is shared
// read infrastructure, not a single-owner execution registry — but
// appends are still serialized in-process.
func OpenStore(path string) (*Store, error) {
	if strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("history path must not contain '?' or '#': %q", path)
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// OpenReadOnly opens the store strictly for verification and query:
// query_only(1) refuses every write at the SQLite layer, so a
// verifier cannot mutate the memory it checks — including the
// side-effects a normal open performs (WAL checkpoint, schema
// migration).
func OpenReadOnly(path string) (*Store, error) {
	if strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("history path must not contain '?' or '#': %q", path)
	}
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("inspect history %s: %w", path, err)
	}
	return &Store{db: db}, nil
}

func (s *Store) migrate() error {
	var v int
	err := s.db.QueryRow(`SELECT version FROM schema_version`).Scan(&v)
	switch {
	case err == nil && v == schemaVersion:
		return nil
	case err == nil && v == 1:
		// v1 → v2: add the trust layer without touching the chain —
		// the events table is carried forward byte-for-byte; the
		// store gains the identity checkpoints bind to.
		if _, err := s.db.Exec(`
			CREATE TABLE IF NOT EXISTS store_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
			CREATE TABLE IF NOT EXISTS assessments(
				seq INTEGER PRIMARY KEY AUTOINCREMENT,
				subject_key TEXT NOT NULL,
				verifier TEXT NOT NULL,
				rules_version TEXT NOT NULL,
				trust_set_sha TEXT NOT NULL,
				input_sha TEXT NOT NULL,
				result TEXT NOT NULL,
				detail TEXT NOT NULL DEFAULT '',
				assessed_at_ms INTEGER NOT NULL,
				UNIQUE(subject_key, verifier, rules_version, trust_set_sha, input_sha, result)
			);
			CREATE INDEX IF NOT EXISTS idx_assessments_subject ON assessments(subject_key)`); err != nil {
			return fmt.Errorf("history migration v2: %w", err)
		}
		if err := s.ensureStoreID(); err != nil {
			return err
		}
		if _, err := s.db.Exec(`UPDATE schema_version SET version = ?`, schemaVersion); err != nil {
			return fmt.Errorf("history migration v2: %w", err)
		}
		return nil
	case err == nil:
		return fmt.Errorf("history schema version %d, expected %d", v, schemaVersion)
	}
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);
		CREATE TABLE IF NOT EXISTS store_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
		CREATE TABLE IF NOT EXISTS events(
			seq INTEGER PRIMARY KEY AUTOINCREMENT,
			dedupe_key TEXT NOT NULL UNIQUE,
			kind TEXT NOT NULL,
			subject TEXT NOT NULL,
			correlation TEXT NOT NULL DEFAULT '',
			source TEXT NOT NULL,
			occurred_at INTEGER NOT NULL,
			payload BLOB NOT NULL,
			sha256 TEXT NOT NULL,
			prev_sha256 TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS assessments(
			seq INTEGER PRIMARY KEY AUTOINCREMENT,
			subject_key TEXT NOT NULL,
			verifier TEXT NOT NULL,
			rules_version TEXT NOT NULL,
			trust_set_sha TEXT NOT NULL,
			input_sha TEXT NOT NULL,
			result TEXT NOT NULL,
			detail TEXT NOT NULL DEFAULT '',
			assessed_at_ms INTEGER NOT NULL,
			UNIQUE(subject_key, verifier, rules_version, trust_set_sha, input_sha, result)
		);
		CREATE INDEX IF NOT EXISTS idx_events_kind_time ON events(kind, occurred_at);
		CREATE INDEX IF NOT EXISTS idx_events_correlation ON events(correlation);
		CREATE INDEX IF NOT EXISTS idx_events_subject ON events(subject);
		CREATE INDEX IF NOT EXISTS idx_assessments_subject ON assessments(subject_key)`); err != nil {
		return fmt.Errorf("history migration: %w", err)
	}
	if err := s.ensureStoreID(); err != nil {
		return err
	}
	if _, err := s.db.Exec(`INSERT INTO schema_version(version) VALUES (?)`, schemaVersion); err != nil {
		return fmt.Errorf("history migration: %w", err)
	}
	return nil
}

// ensureStoreID assigns the store's stable identity exactly once —
// a randomly generated value no operator chooses, written at creation
// (or v1→v2 migration) and bound into every checkpoint thereafter.
func (s *Store) ensureStoreID() error {
	var existing string
	err := s.db.QueryRow(`SELECT value FROM store_meta WHERE key = 'store_id'`).Scan(&existing)
	if err == nil && existing != "" {
		return nil
	}
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("history store identity: %w", err)
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Errorf("history store identity: %w", err)
	}
	id := "hist-" + hex.EncodeToString(b[:])
	if _, err := s.db.Exec(`INSERT INTO store_meta(key, value) VALUES ('store_id', ?)`, id); err != nil {
		return fmt.Errorf("history store identity: %w", err)
	}
	return nil
}

// tail returns the chain head inside tx: the sequence and digest the
// next appended event must link to.
func tail(tx *sql.Tx) (int64, string, error) {
	var seq int64
	var sha string
	err := tx.QueryRow(`SELECT seq, sha256 FROM events ORDER BY seq DESC LIMIT 1`).Scan(&seq, &sha)
	if err == sql.ErrNoRows {
		return 0, genesisPrev, nil
	}
	return seq, sha, err
}

// Append adds events to the chain in one transaction, in slice order.
// Each event's digest is computed over its identity and the running
// chain head, so insertion order is itself committed. An event whose
// dedupe key already exists is skipped — re-ingesting the same
// record is idempotent by construction. Returns the events actually
// appended (with Seq/SHA256/PrevSHA256 filled in).
func (s *Store) Append(events ...*Event) ([]*Event, error) {
	s.wr.Lock()
	defer s.wr.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	seq, prev, err := tail(tx)
	if err != nil {
		return nil, err
	}
	var appended []*Event
	for _, e := range events {
		if err := e.validate(); err != nil {
			return nil, err
		}
		var exists int
		if err := tx.QueryRow(`SELECT 1 FROM events WHERE dedupe_key = ?`, e.DedupeKey).Scan(&exists); err == nil {
			continue
		} else if err != sql.ErrNoRows {
			return nil, err
		}
		e.SHA256 = digest(seq+1, e.DedupeKey, e.Kind, e.Subject, e.Correlation, e.Source, e.OccurredAt, e.Payload, prev)
		e.PrevSHA256 = prev
		res, err := tx.Exec(`INSERT INTO events
			(dedupe_key, kind, subject, correlation, source, occurred_at, payload, sha256, prev_sha256)
			VALUES (?,?,?,?,?,?,?,?,?)`,
			e.DedupeKey, e.Kind, e.Subject, e.Correlation, e.Source, e.OccurredAt,
			e.Payload, e.SHA256, e.PrevSHA256)
		if err != nil {
			return nil, err
		}
		e.Seq, _ = res.LastInsertId()
		seq, prev = e.Seq, e.SHA256
		appended = append(appended, e)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return appended, nil
}

// QueryOpts selects events for Query. Empty fields are unbounded;
// BeforeSeq paginates backwards from a previously returned Seq.
type QueryOpts struct {
	Kinds       []string
	Correlation string
	Subject     string
	Since       int64 // unix ms, inclusive
	Until       int64 // unix ms, inclusive
	BeforeSeq   int64
	Limit       int
}

// Query returns matching events newest-first (chain order).
func (s *Store) Query(q QueryOpts) ([]*Event, error) {
	var b strings.Builder
	b.WriteString(`SELECT seq, dedupe_key, kind, subject, correlation, source, occurred_at, payload, sha256, prev_sha256
		FROM events WHERE 1=1`)
	var args []any
	if len(q.Kinds) > 0 {
		b.WriteString(` AND kind IN (`)
		for i, k := range q.Kinds {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteByte('?')
			args = append(args, k)
		}
		b.WriteByte(')')
	}
	if q.Correlation != "" {
		b.WriteString(` AND correlation = ?`)
		args = append(args, q.Correlation)
	}
	if q.Subject != "" {
		b.WriteString(` AND subject = ?`)
		args = append(args, q.Subject)
	}
	if q.Since != 0 {
		b.WriteString(` AND occurred_at >= ?`)
		args = append(args, q.Since)
	}
	if q.Until != 0 {
		b.WriteString(` AND occurred_at <= ?`)
		args = append(args, q.Until)
	}
	if q.BeforeSeq != 0 {
		b.WriteString(` AND seq < ?`)
		args = append(args, q.BeforeSeq)
	}
	b.WriteString(` ORDER BY seq DESC`)
	if q.Limit > 0 {
		b.WriteString(` LIMIT ?`)
		args = append(args, q.Limit)
	}
	rows, err := s.db.Query(b.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Event
	for rows.Next() {
		e := &Event{}
		var payload []byte
		if err := rows.Scan(&e.Seq, &e.DedupeKey, &e.Kind, &e.Subject, &e.Correlation,
			&e.Source, &e.OccurredAt, &payload, &e.SHA256, &e.PrevSHA256); err != nil {
			return nil, err
		}
		e.Payload = payload
		out = append(out, e)
	}
	return out, rows.Err()
}

// Stats reports the chain's size, per-kind event counts, and the
// digest of the chain's head (the last appended event).
func (s *Store) Stats() (total int, perKind map[string]int, head string, err error) {
	perKind = map[string]int{}
	err = s.db.QueryRow(`SELECT COUNT(*), COALESCE((SELECT sha256 FROM events ORDER BY seq DESC LIMIT 1), '') FROM events`).Scan(&total, &head)
	if err != nil {
		return 0, nil, "", err
	}
	rows, err := s.db.Query(`SELECT kind, COUNT(*) FROM events GROUP BY kind ORDER BY kind`)
	if err != nil {
		return 0, nil, "", err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return 0, nil, "", err
		}
		perKind[k] = n
	}
	return total, perKind, head, rows.Err()
}

// Verify re-derives the entire chain: every event's digest from its
// stored fields, every prev link from the preceding row, seq
// contiguity, and the genesis head. Returns one finding per
// discrepancy; an empty result means the stored history is exactly
// the history this store appended.
func (s *Store) Verify() []string {
	var findings []string
	rows, err := s.db.Query(`SELECT seq, dedupe_key, kind, subject, correlation, source, occurred_at, payload, sha256, prev_sha256
		FROM events ORDER BY seq`)
	if err != nil {
		return []string{fmt.Sprintf("history verify: %v", err)}
	}
	defer rows.Close()
	prev := genesisPrev
	var expectSeq int64 = 1
	for rows.Next() {
		e := &Event{}
		var payload []byte
		if err := rows.Scan(&e.Seq, &e.DedupeKey, &e.Kind, &e.Subject, &e.Correlation,
			&e.Source, &e.OccurredAt, &payload, &e.SHA256, &e.PrevSHA256); err != nil {
			return append(findings, fmt.Sprintf("history verify scan: %v", err))
		}
		e.Payload = payload
		if e.Seq != expectSeq {
			findings = append(findings, fmt.Sprintf("event seq gap: expected %d, found %d", expectSeq, e.Seq))
			expectSeq = e.Seq
		}
		if e.PrevSHA256 != prev {
			findings = append(findings, fmt.Sprintf("event seq %d: prev link broken", e.Seq))
		}
		if want := digest(e.Seq, e.DedupeKey, e.Kind, e.Subject, e.Correlation,
			e.Source, e.OccurredAt, e.Payload, e.PrevSHA256); want != e.SHA256 {
			findings = append(findings, fmt.Sprintf("event seq %d (%s %s): digest mismatch — payload or identity altered", e.Seq, e.Kind, e.Subject))
		}
		prev = e.SHA256
		expectSeq++
	}
	if err := rows.Err(); err != nil {
		findings = append(findings, fmt.Sprintf("history verify: %v", err))
	}
	return findings
}

// Close releases the store.
func (s *Store) Close() error {
	return s.db.Close()
}
