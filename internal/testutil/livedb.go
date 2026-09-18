package testutil

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
)

var liveSchemaName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// OpenLiveDB opens a PostgreSQL connection for live tests, scoped to a
// dedicated schema so concurrent package test binaries cannot interfere.
// `go test` runs each package's test binary in parallel against the same
// database, and the live suites issue broad DELETEs and claim any
// eligible row — a shared schema lets one package delete or claim rows
// mid-flight in another. The schema is created if missing, and every
// pooled connection is pinned to it via the search_path runtime param.
func OpenLiveDB(dbURL, schema string) (*sql.DB, error) {
	if !liveSchemaName.MatchString(schema) {
		return nil, fmt.Errorf("invalid live-test schema name %q", schema)
	}
	admin, err := sql.Open("pgx", dbURL)
	if err != nil {
		return nil, err
	}
	if _, err := admin.ExecContext(context.Background(),
		`CREATE SCHEMA IF NOT EXISTS `+schema); err != nil {
		admin.Close()
		return nil, fmt.Errorf("create live-test schema %s: %w", schema, err)
	}
	admin.Close()

	var scoped string
	if strings.Contains(dbURL, "://") {
		sep := "?"
		if strings.Contains(dbURL, "?") {
			sep = "&"
		}
		scoped = dbURL + sep + "search_path=" + schema
	} else {
		// Keyword DSN — pgx forwards unknown keys as server runtime params.
		scoped = dbURL + " search_path=" + schema
	}
	db, err := sql.Open("pgx", scoped)
	if err != nil {
		return nil, err
	}
	// Cap the pool: unlimited per-test pools across parallel package
	// binaries exhaust the server's max_connections (default 100).
	db.SetMaxOpenConns(10)
	return db, nil
}
