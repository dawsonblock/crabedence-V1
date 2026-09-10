package idempotency

import (
	"database/sql"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// openTestDB opens a PostgreSQL connection for live tests.
func openTestDB(dbURL string) (*sql.DB, error) {
	return sql.Open("pgx", dbURL)
}
