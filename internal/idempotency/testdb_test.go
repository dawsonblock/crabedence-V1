package idempotency

import (
	"database/sql"

	"github.com/openclaw/crabbox/internal/testutil"
)

// openTestDB opens a PostgreSQL connection for live tests, scoped to a
// package-private schema: go test runs package binaries in parallel, and
// this suite issues broad DELETEs and claims any eligible row, so sharing
// the default schema lets other packages' tests steal or remove rows.
func openTestDB(dbURL string) (*sql.DB, error) {
	return testutil.OpenLiveDB(dbURL, "crabbox_test_idempotency")
}
