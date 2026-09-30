// Topology enforcement qualification: the deployment topology is
// explicit, and a declaration that contradicts the replica count or the
// store backend fails closed at startup.

package execution

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openclaw/crabbox/internal/idempotency"
)

func TestResolveTopologyParsing(t *testing.T) {
	cases := []struct {
		name        string
		mode        string
		topology    string
		want        Topology
		wantErrText string
	}{
		{"development defaults to single", "development", "", TopologySingle, ""},
		{"production requires an explicit topology", "production", "", "", "must be explicitly declared in production"},
		{"explicit single", "development", "single", TopologySingle, ""},
		{"explicit cluster", "development", " cluster ", TopologyCluster, ""},
		{"production explicit cluster", "production", "cluster", TopologyCluster, ""},
		{"unknown value fails closed", "development", "sharded", "", "unknown CRABBOX_TOPOLOGY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CRABBOX_MODE", tc.mode)
			t.Setenv("CRABBOX_TOPOLOGY", tc.topology)
			got, err := resolveTopology()
			if tc.wantErrText != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrText) {
					t.Fatalf("resolveTopology() = %q, %v; want an error containing %q", got, err, tc.wantErrText)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveTopology() error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("resolveTopology() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestServeRejectsTopologyContradictions(t *testing.T) {
	cases := []struct {
		name     string
		mode     string
		topology string
		replicas string
		backend  string
		wantErr  string
	}{
		{"single with declared replicas", "development", "single", "2", "sqlite", "contradicts CRABBOX_REPLICAS"},
		{"cluster with sqlite", "development", "cluster", "", "sqlite", "cluster requires the shared postgres store backend"},
		{"cluster with none backend", "development", "cluster", "", "none", "cluster requires the shared postgres store backend"},
		{"cluster with auto-resolved sqlite", "development", "cluster", "", "", "cluster requires the shared postgres store backend"},
		{"production without topology", "production", "", "", "sqlite", "must be explicitly declared in production"},
		{"unknown topology", "development", "sharded", "", "sqlite", "unknown CRABBOX_TOPOLOGY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CRABBOX_GITHUB_ENABLED", "false")
			t.Setenv("CRABBOX_GITHUB_TOKEN", "")
			t.Setenv("GITHUB_TOKEN", "")
			t.Setenv("CRABEDENCE_DATABASE_URL", "")
			t.Setenv("CRABBOX_MODE", tc.mode)
			t.Setenv("CRABBOX_TOPOLOGY", tc.topology)
			t.Setenv("CRABBOX_REPLICAS", tc.replicas)
			t.Setenv("CRABEDENCE_STORE_BACKEND", tc.backend)
			err := Serve(context.Background(), ServeOptions{})
			if err == nil {
				t.Fatal("serve must refuse a contradictory topology declaration")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("serve error = %q, want substring %q", err, tc.wantErr)
			}
		})
	}
}

// TestIndependentSQLiteLedgersMintDivergentProviderTokens demonstrates
// the hazard the cluster topology gate exists to prevent: two replicas
// on independent SQLite files both admit the same idempotency key and
// derive different provider idempotency tokens for it, so a retry
// landing on the peer replica would dispatch the effect a second time.
// Production configuration refuses that topology (see
// TestServeRejectsTopologyContradictions and the cluster key policy).
func TestIndependentSQLiteLedgersMintDivergentProviderTokens(t *testing.T) {
	ctx := context.Background()
	const digest = "digest-for-one-logical-request"
	executions := make(map[string]string)
	tokens := make(map[string]string)
	for _, replica := range []string{"replica-a", "replica-b"} {
		stateDir := filepath.Join(t.TempDir(), replica)
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		db, err := idempotency.OpenSQLiteDB(filepath.Join(stateDir, "crabedence.db"))
		if err != nil {
			t.Fatalf("%s: open store: %v", replica, err)
		}
		store, err := idempotency.NewSQLiteStore(db)
		if err != nil {
			db.Close()
			t.Fatalf("%s: sqlite store: %v", replica, err)
		}
		acq, err := store.AcquireWithAuthority(ctx, "shared-key", "alice@example.com",
			"test.counter.increment", digest, idempotency.AuthorityBinding{}, "MUTATION",
			idempotency.DefaultLeaseDuration)
		if err != nil {
			db.Close()
			t.Fatalf("%s: acquire: %v", replica, err)
		}
		if !acq.Acquired() || acq.Record == nil {
			db.Close()
			t.Fatalf("%s: expected a fresh reservation, got %+v", replica, acq)
		}
		executions[replica] = acq.Record.ExecutionID
		tokens[replica] = idempotency.ProviderIdempotencyKey(acq.Record.ExecutionID, digest, "test-counter")
		db.Close()
	}
	if executions["replica-a"] == executions["replica-b"] {
		t.Fatalf("independent ledgers minted the same execution ID %q", executions["replica-a"])
	}
	if tokens["replica-a"] == tokens["replica-b"] {
		t.Fatalf("independent ledgers minted the same provider token %q for one idempotency key", tokens["replica-a"])
	}
}
