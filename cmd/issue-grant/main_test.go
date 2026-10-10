package main

import (
	"io"
	"reflect"
	"strings"
	"testing"
)

func envOf(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

// The target database is chosen from the environment, so a grant issued here
// is resolvable by a service started the same way. PostgreSQL wins when both
// are set, matching the documented rule in the package comment.
func TestLoadConfigSelectsTheBackendFromTheEnvironment(t *testing.T) {
	args := []string{"--principal", "alice@example.com", "--capability", "test.counter.increment"}

	for _, tc := range []struct {
		name        string
		environment map[string]string
		wantBackend backend
		wantTarget  string
	}{
		{
			name:        "postgres when a DSN is set",
			environment: map[string]string{"CRABEDENCE_DATABASE_URL": "postgres://example/crabbox"},
			wantBackend: backendPostgres,
			wantTarget:  "postgres://example/crabbox",
		},
		{
			name:        "sqlite when only a store path is set",
			environment: map[string]string{"CRABEDENCE_STORE_PATH": "/tmp/crabedence.db"},
			wantBackend: backendSQLite,
			wantTarget:  "/tmp/crabedence.db",
		},
		{
			name: "postgres wins when both are set",
			environment: map[string]string{
				"CRABEDENCE_DATABASE_URL": "postgres://example/crabbox",
				"CRABEDENCE_STORE_PATH":   "/tmp/crabedence.db",
			},
			wantBackend: backendPostgres,
			wantTarget:  "postgres://example/crabbox",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadConfig(args, envOf(tc.environment), io.Discard)
			if err != nil {
				t.Fatalf("loadConfig: %v", err)
			}
			if cfg.backend != tc.wantBackend {
				t.Fatalf("backend: got %q, want %q", cfg.backend, tc.wantBackend)
			}
			target := cfg.dsn
			if cfg.backend == backendSQLite {
				target = cfg.sqlitePath
			}
			if target != tc.wantTarget {
				t.Fatalf("target: got %q, want %q", target, tc.wantTarget)
			}
		})
	}
}

func TestLoadConfigWithoutATargetFailsClosed(t *testing.T) {
	args := []string{"--principal", "alice@example.com", "--capability", "test.counter.increment"}
	_, err := loadConfig(args, envOf(nil), io.Discard)
	if err == nil {
		t.Fatal("a missing target must fail closed")
	}
	// The message must name both backends, so an operator with the embedded
	// default configured knows what to set.
	for _, want := range []string{"CRABEDENCE_DATABASE_URL", "CRABEDENCE_STORE_PATH"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error should name %s, got %q", want, err.Error())
		}
	}
}

func TestLoadConfigStillValidatesItsInputs(t *testing.T) {
	env := envOf(map[string]string{"CRABEDENCE_STORE_PATH": "/tmp/crabedence.db"})
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "principal is required",
			args: []string{"--capability", "test.counter.increment"},
			want: "--principal is required",
		},
		{
			name: "a capability is required",
			args: []string{"--principal", "alice@example.com"},
			want: "at least one --capability",
		},
		{
			name: "expiry must be in the future",
			args: []string{"--principal", "alice@example.com", "--capability", "test.counter.increment", "--expires-at", "2020-01-01T00:00:00Z"},
			want: "is in the past",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadConfig(tc.args, env, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error containing %q, got %v", tc.want, err)
			}
		})
	}
}

var sqliteEnv = envOf(map[string]string{"CRABEDENCE_STORE_PATH": "/tmp/crabedence.db"})

// The regression that motivates the policy: github.issue.create declares repo
// in its descriptor, so a grant that never mentions repo must be a named
// rejection — not the all-repositories grant omission used to mint.
func TestLoadConfigOmittedDeclaredDimensionIsRejection(t *testing.T) {
	_, err := loadConfig(
		[]string{"--principal", "alice@example.com", "--capability", "github.issue.create"},
		sqliteEnv, io.Discard,
	)
	if err == nil {
		t.Fatal("issuing a github.issue.create grant with no repo scope must reject")
	}
	for _, want := range []string{"grant issuance rejected", `"repo"`, "explicit unconstrained acknowledgement"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("rejection should carry %q, got %q", want, err.Error())
		}
	}
}

func TestLoadConfigDeclaredDimensionsAcceptableBothWays(t *testing.T) {
	for _, tc := range []struct {
		name            string
		args            []string
		wantConstraints map[string][]string
	}{
		{
			name: "concrete constraint",
			args: []string{
				"--principal", "alice@example.com",
				"--capability", "github.issue.create",
				"--constraint", "repo=example-org/my-app",
			},
			wantConstraints: map[string][]string{"repo": {"example-org/my-app"}},
		},
		{
			name: "explicit unconstrained acknowledgement",
			args: []string{
				"--principal", "alice@example.com",
				"--capability", "github.issue.create",
				"--unconstrained", "repo",
			},
			wantConstraints: map[string][]string{"repo": {"*"}},
		},
		{
			name: "pull request with both dimensions",
			args: []string{
				"--principal", "alice@example.com",
				"--capability", "github.pr.create",
				"--constraint", "repo=example-org/my-app",
				"--unconstrained", "base",
			},
			wantConstraints: map[string][]string{"repo": {"example-org/my-app"}, "base": {"*"}},
		},
		{
			name: "capability declaring no dimensions",
			args: []string{
				"--principal", "alice@example.com",
				"--capability", "test.counter.increment",
			},
			wantConstraints: nil,
		},
		{
			// The qualification extension resolves through the issuance
			// catalog so its grants stay issuable for the harness.
			name: "qualification extension capability",
			args: []string{
				"--principal", "alice@example.com",
				"--capability", "qualification.critical.commit",
			},
			wantConstraints: nil,
		},
		{
			name: "wildcard capability with every dimension acknowledged",
			args: []string{
				"--principal", "alice@example.com",
				"--capability", "*",
				"--unconstrained", "repo",
				"--unconstrained", "base",
			},
			wantConstraints: map[string][]string{"repo": {"*"}, "base": {"*"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadConfig(tc.args, sqliteEnv, io.Discard)
			if err != nil {
				t.Fatalf("loadConfig: %v", err)
			}
			if !reflect.DeepEqual(map[string][]string(cfg.constraints), tc.wantConstraints) {
				t.Fatalf("effective constraints: got %v, want %v", cfg.constraints, tc.wantConstraints)
			}
		})
	}
}

// Every declared dimension is enforced — repo alone does not satisfy a
// capability that also binds base.
func TestLoadConfigPullRequestRequiresBothDimensions(t *testing.T) {
	_, err := loadConfig(
		[]string{
			"--principal", "alice@example.com",
			"--capability", "github.pr.create",
			"--constraint", "repo=example-org/my-app",
		},
		sqliteEnv, io.Discard,
	)
	if err == nil || !strings.Contains(err.Error(), `"base"`) {
		t.Fatalf("covering repo but not base must name base, got %v", err)
	}
}

// Wildcard-all issuance is deliberate: it cannot be produced by an empty
// scope declaration.
func TestLoadConfigWildcardCapabilityStillRequiresScope(t *testing.T) {
	_, err := loadConfig(
		[]string{"--principal", "alice@example.com", "--capability", "*"},
		sqliteEnv, io.Discard,
	)
	if err == nil {
		t.Fatal("a wildcard-all grant with no scope declarations must reject")
	}
	if !strings.Contains(err.Error(), "grant issuance rejected") {
		t.Fatalf("expected an issuance rejection, got %q", err.Error())
	}
}

func TestLoadConfigScopeRejections(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "conflicting declarations",
			args: []string{
				"--principal", "alice@example.com",
				"--capability", "github.issue.create",
				"--constraint", "repo=example-org/my-app",
				"--unconstrained", "repo",
			},
			want: "declared both constrained and unconstrained",
		},
		{
			name: "unknown dimension",
			args: []string{
				"--principal", "alice@example.com",
				"--capability", "github.issue.create",
				"--constraint", "repo=example-org/my-app",
				"--constraint", "tenant=acme",
			},
			want: `unknown resource dimension "tenant"`,
		},
		{
			name: "wildcard value smuggled through a constraint",
			args: []string{
				"--principal", "alice@example.com",
				"--capability", "github.issue.create",
				"--constraint", "repo=*",
			},
			want: "wildcard shorthand",
		},
		{
			name: "duplicate constraint value",
			args: []string{
				"--principal", "alice@example.com",
				"--capability", "github.issue.create",
				"--constraint", "repo=a/b",
				"--constraint", "repo=a/b",
			},
			want: "declared twice",
		},
		{
			name: "duplicate acknowledgement",
			args: []string{
				"--principal", "alice@example.com",
				"--capability", "github.issue.create",
				"--unconstrained", "repo",
				"--unconstrained", "repo",
			},
			want: "acknowledged unconstrained twice",
		},
		{
			name: "unknown capability",
			args: []string{
				"--principal", "alice@example.com",
				"--capability", "github.nonexistent",
				"--constraint", "repo=a/b",
			},
			want: "not in the issuance catalog",
		},
		{
			name: "wildcard mixed with a named capability",
			args: []string{
				"--principal", "alice@example.com",
				"--capability", "*",
				"--capability", "github.issue.create",
				"--unconstrained", "repo",
				"--unconstrained", "base",
			},
			want: "cannot be combined with named capabilities",
		},
		{
			name: "dimension no requested capability declares",
			args: []string{
				"--principal", "alice@example.com",
				"--capability", "test.counter.increment",
				"--constraint", "repo=a/b",
			},
			want: `unknown resource dimension "repo"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadConfig(tc.args, sqliteEnv, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want a rejection containing %q, got %v", tc.want, err)
			}
		})
	}
}
