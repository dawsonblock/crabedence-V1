package main

import (
	"io"
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
			args: []string{"--principal", "alice@example.com", "--capability", "c", "--expires-at", "2020-01-01T00:00:00Z"},
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
