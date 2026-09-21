package main

import (
	"io"
	"strings"
	"testing"
	"time"
)

func getenvWith(k, v string) func(string) string {
	return func(key string) string {
		if key == k {
			return v
		}
		return ""
	}
}

func TestLoadConfig(t *testing.T) {
	dsn := getenvWith("CRABEDENCE_DATABASE_URL", "postgres://x")
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)

	tests := []struct {
		name    string
		argv    []string
		env     func(string) string
		wantErr string
	}{
		{
			name:    "missing principal",
			argv:    []string{"--capability", "a.b"},
			env:     dsn,
			wantErr: "--principal is required",
		},
		{
			name:    "missing capability",
			argv:    []string{"--principal", "alice@example.com"},
			env:     dsn,
			wantErr: "at least one --capability",
		},
		{
			name:    "missing dsn",
			argv:    []string{"--principal", "alice@example.com", "--capability", "a.b"},
			env:     func(string) string { return "" },
			wantErr: "CRABEDENCE_DATABASE_URL is not set",
		},
		{
			name:    "bad expiry",
			argv:    []string{"--principal", "p", "--capability", "a.b", "--expires-at", "tomorrow"},
			env:     dsn,
			wantErr: "must be RFC3339",
		},
		{
			name:    "past expiry",
			argv:    []string{"--principal", "p", "--capability", "a.b", "--expires-at", past},
			env:     dsn,
			wantErr: "in the past",
		},
		{
			name:    "empty capability rejected",
			argv:    []string{"--principal", "p", "--capability", ""},
			env:     dsn,
			wantErr: "must not be empty",
		},
		{
			name: "ok",
			argv: []string{"--principal", "p", "--capability", "a.b",
				"--capability", "c.d", "--expires-at", future, "--grant-id", "grant_x"},
			env: dsn,
		},
		{
			name: "generated grant id",
			argv: []string{"--principal", "p", "--capability", "a.b"},
			env:  dsn,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := loadConfig(tt.argv, tt.env, io.Discard)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.dsn == "" || cfg.principal == "" || len(cfg.caps) == 0 {
				t.Fatalf("incomplete config: %+v", cfg)
			}
			if cfg.grantID == "" {
				t.Fatal("grant id should be generated when --grant-id is absent")
			}
		})
	}
}

func TestLoadConfigNeverAcceptsGeneration(t *testing.T) {
	dsn := getenvWith("CRABEDENCE_DATABASE_URL", "postgres://x")
	// There is deliberately no --generation flag: the store allocates
	// generations. An operator attempting to pass one must fail parsing.
	_, err := loadConfig([]string{
		"--principal", "p", "--capability", "a.b", "--generation", "7",
	}, dsn, io.Discard)
	if err == nil {
		t.Fatal("--generation must not be accepted: generations are store-allocated")
	}
}
