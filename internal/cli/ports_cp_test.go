package cli

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestPortsCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := App{Stdout: &stdout, Stderr: &stderr}
	err := app.ports(context.Background(), []string{"--provider", "docker-sandbox", "--id", "blue-box", "--publish", "8080"})
	if err != nil {
		t.Fatalf("ports err=%v", err)
	}
	if got := stdout.String(); !strings.Contains(got, "127.0.0.1:41000->3000/tcp") {
		t.Fatalf("stdout=%q", got)
	}

	stdout.Reset()
	err = app.ports(context.Background(), []string{"--provider", "docker-sandbox", "--id", "blue-box", "--json"})
	if err != nil {
		t.Fatalf("ports json err=%v", err)
	}
	if got := stdout.String(); !strings.Contains(got, "127.0.0.1:41000->3000/tcp") {
		t.Fatalf("json stdout=%q", got)
	}

	err = app.ports(context.Background(), []string{"--provider", "docker-sandbox", "--id", "blue-box", "--publish", "8080", "--unpublish", "8080:3000"})
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("conflicting flags err=%v", err)
	}
	err = app.ports(context.Background(), []string{"--provider", "docker-sandbox", "--id", "blue-box", "extra"})
	if err == nil || !strings.Contains(err.Error(), "usage: crabbox ports") {
		t.Fatalf("extra positional err=%v", err)
	}
	stderr.Reset()
	err = app.Run(context.Background(), []string{"ports", "--help"})
	var exitErr ExitError
	if !AsExitError(err, &exitErr) || exitErr.Code != 0 {
		t.Fatalf("ports --help err=%v", err)
	}
	if !strings.Contains(stderr.String(), "Usage") {
		t.Fatalf("ports help=%q", stderr.String())
	}
}

func TestLoadPortsConfigRoutesOrdinaryClaims(t *testing.T) {
	load := func(t *testing.T, identifier string, args ...string) Config {
		t.Helper()
		defaults := defaultConfig()
		fs := newFlagSet("ports claim routing", io.Discard)
		provider := fs.String("provider", defaults.Provider, "")
		providerFlags := registerProviderFlags(fs, defaults)
		targetFlags := registerTargetFlags(fs, defaults)
		if err := parseFlags(fs, args); err != nil {
			t.Fatal(err)
		}
		cfg, err := loadPortsConfig(fs, *provider, providerFlags, targetFlags, identifier)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	for _, tt := range []struct {
		name       string
		leaseID    string
		slug       string
		identifier string
	}{
		{name: "exact id", leaseID: "cbx_1335aa000001", slug: "ports-exact", identifier: "cbx_1335aa000001"},
		{name: "unambiguous slug", leaseID: "cbx_1335aa000002", slug: "Ports Slug", identifier: "ports-slug"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			setupClaimRoutingCommandTest(t, claimRoutingConfiguredProvider)
			mustWriteClaimRoutingTestClaim(t, tt.leaseID, tt.slug, claimRoutingUsableProvider)
			cfg := load(t, tt.identifier)
			if cfg.Provider != claimRoutingUsableProvider || cfg.providerSelectionSource != providerSelectionLeaseContext {
				t.Fatalf("provider=%q source=%q", cfg.Provider, cfg.providerSelectionSource)
			}
		})
	}

	t.Run("explicit provider wins", func(t *testing.T) {
		setupClaimRoutingCommandTest(t, claimRoutingConfiguredProvider)
		mustWriteClaimRoutingTestClaim(t, "cbx_1335aa000003", "ports-explicit", claimRoutingUsableProvider)
		cfg := load(t, "ports-explicit", "--provider", claimRoutingExplicitProvider)
		if cfg.Provider != claimRoutingExplicitProvider || cfg.providerSelectionSource != providerSelectionFlag {
			t.Fatalf("provider=%q source=%q", cfg.Provider, cfg.providerSelectionSource)
		}
	})
}

func TestCopyCommand(t *testing.T) {
	app := App{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	err := app.copyCommand(context.Background(), []string{"--provider", "docker-sandbox", "--id", "blue-box", "./coverage.xml", "SANDBOX:/tmp/coverage.xml"})
	if err != nil {
		t.Fatalf("copy err=%v", err)
	}
	err = app.copyCommand(context.Background(), []string{"--provider", "docker-sandbox", "--id", "blue-box", "./coverage.xml", "./out.xml"})
	if err == nil || !strings.Contains(err.Error(), "usage: crabbox cp") {
		t.Fatalf("missing sandbox path err=%v", err)
	}
	err = app.copyCommand(context.Background(), []string{"./coverage.xml", "SANDBOX:/tmp/coverage.xml"})
	if err == nil || !strings.Contains(err.Error(), "usage: crabbox cp") {
		t.Fatalf("missing id err=%v", err)
	}
}

func TestPortsRejectsUnsupportedProvider(t *testing.T) {
	err := (App{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}).ports(context.Background(), []string{"--provider", "aws", "--id", "cbx_123"})
	if err == nil || !strings.Contains(err.Error(), "does not support ports") {
		t.Fatalf("err=%v", err)
	}
}

func TestCopyRejectsUnsupportedProvider(t *testing.T) {
	err := (App{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}).copyCommand(context.Background(), []string{"--provider", "service-control-test", "--id", "cbx_123", "./file.txt", "SANDBOX:/tmp/file.txt"})
	if err == nil || !strings.Contains(err.Error(), "does not support cp") {
		t.Fatalf("err=%v", err)
	}
}
