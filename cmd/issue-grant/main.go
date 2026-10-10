// Command issue-grant issues an authority grant through the same
// authority.Store the execution service resolves against — never by
// constructing SQL rows by hand. Grants are immutable generations: the
// store assigns the generation under a serialized head lock, so callers
// supply the grant material and read back the assigned generation.
//
// The target database is selected from the environment only — never from
// argv, where a DSN would leak into process listings and shell history:
//
//	CRABEDENCE_DATABASE_URL   PostgreSQL, the clustered backend
//	CRABEDENCE_STORE_PATH     SQLite, the single-host default
//
// PostgreSQL wins when both are set. This mirrors `crabbox serve-exec`, so a
// grant issued here is resolvable by the service started the same way —
// including the embedded SQLite default, which previously had no issuing path
// at all.
//
// Usage:
//
//	issue-grant --principal <id> --capability <id> [--capability <id>...] \
//	  [--constraint <dimension=value>...] [--unconstrained <dimension>...] \
//	  [--grant-id <id>] [--expires-at <RFC3339>]
//
// Every resource dimension the requested capabilities declare must be
// addressed exactly once: --constraint dimension=value binds it, and
// --unconstrained dimension acknowledges deliberate wildcard scope. An omitted
// dimension is a rejection — omission can never silently broaden authority.
//
// Prints the issued authority reference as JSON on stdout:
//
//	{"grant_id":"…","generation":N,"grant_digest":"sha256…",…}
//
// Clients normally carry no reference at all: with peer authentication the
// service brokers the authenticated principal's grants itself. When a
// specific grant must be named, pass grant_id through the
// CRABEDENCE_AUTHORITY_REF environment variable — never on argv, which is
// readable by every account on the host.
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/openclaw/crabbox/internal/authority"
	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/execution"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// grantIssuer is the issuing surface both authority stores share.
type grantIssuer interface {
	IssueGrantWithConstraints(context.Context, string, string, []string, map[string][]string, time.Time) (*capability.Grant, error)
}

type capabilityList []string

func (c *capabilityList) String() string { return fmt.Sprint([]string(*c)) }
func (c *capabilityList) Set(v string) error {
	if v == "" {
		return fmt.Errorf("capability id must not be empty")
	}
	*c = append(*c, v)
	return nil
}

// constraintList collects --constraint dimension=value flags into the
// grant's resource constraints (dimension → admitted values).
type constraintList map[string][]string

func (c constraintList) String() string { return fmt.Sprint(map[string][]string(c)) }
func (c constraintList) Set(v string) error {
	dimension, value, ok := strings.Cut(v, "=")
	if !ok || dimension == "" || value == "" {
		return fmt.Errorf("constraint must be dimension=value (e.g. repo=example-org/my-app)")
	}
	if value == "*" {
		return fmt.Errorf("constraint value %q is wildcard shorthand; use --unconstrained %s to declare deliberate wildcard scope", value, dimension)
	}
	for _, existing := range c[dimension] {
		if existing == value {
			return fmt.Errorf("constraint %s=%s declared twice", dimension, value)
		}
	}
	c[dimension] = append(c[dimension], value)
	return nil
}

// dimensionList collects --unconstrained dimension flags: the issuer's
// explicit acknowledgement that a declared dimension is deliberately wildcard.
type dimensionList []string

func (d *dimensionList) String() string { return fmt.Sprint([]string(*d)) }
func (d *dimensionList) Set(v string) error {
	if v == "" {
		return fmt.Errorf("unconstrained dimension name must not be empty")
	}
	*d = append(*d, v)
	return nil
}

// config is the validated invocation: everything checked before any
// database work happens.
type config struct {
	grantID     string
	principal   string
	caps        []string
	constraints map[string][]string
	expiresAt   time.Time // zero means no expiry
	dsn         string    // PostgreSQL DSN, when backend is backendPostgres
	sqlitePath  string    // SQLite database file, when backend is backendSQLite
	backend     backend
}

// backend is the authority store the grant is issued through.
type backend string

const (
	backendPostgres backend = "postgres"
	backendSQLite   backend = "sqlite"
)

// loadConfig parses and validates flags + environment. It never accepts
// a caller-supplied generation: generations are allocated by the
// authority store under the serialized head lock.
func loadConfig(argv []string, getenv func(string) string, stderr io.Writer) (config, error) {
	fs := flag.NewFlagSet("issue-grant", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		grantID   = fs.String("grant-id", "", "grant identifier (default: generated)")
		principal = fs.String("principal", "", "principal this grant authorizes (required)")
		expiresAt = fs.String("expires-at", "", "RFC3339 expiry; must be in the future (default: no expiry)")
	)
	var caps capabilityList
	fs.Var(&caps, "capability", "capability id to authorize (repeatable, required; \"*\" authorizes every catalog capability)")
	constraints := constraintList{}
	fs.Var(constraints, "constraint", "resource constraint as dimension=value (repeatable; e.g. repo=example-org/my-app)")
	var unconstrained dimensionList
	fs.Var(&unconstrained, "unconstrained", "declare a resource dimension deliberately wildcard (repeatable; e.g. --unconstrained base)")
	if err := fs.Parse(argv); err != nil {
		return config{}, err
	}

	if *principal == "" {
		return config{}, fmt.Errorf("--principal is required")
	}
	if len(caps) == 0 {
		return config{}, fmt.Errorf("at least one --capability is required")
	}

	// Issuance policy, evaluated against the resolved-descriptor catalog:
	// every declared resource dimension must be addressed once — a constraint
	// or an explicit --unconstrained acknowledgement. Omission is a
	// rejection, so this check runs before any backend work.
	catalog, err := execution.IssuanceCatalog()
	if err != nil {
		return config{}, fmt.Errorf("cannot build the issuance catalog: %v", err)
	}
	effectiveConstraints, err := catalog.ValidateIssuanceScope(caps, constraints, unconstrained)
	if err != nil {
		return config{}, err
	}

	dsn := getenv("CRABEDENCE_DATABASE_URL")
	sqlitePath := getenv("CRABEDENCE_STORE_PATH")
	if dsn == "" && sqlitePath == "" {
		return config{}, fmt.Errorf("set CRABEDENCE_DATABASE_URL (PostgreSQL) or CRABEDENCE_STORE_PATH (SQLite); connection details are read from the environment, never argv")
	}
	selected := backendPostgres
	if dsn == "" {
		selected = backendSQLite
	}

	var expiry time.Time
	if *expiresAt != "" {
		var err error
		expiry, err = time.Parse(time.RFC3339, *expiresAt)
		if err != nil {
			return config{}, fmt.Errorf("--expires-at must be RFC3339: %v", err)
		}
		if !expiry.After(time.Now()) {
			return config{}, fmt.Errorf("--expires-at %s is in the past — a staging grant must outlive its use", *expiresAt)
		}
	}

	id := *grantID
	if id == "" {
		var b [12]byte
		if _, err := rand.Read(b[:]); err != nil {
			return config{}, fmt.Errorf("cannot generate grant id: %v", err)
		}
		id = fmt.Sprintf("grant_%x", b)
	}

	return config{
		grantID:     id,
		principal:   *principal,
		caps:        caps,
		constraints: effectiveConstraints,
		expiresAt:   expiry,
		dsn:         dsn,
		sqlitePath:  sqlitePath,
		backend:     selected,
	}, nil
}

func main() {
	cfg, err := loadConfig(os.Args[1:], os.Getenv, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "issue-grant: %v\n", err)
		fmt.Fprintln(os.Stderr, "usage: issue-grant --principal <id> --capability <id> [--capability <id>...] [--constraint <dim=value>...] [--unconstrained <dim>...] [--grant-id <id>] [--expires-at <RFC3339>]")
		os.Exit(2)
	}

	ctx := context.Background()
	driver, target := "pgx", cfg.dsn
	if cfg.backend == backendSQLite {
		driver, target = "sqlite", cfg.sqlitePath
	}
	db, err := sql.Open(driver, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "issue-grant: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "issue-grant: cannot reach database: %v\n", err)
		os.Exit(1)
	}

	var store grantIssuer
	if cfg.backend == backendSQLite {
		store, err = authority.NewSQLiteStore(db)
	} else {
		store, err = authority.NewStore(db)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "issue-grant: %v\n", err)
		os.Exit(1)
	}

	grant, err := store.IssueGrantWithConstraints(ctx, cfg.grantID, cfg.principal, cfg.caps, cfg.constraints, cfg.expiresAt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "issue-grant: %v\n", err)
		os.Exit(1)
	}

	out, _ := json.MarshalIndent(map[string]any{
		"grant_id":     grant.ID,
		"generation":   grant.Generation,
		"grant_digest": grant.Digest,
		"principal":    grant.Principal,
		"capabilities": grant.Capabilities,
		"constraints":  grant.Constraints,
		"issued_at":    grant.IssuedAt.Format(time.RFC3339Nano),
		"expires_at":   expiryOrEmpty(grant.ExpiresAt),
	}, "", "  ")
	fmt.Println(string(out))
}

func expiryOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339Nano)
}
