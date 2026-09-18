package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/openclaw/crabbox/internal/authority"
	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// TestServiceBindsResolvedAuthorityIntoRequestDigest proves the
// immutable-authority binding end to end: the generation + digest of
// the grant that admitted the request become part of the stored
// request digest, and reissuing the same grant_id under different
// material yields a different execution identity — so the same
// idempotency key is an IDEMPOTENCY_CONFLICT, not a silent replay
// under reinterpreted authority.
func TestServiceBindsResolvedAuthorityIntoRequestDigest(t *testing.T) {
	ctx := context.Background()

	// SQLite authority store with an issued grant (generation 1).
	adb, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer adb.Close()
	astore, err := authority.NewSQLiteStore(adb)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	issued, err := astore.IssueGrant(ctx, "grant_x", "alice@example.com",
		[]string{"test.counter.increment"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("issue grant: %v", err)
	}

	istore := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)

	socketPath := testSocketPath(t)
	registry := capability.NewRegistry()
	if err := RegisterCounterCapability(registry); err != nil {
		t.Fatal(err)
	}
	handler := NewMultiHandler(map[string]Handler{
		"test-counter": NewCounterHandler(),
	})
	service := NewService(registry, NewDispatchExecutor(handler, istore), socketPath)
	service.SetGrantResolver(astore)
	if err := service.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer service.Stop()

	args := json.RawMessage(`{"counter":"authbind","by":1}`)
	key := fmt.Sprintf("authbind-%d", time.Now().UnixNano())
	req := Request{
		Capability:     "test.counter.increment",
		Arguments:      args,
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_x"},
		IdempotencyKey: key,
	}

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	resp := sendRequest(t, conn, req)
	conn.Close()
	if resp.Status != StatusSucceeded {
		t.Fatalf("expected SUCCEEDED, got %s: %s", resp.Status, resp.Error)
	}

	// The stored request digest must bind the resolved generation +
	// grant digest, not merely the grant_id.
	rec, err := istore.LookupByKey(ctx, "alice@example.com", "test.counter.increment", key)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	want, err := idempotency.ComputeDigestFromRawWithAuthority(
		1, "alice@example.com", "test.counter.increment", args,
		"grant_x", "MUTATION", issued.Generation, issued.Digest)
	if err != nil {
		t.Fatalf("compute digest: %v", err)
	}
	if rec.RequestDigest != want {
		t.Fatalf("stored digest %s does not bind resolved authority (want %s)", rec.RequestDigest, want)
	}

	// The durable record must carry the authority snapshot itself so
	// the ledger can answer "which authority admitted this?" without
	// re-resolving grants.
	if rec.AuthorityGeneration != issued.Generation || rec.AuthorityDigest != issued.Digest {
		t.Fatalf("record authority snapshot = gen %d digest %q, want gen %d digest %q",
			rec.AuthorityGeneration, rec.AuthorityDigest, issued.Generation, issued.Digest)
	}

	// Reissue the same grant_id under different material → generation
	// 2, different digest → the same idempotency key is a different
	// request, hence IDEMPOTENCY_CONFLICT — never a silent replay under
	// reinterpreted authority.
	if _, err := astore.IssueGrant(ctx, "grant_x", "alice@example.com",
		[]string{"test.counter.increment", "test.counter.decrement"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("reissue grant: %v", err)
	}

	conn, err = net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	resp2 := sendRequest(t, conn, req)
	conn.Close()
	if resp2.Status != StatusDenied || resp2.FailureCode != string(capability.FailureIdempotencyConflict) {
		t.Fatalf("expected IDEMPOTENCY_CONFLICT after grant reissue, got %s (%s): %s",
			resp2.Status, resp2.FailureCode, resp2.Error)
	}
}

// TestCallerCannotForgeAuthorityBinding verifies the service
// overwrites caller-supplied authority generation/digest with the
// resolved grant's values — a caller cannot inject arbitrary authority
// material into its own execution identity.
func TestCallerCannotForgeAuthorityBinding(t *testing.T) {
	ctx := context.Background()

	adb, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer adb.Close()
	astore, err := authority.NewSQLiteStore(adb)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	issued, err := astore.IssueGrant(ctx, "grant_x", "alice@example.com",
		[]string{"test.counter.increment"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("issue grant: %v", err)
	}

	istore := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)

	socketPath := testSocketPath(t)
	registry := capability.NewRegistry()
	if err := RegisterCounterCapability(registry); err != nil {
		t.Fatal(err)
	}
	handler := NewMultiHandler(map[string]Handler{
		"test-counter": NewCounterHandler(),
	})
	service := NewService(registry, NewDispatchExecutor(handler, istore), socketPath)
	service.SetGrantResolver(astore)
	if err := service.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer service.Stop()

	args := json.RawMessage(`{"counter":"forge","by":1}`)
	key := fmt.Sprintf("forge-%d", time.Now().UnixNano())

	// The caller supplies bogus authority material; the service must
	// overwrite it with the resolved generation + digest.
	req := Request{
		Capability: "test.counter.increment",
		Arguments:  args,
		Authority: RequestAuthority{
			Principal:           "alice@example.com",
			AuthorityRef:        "grant_x",
			AuthorityGeneration: 9999,
			AuthorityDigest:     "deadbeef",
		},
		IdempotencyKey: key,
	}
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	resp := sendRequest(t, conn, req)
	conn.Close()
	if resp.Status != StatusSucceeded {
		t.Fatalf("expected SUCCEEDED, got %s: %s", resp.Status, resp.Error)
	}

	rec, err := istore.LookupByKey(ctx, "alice@example.com", "test.counter.increment", key)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	want, err := idempotency.ComputeDigestFromRawWithAuthority(
		1, "alice@example.com", "test.counter.increment", args,
		"grant_x", "MUTATION", issued.Generation, issued.Digest)
	if err != nil {
		t.Fatalf("compute digest: %v", err)
	}
	if rec.RequestDigest != want {
		t.Fatal("caller-supplied authority material leaked into the request digest — " +
			"service must overwrite it with the resolved grant's values")
	}
}
