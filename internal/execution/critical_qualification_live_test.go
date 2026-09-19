package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/authority"
	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/idempotency"
	"github.com/openclaw/crabbox/internal/reconcile"
)

// External CRITICAL qualification.
//
// The full stack, with no mocks in the qualification path:
//
//	client → Unix socket → Service → verified descriptor → authority
//	  (PostgreSQL) → CRITICAL/HIGH_ASSURANCE admission → PostgreSQL
//	  EffectStore (PREPARED → IN_FLIGHT) → external qualification
//	  provider PROCESS (durable ledger + immutable artifacts) →
//	  provider observation → Crabedence recomputes SHA-256 over the
//	  artifact bytes → signed CRITICAL receipt → COMMITTED/FAILED/UNKNOWN
//	  → reconciliation where required.
//
// The provider runs in its own process with its own durable state, so
// killing Crabedence cannot erase the provider's knowledge of whether
// the external operation happened. Faults are injected deterministically
// per request (never by timing), and every expectation is checked
// against the provider's independent ledger.
//
// Requires CRABBOX_TEST_DATABASE_URL. Skipped when absent.

const qualificationCapabilityID = "qualification.critical.commit"

// qualificationAdapter is the executor-side handler for the external
// qualification provider: the full provider contract (capability
// declaration, recovery locator, dispatch, read-only resolution). It
// never trusts the provider's claimed digest — the artifact bytes are
// handed to the executor, which recomputes SHA-256 itself.
type qualificationAdapter struct {
	baseURL string
	client  *http.Client
}

func (a *qualificationAdapter) ProviderCapabilities(string) ProviderCapabilities {
	return ProviderCapabilities{
		SupportsProviderIdempotency: true,
		SupportsStatusLookup:        true,
		SupportsCompletionProof:     true,
		SupportsNonexecutionProof:   true,
		RecoveryLocatorType:         "external-token",
	}
}

func (a *qualificationAdapter) PrepareRecovery(_ context.Context, _ string, in idempotency.RecoveryLocatorInput) (*idempotency.RecoveryLocator, error) {
	return &idempotency.RecoveryLocator{
		Version:        1,
		ProviderID:     "qualification",
		Strategy:       "external-token",
		ExternalToken:  idempotency.ProviderIdempotencyKey(in.ExecutionID, in.RequestDigest, "qualification"),
		RequestDigest:  in.RequestDigest,
		ExecutionID:    in.ExecutionID,
		PrincipalID:    in.Principal,
		CapabilityID:   in.CapabilityID,
		IdempotencyKey: in.IdempotencyKey,
	}, nil
}

type qualificationOperationResponse struct {
	Status      string          `json:"status"`
	OperationID string          `json:"operation_id"`
	RunID       string          `json:"run_id"`
	ArtifactID  string          `json:"artifact_id"`
	Digest      string          `json:"digest"`
	Result      json.RawMessage `json:"result"`
	Artifact    json.RawMessage `json:"artifact"`
}

// Execute dispatches one CRITICAL operation to the provider process.
// Transport failure after the request may have been sent is ambiguous:
// FAILED without DefinitiveFailure, so the executor enters UNKNOWN.
func (a *qualificationAdapter) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	token := ExternalTokenFromContext(ctx)
	if token == "" {
		return Response{
			Status:            StatusFailed,
			FailureCode:       string(capability.FailureInternalError),
			Error:             "missing external operation token",
			DefinitiveFailure: true,
			Execution:         &ExecutionMeta{Provider: "qualification"},
		}
	}
	var args struct {
		Operation string `json:"operation"`
		Fault     string `json:"fault"`
	}
	if err := json.Unmarshal(req.Arguments, &args); err != nil {
		return Response{
			Status:            StatusFailed,
			FailureCode:       string(capability.FailureInvalidRequest),
			Error:             "invalid arguments: " + err.Error(),
			DefinitiveFailure: true,
			Execution:         &ExecutionMeta{Provider: "qualification"},
		}
	}
	body, _ := json.Marshal(map[string]any{
		"token":   token,
		"payload": map[string]string{"operation": args.Operation},
	})
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/operations", bytes.NewReader(body))
	if err != nil {
		return Response{Status: StatusFailed, FailureCode: string(capability.FailureInternalError), Error: err.Error(), DefinitiveFailure: true}
	}
	hreq.Header.Set("Content-Type", "application/json")
	if args.Fault != "" {
		hreq.Header.Set("X-Qualification-Fault", args.Fault)
	}
	resp, err := a.client.Do(hreq)
	if err != nil {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureExecutionFailed),
			Error:       "qualification provider transport: " + err.Error(),
			Execution:   &ExecutionMeta{Provider: "qualification"},
		}
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusConflict {
		// The provider bound this token to a different payload. Definitive
		// non-effect: the collision was rejected before any operation.
		return Response{
			Status:            StatusDenied,
			FailureCode:       string(capability.FailureIdempotencyConflict),
			Error:             "qualification provider rejected an operation-token collision",
			DefinitiveFailure: true,
			Execution:         &ExecutionMeta{Provider: "qualification"},
		}
	}
	if resp.StatusCode != http.StatusOK {
		// A rejection before acceptance. The provider declares whether it
		// accepted anything; only an explicit non-acceptance is a
		// definitive non-effect.
		definitive := strings.Contains(string(respBody), `"accepted":false`)
		return Response{
			Status:            StatusFailed,
			FailureCode:       string(capability.FailureExecutionFailed),
			Error:             fmt.Sprintf("qualification provider returned %d: %s", resp.StatusCode, truncate(string(respBody), 256)),
			DefinitiveFailure: definitive,
			Execution:         &ExecutionMeta{Provider: "qualification"},
		}
	}

	var out qualificationOperationResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return Response{
			Status:      StatusUnknown,
			FailureCode: string(capability.FailureExecutionUnknown),
			Error:       "qualification provider returned an unparseable response: " + err.Error(),
			Execution:   &ExecutionMeta{Provider: "qualification"},
		}
	}
	switch out.Status {
	case "COMMITTED":
		result, _ := json.Marshal(map[string]any{"operation_id": out.OperationID})
		return Response{
			Status:           StatusSucceeded,
			Result:           result,
			Evidence:         &EvidenceRef{ReceiptVersion: 3},
			EvidenceArtifact: out.Artifact,
			Execution:        &ExecutionMeta{Provider: "qualification", RunID: out.OperationID},
		}
	case "REJECTED":
		// Definitive non-effect with the provider's proof artifact.
		return Response{
			Status:            StatusFailed,
			FailureCode:       string(capability.FailureExecutionFailed),
			Error:             "qualification provider definitively rejected the operation",
			DefinitiveFailure: true,
			Evidence:          &EvidenceRef{ReceiptVersion: 3},
			EvidenceArtifact:  out.Artifact,
			Execution:         &ExecutionMeta{Provider: "qualification", RunID: out.OperationID},
		}
	}
	return Response{
		Status:      StatusUnknown,
		FailureCode: string(capability.FailureExecutionUnknown),
		Error:       "qualification provider reported status " + out.Status,
		Execution:   &ExecutionMeta{Provider: "qualification", RunID: out.OperationID},
	}
}

// Resolve implements idempotency.RecoveryResolver: strictly read-only.
// It queries the provider's durable ledger by the stable token and
// fetches the immutable artifact bytes — the digest is recomputed by
// the worker before signing, never taken from the provider's claim.
func (a *qualificationAdapter) Resolve(ctx context.Context, rec *idempotency.Record) (idempotency.RecoveryResult, error) {
	var loc idempotency.RecoveryLocator
	if len(rec.RecoveryLocator) > 0 {
		if err := json.Unmarshal(rec.RecoveryLocator, &loc); err != nil {
			return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
		}
	}
	if loc.ExternalToken == "" {
		return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
	}
	resp, err := a.client.Get(a.baseURL + "/operations/" + url.PathEscape(loc.ExternalToken))
	if err != nil {
		return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusServiceUnavailable, http.StatusBadGateway:
		return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
	case http.StatusNotFound:
		// The provider has no operation for this token: it never accepted
		// one. This is a non-effect, but a definitive CRITICAL decision
		// still needs a proof artifact; without one it stays UNKNOWN.
		return idempotency.RecoveryResult{Decision: idempotency.RecoveryFailed, ProviderID: "qualification"}, nil
	case http.StatusOK:
	default:
		return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
	}
	var op qualificationOperationResponse
	if err := json.NewDecoder(resp.Body).Decode(&op); err != nil {
		return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
	}
	artifact, err := a.fetchArtifact(ctx, op.ArtifactID)
	if err != nil {
		return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
	}
	switch op.Status {
	case "COMMITTED":
		return idempotency.RecoveryResult{
			Decision:         idempotency.RecoveryCommitted,
			Result:           op.Result,
			ProviderID:       "qualification",
			ProviderRunID:    op.OperationID,
			ReceiptVersion:   3,
			EvidenceArtifact: artifact,
		}, nil
	case "REJECTED":
		return idempotency.RecoveryResult{
			Decision:         idempotency.RecoveryFailed,
			ProviderID:       "qualification",
			ProviderRunID:    op.OperationID,
			ReceiptVersion:   3,
			EvidenceArtifact: artifact,
		}, nil
	}
	return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
}

func (a *qualificationAdapter) fetchArtifact(ctx context.Context, artifactID string) ([]byte, error) {
	if artifactID == "" {
		return nil, fmt.Errorf("no artifact id")
	}
	resp, err := a.client.Get(a.baseURL + "/artifacts/" + url.PathEscape(artifactID))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("artifact %s: status %d", artifactID, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// criticalStack is the full qualification stack: PostgreSQL EffectStore
// and authority store, the service on a Unix socket, the external
// provider process, and the reconciliation worker.
type criticalStack struct {
	socket      string
	providerURL string
	signer      *evidence.Signer
	store       *idempotency.Store
	authority   *authority.Store
	service     *Service
	worker      *reconcile.Worker
	adapter     *qualificationAdapter
}

func registerQualificationCapability(t *testing.T, registry *capability.Registry) capability.ResolvedDescriptor {
	t.Helper()
	desc, err := capability.Resolve(capability.CapabilityDescriptor{
		ID:             qualificationCapabilityID,
		ExecutionClass: capability.ClassCritical,
		AdapterID:      "qualification",
		AuthorityPolicy: capability.AuthorityPolicy{
			ID:            qualificationCapabilityID,
			GrantRequired: true,
		},
		Schema: json.RawMessage(`{"type":"object","properties":{"operation":{"type":"string"},"fault":{"type":"string"}},"required":["operation"],"additionalProperties":false}`),
	})
	if err != nil {
		t.Fatalf("resolve qualification descriptor: %v", err)
	}
	if err := registry.RegisterResolved(desc); err != nil {
		t.Fatalf("register qualification descriptor: %v", err)
	}
	return desc
}

func newCriticalStack(t *testing.T) *criticalStack {
	t.Helper()
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live external CRITICAL qualification")
	}
	ctx := context.Background()
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	store, err := idempotency.NewStore(db)
	if err != nil {
		t.Fatalf("effect store: %v", err)
	}
	authorityStore, err := authority.NewStore(db)
	if err != nil {
		t.Fatalf("authority store: %v", err)
	}
	signer, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	store.SetTrustedEvidenceSigners(signer.Fingerprint())

	providerURL, _ := startExternalProvider(t, t.TempDir())
	adapter := &qualificationAdapter{
		baseURL: providerURL,
		client:  &http.Client{Timeout: 2 * time.Second},
	}

	registry := capability.NewRegistry()
	registerQualificationCapability(t, registry)

	exec := NewDispatchExecutor(adapter, store)
	exec.SetEvidenceSigner(signer)

	socketPath := testSocketPath(t)
	service := NewService(registry, exec, socketPath)
	service.SetGrantResolver(authorityStore)
	service.SetAdapterAvailability(capability.AdapterAvailability{
		"qualification": {Status: capability.AvailabilityAvailable},
	})
	if err := service.Start(ctx); err != nil {
		t.Fatalf("start service: %v", err)
	}
	t.Cleanup(func() { service.Stop() })

	worker := reconcile.NewWorker(store, reconcile.NoopResolver{}, 30*time.Second)
	worker.RegisterResolver(qualificationCapabilityID, adapter)
	worker.SetEvidenceSigner(signer)

	return &criticalStack{
		socket:      socketPath,
		providerURL: providerURL,
		signer:      signer,
		store:       store,
		authority:   authorityStore,
		service:     service,
		worker:      worker,
		adapter:     adapter,
	}
}

// issueGrant creates a real authority grant through the PostgreSQL
// authority store.
func (s *criticalStack) issueGrant(t *testing.T, grantID, principal string, capabilities []string, expiresAt time.Time) {
	t.Helper()
	if _, err := s.authority.IssueGrant(context.Background(), grantID, principal, capabilities, expiresAt); err != nil {
		t.Fatalf("issue grant %s: %v", grantID, err)
	}
}

func (s *criticalStack) request(t *testing.T, key, grantID, principal string, args map[string]string) Response {
	t.Helper()
	payload, _ := json.Marshal(args)
	conn, err := net.Dial("unix", s.socket)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	return sendRequest(t, conn, Request{
		Capability:     qualificationCapabilityID,
		Arguments:      payload,
		Authority:      RequestAuthority{Principal: principal, AuthorityRef: grantID},
		IdempotencyKey: key,
	})
}

func (s *criticalStack) providerStats(t *testing.T) (operations, executions int) {
	t.Helper()
	resp, err := http.Get(s.providerURL + "/stats")
	if err != nil {
		t.Fatalf("provider stats: %v", err)
	}
	defer resp.Body.Close()
	var stats struct {
		Operations int `json:"operations"`
		Executions int `json:"executions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatalf("provider stats decode: %v", err)
	}
	return stats.Operations, stats.Executions
}

func (s *criticalStack) lookup(t *testing.T, key string) *idempotency.Record {
	t.Helper()
	rec, err := s.store.LookupByKey(context.Background(), "alice@example.com", qualificationCapabilityID, key)
	if err != nil {
		t.Fatalf("lookup %s: %v", key, err)
	}
	return rec
}

func qualificationKey(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// TestLiveCriticalQualificationCommit is the happy-path acceptance walk:
// a CRITICAL operation commits through the full stack, exactly one
// external operation exists in the provider's durable ledger, and the
// persisted receipt verifies against the artifact bytes Crabedence
// hashed itself.
func TestLiveCriticalQualificationCommit(t *testing.T) {
	stack := newCriticalStack(t)
	grant := "grant-valid-" + qualificationKey("g")
	stack.issueGrant(t, grant, "alice@example.com", []string{qualificationCapabilityID}, time.Now().Add(time.Hour))

	key := qualificationKey("crit-commit")
	resp := stack.request(t, key, grant, "alice@example.com", map[string]string{"operation": "commit-1"})
	if resp.Status != StatusSucceeded {
		t.Fatalf("CRITICAL commit failed: %s — %s", resp.Status, resp.Error)
	}

	rec := stack.lookup(t, key)
	if rec.State != idempotency.StateCommitted {
		t.Fatalf("durable state = %s, want COMMITTED", rec.State)
	}
	if len(rec.EvidenceReceipt) == 0 {
		t.Fatal("CRITICAL commit without a persisted signed receipt")
	}
	if rec.ProviderRunID == "" {
		t.Fatal("committed record carries no provider operation identity")
	}

	// The provider's independent ledger: exactly one operation, one
	// execution, matching the committed provider run identity.
	operations, executions := stack.providerStats(t)
	if operations != 1 || executions != 1 {
		t.Fatalf("provider operations/executions = %d/%d, want 1/1", operations, executions)
	}

	// The receipt must verify over the artifact bytes the provider
	// actually produced — recomputed here, not trusted from the record.
	artifact := fetchProviderArtifact(t, stack, rec.ProviderRunID)
	sum := sha256.Sum256(artifact)
	if err := evidence.VerifyReceipt(rec.EvidenceReceipt, evidence.Binding{
		ExecutionID:    rec.ExecutionID,
		Capability:     qualificationCapabilityID,
		Principal:      "alice@example.com",
		RequestDigest:  rec.RequestDigest,
		ProviderID:     rec.ProviderID,
		ProviderRunID:  rec.ProviderRunID,
		Outcome:        evidence.OutcomeCompleted,
		EvidenceSHA256: fmt.Sprintf("%x", sum),
	}, map[string]bool{stack.signer.Fingerprint(): true}); err != nil {
		t.Fatalf("persisted receipt failed verification: %v", err)
	}

	// A duplicate request with the same idempotency key replays the
	// terminal outcome and must not create a second external operation.
	replay := stack.request(t, key, grant, "alice@example.com", map[string]string{"operation": "commit-1"})
	if replay.Status != StatusSucceeded {
		t.Fatalf("terminal replay failed: %s — %s", replay.Status, replay.Error)
	}
	if operations, executions = stack.providerStats(t); operations != 1 || executions != 1 {
		t.Fatalf("duplicate request created a second operation: %d/%d", operations, executions)
	}
}

// TestLiveCriticalQualificationAmbiguityThenReconcile is the hardest
// case: the provider commits the operation and then drops the connection
// without a response. Crabedence cannot know the result → UNKNOWN; the
// reconciler queries the stable token, the provider proves COMMITTED,
// the artifact is fetched, and the terminal receipt is signed. Exactly
// one external execution must exist.
func TestLiveCriticalQualificationAmbiguityThenReconcile(t *testing.T) {
	stack := newCriticalStack(t)
	ctx := context.Background()
	grant := "grant-valid-" + qualificationKey("g")
	stack.issueGrant(t, grant, "alice@example.com", []string{qualificationCapabilityID}, time.Now().Add(time.Hour))

	key := qualificationKey("crit-reset")
	resp := stack.request(t, key, grant, "alice@example.com", map[string]string{
		"operation": "commit-reset",
		"fault":     faultCommitThenReset,
	})
	if resp.Status != StatusUnknown {
		t.Fatalf("post-dispatch ambiguity must be UNKNOWN, got %s (%s)", resp.Status, resp.Error)
	}
	rec := stack.lookup(t, key)
	if rec.State != idempotency.StateUnknown {
		t.Fatalf("durable state = %s, want UNKNOWN", rec.State)
	}
	if operations, executions := stack.providerStats(t); operations != 1 || executions != 1 {
		t.Fatalf("provider operations/executions = %d/%d, want 1/1 (the commit happened)", operations, executions)
	}

	// Reconciliation: the worker queries the stable token and resolves
	// the ambiguity against external reality.
	if err := stack.worker.RunCycle(ctx); err != nil {
		t.Fatalf("reconcile cycle: %v", err)
	}
	rec = stack.lookup(t, key)
	if rec.State != idempotency.StateCommitted {
		t.Fatalf("post-reconciliation state = %s, want COMMITTED", rec.State)
	}
	if len(rec.EvidenceReceipt) == 0 {
		t.Fatal("reconciled CRITICAL commit without a signed receipt")
	}

	// The provider executed exactly once: reconciliation resolved the
	// ambiguity, it did not re-run the operation.
	if operations, executions := stack.providerStats(t); operations != 1 || executions != 1 {
		t.Fatalf("reconciliation re-dispatched: %d/%d, want 1/1", operations, executions)
	}
}

// TestLiveCriticalQualificationDefinitiveRejection proves the non-effect
// direction: the provider rejects the operation definitively, and the
// durable record terminates without an external execution.
func TestLiveCriticalQualificationDefinitiveRejection(t *testing.T) {
	stack := newCriticalStack(t)
	grant := "grant-valid-" + qualificationKey("g")
	stack.issueGrant(t, grant, "alice@example.com", []string{qualificationCapabilityID}, time.Now().Add(time.Hour))

	key := qualificationKey("crit-reject")
	resp := stack.request(t, key, grant, "alice@example.com", map[string]string{
		"operation": "reject-1",
		"fault":     faultDefinitiveReject,
	})
	if resp.Status != StatusFailed {
		t.Fatalf("definitive rejection must be FAILED, got %s (%s)", resp.Status, resp.Error)
	}
	rec := stack.lookup(t, key)
	if rec.State != idempotency.StateFailed {
		t.Fatalf("durable state = %s, want FAILED (definitive non-effect)", rec.State)
	}
	operations, executions := stack.providerStats(t)
	if executions != 0 {
		t.Fatalf("provider executions = %d, want 0 (definitive rejection)", executions)
	}
	if operations != 1 {
		t.Fatalf("provider operations = %d, want 1 (the rejection is durable proof)", operations)
	}
}

// TestLiveCriticalQualificationEvidenceIntegrity proves Crabedence never
// trusts the provider's claimed digest: the provider claims a
// valid-looking digest that does not cover the bytes it returned, and
// the committed receipt binds the digest Crabedence computed itself.
// It also proves a mutated stored receipt fails signature verification.
func TestLiveCriticalQualificationEvidenceIntegrity(t *testing.T) {
	stack := newCriticalStack(t)
	grant := "grant-valid-" + qualificationKey("g")
	stack.issueGrant(t, grant, "alice@example.com", []string{qualificationCapabilityID}, time.Now().Add(time.Hour))

	key := qualificationKey("crit-wrong-digest")
	resp := stack.request(t, key, grant, "alice@example.com", map[string]string{
		"operation": "wrong-digest",
		"fault":     faultWrongArtifactDig,
	})
	if resp.Status != StatusSucceeded {
		t.Fatalf("the operation itself committed: %s — %s", resp.Status, resp.Error)
	}
	rec := stack.lookup(t, key)
	artifact := fetchProviderArtifact(t, stack, rec.ProviderRunID)
	sum := sha256.Sum256(artifact)
	binding := evidence.Binding{
		ExecutionID:    rec.ExecutionID,
		Capability:     qualificationCapabilityID,
		Principal:      "alice@example.com",
		RequestDigest:  rec.RequestDigest,
		ProviderID:     rec.ProviderID,
		ProviderRunID:  rec.ProviderRunID,
		Outcome:        evidence.OutcomeCompleted,
		EvidenceSHA256: fmt.Sprintf("%x", sum),
	}
	trusted := map[string]bool{stack.signer.Fingerprint(): true}
	if err := evidence.VerifyReceipt(rec.EvidenceReceipt, binding, trusted); err != nil {
		t.Fatalf("receipt must bind the digest of the bytes, not the claim: %v", err)
	}
	// The claimed (wrong) digest must not appear anywhere in the record.
	claimed := strings.Repeat("0", 64)
	if strings.Contains(string(rec.EvidenceReceipt), claimed) {
		t.Fatal("the provider's claimed digest leaked into the signed receipt")
	}

	// Tamper with the stored receipt: signature verification must fail.
	tampered := append([]byte(nil), rec.EvidenceReceipt...)
	for i := range tampered {
		if tampered[i] == 'a' {
			tampered[i] = 'b'
			break
		}
	}
	if err := evidence.VerifyReceipt(tampered, binding, trusted); err == nil {
		t.Fatal("a mutated receipt verified — signature validation is not enforcing integrity")
	}
}

// TestLiveCriticalQualificationFailBeforeAccept proves the pre-accept
// direction: the provider rejects before writing anything, so no
// external effect exists, and the ambiguity is never resolved into a
// fabricated commit.
func TestLiveCriticalQualificationFailBeforeAccept(t *testing.T) {
	stack := newCriticalStack(t)
	grant := "grant-valid-" + qualificationKey("g")
	stack.issueGrant(t, grant, "alice@example.com", []string{qualificationCapabilityID}, time.Now().Add(time.Hour))

	key := qualificationKey("crit-preaccept")
	resp := stack.request(t, key, grant, "alice@example.com", map[string]string{
		"operation": "never-accepted",
		"fault":     faultFailBeforeAccept,
	})
	if resp.Status != StatusUnknown {
		t.Fatalf("post-dispatch ambiguity must be UNKNOWN, got %s (%s)", resp.Status, resp.Error)
	}
	rec := stack.lookup(t, key)
	if rec.State != idempotency.StateUnknown {
		t.Fatalf("durable state = %s, want UNKNOWN", rec.State)
	}
	if operations, executions := stack.providerStats(t); operations != 0 || executions != 0 {
		t.Fatalf("provider operations/executions = %d/%d, want 0/0", operations, executions)
	}

	// Reconciliation finds no operation for the token: a non-effect. It
	// must never fabricate a COMMITTED outcome.
	if err := stack.worker.RunCycle(context.Background()); err != nil {
		t.Fatalf("reconcile cycle: %v", err)
	}
	if rec = stack.lookup(t, key); rec.State == idempotency.StateCommitted {
		t.Fatal("reconciliation fabricated a COMMITTED outcome with no external operation")
	}
	if operations, executions := stack.providerStats(t); operations != 0 || executions != 0 {
		t.Fatalf("reconciliation created an external operation: %d/%d", operations, executions)
	}
}

// TestLiveCriticalQualificationAuthorityMatrix proves authority is
// resolved for real, and that invalid authority produces zero provider
// operations — not merely an error returned to the caller.
func TestLiveCriticalQualificationAuthorityMatrix(t *testing.T) {
	cases := []struct {
		name     string
		grant    func(t *testing.T, stack *criticalStack) (grantID, principal string)
		wantCode capability.FailureCode
	}{
		{
			name: "expired",
			grant: func(t *testing.T, s *criticalStack) (string, string) {
				id := "grant-expired-" + qualificationKey("g")
				s.issueGrant(t, id, "alice@example.com", []string{qualificationCapabilityID}, time.Now().Add(-time.Hour))
				return id, "alice@example.com"
			},
			wantCode: capability.FailureUnauthorized,
		},
		{
			name: "revoked",
			grant: func(t *testing.T, s *criticalStack) (string, string) {
				id := "grant-revoked-" + qualificationKey("g")
				s.issueGrant(t, id, "alice@example.com", []string{qualificationCapabilityID}, time.Now().Add(time.Hour))
				if err := s.authority.RevokeGrant(context.Background(), id); err != nil {
					t.Fatalf("revoke: %v", err)
				}
				return id, "alice@example.com"
			},
			wantCode: capability.FailureUnauthorized,
		},
		{
			name: "unknown-grant",
			grant: func(t *testing.T, s *criticalStack) (string, string) {
				return "grant-never-issued-" + qualificationKey("g"), "alice@example.com"
			},
			wantCode: capability.FailureUnauthorized,
		},
		{
			name: "wrong-principal",
			grant: func(t *testing.T, s *criticalStack) (string, string) {
				id := "grant-other-" + qualificationKey("g")
				s.issueGrant(t, id, "bob@example.com", []string{qualificationCapabilityID}, time.Now().Add(time.Hour))
				return id, "alice@example.com"
			},
			wantCode: capability.FailureUnauthorized,
		},
		{
			name: "wrong-capability",
			grant: func(t *testing.T, s *criticalStack) (string, string) {
				id := "grant-narrow-" + qualificationKey("g")
				s.issueGrant(t, id, "alice@example.com", []string{"some.other.capability"}, time.Now().Add(time.Hour))
				return id, "alice@example.com"
			},
			wantCode: capability.FailureUnauthorized,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stack := newCriticalStack(t)
			grantID, principal := tc.grant(t, stack)
			key := qualificationKey("crit-authz")
			resp := stack.request(t, key, grantID, principal, map[string]string{"operation": "authz"})
			if resp.Status != StatusDenied {
				t.Fatalf("invalid authority must be DENIED, got %s (%s)", resp.Status, resp.Error)
			}
			if resp.FailureCode != string(tc.wantCode) {
				t.Fatalf("failure code = %s, want %s", resp.FailureCode, tc.wantCode)
			}
			if operations, executions := stack.providerStats(t); operations != 0 || executions != 0 {
				t.Fatalf("invalid authority reached the provider: %d/%d operations/executions", operations, executions)
			}
			// No durable record may exist either: the request never
			// reached the EffectStore.
			if _, err := stack.store.LookupByKey(context.Background(), principal, qualificationCapabilityID, key); err == nil {
				t.Fatal("invalid authority created a durable execution record")
			}
		})
	}
}

// TestLiveCriticalQualificationClosedAuthoritySemantics encodes the
// authority store's documented continuity contract, so it is a tested
// expectation rather than a surprise: closing an authority reference
// prevents NEW generations from being issued, while the existing
// generation continues to resolve until it is revoked or expires. An
// operator who needs to kill access revokes the grant.
func TestLiveCriticalQualificationClosedAuthoritySemantics(t *testing.T) {
	stack := newCriticalStack(t)
	grant := "grant-close-" + qualificationKey("g")
	stack.issueGrant(t, grant, "alice@example.com", []string{qualificationCapabilityID}, time.Now().Add(time.Hour))

	if err := stack.authority.CloseAuthorityRef(context.Background(), grant); err != nil {
		t.Fatalf("close authority ref: %v", err)
	}
	// No new generation may be issued for a closed reference.
	if _, err := stack.authority.IssueGrant(context.Background(), grant, "alice@example.com", []string{qualificationCapabilityID}, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("a closed authority reference issued a new generation")
	}
	// The existing generation still resolves: closing is not revocation.
	if grant2, err := stack.authority.Resolve(context.Background(), grant, "alice@example.com"); err != nil || grant2 == nil {
		t.Fatalf("closed reference must keep resolving its existing generation (err=%v)", err)
	}
}

// fetchProviderArtifact reads the immutable artifact bytes from the
// provider for the operation whose provider run ID is opID.
func fetchProviderArtifact(t *testing.T, stack *criticalStack, opID string) []byte {
	t.Helper()
	// The provider's operation ledger is keyed by token; the adapter's
	// resolver path is the public way to fetch artifacts, so use it.
	resp, err := http.Get(stack.providerURL + "/artifacts/" + url.PathEscape(strings.Replace(opID, "op-", "art-", 1)))
	if err != nil {
		t.Fatalf("fetch artifact: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fetch artifact %s: status %d", opID, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	return data
}
