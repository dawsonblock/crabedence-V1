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
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
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
	// lookupFault, when set, injects a deterministic lookup outage into
	// reconciliation (the test clears it to restore the lookup). It is
	// harness state, never part of the provider contract.
	lookupFault string
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
		// The artifact identity must match the provider's durable
		// artifact: a response whose bytes differ from the ledger's copy
		// is transport corruption, and committing it would attest bytes
		// the provider cannot prove. Ambiguous → UNKNOWN.
		if durable, err := a.fetchArtifact(ctx, out.ArtifactID); err == nil {
			if !bytes.Equal(durable, out.Artifact) {
				return Response{
					Status:      StatusUnknown,
					FailureCode: string(capability.FailureExecutionUnknown),
					Error:       "qualification provider artifact does not match its durable artifact",
					Execution:   &ExecutionMeta{Provider: "qualification", RunID: out.OperationID},
				}
			}
		}
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
	lookupURL := a.baseURL + "/operations/" + url.PathEscape(loc.ExternalToken)
	if a.lookupFault != "" {
		lookupURL += "?fault=" + url.QueryEscape(a.lookupFault)
	}
	resp, err := a.client.Get(lookupURL)
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
	binding     qualificationRegistryBinding
}

// qualificationRegistryBinding is the explicit extension record: the
// release registry identity, the qualification registry identity, and
// the exact descriptors the qualification harness added. It is what
// Batch G binds into the release evidence.
type qualificationRegistryBinding struct {
	BaseRegistrySHA256          string              `json:"base_registry_sha256"`
	QualificationRegistrySHA256 string              `json:"qualification_registry_sha256"`
	QualificationExtensions     []registryExtension `json:"qualification_extensions"`
}

type registryExtension struct {
	CapabilityID     string `json:"capability_id"`
	DescriptorSHA256 string `json:"descriptor_sha256"`
}

// buildQualificationRegistry constructs the qualification registry under
// the extension rule:
//
//	exact release registry + explicit qualification descriptors
//	  = qualification registry
//
// It refuses to proceed if adding the extension replaced or modified any
// release descriptor, so the harness can never silently alter production
// policy while exercising test-only capabilities.
func buildQualificationRegistry(t *testing.T) (*capability.Registry, qualificationRegistryBinding) {
	t.Helper()
	registry := capability.NewRegistry()
	if err := RegisterBuiltinCapabilities(registry); err != nil {
		t.Fatalf("register release registry: %v", err)
	}
	baseSHA, err := registry.Digest()
	if err != nil {
		t.Fatalf("base registry digest: %v", err)
	}
	baseDescriptors := map[string]string{}
	for _, id := range registry.List() {
		desc, ok := registry.Lookup(id)
		if !ok {
			t.Fatalf("release capability %s vanished", id)
		}
		digest, err := desc.DescriptorDigest()
		if err != nil {
			t.Fatalf("descriptor digest for %s: %v", id, err)
		}
		baseDescriptors[id] = digest
	}

	extension := registerQualificationCapability(t, registry)
	extensionDigest, err := extension.DescriptorDigest()
	if err != nil {
		t.Fatalf("extension descriptor digest: %v", err)
	}

	for id, want := range baseDescriptors {
		desc, ok := registry.Lookup(id)
		if !ok {
			t.Fatalf("qualification extension replaced release capability %s", id)
		}
		got, err := desc.DescriptorDigest()
		if err != nil {
			t.Fatalf("descriptor digest for %s: %v", id, err)
		}
		if got != want {
			t.Fatalf("qualification extension modified release descriptor %s", id)
		}
	}
	qualificationSHA, err := registry.Digest()
	if err != nil {
		t.Fatalf("qualification registry digest: %v", err)
	}
	if qualificationSHA == baseSHA {
		t.Fatal("the qualification extension did not change the registry identity")
	}
	return registry, qualificationRegistryBinding{
		BaseRegistrySHA256:          baseSHA,
		QualificationRegistrySHA256: qualificationSHA,
		QualificationExtensions: []registryExtension{
			{CapabilityID: qualificationCapabilityID, DescriptorSHA256: extensionDigest},
		},
	}
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

	registry, binding := buildQualificationRegistry(t)

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
		binding:     binding,
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

// TestLiveCriticalQualificationTimeoutThenReconcile is the timeout
// variant of the ambiguity case: the provider commits the operation and
// the response never arrives. Same invariant: UNKNOWN, reconciliation by
// stable token, signed COMMITTED, exactly one external execution.
func TestLiveCriticalQualificationTimeoutThenReconcile(t *testing.T) {
	stack := newCriticalStack(t)
	grant := "grant-valid-" + qualificationKey("g")
	stack.issueGrant(t, grant, "alice@example.com", []string{qualificationCapabilityID}, time.Now().Add(time.Hour))

	key := qualificationKey("crit-timeout")
	resp := stack.request(t, key, grant, "alice@example.com", map[string]string{
		"operation": "commit-timeout",
		"fault":     faultCommitThenTimeout,
	})
	if resp.Status != StatusUnknown {
		t.Fatalf("post-dispatch timeout must be UNKNOWN, got %s (%s)", resp.Status, resp.Error)
	}
	if operations, executions := stack.providerStats(t); operations != 1 || executions != 1 {
		t.Fatalf("provider operations/executions = %d/%d, want 1/1 (the commit happened)", operations, executions)
	}

	if err := stack.worker.RunCycle(context.Background()); err != nil {
		t.Fatalf("reconcile cycle: %v", err)
	}
	rec := stack.lookup(t, key)
	if rec.State != idempotency.StateCommitted {
		t.Fatalf("post-reconciliation state = %s, want COMMITTED", rec.State)
	}
	if len(rec.EvidenceReceipt) == 0 {
		t.Fatal("reconciled CRITICAL commit without a signed receipt")
	}
	if operations, executions := stack.providerStats(t); operations != 1 || executions != 1 {
		t.Fatalf("reconciliation re-dispatched: %d/%d, want 1/1", operations, executions)
	}
}

// TestLiveCriticalQualificationLookupOutageThenRecovery proves that a
// temporary inability to establish external reality can never degrade
// into FAILED: the record stays UNKNOWN while the lookup is down, no
// redispatch occurs, and the same stable token resolves once the lookup
// is restored.
func TestLiveCriticalQualificationLookupOutageThenRecovery(t *testing.T) {
	stack := newCriticalStack(t)
	grant := "grant-valid-" + qualificationKey("g")
	stack.issueGrant(t, grant, "alice@example.com", []string{qualificationCapabilityID}, time.Now().Add(time.Hour))

	key := qualificationKey("crit-outage")
	resp := stack.request(t, key, grant, "alice@example.com", map[string]string{
		"operation": "commit-outage",
		"fault":     faultCommitThenReset,
	})
	if resp.Status != StatusUnknown {
		t.Fatalf("expected UNKNOWN, got %s (%s)", resp.Status, resp.Error)
	}

	// Lookup outage: reconciliation cannot establish external reality.
	stack.adapter.lookupFault = faultLookupUnavailable
	if err := stack.worker.RunCycle(context.Background()); err != nil {
		t.Fatalf("reconcile cycle during outage: %v", err)
	}
	rec := stack.lookup(t, key)
	if rec.State != idempotency.StateUnknown {
		t.Fatalf("state during lookup outage = %s, want UNKNOWN (never FAILED)", rec.State)
	}
	if rec.ReconcileAttempt < 1 {
		t.Fatalf("reconcile attempt = %d, want >= 1 (the outage consumed an attempt)", rec.ReconcileAttempt)
	}
	if operations, executions := stack.providerStats(t); operations != 1 || executions != 1 {
		t.Fatalf("outage caused a redispatch: %d/%d, want 1/1", operations, executions)
	}

	// Lookup restored: the same stable token resolves the ambiguity. The
	// unresolved attempt released the claim with the first reconciliation
	// backoff (30s by design), so wait it out rather than bypassing the
	// scheduler — the backoff is part of what is being qualified.
	stack.adapter.lookupFault = ""
	time.Sleep(31 * time.Second)
	if err := stack.worker.RunCycle(context.Background()); err != nil {
		t.Fatalf("reconcile cycle after recovery: %v", err)
	}
	rec = stack.lookup(t, key)
	if rec.State != idempotency.StateCommitted {
		t.Fatalf("post-recovery state = %s, want COMMITTED", rec.State)
	}
	if len(rec.EvidenceReceipt) == 0 {
		t.Fatal("post-recovery commit without a signed receipt")
	}
	if operations, executions := stack.providerStats(t); operations != 1 || executions != 1 {
		t.Fatalf("recovery re-dispatched: %d/%d, want 1/1", operations, executions)
	}
}

// TestLiveCriticalQualificationTokenPayloadCollision proves the external
// boundary itself rejects a token rebound to a different payload —
// independently of EffectStore deduplication. The original operation and
// its artifact must be untouched.
func TestLiveCriticalQualificationTokenPayloadCollision(t *testing.T) {
	dir := t.TempDir()
	providerURL, logPath := startExternalProvider(t, dir)
	post := func(payload string) (int, []byte) {
		body := fmt.Sprintf(`{"token":"collision-token","payload":{"operation":%q}}`, payload)
		resp, err := http.Post(providerURL+"/operations", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, data
	}

	status, first := post("payload-A")
	if status != http.StatusOK {
		t.Fatalf("first operation status = %d, want 200 (%s)", status, first)
	}
	var op qualificationOperationResponse
	if err := json.Unmarshal(first, &op); err != nil {
		t.Fatalf("decode first operation: %v", err)
	}
	originalArtifact, err := os.ReadFile(filepath.Join(dir, "artifacts", op.ArtifactID))
	if err != nil {
		t.Fatalf("read durable artifact: %v", err)
	}

	status, second := post("payload-B")
	if status != http.StatusConflict {
		t.Fatalf("token rebound to a different payload: status = %d, want 409 (%s)", status, second)
	}

	// The original operation, its artifact, and the execution count are
	// unchanged; no second ledger entry exists.
	after, err := os.ReadFile(filepath.Join(dir, "artifacts", op.ArtifactID))
	if err != nil {
		t.Fatalf("re-read durable artifact: %v", err)
	}
	if !bytes.Equal(originalArtifact, after) {
		t.Fatal("the rejected collision mutated the original artifact")
	}
	statsResp, err := http.Get(providerURL + "/stats")
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	defer statsResp.Body.Close()
	var stats struct {
		Operations int `json:"operations"`
		Executions int `json:"executions"`
	}
	if err := json.NewDecoder(statsResp.Body).Decode(&stats); err != nil {
		t.Fatal(err)
	}
	if stats.Operations != 1 || stats.Executions != 1 {
		t.Fatalf("operations/executions = %d/%d, want 1/1", stats.Operations, stats.Executions)
	}
	ledger, err := os.ReadFile(filepath.Join(filepath.Dir(logPath), "operations.jsonl"))
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if lines := strings.Count(strings.TrimSpace(string(ledger)), "\n") + 1; lines != 1 {
		t.Fatalf("ledger entries = %d, want 1", lines)
	}
}

// TestLiveCriticalQualificationCorruptedArtifact proves corrupted
// transport bytes cannot produce a COMMITTED CRITICAL receipt: the
// adapter refuses the response, the outcome stays UNKNOWN, and the
// eventual commit — resolved by reconciliation — binds the provider's
// durable artifact, never the corrupted copy.
func TestLiveCriticalQualificationCorruptedArtifact(t *testing.T) {
	stack := newCriticalStack(t)
	grant := "grant-valid-" + qualificationKey("g")
	stack.issueGrant(t, grant, "alice@example.com", []string{qualificationCapabilityID}, time.Now().Add(time.Hour))

	key := qualificationKey("crit-corrupt")
	resp := stack.request(t, key, grant, "alice@example.com", map[string]string{
		"operation": "corrupt",
		"fault":     faultCorruptArtifact,
	})
	if resp.Status != StatusUnknown {
		t.Fatalf("corrupted artifact bytes must not commit: got %s (%s)", resp.Status, resp.Error)
	}
	rec := stack.lookup(t, key)
	if rec.State == idempotency.StateCommitted {
		t.Fatal("corrupted artifact bytes produced a COMMITTED record")
	}
	if operations, executions := stack.providerStats(t); operations != 1 || executions != 1 {
		t.Fatalf("provider operations/executions = %d/%d, want 1/1", operations, executions)
	}

	// Reconciliation fetches the durable artifact: the eventual receipt
	// binds the true bytes, not the corrupted copy.
	if err := stack.worker.RunCycle(context.Background()); err != nil {
		t.Fatalf("reconcile cycle: %v", err)
	}
	rec = stack.lookup(t, key)
	if rec.State != idempotency.StateCommitted {
		t.Fatalf("post-reconciliation state = %s, want COMMITTED", rec.State)
	}
	durable := fetchProviderArtifact(t, stack, rec.ProviderRunID)
	sum := sha256.Sum256(durable)
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
		t.Fatalf("receipt must bind the durable artifact: %v", err)
	}
}

// TestLiveCriticalQualificationRegistryExtensionBinding proves the
// qualification registry is the release registry plus explicit
// extensions, and that the harness records both identities — test-only
// capabilities never enter the shipped policy surface, and no release
// descriptor can be silently replaced or modified.
func TestLiveCriticalQualificationRegistryExtensionBinding(t *testing.T) {
	stack := newCriticalStack(t)
	binding := stack.binding

	if len(binding.QualificationExtensions) != 1 {
		t.Fatalf("extensions = %d, want exactly 1", len(binding.QualificationExtensions))
	}
	extension := binding.QualificationExtensions[0]
	if extension.CapabilityID != qualificationCapabilityID {
		t.Fatalf("extension capability = %s, want %s", extension.CapabilityID, qualificationCapabilityID)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(extension.DescriptorSHA256) {
		t.Fatalf("extension descriptor digest = %q, want a SHA-256", extension.DescriptorSHA256)
	}
	if binding.BaseRegistrySHA256 == binding.QualificationRegistrySHA256 {
		t.Fatal("qualification registry identity equals the release registry identity")
	}

	// The base identity is reproducible and extension-free: a fresh
	// release registry digests to exactly the recorded base.
	release := capability.NewRegistry()
	if err := RegisterBuiltinCapabilities(release); err != nil {
		t.Fatalf("release registry: %v", err)
	}
	releaseSHA, err := release.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if releaseSHA != binding.BaseRegistrySHA256 {
		t.Fatalf("release registry digest = %s, recorded base = %s", releaseSHA, binding.BaseRegistrySHA256)
	}
	for _, id := range release.List() {
		if id == qualificationCapabilityID {
			t.Fatal("the qualification capability is in the release registry — it must be qualification-only")
		}
	}
}

// TestCriticalCrashHelperProcess is the pre-restart half of the SIGKILL
// row: it dispatches one CRITICAL operation against PostgreSQL and the
// qualification provider, and SIGKILLs itself at CrashAfterProvider —
// the provider's durable commit is complete, but Crabedence has not
// persisted its observation or terminal receipt.
func TestCriticalCrashHelperProcess(t *testing.T) {
	if os.Getenv("CRABBOX_CRIT_CRASH_HELPER") != "1" {
		return
	}
	db, err := openTestDB(os.Getenv("CRABBOX_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()
	store, err := idempotency.NewStoreWithConfig(db, idempotency.LeaseConfig{
		DefaultDuration: 200 * time.Millisecond,
		MaxDuration:     time.Second,
		RenewalWindow:   50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	adapter := &qualificationAdapter{
		baseURL: os.Getenv("CRABBOX_PROVIDER_URL"),
		client:  &http.Client{Timeout: 2 * time.Second},
	}
	exec := NewDispatchExecutor(adapter, store)
	exec.SetCrashHook(func(p CrashPoint) {
		if p == CrashAfterProvider {
			// Provider committed; Crabedence must not have persisted the
			// observation or terminal receipt yet. Die here.
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
	})
	desc, err := capability.Resolve(capability.CapabilityDescriptor{
		ID:              qualificationCapabilityID,
		ExecutionClass:  capability.ClassCritical,
		AdapterID:       "qualification",
		AuthorityPolicy: capability.AuthorityPolicy{ID: qualificationCapabilityID, GrantRequired: true},
	})
	if err != nil {
		t.Fatalf("resolve descriptor: %v", err)
	}
	resp := exec.ExecuteWithIdempotency(context.Background(), Request{
		Capability: qualificationCapabilityID,
		Arguments:  json.RawMessage(`{"operation":"crash"}`),
		Authority: RequestAuthority{
			Principal:    "alice@example.com",
			AuthorityRef: os.Getenv("CRABBOX_CRIT_CRASH_GRANT"),
		},
		IdempotencyKey: os.Getenv("CRABBOX_CRIT_CRASH_KEY"),
	}, desc)
	// Reaching this line means the crash hook never fired — the test
	// harness is broken, not the runtime.
	fmt.Fprintf(os.Stderr, "helper survived the crash point: %s %s\n", resp.Status, resp.Error)
	os.Exit(3)
}

// TestLiveCriticalQualificationCrashThenRecover is the SIGKILL row: the
// provider's durable commit completes, Crabedence is destroyed before it
// persists the observation, and correctness survives process death —
// restart against the same PostgreSQL, recover the orphaned record, and
// resolve external reality through the persisted operation token to a
// signed COMMITTED receipt with exactly one external execution.
func TestLiveCriticalQualificationCrashThenRecover(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live CRITICAL crash qualification")
	}
	ctx := context.Background()
	providerURL, _ := startExternalProvider(t, t.TempDir())

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()
	authorityStore, err := authority.NewStore(db)
	if err != nil {
		t.Fatalf("authority store: %v", err)
	}
	grant := "grant-crash-" + qualificationKey("g")
	if _, err := authorityStore.IssueGrant(ctx, grant, "alice@example.com", []string{qualificationCapabilityID}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("issue grant: %v", err)
	}

	key := qualificationKey("crit-crash")
	cmd := exec.Command(os.Args[0], "-test.run=TestCriticalCrashHelperProcess")
	cmd.Env = append(os.Environ(),
		"CRABBOX_CRIT_CRASH_HELPER=1",
		"CRABBOX_TEST_DATABASE_URL="+dbURL,
		"CRABBOX_PROVIDER_URL="+providerURL,
		"CRABBOX_CRIT_CRASH_KEY="+key,
		"CRABBOX_CRIT_CRASH_GRANT="+grant,
	)
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("Crabedence should have been killed at the crash point\n%s", out)
	}

	stack := &criticalStack{providerURL: providerURL}
	if operations, executions := stack.providerStats(t); operations != 1 || executions != 1 {
		t.Fatalf("provider operations/executions before restart = %d/%d, want 1/1", operations, executions)
	}

	// Restart against the same PostgreSQL with a short lease.
	store, err := idempotency.NewStoreWithConfig(db, idempotency.LeaseConfig{
		DefaultDuration: 200 * time.Millisecond,
		MaxDuration:     time.Second,
		RenewalWindow:   50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	rec, err := store.LookupByKey(ctx, "alice@example.com", qualificationCapabilityID, key)
	if err != nil {
		t.Fatalf("lookup after crash: %v", err)
	}
	if rec.State.IsDurablyFinal() {
		t.Fatalf("crash produced terminal %s without finalization", rec.State)
	}

	signer, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	store.SetTrustedEvidenceSigners(signer.Fingerprint())
	adapter := &qualificationAdapter{baseURL: providerURL, client: &http.Client{Timeout: 2 * time.Second}}
	worker := reconcile.NewWorker(store, reconcile.NoopResolver{}, 30*time.Second)
	worker.RegisterResolver(qualificationCapabilityID, adapter)
	worker.SetEvidenceSigner(signer)

	// Let the orphaned lease expire, then reconcile external reality.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		if err := worker.RunCycle(ctx); err != nil {
			t.Fatalf("reconcile cycle: %v", err)
		}
		rec, err = store.LookupByKey(ctx, "alice@example.com", qualificationCapabilityID, key)
		if err != nil {
			t.Fatalf("lookup during recovery: %v", err)
		}
		if rec.State == idempotency.StateCommitted {
			break
		}
	}
	if rec.State != idempotency.StateCommitted {
		t.Fatalf("post-restart state = %s, want COMMITTED", rec.State)
	}
	if len(rec.EvidenceReceipt) == 0 {
		t.Fatal("post-restart COMMITTED without a signed receipt")
	}
	// Exactly one external execution, before and after the restart.
	if operations, executions := stack.providerStats(t); operations != 1 || executions != 1 {
		t.Fatalf("provider operations/executions after restart = %d/%d, want 1/1", operations, executions)
	}
	durable := fetchProviderArtifact(t, stack, rec.ProviderRunID)
	sum := sha256.Sum256(durable)
	if err := evidence.VerifyReceipt(rec.EvidenceReceipt, evidence.Binding{
		ExecutionID:    rec.ExecutionID,
		Capability:     qualificationCapabilityID,
		Principal:      "alice@example.com",
		RequestDigest:  rec.RequestDigest,
		ProviderID:     rec.ProviderID,
		ProviderRunID:  rec.ProviderRunID,
		Outcome:        evidence.OutcomeCompleted,
		EvidenceSHA256: fmt.Sprintf("%x", sum),
	}, map[string]bool{signer.Fingerprint(): true}); err != nil {
		t.Fatalf("post-restart receipt failed verification: %v", err)
	}
}
