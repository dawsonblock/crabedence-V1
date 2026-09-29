package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// QualificationCapabilityID is the qualification-only CRITICAL
// capability. It is registered on a service only when
// CRABEDENCE_QUAL_PROVIDER_URL is configured — it is an extension of
// the release registry, never part of the shipped catalog (the
// release registry digest is recorded separately and the qualification
// binding records the extension's descriptor digest).
const QualificationCapabilityID = "qualification.critical.commit"

// QualificationAdapterID binds the qualification capability to its
// external provider adapter.
const QualificationAdapterID = "qualification"

// QualificationDescriptor returns the canonical descriptor for the
// qualification capability — shared by the service (deployed-provider
// wiring) and the qualification harness so both register identical
// policy material.
func QualificationDescriptor() (capability.ResolvedDescriptor, error) {
	return capability.Resolve(capability.CapabilityDescriptor{
		ID:             QualificationCapabilityID,
		ExecutionClass: capability.ClassCritical,
		AdapterID:      QualificationAdapterID,
		AuthorityPolicy: capability.AuthorityPolicy{
			ID:            QualificationCapabilityID,
			GrantRequired: true,
		},
		Schema: json.RawMessage(`{"type":"object","properties":{"operation":{"type":"string"},"fault":{"type":"string"}},"required":["operation"],"additionalProperties":false}`),
	})
}

// QualificationAdapter is the executor-side handler for the external
// qualification provider: the full provider contract (capability
// declaration, recovery locator, dispatch, read-only resolution) over
// the provider's HTTP operation API. It never trusts the provider's
// claimed digest — the artifact bytes are handed to the executor,
// which recomputes SHA-256 itself.
type QualificationAdapter struct {
	baseURL string
	client  *http.Client
	// lookupFault, when set, injects a deterministic lookup outage into
	// reconciliation (a test/proof clears it to restore the lookup). It
	// is harness state, never part of the provider contract.
	lookupFault string
}

// NewQualificationAdapter creates the adapter for a deployed
// qualification provider at baseURL (http://host:port).
//
// The provider contract is loopback-only and unauthenticated: the
// adapter refuses any target that is not the local host, so an
// accidental URL change cannot turn the contract into a remote
// request surface. IP literals must be loopback (127.0.0.0/8 or ::1,
// including IPv4-mapped forms); the only accepted hostname is
// "localhost" (case-insensitive, optional trailing dot). Userinfo,
// alternate IP encodings, and every other hostname are refused.
func NewQualificationAdapter(baseURL string) (*QualificationAdapter, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("CRABEDENCE_QUAL_PROVIDER_URL %q must be an http(s) URL with a host", baseURL)
	}
	if err := requireLoopbackHost(u); err != nil {
		return nil, fmt.Errorf("CRABEDENCE_QUAL_PROVIDER_URL %q must target the local host: %w", baseURL, err)
	}
	return &QualificationAdapter{
		baseURL: strings.TrimRight(baseURL, "/"),
		client: &http.Client{
			Timeout: 30 * time.Second,
			// The provider contract is loopback-only, so a redirect
			// could only ever move the request off the validated local
			// host. Refuse redirects outright rather than validating
			// each hop — the provider API has no legitimate redirect.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return fmt.Errorf("qualification provider redirect to %s refused: the provider contract is loopback-only", req.URL.Redacted())
			},
		},
	}, nil
}

// requireLoopbackHost validates that a parsed provider URL targets the
// local host. The check is structural — it never performs DNS — so a
// hostname that is not exactly "localhost" is refused regardless of
// what it might resolve to.
func requireLoopbackHost(u *url.URL) error {
	if u.User != nil {
		return fmt.Errorf("URLs with userinfo are not accepted")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("missing host")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Is4In6() {
			addr = addr.Unmap()
		}
		if !addr.IsLoopback() {
			return fmt.Errorf("host %q is not a loopback address", host)
		}
		return nil
	}
	if name := strings.TrimSuffix(strings.ToLower(host), "."); name == "localhost" {
		return nil
	}
	return fmt.Errorf("host %q is not a loopback address or localhost", host)
}

// SetLookupFault injects a deterministic lookup outage for
// reconciliation proofs; empty restores normal lookups.
func (a *QualificationAdapter) SetLookupFault(fault string) { a.lookupFault = fault }

// ping performs the provider's side-effect-free stats lookup so
// startup can fail closed when a configured provider is unreachable.
func (a *QualificationAdapter) ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+"/stats", nil)
	if err != nil {
		return err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}

func (a *QualificationAdapter) ProviderCapabilities(string) ProviderCapabilities {
	return ProviderCapabilities{
		SupportsProviderIdempotency: true,
		SupportsStatusLookup:        true,
		SupportsCompletionProof:     true,
		SupportsNonexecutionProof:   true,
		RecoveryLocatorType:         "external-token",
	}
}

func (a *QualificationAdapter) PrepareRecovery(_ context.Context, in idempotency.RecoveryLocatorInput) (*idempotency.RecoveryLocator, error) {
	return &idempotency.RecoveryLocator{
		Version:        1,
		ProviderID:     QualificationAdapterID,
		Strategy:       "external-token",
		ExternalToken:  idempotency.ProviderIdempotencyKey(in.ExecutionID, in.RequestDigest, QualificationAdapterID),
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
func (a *QualificationAdapter) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	token := ExternalTokenFromContext(ctx)
	if token == "" {
		return Response{
			Status:            StatusFailed,
			FailureCode:       string(capability.FailureInternalError),
			Error:             "missing external operation token",
			DefinitiveFailure: true,
			Execution:         &ExecutionMeta{Provider: QualificationAdapterID},
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
			Execution:         &ExecutionMeta{Provider: QualificationAdapterID},
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
			Execution:   &ExecutionMeta{Provider: QualificationAdapterID},
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
			Execution:         &ExecutionMeta{Provider: QualificationAdapterID},
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
			Execution:         &ExecutionMeta{Provider: QualificationAdapterID},
		}
	}

	var out qualificationOperationResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return Response{
			Status:      StatusUnknown,
			FailureCode: string(capability.FailureExecutionUnknown),
			Error:       "qualification provider returned an unparseable response: " + err.Error(),
			Execution:   &ExecutionMeta{Provider: QualificationAdapterID},
		}
	}
	switch out.Status {
	case "COMMITTED":
		// The artifact identity must match the provider's durable
		// artifact: a response whose bytes differ from the ledger's copy
		// is transport corruption, and committing it would attest bytes
		// the provider cannot prove. Ambiguous → UNKNOWN.
		durable, err := a.fetchArtifact(ctx, out.ArtifactID)
		if err != nil {
			// The artifact bytes cannot be verified against the
			// provider's durable copy: committing them would attest
			// bytes the provider cannot prove. Ambiguous → UNKNOWN;
			// reconciliation resolves from the provider ledger.
			return Response{
				Status:      StatusUnknown,
				FailureCode: string(capability.FailureExecutionUnknown),
				Error:       "qualification provider artifact could not be verified against its durable artifact: " + err.Error(),
				Execution:   &ExecutionMeta{Provider: QualificationAdapterID, RunID: out.OperationID},
			}
		}
		if !bytes.Equal(durable, out.Artifact) {
			return Response{
				Status:      StatusUnknown,
				FailureCode: string(capability.FailureExecutionUnknown),
				Error:       "qualification provider artifact does not match its durable artifact",
				Execution:   &ExecutionMeta{Provider: QualificationAdapterID, RunID: out.OperationID},
			}
		}
		result, _ := json.Marshal(map[string]any{"operation_id": out.OperationID})
		return Response{
			Status:           StatusSucceeded,
			Result:           result,
			Evidence:         &EvidenceRef{ReceiptVersion: 3},
			EvidenceArtifact: out.Artifact,
			Execution:        &ExecutionMeta{Provider: QualificationAdapterID, RunID: out.OperationID},
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
			Execution:         &ExecutionMeta{Provider: QualificationAdapterID, RunID: out.OperationID},
		}
	}
	return Response{
		Status:      StatusUnknown,
		FailureCode: string(capability.FailureExecutionUnknown),
		Error:       "qualification provider reported status " + out.Status,
		Execution:   &ExecutionMeta{Provider: QualificationAdapterID, RunID: out.OperationID},
	}
}

// Resolve implements idempotency.RecoveryResolver: strictly read-only.
// It queries the provider's durable ledger by the stable token and
// fetches the immutable artifact bytes — the digest is recomputed by
// the worker before signing, never taken from the provider's claim.
func (a *QualificationAdapter) Resolve(ctx context.Context, rec *idempotency.Record) (idempotency.RecoveryResult, error) {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, lookupURL, nil)
	if err != nil {
		return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
	}
	resp, err := a.client.Do(req)
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
		return idempotency.RecoveryResult{Decision: idempotency.RecoveryFailed, ProviderID: QualificationAdapterID}, nil
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
			ProviderID:       QualificationAdapterID,
			ProviderRunID:    op.OperationID,
			ReceiptVersion:   3,
			EvidenceArtifact: artifact,
		}, nil
	case "REJECTED":
		return idempotency.RecoveryResult{
			Decision:         idempotency.RecoveryFailed,
			ProviderID:       QualificationAdapterID,
			ProviderRunID:    op.OperationID,
			ReceiptVersion:   3,
			EvidenceArtifact: artifact,
		}, nil
	}
	return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
}

func (a *QualificationAdapter) fetchArtifact(ctx context.Context, artifactID string) ([]byte, error) {
	if artifactID == "" {
		return nil, fmt.Errorf("no artifact id")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+"/artifacts/"+url.PathEscape(artifactID), nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("artifact %s: status %d", artifactID, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
