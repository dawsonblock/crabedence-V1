package providertransport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// DecisionKind is the outbound-DLP verdict.
type DecisionKind int

const (
	// DecisionAllow permits the payload unchanged.
	DecisionAllow DecisionKind = iota
	// DecisionBlock refuses the payload before dispatch — a definite
	// no-effect, never an UNKNOWN.
	DecisionBlock
	// DecisionTransform permits the payload after a transformation;
	// the transformed bytes are what reach the wire and the request
	// digest.
	DecisionTransform
	// DecisionRequireApproval refuses the payload pending approval.
	// It is never silently converted to Allow.
	DecisionRequireApproval
)

// String renders the decision for audit.
func (d DecisionKind) String() string {
	switch d {
	case DecisionAllow:
		return "ALLOW"
	case DecisionBlock:
		return "BLOCK"
	case DecisionTransform:
		return "TRANSFORM"
	case DecisionRequireApproval:
		return "REQUIRE_APPROVAL"
	default:
		return fmt.Sprintf("UNRECOGNIZED(%d)", int(d))
	}
}

// DLPInput is everything the outbound policy may consider. Body is
// the canonical outbound payload — the exact bytes that would reach
// the provider. Headers are the pre-secret headers only: the
// credential is attached after DLP, so no evaluation can be gamed by
// or leak through the Authorization header the transport owns.
type DLPInput struct {
	Principal      string
	Capability     string
	ExecutionClass string
	Provider       string
	Origin         string
	Resource       string
	AuthorityID    string
	ExecutionID    string
	Method         string
	Path           string
	Headers        map[string]string
	Body           []byte
	ContentType    string
}

// DLPDecision is the verdict plus the non-secret provenance audit
// needs. Reason and PolicyDigest are recorded; the offending secret
// material is never stored or logged.
type DLPDecision struct {
	Kind             DecisionKind
	Reason           string
	PolicyDigest     string
	TransformedBody  []byte
	TransformSummary string
}

// OutboundDLP evaluates a canonical outbound payload immediately
// before credential attachment and network dispatch.
type OutboundDLP interface {
	Evaluate(ctx context.Context, input DLPInput) (DLPDecision, error)
}

// ChainDLP composes evaluators: the first non-allow verdict wins —
// BLOCK beats TRANSFORM beats REQUIRE_APPROVAL by construction of the
// order callers assemble the chain — and any evaluator error fails
// the request closed.
type ChainDLP []OutboundDLP

// Evaluate implements OutboundDLP.
func (c ChainDLP) Evaluate(ctx context.Context, in DLPInput) (DLPDecision, error) {
	combined := DLPDecision{Kind: DecisionAllow}
	var digests []string
	body := in.Body
	for _, dlp := range c {
		// Each evaluator sees the current payload, so a transform
		// upstream is what later evaluators and the wire agree on.
		decision, err := dlp.Evaluate(ctx, DLPInput{
			Principal:      in.Principal,
			Capability:     in.Capability,
			ExecutionClass: in.ExecutionClass,
			Provider:       in.Provider,
			Origin:         in.Origin,
			Resource:       in.Resource,
			AuthorityID:    in.AuthorityID,
			ExecutionID:    in.ExecutionID,
			Method:         in.Method,
			Path:           in.Path,
			Headers:        in.Headers,
			Body:           body,
			ContentType:    in.ContentType,
		})
		if err != nil {
			return DLPDecision{}, fmt.Errorf("dlp evaluator failed: %w", err)
		}
		if decision.PolicyDigest != "" {
			digests = append(digests, decision.PolicyDigest)
		}
		switch decision.Kind {
		case DecisionAllow:
		case DecisionTransform:
			body = decision.TransformedBody
			combined = DLPDecision{Kind: DecisionTransform, TransformedBody: body}
		default:
			// BLOCK and REQUIRE_APPROVAL end evaluation — the strictest
			// answer is the answer.
			sort.Strings(digests)
			decision.PolicyDigest = digestStrings(digests)
			return decision, nil
		}
	}
	sort.Strings(digests)
	combined.PolicyDigest = digestStrings(digests)
	return combined, nil
}

// digestStrings folds policy digests into one audit identity.
func digestStrings(parts []string) string {
	h := sha256.New()
	for _, p := range parts {
		fmt.Fprintf(h, "%s\n", p)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// ─── Protected-value registry ───────────────────────────────────────
//
// ProtectedValues is the strongest leak check available: the runtime
// registers the actual secret values it holds (provider tokens,
// signing material, connection strings), and any of them appearing in
// an outbound payload or header is a hard block. A token that was
// about to be sent inside an issue title is caught before any
// credential attaches.

// ProtectedValues blocks payloads containing registered secrets.
type ProtectedValues struct {
	mu     sync.RWMutex
	values map[string]string // value → non-secret label for the reason
}

// NewProtectedValues returns an empty registry.
func NewProtectedValues() *ProtectedValues {
	return &ProtectedValues{values: map[string]string{}}
}

// Protect registers value under a non-secret label (e.g. "github
// credential", "evidence signing key"). Labels are what audit and
// refusal reasons may name; the values never are.
func (p *ProtectedValues) Protect(label, value string) {
	if value == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.values[value] = label
}

// Evaluate implements OutboundDLP.
func (p *ProtectedValues) Evaluate(_ context.Context, in DLPInput) (DLPDecision, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for value, label := range p.values {
		if strings.Contains(string(in.Body), value) {
			return DLPDecision{
				Kind:         DecisionBlock,
				Reason:       fmt.Sprintf("payload contains a protected value (%s)", label),
				PolicyDigest: "sha256:protected-values-v1",
			}, nil
		}
		for name, header := range in.Headers {
			if strings.Contains(header, value) {
				return DLPDecision{
					Kind:         DecisionBlock,
					Reason:       fmt.Sprintf("header %s contains a protected value (%s)", name, label),
					PolicyDigest: "sha256:protected-values-v1",
				}, nil
			}
		}
	}
	return DLPDecision{Kind: DecisionAllow, PolicyDigest: "sha256:protected-values-v1"}, nil
}

// ─── Secret-shape scanner ───────────────────────────────────────────
//
// SecretPatterns catches credential-shaped material the registry
// cannot know about — a token copied into a title, a private key
// pasted into a body, a database URL with an embedded password. It is
// shape detection: it never learns what the runtime's secrets are,
// only what secrets look like.

// secretPattern pairs a detector with its non-secret audit name.
type secretPattern struct {
	name    string
	pattern *regexp.Regexp
}

// secretPatterns is the baseline credential corpus. New shapes are
// additive — the policy digest below names this exact rule set so a
// change in detection is a change in audit identity.
var secretPatterns = []secretPattern{
	{name: "github-pat", pattern: regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr|ghc)_[A-Za-z0-9]{30,}\b`)},
	{name: "github-fine-grained-pat", pattern: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}\b`)},
	{name: "github-oauth", pattern: regexp.MustCompile(`\bgho_[A-Za-z0-9]{30,}\b`)},
	{name: "aws-access-key", pattern: regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{name: "private-key", pattern: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----`)},
	{name: "jwt", pattern: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)},
	{name: "bearer-token", pattern: regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b`)},
	{name: "slack-token", pattern: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{name: "openai-key", pattern: regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`)},
	{name: "database-url-with-password", pattern: regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)://[^/\s:@]+:[^@\s/]+@`)},
}

// SecretPatterns blocks outbound payloads carrying credential-shaped
// material. It scans the body and every header value.
type SecretPatterns struct{}

// Evaluate implements OutboundDLP.
func (SecretPatterns) Evaluate(_ context.Context, in DLPInput) (DLPDecision, error) {
	if hit := scanPatterns(in.Body); hit != "" {
		return DLPDecision{
			Kind:         DecisionBlock,
			Reason:       fmt.Sprintf("payload contains credential-shaped material (%s)", hit),
			PolicyDigest: "sha256:secret-patterns-v1",
		}, nil
	}
	for name, value := range in.Headers {
		if hit := scanPatterns([]byte(value)); hit != "" {
			return DLPDecision{
				Kind:         DecisionBlock,
				Reason:       fmt.Sprintf("header %s contains credential-shaped material (%s)", name, hit),
				PolicyDigest: "sha256:secret-patterns-v1",
			}, nil
		}
	}
	return DLPDecision{Kind: DecisionAllow, PolicyDigest: "sha256:secret-patterns-v1"}, nil
}

func scanPatterns(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	s := string(data)
	for _, p := range secretPatterns {
		if p.pattern.MatchString(s) {
			return p.name
		}
	}
	return ""
}

// ─── Capability field policy ────────────────────────────────────────
//
// FieldPolicy is the capability-aware half: for a mutation capability
// it names the exact top-level JSON fields the canonical payload may
// carry, and the fields that may never appear. This is defence in
// depth under the admission-time argument schemas — a payload is the
// provider-bound projection of the arguments, and the projection gets
// its own fence. Unknown capabilities fail closed for mutating
// execution classes.

// FieldPolicy names the allowed and forbidden top-level fields of a
// capability's canonical JSON payload.
type FieldPolicy struct {
	// AllowedFields is the exhaustive top-level field set; nil means
	// any field may appear.
	AllowedFields map[string]bool
	// ForbiddenFields may never appear — credential-shaped projection
	// fields a legitimate provider payload does not carry.
	ForbiddenFields map[string]bool
}

// CapabilityFieldPolicy applies per-capability field rules to JSON
// payloads, plus structure bounds every payload must satisfy.
type CapabilityFieldPolicy struct {
	// Policies maps capability ID to its field policy.
	Policies map[string]FieldPolicy
	// RequirePolicyForClasses lists execution classes for which an
	// unlisted capability fails closed.
	RequirePolicyForClasses map[string]bool
	// MaxDepth bounds JSON nesting (defence against pathological
	// payload structure).
	MaxDepth int
	// MaxFieldBytes bounds any single string field.
	MaxFieldBytes int
}

// DefaultStructureBounds are the production payload-structure bounds.
func DefaultStructureBounds() (depth, fieldBytes int) {
	return 24, 512 * 1024
}

// Evaluate implements OutboundDLP.
func (p *CapabilityFieldPolicy) Evaluate(_ context.Context, in DLPInput) (DLPDecision, error) {
	maxDepth, maxField := DefaultStructureBounds()
	if p.MaxDepth > 0 {
		maxDepth = p.MaxDepth
	}
	if p.MaxFieldBytes > 0 {
		maxField = p.MaxFieldBytes
	}
	if len(in.Body) == 0 {
		return DLPDecision{Kind: DecisionAllow, PolicyDigest: "sha256:field-policy-v1"}, nil
	}
	// Structure bounds apply to every body — JSON or not, an
	// oversized string field can't hide inside a non-JSON blob.
	if len(in.Body) > 0 {
		var parsed any
		if err := json.Unmarshal(in.Body, &parsed); err == nil {
			if depth := jsonDepth(parsed); depth > maxDepth {
				return DLPDecision{
					Kind:         DecisionBlock,
					Reason:       fmt.Sprintf("payload nests %d levels, exceeding the %d-level bound", depth, maxDepth),
					PolicyDigest: "sha256:field-policy-v1",
				}, nil
			}
			if over := oversizedField(parsed, maxField); over != "" {
				return DLPDecision{
					Kind:         DecisionBlock,
					Reason:       fmt.Sprintf("payload field %s exceeds the %d-byte field bound", over, maxField),
					PolicyDigest: "sha256:field-policy-v1",
				}, nil
			}
			policy, known := p.Policies[in.Capability]
			if !known {
				if p.RequirePolicyForClasses[in.ExecutionClass] {
					return DLPDecision{
						Kind:         DecisionBlock,
						Reason:       fmt.Sprintf("capability %q has no outbound field policy — %s payloads fail closed", in.Capability, in.ExecutionClass),
						PolicyDigest: "sha256:field-policy-v1",
					}, nil
				}
				return DLPDecision{Kind: DecisionAllow, PolicyDigest: "sha256:field-policy-v1"}, nil
			}
			obj, isObj := parsed.(map[string]any)
			if !isObj {
				return DLPDecision{Kind: DecisionAllow, PolicyDigest: "sha256:field-policy-v1"}, nil
			}
			for field := range obj {
				if policy.ForbiddenFields[field] {
					return DLPDecision{
						Kind:         DecisionBlock,
						Reason:       fmt.Sprintf("payload field %q is forbidden for %s", field, in.Capability),
						PolicyDigest: "sha256:field-policy-v1",
					}, nil
				}
				if policy.AllowedFields != nil && !policy.AllowedFields[field] {
					return DLPDecision{
						Kind:         DecisionBlock,
						Reason:       fmt.Sprintf("payload field %q is not in the %s outbound field policy", field, in.Capability),
						PolicyDigest: "sha256:field-policy-v1",
					}, nil
				}
			}
		}
	}
	return DLPDecision{Kind: DecisionAllow, PolicyDigest: "sha256:field-policy-v1"}, nil
}

// jsonDepth measures the nesting depth of a decoded JSON value.
func jsonDepth(v any) int {
	switch t := v.(type) {
	case map[string]any:
		deepest := 0
		for _, val := range t {
			if d := jsonDepth(val); d > deepest {
				deepest = d
			}
		}
		return deepest + 1
	case []any:
		deepest := 0
		for _, val := range t {
			if d := jsonDepth(val); d > deepest {
				deepest = d
			}
		}
		return deepest + 1
	default:
		return 0
	}
}

// oversizedField returns the path of the first string field over the
// bound, or "" when every field fits.
func oversizedField(v any, maxBytes int) string {
	switch t := v.(type) {
	case string:
		if len(t) > maxBytes {
			return "(string)"
		}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if hit := oversizedField(t[k], maxBytes); hit != "" {
				return k + "/" + hit
			}
		}
	case []any:
		for i, val := range t {
			if hit := oversizedField(val, maxBytes); hit != "" {
				return fmt.Sprintf("[%d]/%s", i, hit)
			}
		}
	}
	return ""
}
