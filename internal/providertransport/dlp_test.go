package providertransport

import (
	"context"
	"strings"
	"testing"
)

func eval(t *testing.T, dlp OutboundDLP, in DLPInput) DLPDecision {
	t.Helper()
	d, err := dlp.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return d
}

func TestProtectedValueInBodyBlocked(t *testing.T) {
	p := NewProtectedValues()
	p.Protect("test credential", "s3cr3t-value-xyz")
	d := eval(t, p, DLPInput{Body: []byte(`{"title":"see s3cr3t-value-xyz here"}`)})
	if d.Kind != DecisionBlock {
		t.Fatalf("decision = %s", d.Kind)
	}
	// The refusal reason names the protected class, never the value.
	if strings.Contains(d.Reason, "s3cr3t-value-xyz") {
		t.Fatal("refusal reason leaks the protected value")
	}
}

func TestProtectedValueInHeaderBlocked(t *testing.T) {
	p := NewProtectedValues()
	p.Protect("test credential", "s3cr3t-value-xyz")
	d := eval(t, p, DLPInput{Headers: map[string]string{"X-Trace": "s3cr3t-value-xyz"}})
	if d.Kind != DecisionBlock {
		t.Fatalf("decision = %s", d.Kind)
	}
}

func TestSafePayloadAllowed(t *testing.T) {
	chain := ChainDLP{NewProtectedValues(), SecretPatterns{}}
	d := eval(t, chain, DLPInput{Body: []byte(`{"title":"a normal issue","body":"nothing sensitive"}`)})
	if d.Kind != DecisionAllow {
		t.Fatalf("decision = %s", d.Kind)
	}
}

func TestSecretPatternCorpus(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"github pat", `{"body":"token ghp_` + strings.Repeat("a", 36) + `"}`},
		{"github fine-grained", `{"body":"github_pat_` + strings.Repeat("a", 40) + `"}`},
		{"aws key", `{"body":"AKIA` + strings.Repeat("B", 16) + `"}`},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIB"},
		{"private key generic", "-----BEGIN PRIVATE KEY-----\nMIIB"},
		{"jwt", `{"body":"eyJ` + strings.Repeat("a", 20) + `.` + strings.Repeat("b", 20) + `.` + strings.Repeat("c", 20) + `"}`},
		{"bearer", `{"body":"Authorization: Bearer ` + strings.Repeat("t", 30) + `"}`},
		{"db url with password", `{"body":"postgres://admin:hunter2@db.internal:5432/app"}`},
		{"mysql url with password", `{"body":"mysql://root:pw@db/x"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := eval(t, SecretPatterns{}, DLPInput{Body: []byte(tc.body)})
			if d.Kind != DecisionBlock {
				t.Fatalf("%s: decision = %s", tc.name, d.Kind)
			}
		})
	}
}

func TestSecretPatternInHeaderBlocked(t *testing.T) {
	d := eval(t, SecretPatterns{}, DLPInput{
		Headers: map[string]string{"X-Debug": "ghp_" + strings.Repeat("a", 36)},
	})
	if d.Kind != DecisionBlock {
		t.Fatalf("decision = %s", d.Kind)
	}
}

func TestFieldPolicyForbiddenField(t *testing.T) {
	p := &CapabilityFieldPolicy{
		Policies: map[string]FieldPolicy{
			"cap.mutate": {ForbiddenFields: map[string]bool{"credentials": true}},
		},
		RequirePolicyForClasses: map[string]bool{"MUTATION": true},
	}
	d := eval(t, p, DLPInput{
		Capability:     "cap.mutate",
		ExecutionClass: "MUTATION",
		Body:           []byte(`{"title":"x","credentials":"y"}`),
	})
	if d.Kind != DecisionBlock {
		t.Fatalf("decision = %s", d.Kind)
	}
}

func TestFieldPolicyUnlistedFieldBlocked(t *testing.T) {
	p := &CapabilityFieldPolicy{
		Policies: map[string]FieldPolicy{
			"cap.mutate": {AllowedFields: map[string]bool{"title": true, "body": true}},
		},
	}
	d := eval(t, p, DLPInput{
		Capability: "cap.mutate",
		Body:       []byte(`{"title":"x","exfil":"/etc/passwd"}`),
	})
	if d.Kind != DecisionBlock {
		t.Fatalf("decision = %s", d.Kind)
	}
}

func TestUnknownCapabilityMutationFailsClosed(t *testing.T) {
	p := &CapabilityFieldPolicy{
		Policies:                map[string]FieldPolicy{},
		RequirePolicyForClasses: map[string]bool{"MUTATION": true, "CRITICAL": true},
	}
	d := eval(t, p, DLPInput{
		Capability:     "cap.unlisted",
		ExecutionClass: "MUTATION",
		Body:           []byte(`{"anything":true}`),
	})
	if d.Kind != DecisionBlock {
		t.Fatalf("unlisted mutation capability must fail closed, got %s", d.Kind)
	}
	// The same capability under a non-mutating class is not required
	// to declare a payload policy.
	d = eval(t, p, DLPInput{
		Capability:     "cap.unlisted",
		ExecutionClass: "READ",
		Body:           []byte(`{"anything":true}`),
	})
	if d.Kind != DecisionAllow {
		t.Fatalf("read-shaped unlisted capability = %s", d.Kind)
	}
}

func TestPayloadDepthBound(t *testing.T) {
	p := &CapabilityFieldPolicy{Policies: map[string]FieldPolicy{}}
	deep := strings.Repeat(`{"a":`, 40) + `1` + strings.Repeat(`}`, 40)
	d := eval(t, p, DLPInput{Capability: "cap.any", Body: []byte(deep)})
	if d.Kind != DecisionBlock {
		t.Fatalf("over-deep payload = %s", d.Kind)
	}
}

func TestPayloadFieldSizeBound(t *testing.T) {
	p := &CapabilityFieldPolicy{
		Policies:      map[string]FieldPolicy{},
		MaxFieldBytes: 16,
	}
	d := eval(t, p, DLPInput{
		Capability: "cap.any",
		Body:       []byte(`{"title":"` + strings.Repeat("x", 64) + `"}`),
	})
	if d.Kind != DecisionBlock {
		t.Fatalf("oversized field = %s", d.Kind)
	}
}

func TestChainFirstBlockWins(t *testing.T) {
	p := NewProtectedValues()
	p.Protect("known", "SECRETVAL")
	chain := ChainDLP{p, blockerDLP{reason: "second"}}
	d := eval(t, chain, DLPInput{Body: []byte("has SECRETVAL")})
	if d.Kind != DecisionBlock || !strings.Contains(d.Reason, "protected") {
		t.Fatalf("first block should win: %+v", d)
	}
}

func TestChainTransformPropagates(t *testing.T) {
	chain := ChainDLP{transformDLP{to: []byte("clean")}, SecretPatterns{}}
	d := eval(t, chain, DLPInput{Body: []byte("dirty")})
	if d.Kind != DecisionTransform || string(d.TransformedBody) != "clean" {
		t.Fatalf("transform = %+v", d)
	}
}
