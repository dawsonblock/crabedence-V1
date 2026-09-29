package execution

import "testing"

// ParseInvocationRequest is the entry point for bridges that must preserve
// wire semantics rather than normalize them. The stable authority field is
// `authority_ref`; `grant_id` is only a deprecated alias, so a bridge that
// understands only the alias silently discards valid authority.

func TestParseInvocationRequestPreservesTheStableAuthorityField(t *testing.T) {
	request, err := ParseInvocationRequest([]byte(
		`{"capability":"test.counter.increment","arguments":{},"authority":{"principal":"alice@example.com","authority_ref":"grant-1"}}`,
	))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := request.Authority.EffectiveAuthorityRef(); got != "grant-1" {
		t.Fatalf("authority_ref must survive parsing, got %q", got)
	}
}

func TestParseInvocationRequestKeepsTheDeprecatedAlias(t *testing.T) {
	request, err := ParseInvocationRequest([]byte(
		`{"capability":"test.counter.increment","arguments":{},"authority":{"principal":"alice@example.com","grant_id":"grant-1"}}`,
	))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := request.Authority.EffectiveAuthorityRef(); got != "grant-1" {
		t.Fatalf("grant_id must remain a working alias, got %q", got)
	}
}

func TestParseInvocationRequestRefusesServerResolvedFields(t *testing.T) {
	for _, field := range []string{
		`"execution_route":"LOCAL"`,
		`"assurance_profile":"DURABLE"`,
		`"provider":"github"`,
		`"schema":{}`,
		`"receipt_version":3`,
		`"evidence":{}`,
	} {
		wire := `{"capability":"test.counter.increment","arguments":{},"authority":{"principal":"alice@example.com"},` + field + `}`
		if _, err := ParseInvocationRequest([]byte(wire)); err == nil {
			t.Fatalf("%s must be refused as an unknown field", field)
		}
	}
}
