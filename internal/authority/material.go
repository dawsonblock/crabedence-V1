package authority

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ErrGrantMaterialUnverified reports that persisted authority material
// could not be verified: malformed JSON, an undecodable constraint map,
// or a stored digest that does not match the material it covers.
//
// It is deliberately an error rather than a silent denial: admission
// treats a resolution error as UNAUTHORIZED (fail closed), and the
// failure is observable instead of being indistinguishable from "no
// such grant".
var ErrGrantMaterialUnverified = errors.New("grant material could not be verified")

// Persisted authority material is decoded STRICTLY.
//
// The grant semantics make a permissive decode a security defect: an
// empty capability list is the wildcard, and a nil constraint map is
// unconstrained. A decode failure that produced either would therefore
// BROADEN authority — corrupted security metadata must deny instead.

// decodeCapabilitiesJSON decodes a stored capability list strictly.
//
// The issuer always writes a canonical encoding (`json.Marshal`), so the
// stored text must equal the canonical re-encoding of what it decodes
// to. Blank, whitespace, and non-canonical text are unverifiable, and a
// decode failure must never become an empty list — an empty capability
// list is the wildcard, so a permissive decode would BROADEN authority.
//
// `null` remains valid, and the distinction is precise: `json.Marshal`
// encodes a NIL slice as `null` and an ALLOCATED empty slice as `[]`.
// Both mean "no capabilities", which this lifecycle treats as the
// wildcard — so a later cleanup that normalizes nil and empty slices
// would silently change authority semantics. The wildcard test pins both
// stored representations for exactly that reason.
//
// Distinguishing an issued wildcard from material corrupted into `null`
// is impossible under that convention; removing the convention (requiring
// an explicit `*`) is a compatibility-breaking change.
func decodeCapabilitiesJSON(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("capabilities: empty material")
	}
	var caps []string
	if err := json.Unmarshal([]byte(raw), &caps); err != nil {
		return nil, fmt.Errorf("capabilities: %w", err)
	}
	canonical, err := json.Marshal(caps)
	if err != nil || string(canonical) != raw {
		return nil, fmt.Errorf("capabilities: %q is not the canonical encoding of its value", raw)
	}
	return caps, nil
}

// decodeConstraintsJSON decodes a stored constraint map strictly, under
// the same canonical-encoding rule: a nil map is unconstrained, so a
// permissive decode would broaden authority.
func decodeConstraintsJSON(raw string) (map[string][]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("constraints: empty material")
	}
	var constraints map[string][]string
	if err := json.Unmarshal([]byte(raw), &constraints); err != nil {
		return nil, fmt.Errorf("constraints: %w", err)
	}
	canonical, err := json.Marshal(constraints)
	if err != nil || string(canonical) != raw {
		return nil, fmt.Errorf("constraints: %q is not the canonical encoding of its value", raw)
	}
	return constraints, nil
}

// decodeJSONBConstraints decodes PostgreSQL's jsonb text output, which is
// NOT canonical (it contains spaces), so the canonical-encoding rule
// cannot apply. Blank and malformed text are still errors, and the
// column type already prevents them from being stored.
func decodeJSONBConstraints(raw string) (map[string][]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("constraints: empty material")
	}
	var constraints map[string][]string
	if err := json.Unmarshal([]byte(raw), &constraints); err != nil {
		return nil, fmt.Errorf("constraints: %w", err)
	}
	return constraints, nil
}

// decodeGrantMaterial decodes both persisted fields, aborting on either.
func decodeGrantMaterial(capsRaw, constraintsRaw string) ([]string, map[string][]string, error) {
	caps, err := decodeCapabilitiesJSON(capsRaw)
	if err != nil {
		return nil, nil, err
	}
	constraints, err := decodeConstraintsJSON(constraintsRaw)
	if err != nil {
		return nil, nil, err
	}
	return caps, constraints, nil
}

// parsePostgresTextArray parses a PostgreSQL text[] representation like
// {cap1,cap2} strictly: anything that is not a well-formed, unquoted
// array literal is an error rather than an empty (wildcard) list. The
// store writes only unquoted identifier elements, and capability
// identifiers cannot contain commas, braces, or quotes.
func parsePostgresTextArray(s string) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	if len(s) < 2 || s[0] != '{' || s[len(s)-1] != '}' {
		return nil, fmt.Errorf("capabilities: %q is not a text[] literal", s)
	}
	inner := s[1 : len(s)-1]
	if inner == "" {
		return nil, nil
	}
	if strings.ContainsAny(inner, `"\{`) {
		return nil, fmt.Errorf("capabilities: unexpected quoting in %q", s)
	}
	return strings.Split(inner, ","), nil
}

// decodePostgresGrantMaterial decodes the PostgreSQL representation of
// both persisted fields, aborting on either.
func decodePostgresGrantMaterial(capsRaw, constraintsRaw []byte) ([]string, map[string][]string, error) {
	caps, err := parsePostgresTextArray(string(capsRaw))
	if err != nil {
		return nil, nil, err
	}
	constraints, err := decodeJSONBConstraints(string(constraintsRaw))
	if err != nil {
		return nil, nil, err
	}
	return caps, constraints, nil
}
