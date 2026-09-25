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
func decodeCapabilitiesJSON(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var caps []string
	if err := json.Unmarshal([]byte(raw), &caps); err != nil {
		return nil, fmt.Errorf("capabilities: %w", err)
	}
	return caps, nil
}

// decodeConstraintsJSON decodes a stored constraint map strictly.
func decodeConstraintsJSON(raw string) (map[string][]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
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
	constraints, err := decodeConstraintsJSON(string(constraintsRaw))
	if err != nil {
		return nil, nil, err
	}
	return caps, constraints, nil
}
