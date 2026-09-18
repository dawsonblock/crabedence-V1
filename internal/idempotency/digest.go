package idempotency

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
)

// ErrTrailingJSON is returned when a document that must contain exactly
// one JSON value carries additional data after the first value. It is a
// deterministic validation error — never a panic — so callers can
// distinguish malformed input from a canonicalization defect.
var ErrTrailingJSON = errors.New("trailing data after first JSON value")

// CanonicalJSON produces deterministic JSON for idempotency digests.
//
// It delegates to Go's standard encoding/json, which provides the
// required guarantees:
//   - map[string]any keys are sorted (byte order = UTF-8 code-point order)
//   - output is deterministic for the same input value
//
// NUMBER SEMANTICS (ABI decision): json.Number values are normalized
// to their canonical form by callers before marshaling — see
// canonicalJSONNumber. Semantically equal numbers produce identical
// output regardless of lexical representation (1, 1.0, 1e0 all
// canonicalize to "1e0"), and precision is never routed through
// float64. The canonical form is normalized scientific notation —
// it never expands zeros according to the exponent, so output size
// stays proportional to input size even for hostile literals like
// 1e-99999999999999999999, and exponent arithmetic is arbitrary
// precision so 1e18446744073709551616 cannot wrap into collision
// with a small value.
//
// RELATIONSHIP TO THE EVIDENCE CANONICALIZATION:
// The RunEvidenceV1 canonicalization (internal/cli/run_evidence.go)
// is a cross-language Go↔TypeScript format that disables HTML escaping
// and mirrors JavaScript's JSON.stringify byte-for-byte. This
// canonicalization is Go-only and uses the standard encoder defaults.
// They are intentionally separate: the evidence protocol has a
// cross-language conformance corpus; this one has its own (see
// digest_conformance_test.go). Do not merge them without a shared
// conformance corpus covering both.
func CanonicalJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// canonicalJSONNumber normalizes a JSON numeric literal to its
// canonical form: a normalized scientific representation of the same
// mathematical value that never expands according to the exponent:
//
//	1, 1.0, 1.00, 1e0, 1e+0  → "1e0"
//	10, 100.0                → "1e1", "1e2"
//	0.01, 0.0100             → "1e-2"
//	12.34                    → "1.234e1"
//	1.5e3                    → "1.5e3"
//	1.5e-3                   → "1.5e-3"
//	-0, -0.0, 0e999999       → "0"
//
// The rewrite is purely lexical — digits are rearranged, never routed
// through float64 — so arbitrary precision is preserved and the rule is
// trivially implementable in any language. Exponent arithmetic uses
// math/big: the exponent is never parsed into a fixed-width integer,
// so literals like 1e18446744073709551616 cannot wrap into collision
// with a small value, and a hostile negative exponent can never force
// a multi-megabyte zero expansion. Output size stays proportional to
// input size.
//
// The function fails closed: any input that is not a well-formed JSON
// number literal (the only inputs a json.Decoder produces for
// json.Number, but defensive for constructed values) returns a
// deterministic error rather than a partially-canonicalized string.
func canonicalJSONNumber(s string) (string, error) {
	// Parse the JSON number grammar: -?(0|[1-9]digits)(.digits)?([eE][+-]?digits)?
	i := 0
	neg := false
	if i < len(s) && s[i] == '-' {
		neg = true
		i++
	}
	intStart := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	intPart := s[intStart:i]
	if intPart == "" {
		return "", fmt.Errorf("invalid JSON number %q: missing integer digits", s)
	}
	if len(intPart) > 1 && intPart[0] == '0' {
		return "", fmt.Errorf("invalid JSON number %q: leading zero", s)
	}
	fracPart := ""
	if i < len(s) && s[i] == '.' {
		i++
		fs := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		fracPart = s[fs:i]
		if fracPart == "" {
			return "", fmt.Errorf("invalid JSON number %q: missing fraction digits", s)
		}
	}
	exp := new(big.Int)
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		i++
		expNeg := false
		if i < len(s) && (s[i] == '+' || s[i] == '-') {
			expNeg = s[i] == '-'
			i++
		}
		es := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if es == i {
			return "", fmt.Errorf("invalid JSON number %q: missing exponent digits", s)
		}
		// es:i is all digits, so SetString cannot fail.
		exp.SetString(s[es:i], 10)
		if expNeg {
			exp.Neg(exp)
		}
	}
	if i != len(s) {
		return "", fmt.Errorf("invalid JSON number %q: trailing characters", s)
	}

	// value = digits × 10^decimalExp
	digits := intPart + fracPart
	decimalExp := new(big.Int).Sub(exp, big.NewInt(int64(len(fracPart))))
	// Each trailing zero stripped moves one power of ten into the exponent.
	trimmed := strings.TrimRight(digits, "0")
	decimalExp.Add(decimalExp, big.NewInt(int64(len(digits)-len(trimmed))))
	digits = strings.TrimLeft(trimmed, "0")
	if digits == "" {
		return "0", nil
	}

	// Normalized scientific form: the decimal point sits after the
	// first significant digit, so the printed exponent is
	// decimalExp + len(digits) - 1, computed in arbitrary precision.
	e := new(big.Int).Add(decimalExp, big.NewInt(int64(len(digits))-1))
	var b strings.Builder
	b.Grow(len(digits) + 8)
	if neg {
		b.WriteByte('-')
	}
	b.WriteByte(digits[0])
	if len(digits) > 1 {
		b.WriteByte('.')
		b.WriteString(digits[1:])
	}
	b.WriteByte('e')
	b.WriteString(e.String())
	return b.String(), nil
}

// canonicalNumberLiteral converts a Go-native numeric value to its
// shortest decimal literal and canonicalizes it, so a caller-supplied
// int or float64 digests identically to the same number arriving as
// raw JSON.
func canonicalNumberLiteral(lit string) (json.Number, error) {
	c, err := canonicalJSONNumber(lit)
	if err != nil {
		return "", err
	}
	return json.Number(c), nil
}

// normalizeNumbers rewrites every numeric value in a decoded JSON tree
// to canonicalJSONNumber form, so semantically equal documents marshal
// to identical bytes regardless of lexical representation or the Go
// type the caller happened to decode into. Any malformed numeric value
// is a deterministic error — the digest path fails closed.
func normalizeNumbers(v any) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			n, err := normalizeNumbers(e)
			if err != nil {
				return nil, err
			}
			t[k] = n
		}
		return t, nil
	case []any:
		for i, e := range t {
			n, err := normalizeNumbers(e)
			if err != nil {
				return nil, err
			}
			t[i] = n
		}
		return t, nil
	case json.Number:
		return canonicalNumberLiteral(t.String())
	case json.RawMessage:
		// Raw JSON embedded in a decoded tree must canonicalize like
		// any other numeric content, not pass through verbatim.
		c, err := canonicalizeJSON(t)
		if err != nil {
			return nil, err
		}
		return json.RawMessage(c), nil
	case float64:
		return canonicalNumberLiteral(strconv.FormatFloat(t, 'g', -1, 64))
	case float32:
		return canonicalNumberLiteral(strconv.FormatFloat(float64(t), 'g', -1, 32))
	case int:
		return canonicalNumberLiteral(strconv.FormatInt(int64(t), 10))
	case int8:
		return canonicalNumberLiteral(strconv.FormatInt(int64(t), 10))
	case int16:
		return canonicalNumberLiteral(strconv.FormatInt(int64(t), 10))
	case int32:
		return canonicalNumberLiteral(strconv.FormatInt(int64(t), 10))
	case int64:
		return canonicalNumberLiteral(strconv.FormatInt(t, 10))
	case uint:
		return canonicalNumberLiteral(strconv.FormatUint(uint64(t), 10))
	case uint8:
		return canonicalNumberLiteral(strconv.FormatUint(uint64(t), 10))
	case uint16:
		return canonicalNumberLiteral(strconv.FormatUint(uint64(t), 10))
	case uint32:
		return canonicalNumberLiteral(strconv.FormatUint(uint64(t), 10))
	case uint64:
		return canonicalNumberLiteral(strconv.FormatUint(t, 10))
	default:
		return v, nil
	}
}

// DigestInput is the input to the idempotency digest.
type DigestInput struct {
	ProtocolVersion int            `json:"protocol_version"`
	Principal       string         `json:"principal"`
	Capability      string         `json:"capability"`
	Arguments       map[string]any `json:"arguments"`
	GrantID         string         `json:"grant_id"`
	ExecutionClass  string         `json:"execution_class"`
	// AuthorityGeneration and AuthorityDigest bind the exact immutable
	// authority material that admitted the request — reissuing a grant
	// produces a new generation and a new digest, so the same grant_id
	// under different authority material is a different execution
	// identity. Zero values mean no grant-bound authority; they are
	// omitted from the canonical form so pre-existing digests are
	// unchanged (the binding is additive, not a format change).
	AuthorityGeneration int64  `json:"authority_generation,omitempty"`
	AuthorityDigest     string `json:"authority_digest,omitempty"`
	// AssuranceProfile and ExecutionRoute bind the resolved admission
	// decision into the execution identity — the same request admitted
	// under a different assurance profile or route is a different
	// durable execution. Empty values are omitted so callers that have
	// no resolved profile/route produce unchanged digests (the binding
	// is additive, not a format change).
	AssuranceProfile string `json:"assurance_profile,omitempty"`
	ExecutionRoute   string `json:"execution_route,omitempty"`
}

// ComputeDigest computes the SHA-256 digest of the canonical JSON
// representation of the digest input.
//
// The digest binds:
//   - protocol version
//   - principal
//   - capability
//   - canonical arguments (sorted keys)
//   - grant identity
//   - authoritative execution class
//   - authority generation + digest, when present
//
// Same idempotency key + different digest = IDEMPOTENCY_CONFLICT.
func ComputeDigest(input DigestInput) (string, error) {
	// Normalize numbers on every entry path, not just raw-JSON
	// decoding, so a Go-native int/float64/json.Number digests
	// identically to the same value arriving as a raw JSON literal.
	args, err := normalizeNumbers(input.Arguments)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize digest input: %w", err)
	}
	canonicalInput := map[string]any{
		"protocol_version": input.ProtocolVersion,
		"principal":        input.Principal,
		"capability":       input.Capability,
		"arguments":        args,
		"grant_id":         input.GrantID,
		"execution_class":  input.ExecutionClass,
	}
	// Authority material is bound only when present — a zero generation
	// or empty digest adds nothing, preserving the digest bytes of
	// requests that carry no grant-bound authority.
	if input.AuthorityGeneration != 0 {
		canonicalInput["authority_generation"] = input.AuthorityGeneration
	}
	if input.AuthorityDigest != "" {
		canonicalInput["authority_digest"] = input.AuthorityDigest
	}
	if input.AssuranceProfile != "" {
		canonicalInput["assurance_profile"] = input.AssuranceProfile
	}
	if input.ExecutionRoute != "" {
		canonicalInput["execution_route"] = input.ExecutionRoute
	}
	canonical, err := CanonicalJSON(canonicalInput)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize digest input: %w", err)
	}

	hash := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(hash[:]), nil
}

// ComputeDigestFromRaw computes the digest from raw JSON arguments.
// The arguments are parsed and re-canonicalized to ensure determinism.
//
// Uses json.Decoder with UseNumber() to preserve numeric precision.
// Go's default json.Unmarshal into map[string]any decodes all numbers
// as float64, which collapses distinct large integers beyond IEEE-754
// exact range (e.g., 9007199254740992 and 9007199254740993 both map
// to the same float64). UseNumber() preserves them as json.Number,
// keeping the original lexical representation intact.
func ComputeDigestFromRaw(protocolVersion int, principal, capability string, args json.RawMessage, grantID, class string) (string, error) {
	return ComputeDigestFromRawWithAuthority(protocolVersion, principal, capability,
		args, grantID, class, 0, "", "", "")
}

// ComputeDigestFromRawWithAuthority is ComputeDigestFromRaw plus the
// immutable admission binding: the grant generation, grant digest,
// resolved assurance profile, and resolved execution route that
// admitted the request become part of the execution identity.
// Zero values bind nothing and produce byte-identical digests to
// ComputeDigestFromRaw.
func ComputeDigestFromRawWithAuthority(protocolVersion int, principal, capability string, args json.RawMessage, grantID, class string, authorityGeneration int64, authorityDigest, assuranceProfile, executionRoute string) (string, error) {
	dec := json.NewDecoder(strings.NewReader(string(args)))
	dec.UseNumber()
	var argsMap map[string]any
	if err := dec.Decode(&argsMap); err != nil {
		return "", fmt.Errorf("failed to parse arguments: %w", err)
	}
	// Require complete consumption — a second JSON value after the
	// first is malformed input, not extra arguments. Same strict
	// single-value rule as canonicalizeJSON.
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return "", fmt.Errorf("failed to parse arguments: %w", ErrTrailingJSON)
		}
		return "", fmt.Errorf("failed to parse arguments: %w", err)
	}
	normalized, err := normalizeNumbers(argsMap)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize arguments: %w", err)
	}
	return ComputeDigest(DigestInput{
		ProtocolVersion:     protocolVersion,
		Principal:           principal,
		Capability:          capability,
		Arguments:           normalized.(map[string]any),
		GrantID:             grantID,
		ExecutionClass:      class,
		AuthorityGeneration: authorityGeneration,
		AuthorityDigest:     authorityDigest,
		AssuranceProfile:    assuranceProfile,
		ExecutionRoute:      executionRoute,
	})
}

// isValidEvidenceDigest checks that a digest is a 64-character lowercase
// hexadecimal SHA-256 digest. This is used by the store to validate
// CRITICAL recovery evidence with the same strength as normal finalization.
func isValidEvidenceDigest(digest string) bool {
	if len(digest) != 64 {
		return false
	}
	for _, c := range digest {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
