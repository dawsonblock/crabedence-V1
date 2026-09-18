package idempotency

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

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
// canonicalize to "1"), and precision is never routed through float64.
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
// canonical form — the minimal exact decimal representation of the
// same mathematical value:
//
//	1, 1.0, 1.00, 1e0, 1e+0  → "1"
//	1.5e3                    → "1500"
//	1.5e-3                   → "0.0015"
//	-0, -0.0                 → "0"
//
// The rewrite is purely lexical — digits are rearranged, never routed
// through float64 — so arbitrary precision is preserved and the rule is
// trivially implementable in any language. If the expanded plain
// decimal form would exceed 4096 characters (absurd exponents like
// 1e999999), the canonical form is scientific notation
// "d[.digits]e<exp>" with the same trailing-zero-stripped mantissa.
func canonicalJSONNumber(s string) string {
	// Parse the JSON number grammar: -?digits(.digits)?([eE][+-]?digits)?
	i := 0
	neg := false
	if i < len(s) && s[i] == '-' {
		neg = true
		i++
	}
	intStart := i
	for i < len(s) && s[i] != '.' && s[i] != 'e' && s[i] != 'E' {
		i++
	}
	intPart := s[intStart:i]
	fracPart := ""
	if i < len(s) && s[i] == '.' {
		i++
		fs := i
		for i < len(s) && s[i] != 'e' && s[i] != 'E' {
			i++
		}
		fracPart = s[fs:i]
	}
	var exp int64
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		i++
		esign := int64(1)
		if i < len(s) && (s[i] == '+' || s[i] == '-') {
			if s[i] == '-' {
				esign = -1
			}
			i++
		}
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			exp = exp*10 + int64(s[i]-'0')
			i++
		}
		exp *= esign
	}

	digits := intPart + fracPart
	// value = digits × 10^decimalExp
	decimalExp := exp - int64(len(fracPart))
	// Each trailing zero stripped moves one power of ten into the exponent.
	trimmed := strings.TrimRight(digits, "0")
	decimalExp += int64(len(digits) - len(trimmed))
	digits = strings.TrimLeft(trimmed, "0")
	if digits == "" {
		return "0"
	}

	// Expanded output length: plain decimal when decimalExp >= 0 is
	// len(digits)+decimalExp; when negative it is at most
	// len(digits)+2. Bound it to avoid absurd expansions like 1e999999999.
	plainLen := len(digits) + 2
	if decimalExp >= 0 {
		plainLen = len(digits) + int(decimalExp)
	}
	if plainLen > 4096 {
		// Canonical scientific form: mantissa digits with point after
		// the first digit, exponent = decimalExp + len(digits) - 1.
		mant := digits[:1]
		if len(digits) > 1 {
			mant += "." + digits[1:]
		}
		if neg {
			mant = "-" + mant
		}
		return mant + "e" + strconv.FormatInt(decimalExp+int64(len(digits))-1, 10)
	}

	var out string
	switch {
	case decimalExp >= 0:
		out = digits + strings.Repeat("0", int(decimalExp))
	default:
		point := len(digits) + int(decimalExp)
		if point > 0 {
			out = digits[:point] + "." + digits[point:]
		} else {
			out = "0." + strings.Repeat("0", -point) + digits
		}
	}
	if neg {
		return "-" + out
	}
	return out
}

// normalizeNumbers rewrites every json.Number in a decoded JSON tree
// to canonicalJSONNumber form, so semantically equal documents marshal
// to identical bytes.
func normalizeNumbers(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			t[k] = normalizeNumbers(e)
		}
		return t
	case []any:
		for i, e := range t {
			t[i] = normalizeNumbers(e)
		}
		return t
	case json.Number:
		return json.Number(canonicalJSONNumber(t.String()))
	default:
		return v
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
	canonicalInput := map[string]any{
		"protocol_version": input.ProtocolVersion,
		"principal":        input.Principal,
		"capability":       input.Capability,
		"arguments":        input.Arguments,
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
		args, grantID, class, 0, "")
}

// ComputeDigestFromRawWithAuthority is ComputeDigestFromRaw plus the
// immutable authority binding: the grant generation and grant digest
// that admitted the request become part of the execution identity.
// Zero values bind nothing and produce byte-identical digests to
// ComputeDigestFromRaw.
func ComputeDigestFromRawWithAuthority(protocolVersion int, principal, capability string, args json.RawMessage, grantID, class string, authorityGeneration int64, authorityDigest string) (string, error) {
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
			return "", fmt.Errorf("failed to parse arguments: trailing data after first JSON value")
		}
		return "", fmt.Errorf("failed to parse arguments: %w", err)
	}
	return ComputeDigest(DigestInput{
		ProtocolVersion:     protocolVersion,
		Principal:           principal,
		Capability:          capability,
		Arguments:           normalizeNumbers(argsMap).(map[string]any),
		GrantID:             grantID,
		ExecutionClass:      class,
		AuthorityGeneration: authorityGeneration,
		AuthorityDigest:     authorityDigest,
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
