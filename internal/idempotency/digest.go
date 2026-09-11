package idempotency

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// CanonicalJSON produces deterministic JSON for idempotency digests.
//
// It delegates to Go's standard encoding/json, which provides the
// required guarantees:
//   - map[string]any keys are sorted (byte order = UTF-8 code-point order)
//   - json.Number values preserve their lexical representation
//   - output is deterministic for the same input value
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

// DigestInput is the input to the idempotency digest.
type DigestInput struct {
	ProtocolVersion int            `json:"protocol_version"`
	Principal       string         `json:"principal"`
	Capability      string         `json:"capability"`
	Arguments       map[string]any `json:"arguments"`
	GrantID         string         `json:"grant_id"`
	ExecutionClass  string         `json:"execution_class"`
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
//
// Same idempotency key + different digest = IDEMPOTENCY_CONFLICT.
func ComputeDigest(input DigestInput) (string, error) {
	canonical, err := CanonicalJSON(map[string]any{
		"protocol_version": input.ProtocolVersion,
		"principal":        input.Principal,
		"capability":       input.Capability,
		"arguments":        input.Arguments,
		"grant_id":         input.GrantID,
		"execution_class":  input.ExecutionClass,
	})
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
	dec := json.NewDecoder(strings.NewReader(string(args)))
	dec.UseNumber()
	var argsMap map[string]any
	if err := dec.Decode(&argsMap); err != nil {
		return "", fmt.Errorf("failed to parse arguments: %w", err)
	}
	return ComputeDigest(DigestInput{
		ProtocolVersion: protocolVersion,
		Principal:       principal,
		Capability:      capability,
		Arguments:       argsMap,
		GrantID:         grantID,
		ExecutionClass:  class,
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
