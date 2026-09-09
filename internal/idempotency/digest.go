package idempotency

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// CanonicalJSON produces deterministic JSON with sorted keys at all levels.
// This ensures that property insertion order does not affect the digest.
func CanonicalJSON(v any) (string, error) {
	return canonicalValue(v)
}

func canonicalValue(v any) (string, error) {
	switch val := v.(type) {
	case nil:
		return "null", nil
	case bool:
		if val {
			return "true", nil
		}
		return "false", nil
	case json.Number:
		return string(val), nil
	case float64:
		return formatFloat(val), nil
	case int:
		return fmt.Sprintf("%d", val), nil
	case int64:
		return fmt.Sprintf("%d", val), nil
	case string:
		b, err := json.Marshal(val)
		if err != nil {
			return "", err
		}
		return string(b), nil
	case []any:
		parts := make([]string, len(val))
		for i, item := range val {
			s, err := canonicalValue(item)
			if err != nil {
				return "", err
			}
			parts[i] = s
		}
		return "[" + strings.Join(parts, ",") + "]", nil
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			ks, err := json.Marshal(k)
			if err != nil {
				return "", err
			}
			vs, err := canonicalValue(val[k])
			if err != nil {
				return "", err
			}
			parts = append(parts, string(ks)+":"+vs)
		}
		return "{" + strings.Join(parts, ",") + "}", nil
	default:
		b, err := json.Marshal(val)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
}

// formatFloat formats a float64 in a canonical way.
func formatFloat(f float64) string {
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%g", f)
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
func ComputeDigestFromRaw(protocolVersion int, principal, capability string, args json.RawMessage, grantID, class string) (string, error) {
	var argsMap map[string]any
	if err := json.Unmarshal(args, &argsMap); err != nil {
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
