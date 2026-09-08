package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ParseRunEvidenceV1 parses a JSON document into RunEvidenceV1 using strict
// validation: a single JSON object, no trailing data, no duplicate keys, no
// unknown fields, and correct JSON types. It returns an error if any of these
// constraints are violated.
//
// This is the parser used by the evidence verification path. It must be
// stricter than json.Unmarshal because evidence is a cryptographic boundary:
// an unknown field or a duplicate key could silently alter the canonical bytes
// and therefore the digest, producing a valid-but-wrong record.
func ParseRunEvidenceV1(data []byte) (RunEvidenceV1, error) {
	var ev RunEvidenceV1
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ev); err != nil {
		return ev, fmt.Errorf("malformed evidence: %w", err)
	}
	// Reject trailing JSON: the document must be exactly one object.
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return ev, fmt.Errorf("malformed evidence: trailing data after JSON object")
	}
	if err := detectDuplicateKeys(data); err != nil {
		return ev, fmt.Errorf("malformed evidence: %w", err)
	}
	if err := rejectUnpairedSurrogates(data); err != nil {
		return ev, fmt.Errorf("malformed evidence: %w", err)
	}
	return ev, nil
}

// rejectUnpairedSurrogates scans the raw JSON for \uXXXX escape sequences
// that represent unpaired UTF-16 surrogates. Go's json.Decoder silently
// replaces unpaired surrogates with U+FFFD, while JavaScript's JSON.parse
// preserves them as unpaired surrogates in the string. This divergence
// produces different canonical bytes and different digests, breaking
// cross-runtime evidence coherence. Rejecting them at parse time ensures
// both runtimes see the same bytes.
//
// This scan is byte-level and does not parse JSON; it simply looks for
// the pattern \uXXXX where XXXX is a surrogate code point (D800-DFFF)
// and checks whether high surrogates (D800-DBFF) are followed by a low
// surrogate (DC00-DFFF) in the next \uXXXX escape.
func rejectUnpairedSurrogates(data []byte) error {
	for i := 0; i < len(data)-5; i++ {
		if data[i] != '\\' || data[i+1] != 'u' {
			continue
		}
		hex := string(data[i+2 : i+6])
		code, err := parseHex4(hex)
		if err != nil {
			continue // not a valid \uXXXX, let json.Decoder handle it
		}
		if code < 0xD800 || code > 0xDFFF {
			continue // not a surrogate
		}
		if code >= 0xDC00 && code <= 0xDFFF {
			// Low surrogate without a preceding high surrogate.
			if i < 6 || !isHighSurrogateEscape(data[i-6:]) {
				return fmt.Errorf("unpaired low surrogate \\u%s", hex)
			}
			continue
		}
		// High surrogate (D800-DBFF): must be followed by a low surrogate.
		if i+12 > len(data) || !isLowSurrogateEscape(data[i+6:]) {
			return fmt.Errorf("unpaired high surrogate \\u%s", hex)
		}
	}
	return nil
}

func parseHex4(s string) (uint16, error) {
	var val uint16
	for _, c := range s {
		val <<= 4
		switch {
		case c >= '0' && c <= '9':
			val |= uint16(c - '0')
		case c >= 'a' && c <= 'f':
			val |= uint16(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			val |= uint16(c - 'A' + 10)
		default:
			return 0, fmt.Errorf("invalid hex digit %q", c)
		}
	}
	return val, nil
}

func isHighSurrogateEscape(data []byte) bool {
	return len(data) >= 6 && data[0] == '\\' && data[1] == 'u' &&
		data[2] == 'd' && (data[3] >= '8' && data[3] <= 'b')
}

func isLowSurrogateEscape(data []byte) bool {
	return len(data) >= 6 && data[0] == '\\' && data[1] == 'u' &&
		data[2] == 'd' && (data[3] >= 'c' && data[3] <= 'f')
}

// detectDuplicateKeys scans a JSON object for duplicate keys at any nesting
// level. json.Decoder with DisallowUnknownFields does not catch duplicate keys
// (it silently takes the last value), so we need a separate scan.
//
// This uses a streaming tokenizer rather than unmarshalling into a map, so it
// works for any valid JSON regardless of schema.
func detectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	return scanForDuplicateKeys(dec)
}

// scanForDuplicateKeys recursively scans JSON tokens for duplicate object keys.
// It tracks the set of keys seen at the current object level and recurses into
// nested objects and arrays.
func scanForDuplicateKeys(dec *json.Decoder) error {
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			continue // scalar value at top level (shouldn't happen for valid evidence)
		}
		if delim == json.Delim('{') {
			if err := scanObjectForDuplicateKeys(dec); err != nil {
				return err
			}
		} else if delim == json.Delim('[') {
			if err := scanArrayForDuplicateKeys(dec); err != nil {
				return err
			}
		}
	}
}

func scanObjectForDuplicateKeys(dec *json.Decoder) error {
	seen := make(map[string]bool)
	for dec.More() {
		// Read key.
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("expected string key, got %T", keyTok)
		}
		if seen[key] {
			return fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = true
		// Read value (which may be a nested object/array or a scalar).
		// For scalars, Token() consumes the value entirely. For objects/arrays,
		// Token() returns the opening delim and the recursion consumes the
		// closing delim.
		valueTok, err := dec.Token()
		if err != nil {
			return err
		}
		if delim, ok := valueTok.(json.Delim); ok {
			if delim == json.Delim('{') {
				if err := scanObjectForDuplicateKeys(dec); err != nil {
					return err
				}
			} else if delim == json.Delim('[') {
				if err := scanArrayForDuplicateKeys(dec); err != nil {
					return err
				}
			}
		}
		// No extra token to consume: scalars are fully consumed by Token(),
		// and objects/arrays have their closing delim consumed by the recursion.
	}
	// Consume the closing } delim.
	if _, err := dec.Token(); err != nil {
		return err
	}
	return nil
}

func scanArrayForDuplicateKeys(dec *json.Decoder) error {
	for dec.More() {
		valueTok, err := dec.Token()
		if err != nil {
			return err
		}
		if delim, ok := valueTok.(json.Delim); ok {
			if delim == json.Delim('{') {
				if err := scanObjectForDuplicateKeys(dec); err != nil {
					return err
				}
			} else if delim == json.Delim('[') {
				if err := scanArrayForDuplicateKeys(dec); err != nil {
					return err
				}
			}
		}
		// Scalars are fully consumed by Token(). Objects/arrays have their
		// closing delim consumed by the recursion.
	}
	// Consume the closing ] delim.
	if _, err := dec.Token(); err != nil {
		return err
	}
	return nil
}

// maxJSONSafeInteger is the IEEE-754 safe integer bound (2^53 - 1).
// Integers crossing the Go↔JavaScript boundary must be within
// [-(2^53 - 1), 2^53 - 1] to round-trip without precision loss.
const maxJSONSafeInteger int64 = 9007199254740991

// ValidateRunEvidenceV1 performs semantic validation of a parsed RunEvidenceV1
// record: schema version, evidence type, run-status/exit-code consistency,
// timing non-negativity, safe-integer bounds, and structural limits. It does
// NOT verify the digest.
//
// This is a superset of validateRunEvidenceStructure that also checks semantic
// invariants (status/exit-code consistency, non-negative timing, safe integers).
func ValidateRunEvidenceV1(ev RunEvidenceV1) error {
	if err := validateRunEvidenceStructure(ev); err != nil {
		return err
	}
	// Semantic invariants.
	if err := validateRunStatusInvariant(ev); err != nil {
		return err
	}
	if err := validateTimingNonNegative(ev); err != nil {
		return err
	}
	if err := validateSafeIntegers(ev); err != nil {
		return err
	}
	if err := validateStartupConfirm(ev); err != nil {
		return err
	}
	return nil
}

// validateStartupConfirm validates the startup_confirm nested object.
func validateStartupConfirm(ev RunEvidenceV1) error {
	if ev.StartupConfirm == nil {
		return nil
	}
	sc := ev.StartupConfirm
	switch sc.Stage {
	case "timeout-window", "file-handoff", "process-exit":
		// valid
	default:
		return fmt.Errorf("startup_confirm.stage must be one of timeout-window/file-handoff/process-exit, got %q", sc.Stage)
	}
	return nil
}

// validateRunStatusInvariant checks that run_status is consistent with
// exit_code per the frozen invariant:
//
//	exit_code == 0 && error_kind == ""  → succeeded
//	exit_code != 0                       → failed
//
// timed-out and canceled are special statuses that may use non-zero exit codes
// but must have a matching error_kind.
func validateRunStatusInvariant(ev RunEvidenceV1) error {
	switch ev.RunStatus {
	case "succeeded":
		if ev.ExitCode != 0 {
			return fmt.Errorf("run_status=succeeded but exit_code=%d (must be 0)", ev.ExitCode)
		}
	case "failed":
		if ev.ExitCode == 0 {
			return fmt.Errorf("run_status=failed but exit_code=0 (must be non-zero)")
		}
	case "timed-out":
		// Timeout may use any exit code; error_kind should be set.
		if ev.ErrorKind == "" {
			return fmt.Errorf("run_status=timed-out requires error_kind")
		}
	case "canceled":
		// Cancellation may use any exit code; error_kind should be set.
		if ev.ErrorKind == "" {
			return fmt.Errorf("run_status=canceled requires error_kind")
		}
	default:
		return fmt.Errorf("run_status must be one of succeeded/failed/timed-out/canceled, got %q", ev.RunStatus)
	}
	return nil
}

// validateTimingNonNegative checks that all timing fields are non-negative.
func validateTimingNonNegative(ev RunEvidenceV1) error {
	fields := []struct {
		name  string
		value int64
	}{
		{"total_ms", ev.TotalMs},
		{"command_ms", ev.CommandMs},
		{"sync_ms", ev.SyncMs},
		{"runner_total_ms", ev.RunnerTotalMs},
		{"end_to_end_ms", ev.EndToEndMs},
		{"lease_ms", ev.LeaseMs},
		{"bootstrap_ms", ev.BootstrapMs},
		{"hydrate_ms", ev.HydrateMs},
		{"probe_ms", ev.ProbeMs},
		{"sync_transfer_bytes", ev.SyncTransferBytes},
	}
	for _, f := range fields {
		if f.value < 0 {
			return fmt.Errorf("%s must be non-negative, got %d", f.name, f.value)
		}
	}
	if ev.SyncTransferFiles < 0 {
		return fmt.Errorf("sync_transfer_files must be non-negative, got %d", ev.SyncTransferFiles)
	}
	return nil
}

// validateSafeIntegers checks that every integer crossing the Go↔JavaScript
// boundary is within the IEEE-754 safe range (-(2^53-1) through 2^53-1).
// Larger values lose precision when parsed as JavaScript numbers and cannot
// round-trip a digest.
func validateSafeIntegers(ev RunEvidenceV1) error {
	// exit_code crosses the Go↔JavaScript boundary and must be a safe integer.
	if int64(ev.ExitCode) > maxJSONSafeInteger || int64(ev.ExitCode) < -maxJSONSafeInteger {
		return fmt.Errorf("exit_code exceeds IEEE-754 safe integer range: %d", ev.ExitCode)
	}
	int64Fields := []struct {
		name  string
		value int64
	}{
		{"total_ms", ev.TotalMs},
		{"command_ms", ev.CommandMs},
		{"sync_ms", ev.SyncMs},
		{"runner_total_ms", ev.RunnerTotalMs},
		{"end_to_end_ms", ev.EndToEndMs},
		{"lease_ms", ev.LeaseMs},
		{"bootstrap_ms", ev.BootstrapMs},
		{"hydrate_ms", ev.HydrateMs},
		{"probe_ms", ev.ProbeMs},
		{"sync_transfer_bytes", ev.SyncTransferBytes},
	}
	for _, f := range int64Fields {
		if f.value > maxJSONSafeInteger || f.value < -maxJSONSafeInteger {
			return fmt.Errorf("%s exceeds IEEE-754 safe integer range: %d", f.name, f.value)
		}
	}
	if int64(ev.SyncTransferFiles) > maxJSONSafeInteger || ev.SyncTransferFiles < 0 {
		return fmt.Errorf("sync_transfer_files exceeds IEEE-754 safe integer range: %d", ev.SyncTransferFiles)
	}
	// Validate phase timings.
	for i, p := range ev.RunnerPhases {
		if p.Ms > maxJSONSafeInteger || p.Ms < 0 {
			return fmt.Errorf("runner_phases[%d].ms exceeds IEEE-754 safe integer range: %d", i, p.Ms)
		}
		if int64(p.TransferCount) > maxJSONSafeInteger || p.TransferCount < 0 {
			return fmt.Errorf("runner_phases[%d].transfer_count exceeds IEEE-754 safe integer range: %d", i, p.TransferCount)
		}
		if p.TransferBytes > maxJSONSafeInteger || p.TransferBytes < 0 {
			return fmt.Errorf("runner_phases[%d].transfer_bytes exceeds IEEE-754 safe integer range: %d", i, p.TransferBytes)
		}
	}
	for i, p := range ev.SyncPhases {
		if p.Ms > maxJSONSafeInteger || p.Ms < 0 {
			return fmt.Errorf("sync_phases[%d].ms exceeds IEEE-754 safe integer range: %d", i, p.Ms)
		}
	}
	for i, p := range ev.CommandPhases {
		if p.Ms > maxJSONSafeInteger || p.Ms < 0 {
			return fmt.Errorf("command_phases[%d].ms exceeds IEEE-754 safe integer range: %d", i, p.Ms)
		}
	}
	// Validate artifact bytes.
	for i, a := range ev.Artifacts {
		if int64(a.Bytes) > maxJSONSafeInteger || a.Bytes < 0 {
			return fmt.Errorf("artifacts[%d].bytes exceeds IEEE-754 safe integer range: %d", i, a.Bytes)
		}
	}
	// Validate startup_confirm duration.
	if ev.StartupConfirm != nil {
		if ev.StartupConfirm.DurationMs < 0 {
			return fmt.Errorf("startup_confirm.duration_ms must be non-negative, got %d", ev.StartupConfirm.DurationMs)
		}
		if ev.StartupConfirm.DurationMs > maxJSONSafeInteger {
			return fmt.Errorf("startup_confirm.duration_ms exceeds IEEE-754 safe integer range: %d", ev.StartupConfirm.DurationMs)
		}
	}
	return nil
}

// VerifyRunEvidenceDigestError returns nil if the evidence's digest matches the
// recomputed SHA-256 over canonical JSON (with digest set to ""), or an error
// describing the mismatch. This is the error-returning counterpart to
// VerifyRunEvidenceDigest.
func VerifyRunEvidenceDigestError(ev RunEvidenceV1) error {
	recomputed, err := runEvidenceDigestBytes(ev)
	if err != nil {
		return fmt.Errorf("recompute digest: %w", err)
	}
	expected := strings.ToLower(ev.Digest)
	if expected != string(recomputed) {
		return fmt.Errorf("evidence digest mismatch: expected %s, recomputed %s", ev.Digest, string(recomputed))
	}
	return nil
}
