package shared

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// MaxControlPlaneResponseBytes bounds a finite provider control-plane
// response (JSON API payload). Real control-plane responses are far
// smaller; the bound exists so a hostile or broken endpoint cannot
// stream unbounded data into memory.
const MaxControlPlaneResponseBytes = 16 << 20

// ReadBoundedResponse reads a finite control-plane response body,
// failing when it exceeds limit instead of returning a truncated
// read: a response past the bound is never valid input, and silently
// truncating would let a caller decode a prefix as if it were whole.
func ReadBoundedResponse(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return data, nil
}

// DecodeBoundedJSONResponse consumes and closes a finite control-plane response.
// Read failures and overflow take precedence over HTTP status; adapters retain
// their typed API errors and redaction policy. limit must be positive and below
// the maximum int64 value. Streaming responses use a different contract.
func DecodeBoundedJSONResponse(resp *http.Response, limit int64, out any, provider string, apiError func(int, string, string) error) error {
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > limit {
		return fmt.Errorf("%s response exceeds %d bytes", provider, limit)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return apiError(resp.StatusCode, resp.Status, strings.TrimSpace(string(data)))
	}
	if out != nil && len(strings.TrimSpace(string(data))) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode %s data: %w", provider, err)
		}
	}
	return nil
}
