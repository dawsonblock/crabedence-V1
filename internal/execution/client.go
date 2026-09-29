package execution

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// ─── Transport classification ─────────────────────────────────────────
//
// Every planner client must obey the durable execution contract's
// dispatch boundary: once a request frame has been transmitted, a lost
// or late response is an UNKNOWN outcome — the side effect may have
// occurred — and must never be rewritten into a definitive FAILED.
// The classification below is the same one the NeMo CrabedenceClient
// applies, so the Go CLI, the native adapter, and any future planner
// agree on what a transport failure means.

// TransportErrorKind classifies a client-side transport failure
// relative to the request write boundary.
type TransportErrorKind string

const (
	// TransportPreDispatch means the request provably never reached the
	// service: the connection failed, the request could not be encoded,
	// or the frame was not fully written (the service parses only
	// complete frames). The invocation did not happen; a retry is safe.
	TransportPreDispatch TransportErrorKind = "PRE_DISPATCH"
	// TransportPostDispatch means the request frame was fully
	// transmitted but no definitive response was received — timeout,
	// connection loss, or an unreadable response. The side effect may
	// have occurred; the outcome is UNKNOWN.
	TransportPostDispatch TransportErrorKind = "POST_DISPATCH"
	// TransportProtocol means the service responded, but the response
	// violated the ABI (oversized frame, invalid JSON, unknown status).
	// The request was transmitted, so the outcome is exactly as
	// ambiguous as POST_DISPATCH.
	TransportProtocol TransportErrorKind = "PROTOCOL"
)

// TransportError is a client-side failure carrying its dispatch
// classification. Callers must not convert an ambiguous failure
// (POST_DISPATCH or PROTOCOL) into a definitive FAILED outcome.
type TransportError struct {
	Kind TransportErrorKind
	Err  error
}

func (e *TransportError) Error() string { return string(e.Kind) + ": " + e.Err.Error() }

// Unwrap exposes the underlying transport error.
func (e *TransportError) Unwrap() error { return e.Err }

// AmbiguousOutcome reports whether err is a transport failure whose
// outcome cannot be known: the request was transmitted but no
// definitive response was received. A caller that sees true must treat
// the execution as UNKNOWN (reconcile before retrying), never as
// FAILED.
func AmbiguousOutcome(err error) bool {
	var transport *TransportError
	return errors.As(err, &transport) && transport.Kind != TransportPreDispatch
}

// ─── Client ───────────────────────────────────────────────────────────

// DefaultClientTimeout bounds the client's wait for a response AFTER
// the request frame is transmitted. It is a client-side bound only: a
// timeout means the outcome is UNKNOWN, never that the invocation
// failed. The service's provider budget is intentionally longer
// (minutes), so callers that can afford to wait set ClientOptions.Timeout
// — an expired wait is not a failed execution.
const DefaultClientTimeout = 30 * time.Second

// DefaultDialTimeout bounds the connect to the execution service.
const DefaultDialTimeout = 10 * time.Second

// ClientOptions tunes one client's bounds. Zero fields take the
// defaults above.
type ClientOptions struct {
	// Timeout bounds the wait for a response after transmission.
	Timeout time.Duration
	// DialTimeout bounds the connect.
	DialTimeout time.Duration
}

// Client is the canonical Go client for the execution service's
// length-prefixed JSON ABI (one request, one response, per
// connection). It is shared by `crabbox exec`, `crabbox invoke`, and
// tests so no caller re-implements framing or dispatch
// classification.
type Client struct {
	socketPath  string
	timeout     time.Duration
	dialTimeout time.Duration
}

// NewClient returns a client for the execution service at socketPath.
func NewClient(socketPath string, opts ClientOptions) *Client {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultClientTimeout
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = DefaultDialTimeout
	}
	return &Client{socketPath: socketPath, timeout: opts.Timeout, dialTimeout: opts.DialTimeout}
}

// Invoke transmits one request and returns the parsed response. A
// failure is returned as a *TransportError: PRE_DISPATCH failures are
// safe to retry, while POST_DISPATCH and PROTOCOL failures mean the
// outcome is UNKNOWN and must be reconciled, not reported as FAILED.
func (c *Client) Invoke(ctx context.Context, req Request) (Response, error) {
	frame, err := encodeRequestFrame(req)
	if err != nil {
		return Response{}, &TransportError{Kind: TransportPreDispatch, Err: err}
	}

	dialer := net.Dialer{Timeout: c.dialTimeout}
	conn, err := dialer.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return Response{}, &TransportError{
			Kind: TransportPreDispatch,
			Err: fmt.Errorf(
				"connect to execution service at %s: %w (is 'crabbox serve-exec' running?)",
				c.socketPath, err,
			),
		}
	}
	defer conn.Close()

	// Honor caller cancellation: a cancelled context closes the socket,
	// and the resulting failure is classified like any other after the
	// write boundary — never silently swallowed.
	stopCancellationWatch := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancellationWatch()

	// Bound the whole exchange; the caller's deadline wins when it is
	// sooner.
	deadline := time.Now().Add(c.timeout)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	_ = conn.SetDeadline(deadline)

	written, err := writeFrame(conn, frame)
	if err != nil {
		if written < len(frame) {
			// The frame was not fully written, and the service parses
			// only complete frames: the invocation cannot have been
			// dispatched, so a retry is safe.
			return Response{}, &TransportError{
				Kind: TransportPreDispatch,
				Err:  fmt.Errorf("write request frame (%d of %d bytes): %w", written, len(frame), err),
			}
		}
		// The kernel accepted the whole frame; the failure is on the
		// response side and the outcome is ambiguous.
		return Response{}, &TransportError{
			Kind: TransportPostDispatch,
			Err:  fmt.Errorf("write request frame: %w", err),
		}
	}

	// From here the request has been transmitted. Every failure is an
	// UNKNOWN outcome until a definitive response arrives.
	return readResponseFrame(conn)
}

// encodeRequestFrame marshals the request and prefixes its length.
func encodeRequestFrame(req Request) ([]byte, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	if len(payload) > maxMessageBytes {
		return nil, fmt.Errorf("request exceeds the %d-byte frame bound", maxMessageBytes)
	}
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	return frame, nil
}

// writeFrame writes the entire frame, returning how many bytes the
// kernel accepted even on failure — the dispatch classification needs
// the exact write boundary, so short writes are tracked rather than
// hidden behind a single Write call.
func writeFrame(conn net.Conn, frame []byte) (int, error) {
	written := 0
	for written < len(frame) {
		n, err := conn.Write(frame[written:])
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrUnexpectedEOF
		}
	}
	return written, nil
}

// readResponseFrame reads one length-prefixed response frame and
// validates the wire status. Every failure is post-transmission.
func readResponseFrame(conn net.Conn) (Response, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return Response{}, &TransportError{
			Kind: TransportPostDispatch,
			Err:  fmt.Errorf("no response received: %w", err),
		}
	}
	respLen := binary.BigEndian.Uint32(lenBuf)
	if respLen > maxMessageBytes {
		return Response{}, &TransportError{
			Kind: TransportProtocol,
			Err:  fmt.Errorf("response frame length %d exceeds the %d-byte bound", respLen, maxMessageBytes),
		}
	}
	payload := make([]byte, respLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return Response{}, &TransportError{
			Kind: TransportPostDispatch,
			Err:  fmt.Errorf("response frame truncated: %w", err),
		}
	}
	var resp Response
	if err := json.Unmarshal(payload, &resp); err != nil {
		return Response{}, &TransportError{
			Kind: TransportProtocol,
			Err:  fmt.Errorf("parse response frame: %w", err),
		}
	}
	switch resp.Status {
	case StatusSucceeded, StatusFailed, StatusDenied, StatusUnknown, StatusInFlight:
	default:
		return Response{}, &TransportError{
			Kind: TransportProtocol,
			Err:  fmt.Errorf("invalid response status %q", resp.Status),
		}
	}
	return resp, nil
}
