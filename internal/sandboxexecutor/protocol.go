package sandboxexecutor

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Wire protocol v1: one JSON request per line, one JSON response per
// line, on a Unix stream socket inside an owner-only directory. The
// protocol is deliberately minimal — PR-03 establishes the
// authenticated channel; the signed job contract (PR-04) extends the
// request shape rather than replacing it.
const (
	ProtocolVersion = 1
	// maxFrameBytes bounds a single request line. A submission is a
	// small manifest, not a payload channel — anything larger is a
	// client error or an attack on the executor's memory.
	maxFrameBytes = 1 << 20

	RequestTypeSubmit = "submit"
)

// Request is a single client frame. Token authenticates the
// connection against the shared submission token (when the server is
// configured with one); the peer's kernel UID is resolved out-of-band
// and is never read from the frame.
type Request struct {
	Version int            `json:"version"`
	Type    string         `json:"type"`
	Token   string         `json:"token,omitempty"`
	Job     *JobSubmission `json:"job,omitempty"`
}

// JobSubmission is the PR-03 job shape — the minimum a submit needs
// to be recorded. The signed admission contract (SandboxJobV1) binds
// these fields to an authority signature in PR-04; until then the
// executor records but does not run them.
type JobSubmission struct {
	JobID     string   `json:"job_id"`
	Principal string   `json:"principal"`
	Image     string   `json:"image"`
	Argv      []string `json:"argv"`
}

// Validate checks the fields the protocol itself can check. It cannot
// prove authority — that arrives with the signed admission in PR-04 —
// but a malformed submission is refused here rather than stored.
func (j *JobSubmission) Validate() error {
	if j == nil {
		return fmt.Errorf("missing job")
	}
	if strings.TrimSpace(j.JobID) == "" {
		return fmt.Errorf("job_id is required")
	}
	if len(j.JobID) > 256 {
		return fmt.Errorf("job_id exceeds 256 bytes")
	}
	if strings.TrimSpace(j.Principal) == "" {
		return fmt.Errorf("principal is required")
	}
	if strings.TrimSpace(j.Image) == "" {
		return fmt.Errorf("image is required")
	}
	if len(j.Argv) == 0 {
		return fmt.Errorf("argv is required")
	}
	for i, arg := range j.Argv {
		if len(arg) > 4096 {
			return fmt.Errorf("argv[%d] exceeds 4096 bytes", i)
		}
	}
	return nil
}

// Response is a single server frame. Error is a stable refusal string;
// State reports the recorded lifecycle of an accepted submission.
type Response struct {
	Version int    `json:"version"`
	OK      bool   `json:"ok"`
	JobID   string `json:"job_id,omitempty"`
	State   string `json:"state,omitempty"`
	Error   string `json:"error,omitempty"`
}

// readRequest reads one bounded line and parses it. Reads stop at the
// first byte over maxFrameBytes — an unbounded client write never
// becomes an unbounded allocation.
func readRequest(r *bufio.Reader) (*Request, error) {
	line, err := readBoundedLine(r, maxFrameBytes)
	if err != nil {
		return nil, err
	}
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		return nil, fmt.Errorf("malformed request frame: %w", err)
	}
	if req.Version != ProtocolVersion {
		return nil, fmt.Errorf("unsupported protocol version %d", req.Version)
	}
	return &req, nil
}

// readBoundedLine reads a single newline-terminated line, refusing
// lines over the bound without consuming unbounded memory.
func readBoundedLine(r *bufio.Reader, bound int64) ([]byte, error) {
	var buf []byte
	for {
		frag, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, fmt.Errorf("read request: %w", err)
		}
		buf = append(buf, frag...)
		if int64(len(buf)) > bound {
			return nil, fmt.Errorf("request exceeds %d byte bound", bound)
		}
		if !isPrefix {
			return buf, nil
		}
	}
}

// writeResponse serializes a response frame.
func writeResponse(w io.Writer, resp *Response) error {
	resp.Version = ProtocolVersion
	line, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	_, err = w.Write(append(line, '\n'))
	return err
}
