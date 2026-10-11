package sandboxexecutor

import (
	"context"
	"errors"
	"time"
)

// ErrAmbiguousDispatch is returned by a backend that cannot say
// whether the job reached the executor — the launch may have
// happened. The ledger records the job DISPATCH_AMBIGUOUS and it is
// never retried blind: a duplicate microVM is a worse failure than a
// stalled submission.
var ErrAmbiguousDispatch = errors.New("dispatch outcome uncertain — the job may already be running")

// Backend is where an authorized, persisted job goes for execution.
// The contract it receives has already been signature-verified,
// window-checked, and durably recorded — the backend enforces the
// contract's declared limits, it does not re-adjudicate them.
//
// Dispatch is split from Wait so the admission path learns the
// launch outcome synchronously (definitive refusal vs. accepted vs.
// ambiguous) while result collection happens asynchronously in a
// monitor goroutine.
type Backend interface {
	// Name is the backend's stable provider identity — attested in
	// execution receipts and recorded on the ledger row so evidence
	// binds who ran the job, not just what ran.
	Name() string

	// Dispatch starts the job and returns the backend's handle for
	// it (e.g. the sandbox name). Returned errors classify as:
	//   nil           — launched, handle valid
	//   ErrAmbiguousDispatch (wrapped) — outcome unknown; the handle,
	//                   if also returned, may be live
	//   other error   — definitive refusal, nothing launched
	Dispatch(ctx context.Context, job *JobContractV2) (handle string, err error)

	// Wait blocks until the job finishes or ctx is canceled, then
	// reports the bound result. A ctx cancellation means the monitor
	// stopped watching — it does not mean the job stopped running.
	Wait(ctx context.Context, handle string) (*ExecResult, error)

	// Inspect reports whether handle still names a live workload —
	// the reconcile aid after a daemon restart, never a re-dispatch
	// trigger.
	Inspect(ctx context.Context, handle string) (live bool, err error)

	// Close releases backend resources at daemon shutdown.
	Close() error
}

// ExecResult binds a finished run back to its job: exit status plus
// the captured-output digest and where the artifact lives. Output
// itself never goes through the ledger — the hash does.
type ExecResult struct {
	ExitCode     int       `json:"exit_code"`
	OutputSHA256 string    `json:"output_sha256"`
	OutputPath   string    `json:"output_path"`
	OutputBytes  int64     `json:"output_bytes"`
	Truncated    bool      `json:"truncated"`
	FinishedAt   time.Time `json:"finished_at"`
}
