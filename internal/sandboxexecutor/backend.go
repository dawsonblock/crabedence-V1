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

// ErrExecutionUnobserved is returned when the backend cannot
// demonstrate how the workload ended — a lost runtime, a vanished
// sandbox, or an observation deadline that expired. The job stays
// unresolved for reconciliation: an unobserved outcome is never
// recorded as a guest exit.
var ErrExecutionUnobserved = errors.New("execution outcome was never observed — reconciliation required")

// DispatchResult identifies one launched job: the backend's handle for
// the sandbox that runs it plus the runtime-owned run identity, when
// the backend has one. The run identity is what makes a launch
// observable after the daemon that started it is gone — a backend
// that cannot name the run cannot reconcile it.
type DispatchResult struct {
	Handle string
	RunID  string
}

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
	// it (e.g. the sandbox name) plus its runtime-owned run identity
	// when the backend has one. Returned errors classify as:
	//   nil           — launched, handle valid
	//   ErrAmbiguousDispatch (wrapped) — outcome unknown; the handle,
	//                   if also returned, may be live
	//   other error   — definitive refusal, nothing launched
	Dispatch(ctx context.Context, job *JobContractV2) (DispatchResult, error)

	// Wait observes the job until it demonstrably finished or ctx is
	// canceled, then captures its bounded output artifact and reports
	// the bound result. A ctx cancellation means the monitor stopped
	// watching — it does not mean the job stopped running.
	//
	// The result distinguishes observed outcomes: a verified guest
	// termination (ExitVerified), a runtime-killed deadline
	// (TimedOut), and a command the guest rejected before it started
	// (FailureKind). Anything the backend cannot demonstrate returns
	// ErrExecutionUnobserved — or, when the exit was observed but the
	// artifact could not be finalized, a non-nil result with a
	// non-nil error: the plan's "result not fully verified", never a
	// terminal claim without its evidence.
	Wait(ctx context.Context, job *JobContractV2, handle, runID string) (*ExecResult, error)

	// Inspect reports whether handle still names a live workload —
	// the reconcile aid after a daemon restart, never a re-dispatch
	// trigger.
	Inspect(ctx context.Context, handle string) (live bool, err error)

	// Cleanup removes the backend resources a finished job leaves
	// behind (e.g. its sandbox). A failure is recorded as cleanup
	// pending — the VM's own contract bound is the backstop — and
	// never masks the job's already-observed result.
	Cleanup(ctx context.Context, handle string) error

	// Close releases backend resources at daemon shutdown.
	Close() error
}

// ExecResult binds a finished run back to its job: the observed
// outcome, the runtime identity it was observed from, plus the
// captured-output digest and where the artifact lives. Output itself
// never goes through the ledger — the hash does.
type ExecResult struct {
	// ExitCode is the guest's exit status, meaningful only when
	// ExitVerified is true. It is never derived from a CLI process
	// exit code: a transport failure is an unobserved outcome, not
	// an exit status.
	ExitCode int `json:"exit_code"`
	// ExitVerified is true only when the runtime's own durable job
	// record reported the guest's termination. A result that is not
	// verified is not a result this executor will sign.
	ExitVerified bool `json:"exit_verified"`
	// TimedOut is true when the runtime killed the command at the
	// contract deadline — an observed outcome, but not a guest exit.
	TimedOut bool `json:"timed_out,omitempty"`
	// FailureKind names the runtime's typed spawn-failure kind when
	// the guest rejected the command before it started; the workload
	// provably produced no effect.
	FailureKind string `json:"failure_kind,omitempty"`
	// FailureMessage is the runtime's own explanation of that
	// rejection, recorded for the operator.
	FailureMessage string `json:"failure_message,omitempty"`
	// RuntimeState is the runtime's own job-state vocabulary
	// (exited, failed, lost) — recorded verbatim so evidence carries
	// what was actually observed, not a normalized guess.
	RuntimeState string `json:"runtime_state,omitempty"`
	// RunID is the runtime-owned job identity the outcome was
	// observed from.
	RunID string `json:"run_id,omitempty"`
	// CaptureSource names where the artifact's bytes came from. The
	// runtime's job store retains a bounded capture, so the artifact
	// is exactly those stored bytes — a durable, hashed record, not
	// a claim of byte-completeness beyond what the runtime retained.
	CaptureSource string    `json:"capture_source,omitempty"`
	OutputSHA256  string    `json:"output_sha256"`
	OutputPath    string    `json:"output_path"`
	OutputBytes   int64     `json:"output_bytes"`
	Truncated     bool      `json:"truncated"`
	FinishedAt    time.Time `json:"finished_at"`
}
