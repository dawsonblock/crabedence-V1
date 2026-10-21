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

// DispatchClass is the explicit outcome class of a dispatch attempt —
// the vocabulary the ledger records and the evidence rules key on. It
// exists so no caller ever has to infer, from an error's shape,
// whether an execution may have happened.
type DispatchClass string

const (
	// DispatchNotAttempted: no launch was attempted at all (the job
	// was refused before the backend was asked to do anything).
	DispatchNotAttempted DispatchClass = "NOT_ATTEMPTED"
	// DispatchProvenRejected: the backend proved nothing launched —
	// the only class that may attest NO_EFFECT.
	DispatchProvenRejected DispatchClass = "PROVEN_REJECTED"
	// DispatchStarted: the launch was admitted and its identity
	// verified.
	DispatchStarted DispatchClass = "STARTED"
	// DispatchUncertain: the workload may have started and its
	// outcome is unknown. Never a no-effect claim, never retried
	// blind.
	DispatchUncertain DispatchClass = "UNCERTAIN"
)

// ClassifyDispatchError maps a dispatch error to its explicit class.
// A nil error is STARTED; a proven pre-launch refusal is
// PROVEN_REJECTED; everything else — including an unclassified error —
// is UNCERTAIN, so a caller that cannot prove nothing executed never
// claims it.
func ClassifyDispatchError(err error) DispatchClass {
	switch {
	case err == nil:
		return DispatchStarted
	case errors.Is(err, ErrDispatchRefused):
		return DispatchProvenRejected
	default:
		return DispatchUncertain
	}
}

// ErrDispatchRefused marks a dispatch that definitively launched
// nothing: the runtime refused before any workload started. Only this
// class may produce a NO_EFFECT claim — a NO_EFFECT receipt asserts
// that nothing executed, and the executor may only assert that when it
// can prove it. Every other dispatch error is uncertain by default, so
// a post-launch failure can never be recorded as a refusal.
var ErrDispatchRefused = errors.New("dispatch refused before launch — nothing executed")

// ErrExecutionUnobserved is returned when the backend cannot
// demonstrate how the workload ended — a lost runtime, a vanished
// sandbox, or an observation deadline that expired. The job stays
// unresolved for reconciliation: an unobserved outcome is never
// recorded as a guest exit.
var ErrExecutionUnobserved = errors.New("execution outcome was never observed — reconciliation required")

// RunIdentity is the complete execution identity of one dispatch: the
// backend's handle for the sandbox, the runtime-owned run identity,
// the VM boot generation the run was verified in, and the digest of
// the effective policy it was authorized under. Every later
// observation must carry the same identity — a run that names a
// different boot generation is a substituted VM and is never adopted,
// and a result that cannot name its policy is not evidence.
type RunIdentity struct {
	Handle       string
	RunID        string
	BootID       string
	PolicyDigest string
	// Nonce is the per-dispatch authorization nonce the VM carries as
	// its dispatch label. Recovery admits a discovered VM only when it
	// presents this exact nonce — a matching command or sandbox name
	// alone never authorizes adoption.
	Nonce string
	// RetainedByPolicy reports that a refused dispatch left a real
	// instance the backend's retention policy intentionally keeps.
	// Set only alongside ErrDispatchRefused — never on a launched
	// run — so the caller can inventory the retained resource while
	// still attesting the workload never ran.
	RetainedByPolicy bool
}

// DispatchPlan is the dispatch identity computed BEFORE any VM exists:
// the deterministic handle, the per-dispatch nonce, the canonical
// policy and its digest, the authorized image digest, and the
// qualified runtime identity the launch will be made under.
//
// The caller persists the plan before the backend creates anything, so
// a crash can never leave a VM whose authorization is not on disk, and
// recovery validates a discovered VM against the stored plan instead of
// reconstructing authority from a matching command.
type DispatchPlan struct {
	Handle                string
	Nonce                 string
	Policy                *EffectivePolicyV1
	PolicyDigest          string
	ImageDigest           string
	RuntimeVersion        string
	RuntimeMSBSHA256      string
	RuntimeFirmwareSHA256 string
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

	// Prepare computes the dispatch identity — handle, nonce, canonical
	// policy and digest, image digest, runtime identity — without
	// creating anything. The caller persists it before Dispatch, so the
	// authorization on disk always precedes the VM it authorizes.
	Prepare(ctx context.Context, job *JobContractV2) (*DispatchPlan, error)

	// Dispatch starts the job under the plan's identity and returns the
	// backend's execution identity for it. A nil plan means the caller
	// did not pre-persist one (tests, record-only flows); the backend
	// then prepares internally. Returned errors classify as:
	//   nil           — launched, identity valid
	//   ErrDispatchRefused (wrapped) — definitively nothing launched;
	//                   the only class that may produce a NO_EFFECT
	//                   claim
	//   ErrAmbiguousDispatch (wrapped) — the workload may have started;
	//                   never a no-effect claim, never retried blind
	//   other error   — unclassified; callers must treat it as
	//                   uncertain (fail closed), never as a refusal
	Dispatch(ctx context.Context, job *JobContractV2, plan *DispatchPlan) (RunIdentity, error)

	// Wait observes the job until it demonstrably finished or ctx is
	// canceled, then captures its bounded output artifact and reports
	// the bound result. The observation must match the dispatch's
	// execution identity exactly. A ctx cancellation means the monitor
	// stopped watching — it does not mean the job stopped running.
	//
	// The result distinguishes observed outcomes: a verified guest
	// termination (ExitVerified), a runtime-killed deadline
	// (TimedOut), and a command the guest rejected before it started
	// (FailureKind). Anything the backend cannot demonstrate returns
	// ErrExecutionUnobserved — or, when the exit was observed but the
	// artifact could not be finalized, a non-nil result with a
	// non-nil error: the plan's "result not fully verified", never a
	// terminal claim without its evidence.
	Wait(ctx context.Context, job *JobContractV2, run RunIdentity) (*ExecResult, error)

	// Inspect reports whether handle still names a live workload —
	// the reconcile aid after a daemon restart, never a re-dispatch
	// trigger.
	Inspect(ctx context.Context, handle string) (live bool, err error)

	// Resume re-establishes observation of a run a previous daemon
	// lifetime left unresolved: it recovers the runtime-owned run
	// identity — adopting the runtime's own record when the identity
	// was lost with the crash — verifies the boot generation matches
	// the one the ledger recorded, and observes the run to a terminal
	// result, exactly as Wait would. It never launches anything: a run
	// it cannot find, or one whose boot generation differs, is
	// unobserved — never duplicated, never adopted. The returned
	// identity carries any adopted fields so the caller can persist
	// them.
	Resume(ctx context.Context, job *JobContractV2, run RunIdentity) (RunIdentity, *ExecResult, error)

	// Cleanup removes the backend resources a finished job leaves
	// behind (e.g. its sandbox), but only when it can bind the
	// destructive operation to the exact authorized resource
	// instance: the request carries the persisted dispatch identity
	// (handle, dispatch nonce, boot generation, policy digest, run
	// identity) and an optional recovery fence, and the removal is
	// conditioned on that identity — a sandbox that cannot present
	// the dispatch's ownership proof is a substituted or foreign
	// instance and is never destroyed. The result classifies the
	// outcome explicitly: REMOVED_VERIFIED and
	// ALREADY_ABSENT_VERIFIED prove the authorized instance is gone;
	// RETAINED_BY_POLICY discharges the obligation because the backend
	// intentionally keeps the instance — a resolution, never a claim
	// of absence; IDENTITY_MISMATCH, IDENTITY_UNVERIFIABLE and
	// REMOVAL_UNCERTAIN leave the cleanup pending for retry and
	// operator escalation.
	// A non-nil error means the operation could not be attempted or
	// its outcome could not be classified — the cleanup stays
	// pending either way, and never masks the job's already-observed
	// result.
	Cleanup(ctx context.Context, request CleanupRequest) (CleanupResult, error)

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
	// FailureStage is the runtime's own statement of where that
	// failure occurred. It is what makes the no-effect claim auditable
	// rather than asserted: a receipt carrying a pre-execution stage
	// names the proof that nothing ran, and a stage that is not
	// pre-execution never reaches a receipt at all.
	FailureStage string `json:"failure_stage,omitempty"`
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
	// BootID is the VM boot generation the run was verified in — the
	// substituted-instance control.
	BootID string `json:"boot_id,omitempty"`
	// PolicyDigest is the digest of the effective policy the run was
	// authorized under: the canonical identity an independent verifier
	// compares against the ledger.
	PolicyDigest string `json:"policy_digest,omitempty"`
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
