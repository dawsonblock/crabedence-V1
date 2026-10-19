package sandboxexecutor

import (
	"fmt"
	"strings"
	"time"
)

// Identity-bound destruction (RC7.5, INV-01/INV-04).
//
// A sandbox name is reusable: a handle that named one VM can name a
// different one a moment later, so a destructive operation keyed on
// the name alone can destroy a resource it was never authorized to
// touch. Every automatic cleanup is therefore issued against an
// explicit identity — the persisted dispatch authorization the VM was
// created under — and reports an explicit outcome. A caller may clear
// a pending cleanup only for an outcome that proves the authorized
// instance is gone; everything else stays pending for retry and,
// eventually, for an operator.

// CleanupOutcome is the explicit disposition of one identity-bound
// removal. The caller never has to infer, from an error's shape,
// whether the authorized resource is gone.
type CleanupOutcome string

const (
	// CleanupRemovedVerified: the authorized instance was destroyed
	// and absence was independently verified afterward.
	CleanupRemovedVerified CleanupOutcome = "REMOVED_VERIFIED"
	// CleanupAlreadyAbsentVerified: nothing carrying the authorized
	// identity exists — the goal (absence) was already true.
	CleanupAlreadyAbsentVerified CleanupOutcome = "ALREADY_ABSENT_VERIFIED"
	// CleanupIdentityMismatch: a resource occupies the name but its
	// identity is not the authorized one — a substituted or foreign
	// instance. It is never destroyed; it belongs to an operator.
	CleanupIdentityMismatch CleanupOutcome = "IDENTITY_MISMATCH"
	// CleanupIdentityUnverifiable: the request or the runtime could
	// not establish which instance the removal would authorize.
	// Destruction without provable identity is refused outright —
	// the resource is quarantined, not removed.
	CleanupIdentityUnverifiable CleanupOutcome = "IDENTITY_UNVERIFIABLE"
	// CleanupRemovalUncertain: the destructive operation was issued
	// (or may have been) but its result could not be demonstrated —
	// a timeout after removal was sent, or post-removal verification
	// failed. The resource may be gone or may still exist.
	CleanupRemovalUncertain CleanupOutcome = "REMOVAL_UNCERTAIN"
	// CleanupRetainedByPolicy: the authorized instance still exists —
	// the backend's retention policy intentionally keeps it (forensic
	// retention). The obligation is discharged by the policy decision
	// itself; the outcome must never be read as evidence of absence.
	CleanupRetainedByPolicy CleanupOutcome = "RETAINED_BY_POLICY"
)

// ProvesAbsent reports whether the outcome demonstrates that the
// authorized instance no longer exists — the only outcomes under
// which a pending cleanup may be cleared. Everything else is residue:
// retried on the next pass, escalated to an operator, never assumed.
func (o CleanupOutcome) ProvesAbsent() bool {
	return o == CleanupRemovedVerified || o == CleanupAlreadyAbsentVerified
}

// ResolvesObligation reports whether the outcome discharges a pending
// cleanup: either the authorized instance is proven gone, or the
// backend's retention policy intentionally keeps it. This is wider
// than ProvesAbsent by design — retention settles the obligation
// without claiming the resource is absent, and must never feed
// accounting that asserts the instance no longer exists.
func (o CleanupOutcome) ResolvesObligation() bool {
	return o.ProvesAbsent() || o == CleanupRetainedByPolicy
}

// RecoveryFence carries the caller's current recovery claim to the
// external effect boundary. The ledger fence decides who may commit;
// this token is what a backend sees of that ownership — a backend that
// can enforce fencing can refuse a stale operation outright, and every
// backend records it so the audit trail names which claim generation
// each external effect ran under.
//
// The full claim travels, never a boolean: an effect boundary that
// reduced the fence to "claimed or not" could not distinguish a live
// claimant from a stale one.
type RecoveryFence struct {
	// JobID and Action name the claimed recovery work.
	JobID  string
	Action string
	// Attempt is the durable, monotonic attempt ordinal this claim
	// generation owns.
	Attempt int
	// OwnerEpoch is the ledger lifetime that holds the claim.
	OwnerEpoch uint64
	// ClaimID is the claim's durable generation identifier: unique for
	// the life of the pacing row, and preserved across delete and
	// recreate so a replayed claim from an older generation can never
	// be mistaken for the current one.
	ClaimID int64
	// LeaseUntil is when the claim's ownership lapses.
	LeaseUntil time.Time
}

// fenceFromClaim renders a ledger claim as the boundary token.
func fenceFromClaim(c *RecoveryClaim) *RecoveryFence {
	if c == nil {
		return nil
	}
	return &RecoveryFence{
		JobID:      c.JobID,
		Action:     c.Action,
		Attempt:    c.Attempt,
		OwnerEpoch: c.OwnerEpoch,
		ClaimID:    c.ClaimID,
		LeaseUntil: c.LeaseUntil,
	}
}

// String renders the fence for audit lines — identity, never secrets.
func (f *RecoveryFence) String() string {
	if f == nil {
		return "none"
	}
	return fmt.Sprintf("%s/%s attempt=%d epoch=%d claim=%d lease=%s",
		f.JobID, f.Action, f.Attempt, f.OwnerEpoch, f.ClaimID, f.LeaseUntil.UTC().Format(time.RFC3339))
}

// CleanupRequest is the complete identity under which one destructive
// cleanup is authorized. Fields fall into two classes:
//
//   - Verified identities — values the ledger recorded when the
//     dispatch was authorized and the VM was verified: DispatchNonce,
//     BootID, PolicyDigest. The removal is conditioned on these; an
//     instance that cannot present them is not the authorized
//     resource.
//   - Provisional identities — name-based lookups (Handle) and
//     correlation aids (JobID, RunID, InstanceID) that help locate and
//     classify the resource but never alone authorize destroying it.
//
// An empty verified field is not a wildcard: a request that cannot
// supply the dispatch's persisted ownership proof is
// IDENTITY_UNVERIFIABLE, and the resource is left for an operator.
type CleanupRequest struct {
	// JobID is the durable execution record the cleanup belongs to.
	JobID string
	// BackendID is the provider that was authorized to run the job.
	BackendID string
	// Handle is the sandbox lookup name — provisional: reusable, so
	// never sufficient on its own.
	Handle string
	// InstanceID is the runtime's immutable sandbox-instance identity
	// when the backend exposes one; empty means the backend identifies
	// instances by other means (dispatch labels, boot generation).
	InstanceID string
	// DispatchNonce is the per-dispatch ownership proof the instance
	// was labeled with at creation — the verified identity a
	// substitute cannot inherit.
	DispatchNonce string
	// BootID is the boot generation verified at dispatch — an
	// additional verified binding: a re-created VM under the same name
	// cannot carry it.
	BootID string
	// PolicyDigest is the effective authorized policy the dispatch
	// ran under.
	PolicyDigest string
	// RunID is the runtime-owned job identity observed for the run.
	RunID string
	// RecoveryFence, when non-nil, is the recovery claim the caller
	// holds and under which this effect runs.
	RecoveryFence *RecoveryFence
}

// Validate refuses a request that cannot bind a destructive operation
// to a verified identity: the lookup name and the dispatch ownership
// proof are mandatory. An unverified request fails closed — the
// caller's resource stays quarantined rather than name-destroyed.
func (r CleanupRequest) Validate() error {
	if strings.TrimSpace(r.Handle) == "" {
		return fmt.Errorf("cleanup request for job %s carries no handle — nothing to look the instance up by", r.JobID)
	}
	if strings.TrimSpace(r.DispatchNonce) == "" {
		return fmt.Errorf("cleanup request for job %s (handle %s) carries no dispatch nonce — the persisted ownership proof a substitute cannot present", r.JobID, r.Handle)
	}
	return nil
}

// CleanupResult is the backend's explicit account of one identity-bound
// removal attempt: what happened to the authorized resource, plus the
// evidence the caller records. It is never nil when err is nil.
type CleanupResult struct {
	// Outcome is the disposition — see CleanupOutcome.
	Outcome CleanupOutcome
	// Detail is the operator-facing evidence: what was verified, what
	// contradicted it, or why nothing could be proven. It lands in the
	// ledger's cleanup record and the audit line.
	Detail string
}

// refuse builds a non-destructive outcome with its evidence.
func refuse(outcome CleanupOutcome, format string, args ...any) (CleanupResult, error) {
	return CleanupResult{Outcome: outcome, Detail: fmt.Sprintf(format, args...)}, nil
}
