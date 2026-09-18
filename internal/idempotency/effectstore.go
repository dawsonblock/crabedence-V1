package idempotency

import (
	"context"
	"encoding/json"
	"time"
)

// EffectStore is the durable execution contract boundary. The
// PostgreSQL Store and the embedded SQLiteStore both implement it;
// execution and reconciliation consumers depend only on this
// interface, so the storage engine can change without changing the
// execution semantics defined in docs/spec/durable-execution-contract.md.
type EffectStore interface {
	// Acquisition and lease-fenced lifecycle.
	Acquire(ctx context.Context, key, principal, capability, digest, grantID, class string, leaseDuration time.Duration) (*AcquireResult, error)
	// AcquireWithAuthority is Acquire plus the immutable authority
	// snapshot — the generation + digest of the grant material that
	// admitted the request are persisted on the record so the ledger
	// can prove which authority admitted each execution.
	AcquireWithAuthority(ctx context.Context, key, principal, capability, digest string, authority AuthorityBinding, class string, leaseDuration time.Duration) (*AcquireResult, error)
	BeginExecution(ctx context.Context, executionID, leaseToken string, leaseGeneration int) error
	MarkInFlight(ctx context.Context, executionID, leaseToken string, leaseGeneration int, providerID string, recoveryLocator json.RawMessage) error
	RenewLease(ctx context.Context, executionID, leaseToken string, leaseGeneration int, duration time.Duration) error
	AbandonPreDispatch(ctx context.Context, executionID, leaseToken string, leaseGeneration int) error

	// Terminal transitions and durable provider observation.
	Finalize(ctx context.Context, executionID, leaseToken string, leaseGeneration int, expectedState State, receipt TerminalReceipt) error
	RecordProviderObservation(ctx context.Context, executionID, leaseToken string, leaseGeneration int, obs ProviderObservation) error
	EnterRecovery(ctx context.Context, executionID string, expectedState State, expectedVersion int) error
	EnterRecoveryWithObservation(ctx context.Context, executionID string, expectedState State, expectedVersion int, obs ProviderObservation) error

	// Recovery and reconciliation work distribution.
	ResolveRecovery(ctx context.Context, executionID string, expectedVersion int, result RecoveryResult) error
	RecoverExpiredPreDispatch(ctx context.Context, executionID string, expectedVersion int) error
	ScrubStaleRecoveryLocators(ctx context.Context, olderThan time.Duration) (int64, error)
	ClaimUnknownBatch(ctx context.Context, owner string, batchSize int, claimDuration time.Duration) ([]*Record, error)
	ClaimExpiredBatch(ctx context.Context, owner string, batchSize int, claimDuration time.Duration) ([]*Record, error)
	ReleaseReconcileClaim(ctx context.Context, executionID string, expectedVersion int, backoffDuration time.Duration, lastError string) error
	SuspendReconciliation(ctx context.Context, executionID string, expectedVersion int, reason string) error
	RenewReconcileClaim(ctx context.Context, executionID string, expectedVersion int, duration time.Duration) error

	// Reads.
	Lookup(ctx context.Context, executionID string) (*Record, error)
	LookupByKey(ctx context.Context, principal, capability, key string) (*Record, error)
	ListUnknown(ctx context.Context) ([]*Record, error)
	ListExpiredLeases(ctx context.Context) ([]*Record, error)
	ListStuck(ctx context.Context) ([]*Record, error)
	// ListEffectEvents returns the execution's ordered forensic event
	// history (sequence-ordered, append-only, read-only).
	ListEffectEvents(ctx context.Context, executionID string) ([]EffectEvent, error)
	// ListProviderObservations returns the execution's immutable
	// provider-observation ledger rows in commit order.
	ListProviderObservations(ctx context.Context, executionID string) ([]ObservationRecord, error)

	// Cluster-epoch disaster-recovery fencing.
	// ClusterEpoch returns the epoch this store was admitted under.
	ClusterEpoch() int64
	// AdvanceClusterEpoch CAS-bumps the cluster epoch by exactly one
	// when it still equals expected. Call it as part of a
	// restore/environment rebuild: every store admitted under the old
	// epoch is permanently fenced from writes afterward.
	AdvanceClusterEpoch(ctx context.Context, expected int64, reason string) (int64, error)

	// Configuration and schema introspection.
	LeaseConfig() LeaseConfig
	SchemaVersion(ctx context.Context) (int, error)
	SetLocatorRedactor(f func(json.RawMessage) (json.RawMessage, error))
	SetEvidenceVerifier(v EvidenceVerifier)
	SetTrustedEvidenceSigners(fingerprints ...string)
}

// Compile-time conformance: both engines must satisfy the contract.
var (
	_ EffectStore = (*Store)(nil)
	_ EffectStore = (*SQLiteStore)(nil)
)
