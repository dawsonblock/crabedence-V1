/**
 * Lease storage: the durable-object adapter behind the lease
 * lifecycle's LeaseRepository contract, plus the lease storage-key
 * layout.
 *
 * The adapter is thin: the transition rules and the record edits live in
 * ./lease-lifecycle. Callers cannot assign a lease state directly — every
 * state change goes through a semantic operation here, and each
 * operation persists exactly the transition it names.
 */
import type { LeaseConfig } from "./config";
import {
  activatedLease,
  clearProvisioningRecoveryMetadata,
  expiredRegisteredLease,
  failedUnprovisionedExpiryLease,
  finalizedReleasedLease,
  isLegalLeaseTransition,
  leaseIncarnation,
  retainUnresolvedProviderResource,
  sameLeaseIncarnation,
  terminalizeManualProviderCleanup,
  type LeaseState,
} from "./lease-lifecycle";
import type { LeaseRecord, ProviderMachine } from "./types";

export function leaseKey(leaseID: string): string {
  return `lease:${leaseID}`;
}

/** The storage surface this module needs; the DO storage satisfies it. */
export interface LeaseStorageView {
  get<T>(key: string, options?: { noCache?: boolean }): Promise<T | undefined>;
  put<T>(key: string, value: T, options?: { noCache?: boolean }): Promise<void>;
}

/** Evidence restored when a release must keep its original dispatch. */
export interface DispatchEvidenceRestore {
  provisioningRequestStartedAt: string;
  provisioningCoordinatorVersion?: string | undefined;
  provisioningRequestSettledAt?: string | undefined;
  provisioningRecoveryObservedAt?: string | undefined;
  provisioningRecoveryMissingSince?: string | undefined;
}

export interface ActivateLeaseInput {
  at: string;
}

export interface ReleaseLeaseInput {
  deleteServer: boolean;
  keep?: boolean | undefined;
  /**
   * Restore the original dispatch evidence: the provider request was
   * canceled before a provider identity existed, so the release must not
   * erase what is known about it — and the unverified request stays
   * visible as retryable debt rather than disappearing with the release.
   */
  restoreDispatchEvidence?: DispatchEvidenceRestore | undefined;
  /** Claim bookkeeping for a queued or claimed deletion. */
  cleanupClaim?: { startedAt: string; expiresAt: string } | undefined;
  /** Final release after cleanup: clear recovery metadata and key debt. */
  finalize?: boolean | undefined;
}

export interface UnresolvedLeaseInput {
  message: string;
  at: string;
}

export interface ManualExpiryInput {
  error: string;
  at: string;
}

export interface LeaseExpiryInput {
  at: string;
}

/**
 * The narrow persistence contract the lease lifecycle depends on.
 * Operations are semantic — there is deliberately no state setter.
 */
export interface LeaseRepository {
  loadLease(leaseID: string, options?: { noCache?: boolean }): Promise<LeaseRecord | null>;
  /** Activation of a lease whose provider identity is already bound. */
  activateLease(lease: LeaseRecord, input: ActivateLeaseInput): Promise<LeaseRecord>;
  /** Release: record the user's intent to delete the provider resource. */
  releaseLease(lease: LeaseRecord, input: ReleaseLeaseInput): Promise<LeaseRecord>;
  /** Failure with an unresolved provider resource (explicit debt). */
  retainUnresolvedLease(lease: LeaseRecord, input: UnresolvedLeaseInput): Promise<LeaseRecord>;
  /** Terminal expiry for a cleanup that needs manual resolution. */
  expireLeaseForManualCleanup(lease: LeaseRecord, input: ManualExpiryInput): Promise<LeaseRecord>;
  /** Expiry of a registered (externally created) lease. */
  expireRegisteredLease(lease: LeaseRecord, input: LeaseExpiryInput): Promise<LeaseRecord>;
  /** Expiry of a lease whose provider request never produced a resource. */
  failUnprovisionedExpiredLease(lease: LeaseRecord, input: LeaseExpiryInput): Promise<LeaseRecord>;
}

/**
 * A transition the repository refused: the record is not what the caller
 * believes it is (a different incarnation, a different state, or a
 * target state the lifecycle does not define from there).
 */
export class LeaseTransitionRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LeaseTransitionRefused";
  }
}

export class DurableObjectLeaseRepository implements LeaseRepository {
  constructor(private readonly storage: LeaseStorageView) {}

  /**
   * Reload the record and prove the caller's expectation still holds:
   * same incarnation, same state, and — applying the transition to a
   * probe copy of the reloaded record — a resulting state the lifecycle
   * defines from there. Every state-changing operation routes through
   * this, so a caller holding a stale record, or a terminal one, can
   * never transition a record someone else has moved.
   *
   * The check is on the RESULTING state, not a named target: a
   * liveness-guarded transition (unresolved-resource evidence, manual
   * expiry) legitimately records debt on a terminal record without
   * changing its state, and that must remain possible — while a
   * transition that would move a terminal record back to a live state is
   * refused.
   *
   * The transition itself is then applied to the CALLER's record, not
   * the reloaded one, so a flow that edited fields before transitioning
   * persists exactly those edits — the reload exists to validate, not to
   * replace the caller's work.
   *
   * Callers that need mutual exclusion against concurrent flows still
   * hold their own serialization boundary; this makes the transition
   * itself safe regardless, rather than relying on the caller to be
   * correct about what it is transitioning.
   */
  private async assertTransition(
    expected: LeaseRecord,
    apply: (lease: LeaseRecord) => LeaseRecord,
  ): Promise<void> {
    const current = await this.loadLease(expected.id);
    if (!current) {
      throw new LeaseTransitionRefused(`lease ${expected.id} is missing`);
    }
    if (!sameLeaseIncarnation(current, leaseIncarnation(expected))) {
      throw new LeaseTransitionRefused(`lease ${expected.id} incarnation changed`);
    }
    if (current.state !== expected.state) {
      throw new LeaseTransitionRefused(
        `lease ${expected.id} state changed from ${expected.state} to ${current.state}`,
      );
    }
    const resulting = apply(structuredClone(current));
    if (
      resulting.state !== current.state &&
      !isLegalLeaseTransition(current.state, resulting.state)
    ) {
      throw new LeaseTransitionRefused(
        `lease ${expected.id} may not move from ${current.state} to ${resulting.state}`,
      );
    }
  }

  async loadLease(leaseID: string, options?: { noCache?: boolean }): Promise<LeaseRecord | null> {
    return (await this.storage.get<LeaseRecord>(leaseKey(leaseID), options)) ?? null;
  }

  /**
   * Activation of a lease whose provider identity is already bound (a
   * released incarnation reactivated for a new create attempt).
   */
  async activateLease(lease: LeaseRecord, input: ActivateLeaseInput): Promise<LeaseRecord> {
    await this.assertTransition(lease, (probe) => {
      activatedLease(probe, input.at);
      return probe;
    });
    activatedLease(lease, input.at);
    await this.storage.put(leaseKey(lease.id), lease);
    return lease;
  }

  async releaseLease(lease: LeaseRecord, input: ReleaseLeaseInput): Promise<LeaseRecord> {
    await this.assertTransition(lease, (probe) =>
      finalizedReleasedLease(probe, input.deleteServer, input.keep),
    );
    const next = finalizedReleasedLease(lease, input.deleteServer, input.keep);
    if (input.restoreDispatchEvidence) {
      const evidence = input.restoreDispatchEvidence;
      next.provisioningRequestStartedAt = evidence.provisioningRequestStartedAt;
      if (evidence.provisioningCoordinatorVersion) {
        next.provisioningCoordinatorVersion = evidence.provisioningCoordinatorVersion;
      }
      if (evidence.provisioningRequestSettledAt) {
        next.provisioningRequestSettledAt = evidence.provisioningRequestSettledAt;
      }
      if (evidence.provisioningRecoveryObservedAt) {
        next.provisioningRecoveryObservedAt = evidence.provisioningRecoveryObservedAt;
      }
      if (evidence.provisioningRecoveryMissingSince) {
        next.provisioningRecoveryMissingSince = evidence.provisioningRecoveryMissingSince;
      }
      next.releaseDeletesServer = true;
      next.provisioningResourceMayExist = true;
      next.provisioningFailureRetryable = true;
    }
    if (input.cleanupClaim) {
      next.releaseDeletesServer = true;
      next.cleanupStartedAt = input.cleanupClaim.startedAt;
      next.cleanupClaimExpiresAt = input.cleanupClaim.expiresAt;
    }
    if (input.finalize) {
      clearProvisioningRecoveryMetadata(next);
      delete next.providerKeyCleanupPending;
      delete next.providerKeyCleanupID;
    }
    await this.storage.put(leaseKey(next.id), next);
    return next;
  }

  async retainUnresolvedLease(
    lease: LeaseRecord,
    input: UnresolvedLeaseInput,
  ): Promise<LeaseRecord> {
    await this.assertTransition(lease, (probe) => {
      retainUnresolvedProviderResource(probe, input.message, input.at);
      return probe;
    });
    retainUnresolvedProviderResource(lease, input.message, input.at);
    await this.storage.put(leaseKey(lease.id), lease);
    return lease;
  }

  async expireLeaseForManualCleanup(
    lease: LeaseRecord,
    input: ManualExpiryInput,
  ): Promise<LeaseRecord> {
    await this.assertTransition(lease, (probe) => {
      terminalizeManualProviderCleanup(probe, input.error, input.at);
      return probe;
    });
    terminalizeManualProviderCleanup(lease, input.error, input.at);
    await this.storage.put(leaseKey(lease.id), lease);
    return lease;
  }

  async expireRegisteredLease(lease: LeaseRecord, input: LeaseExpiryInput): Promise<LeaseRecord> {
    await this.assertTransition(lease, (probe) => expiredRegisteredLease(probe, input.at));
    const next = expiredRegisteredLease(lease, input.at);
    await this.storage.put(leaseKey(next.id), next, { noCache: true });
    return next;
  }

  async failUnprovisionedExpiredLease(
    lease: LeaseRecord,
    input: LeaseExpiryInput,
  ): Promise<LeaseRecord> {
    await this.assertTransition(lease, (probe) => failedUnprovisionedExpiryLease(probe, input.at));
    const next = failedUnprovisionedExpiryLease(lease, input.at);
    await this.storage.put(leaseKey(next.id), next, { noCache: true });
    return next;
  }
}
