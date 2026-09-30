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
} from "./lease-lifecycle";
import type { LeaseRecord } from "./types";

export function leaseKey(leaseID: string): string {
  return `lease:${leaseID}`;
}

/** The storage surface this module needs; the DO storage satisfies it. */
export interface LeaseStorageView {
  get<T>(key: string, options?: { noCache?: boolean }): Promise<T | undefined>;
  put<T>(key: string, value: T, options?: { noCache?: boolean }): Promise<void>;
}

/**
 * The transactional surface the repository requires. A transition must be
 * able to reload, validate, and persist atomically: a read-then-write
 * pair with an await in between is not a guarantee, it is a hope.
 */
export interface LeaseRepositoryStorage extends LeaseStorageView {
  transaction<T>(closure: (txn: LeaseStorageView) => Promise<T>): Promise<T>;
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
  /**
   * Cleanup debt the failed attempt still owes: a provider deletion is
   * outstanding. The transition records it on the RELOADED record; a
   * caller that mutates its own copy instead will have the edit
   * discarded.
   */
  releaseDeletesServer?: boolean | undefined;
  /** The record's validity window ends with the failure. */
  expiresAt?: string | undefined;
}

export interface ManualExpiryInput {
  error: string;
  at: string;
  /**
   * The record's validity window ends with the failure. Deletion debt is
   * NOT carried: manual resolution disclaims the provider resource, and
   * the transition owns that decision.
   */
  expiresAt?: string | undefined;
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

/**
 * Record a failed cleanup's outstanding debt on the reloaded record.
 * Kept beside the transitions so every caller records debt the same way —
 * through input, never by mutating the record it passed in (which the
 * transition would discard).
 */
function applyCleanupFailureDebt(
  record: LeaseRecord,
  releaseDeletesServer: boolean | undefined,
  expiresAt: string | undefined,
): void {
  if (releaseDeletesServer !== undefined) record.releaseDeletesServer = releaseDeletesServer;
  if (expiresAt !== undefined) record.expiresAt = expiresAt;
}

export class DurableObjectLeaseRepository implements LeaseRepository {
  constructor(private readonly storage: LeaseRepositoryStorage) {}

  /**
   * Run one transition inside a storage transaction: reload the record,
   * prove the caller's expectation still holds (same incarnation, same
   * state, and same storage revision), apply the named operation to the
   * RELOADED record, validate the resulting state, and persist. Reload,
   * validation, and write are one atomic unit, so a concurrent writer
   * cannot interleave between the check and the write.
   *
   * The operation is applied to the reloaded record — never to the
   * caller's possibly stale copy — so a field another writer committed
   * between the caller's load and this transaction is preserved rather
   * than silently reverted. The revision check additionally refuses a
   * caller whose record was superseded by a same-state write, which a
   * state comparison alone cannot detect.
   *
   * The check is on the RESULTING state, not a named target: a
   * liveness-guarded transition (unresolved-resource evidence, manual
   * expiry) legitimately records debt on a terminal record without
   * changing its state, and that must remain possible — while a
   * transition that would move a terminal record back to a live state is
   * refused.
   *
   * Callers that need to persist an edit express it as transition input;
   * they do not mutate a loaded record and hope the transition smuggles
   * the edit through.
   */
  /**
   * Test seam: a hook that runs after a transaction's reload, before its
   * write. Production never sets it; the adversarial serialization test
   * uses it to prove a paused writer cannot lose an update.
   */
  afterTransactionRead: (() => Promise<void>) | undefined;

  private async transition(
    expected: LeaseRecord,
    operation: (current: LeaseRecord) => LeaseRecord,
    options?: { noCache?: boolean },
  ): Promise<LeaseRecord> {
    return this.storage.transaction(async (txn) => {
      const current = await txn.get<LeaseRecord>(leaseKey(expected.id));
      await this.afterTransactionRead?.();
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
      const currentRevision = current.storageRevision ?? 0;
      if (currentRevision !== (expected.storageRevision ?? 0)) {
        throw new LeaseTransitionRefused(
          `lease ${expected.id} revision changed from ${expected.storageRevision ?? 0} to ${currentRevision}`,
        );
      }
      const next = operation(structuredClone(current));
      if (next.state !== current.state && !isLegalLeaseTransition(current.state, next.state)) {
        throw new LeaseTransitionRefused(
          `lease ${expected.id} may not move from ${current.state} to ${next.state}`,
        );
      }
      next.storageRevision = currentRevision + 1;
      await txn.put(leaseKey(next.id), next, options);
      return next;
    });
  }

  async loadLease(leaseID: string, options?: { noCache?: boolean }): Promise<LeaseRecord | null> {
    return (await this.storage.get<LeaseRecord>(leaseKey(leaseID), options)) ?? null;
  }

  /**
   * Activation of a lease whose provider identity is already bound (a
   * released incarnation reactivated for a new create attempt).
   */
  async activateLease(lease: LeaseRecord, input: ActivateLeaseInput): Promise<LeaseRecord> {
    return this.transition(lease, (current) => {
      activatedLease(current, input.at);
      return current;
    });
  }

  async releaseLease(lease: LeaseRecord, input: ReleaseLeaseInput): Promise<LeaseRecord> {
    return this.transition(lease, (current) => {
      const next = finalizedReleasedLease(current, input.deleteServer, input.keep);
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
      return next;
    });
  }

  async retainUnresolvedLease(
    lease: LeaseRecord,
    input: UnresolvedLeaseInput,
  ): Promise<LeaseRecord> {
    return this.transition(lease, (current) => {
      retainUnresolvedProviderResource(current, input.message, input.at);
      applyCleanupFailureDebt(current, input.releaseDeletesServer, input.expiresAt);
      return current;
    });
  }

  async expireLeaseForManualCleanup(
    lease: LeaseRecord,
    input: ManualExpiryInput,
  ): Promise<LeaseRecord> {
    return this.transition(lease, (current) => {
      terminalizeManualProviderCleanup(current, input.error, input.at);
      // Manual resolution disclaims provider deletion, so the transition's
      // releaseDeletesServer stands; only the validity window carries over.
      if (input.expiresAt !== undefined) current.expiresAt = input.expiresAt;
      return current;
    });
  }

  async expireRegisteredLease(lease: LeaseRecord, input: LeaseExpiryInput): Promise<LeaseRecord> {
    return this.transition(lease, (current) => expiredRegisteredLease(current, input.at), {
      noCache: true,
    });
  }

  async failUnprovisionedExpiredLease(
    lease: LeaseRecord,
    input: LeaseExpiryInput,
  ): Promise<LeaseRecord> {
    return this.transition(lease, (current) => failedUnprovisionedExpiryLease(current, input.at), {
      noCache: true,
    });
  }
}
