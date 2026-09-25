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
  clearProvisioningRecoveryMetadata,
  expiredRegisteredLease,
  failedUnprovisionedExpiryLease,
  finalizedReleasedLease,
  provisionedLeaseRecord,
  retainUnresolvedProviderResource,
  terminalizeManualProviderCleanup,
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
  config: LeaseConfig;
  server: ProviderMachine;
  serverType: string;
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
  /** Persist a newly created managed lease (state provisioning). */
  createManagedLease(lease: LeaseRecord): Promise<void>;
  /** Activation: bind the provider instance the attempt produced. */
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

export class DurableObjectLeaseRepository implements LeaseRepository {
  constructor(private readonly storage: LeaseStorageView) {}

  async loadLease(leaseID: string, options?: { noCache?: boolean }): Promise<LeaseRecord | null> {
    return (await this.storage.get<LeaseRecord>(leaseKey(leaseID), options)) ?? null;
  }

  async createManagedLease(lease: LeaseRecord): Promise<void> {
    await this.storage.put(leaseKey(lease.id), lease);
  }

  async activateLease(lease: LeaseRecord, input: ActivateLeaseInput): Promise<LeaseRecord> {
    const next = provisionedLeaseRecord(lease, input.config, input.server, input.serverType);
    await this.storage.put(leaseKey(next.id), next);
    return next;
  }

  async releaseLease(lease: LeaseRecord, input: ReleaseLeaseInput): Promise<LeaseRecord> {
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
    retainUnresolvedProviderResource(lease, input.message, input.at);
    await this.storage.put(leaseKey(lease.id), lease);
    return lease;
  }

  async expireLeaseForManualCleanup(
    lease: LeaseRecord,
    input: ManualExpiryInput,
  ): Promise<LeaseRecord> {
    terminalizeManualProviderCleanup(lease, input.error, input.at);
    await this.storage.put(leaseKey(lease.id), lease);
    return lease;
  }

  async expireRegisteredLease(lease: LeaseRecord, input: LeaseExpiryInput): Promise<LeaseRecord> {
    const next = expiredRegisteredLease(lease, input.at);
    await this.storage.put(leaseKey(next.id), next, { noCache: true });
    return next;
  }

  async failUnprovisionedExpiredLease(
    lease: LeaseRecord,
    input: LeaseExpiryInput,
  ): Promise<LeaseRecord> {
    const next = failedUnprovisionedExpiryLease(lease, input.at);
    await this.storage.put(leaseKey(next.id), next, { noCache: true });
    return next;
  }
}
