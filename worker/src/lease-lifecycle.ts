/**
 * Lease lifecycle: the rules that decide how a lease — the record that
 * binds this coordinator to a provider instance — changes state.
 *
 * States: `provisioning | active | released | expired | failed`. There
 * is no generic state setter: the only transitions are the builders
 * defined here, and the transition matrix is documented with them.
 * Terminal states never return to an active one; a terminal record can
 * still record new cleanup intent (release), which is evidence, not a
 * resurrection.
 *
 * Layering: this module depends on the domain types and the provider
 * key helper only. It must not import the fleet router, the storage
 * layer, Cloudflare runtime globals, HTTP routing code, or environment
 * parsing — the lease repository supplies persistence.
 */
import type { LeaseConfig } from "./config";
import { providerKeyForLease } from "./provider-key";
import type { LeaseRecord, ProviderMachine } from "./types";

export type LeaseState = LeaseRecord["state"];

export const LEASE_STATES: readonly LeaseState[] = [
  "provisioning",
  "active",
  "released",
  "expired",
  "failed",
];

/** The state a newly created managed lease starts in. */
export const INITIAL_LEASE_STATE: LeaseState = "provisioning";
/** The state an externally created (registered) lease is recorded in. */
export const REGISTERED_LEASE_STATE: LeaseState = "active";

/** Released, expired, and failed are terminal: no provider authority. */
export function isTerminalLeaseState(state: LeaseState): boolean {
  return state === "released" || state === "expired" || state === "failed";
}

/** Live leases are the only ones that may hold provider resources. */
export function leaseIsLive(lease: LeaseRecord): boolean {
  return lease.state === "active" || lease.state === "provisioning";
}

export function isRegisteredLease(lease: LeaseRecord): boolean {
  return lease.lifecycle === "registered";
}

/** Why a heartbeat must be refused, if it must. */
export function leaseHeartbeatStateError(
  lease: LeaseRecord,
  now = Date.now(),
): "lease_ended" | "lease_expired" | undefined {
  if (!leaseIsLive(lease)) {
    return "lease_ended";
  }
  const expiresAt = Date.parse(lease.expiresAt);
  if (!Number.isFinite(expiresAt) || expiresAt <= now) {
    return "lease_expired";
  }
  return undefined;
}

/**
 * Unresolved cleanup: the provider resource may exist, cannot be
 * retried, and has no scheduled retry. This is explicit debt — never
 * "no instance".
 */
export function leaseCleanupIsUnresolved(lease: LeaseRecord): boolean {
  return Boolean(
    lease.provisioningResourceMayExist === true &&
    lease.provisioningFailureRetryable === false &&
    lease.failureError &&
    lease.cleanupError &&
    !lease.cleanupRetryAt,
  );
}

// ─── Metadata clearing (pure record edits) ────────────────────────────

export function clearLeaseCleanupMetadata(lease: LeaseRecord): void {
  delete lease.cleanupAttempts;
  delete lease.cleanupError;
  delete lease.cleanupFailedAt;
  delete lease.cleanupRetryAt;
}

export function clearProvisioningRecoveryMetadata(lease: LeaseRecord): void {
  delete lease.provisioningRequestStartedAt;
  delete lease.provisioningCoordinatorVersion;
  delete lease.provisioningRequestSettledAt;
  delete lease.provisioningRecoveryObservedAt;
  delete lease.provisioningRecoveryMissingSince;
  if (lease.provisioningResourceMayExist !== undefined) lease.provisioningResourceMayExist = false;
  if (lease.provisioningFailureRetryable !== undefined) lease.provisioningFailureRetryable = false;
}

export function clearRuntimeAdapterDeleteMetadata(lease: LeaseRecord): void {
  delete lease.runtimeAdapterDeleteRequestedAt;
  delete lease.runtimeAdapterDeleteClaimID;
  delete lease.runtimeAdapterDeleteRetryAt;
  delete lease.runtimeAdapterDeleteDispatchUntil;
  delete lease.runtimeAdapterDeleteAttempts;
  delete lease.runtimeAdapterDeleteError;
}

// ─── Configuration-derived provider identity ──────────────────────────

export function providerRegionForConfig(config: LeaseConfig): string | undefined {
  if (config.provider === "gcp") return config.gcpZone;
  if (config.provider === "azure") return config.azureLocation;
  return config.provider === "aws" ? config.awsRegion : undefined;
}

export function providerProjectForConfig(config: LeaseConfig): string | undefined {
  return config.provider === "gcp" ? config.gcpProject : undefined;
}

// ─── Transitions ──────────────────────────────────────────────────────

/**
 * Activation: bind the provider instance a provisioning attempt
 * produced. The record keeps its identity — including the create-attempt
 * generation that authorized the attempt.
 */
export function provisionedLeaseRecord(
  lease: LeaseRecord,
  config: LeaseConfig,
  server: ProviderMachine,
  serverType: string,
): LeaseRecord {
  const providerProject = lease.providerProject ?? providerProjectForConfig(config);
  const providerKey = server.providerKey?.trim() || config.providerKey;
  const providerKeyCleanupOwned =
    (config.provider === "aws" || config.provider === "hetzner") &&
    providerKey === providerKeyForLease(lease.id);
  return {
    ...lease,
    state: "active",
    cloudID: server.cloudID,
    serverID: server.id,
    ...(server.providerResourceID ? { providerResourceID: server.providerResourceID } : {}),
    serverName: server.name,
    serverType,
    providerKey,
    providerKeyCleanupOwned,
    host: server.host,
    region: server.region ?? lease.region ?? providerRegionForConfig(config) ?? "",
    ...(providerProject ? { providerProject } : {}),
    ...(server.hostID ? { hostId: server.hostID } : {}),
  };
}

/**
 * Failure with an unresolved provider resource: the lease becomes
 * terminal `failed`, and the unresolved evidence is recorded rather than
 * erased — a later reconciliation must still be able to find the
 * resource.
 */
export function retainUnresolvedProviderResource(
  lease: LeaseRecord,
  message: string,
  at: string,
): void {
  if (leaseIsLive(lease)) {
    lease.state = "failed";
    lease.endedAt = at;
  }
  lease.updatedAt = at;
  lease.failureError = message;
  lease.cleanupError = message;
  lease.cleanupFailedAt = at;
  lease.provisioningResourceMayExist = true;
  lease.provisioningFailureRetryable = false;
  delete lease.cleanupRetryAt;
  delete lease.cleanupStartedAt;
  delete lease.cleanupClaimExpiresAt;
  // Preserve original dispatch/scope and user intent. No next attempt can make
  // progress without identity resolution, and elapsed TTL is not observed deletion.
}

/**
 * Terminal expiry for a manual-resolution cleanup: the lease is kept,
 * provider deletion is disclaimed, and every retry marker is cleared so
 * the record cannot be picked up by maintenance again.
 */
export function terminalizeManualProviderCleanup(
  lease: LeaseRecord,
  error: string,
  terminalAt: string,
): void {
  if (leaseIsLive(lease)) {
    lease.state = "expired";
  }
  lease.keep = true;
  lease.releaseDeletesServer = false;
  lease.failureError = error;
  lease.updatedAt = terminalAt;
  lease.endedAt = terminalAt;
  clearLeaseCleanupMetadata(lease);
  delete lease.cleanupStartedAt;
  delete lease.cleanupClaimExpiresAt;
  delete lease.provisioningResourceMayExist;
  delete lease.provisioningFailureRetryable;
  delete lease.provisioningCoordinatorVersion;
  delete lease.provisioningRequestSettledAt;
  delete lease.provisioningRecoveryObservedAt;
  delete lease.provisioningRecoveryMissingSince;
}

/**
 * Release: record the user's intent that the provider resource should be
 * deleted. An unresolved creation keeps its recovery evidence and its
 * visible debt — release records intent, it does not cancel an
 * already-dispatched provider request.
 */
export function finalizedReleasedLease(
  current: LeaseRecord,
  deleteServer: boolean,
  keep?: boolean,
): LeaseRecord {
  const lease = structuredClone(current);
  const unresolvedCreation =
    !lease.cloudID &&
    Boolean(lease.provisioningRequestStartedAt || lease.provisioningResourceMayExist);
  const wasUnprovisionedRelease =
    !lease.cloudID &&
    (lease.state === "provisioning" || lease.state === "released" || unresolvedCreation);
  const now = new Date().toISOString();
  lease.state = "released";
  lease.updatedAt = now;
  lease.releasedAt = now;
  lease.endedAt = now;
  if (!unresolvedCreation) {
    delete lease.provisioningCoordinatorVersion;
    delete lease.provisioningRequestSettledAt;
    delete lease.provisioningRecoveryObservedAt;
    delete lease.provisioningRecoveryMissingSince;
    clearLeaseCleanupMetadata(lease);
  } else {
    lease.provisioningResourceMayExist = true;
    lease.cleanupError ??= "provider creation is unresolved; cleanup has not been confirmed";
  }
  if (wasUnprovisionedRelease) {
    lease.releaseDeletesServer = deleteServer;
  } else if (
    !deleteServer &&
    !isRegisteredLease(lease) &&
    (lease.cloudID || lease.providerKeyCleanupPending)
  ) {
    lease.releaseDeletesServer = false;
  } else {
    delete lease.releaseDeletesServer;
  }
  clearRuntimeAdapterDeleteMetadata(lease);
  delete lease.cleanupStartedAt;
  delete lease.cleanupClaimExpiresAt;
  if (keep !== undefined) {
    lease.keep = keep;
  }
  return lease;
}
