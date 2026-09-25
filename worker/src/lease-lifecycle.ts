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
function providerIdentityFields(
  lease: LeaseRecord,
  config: LeaseConfig,
  server: ProviderMachine,
  serverType: string,
): Record<string, unknown> {
  const providerProject = lease.providerProject ?? providerProjectForConfig(config);
  const providerKey = server.providerKey?.trim() || config.providerKey;
  const providerKeyCleanupOwned =
    (config.provider === "aws" || config.provider === "hetzner") &&
    providerKey === providerKeyForLease(lease.id);
  return {
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
 * Bind the provider instance an attempt produced WITHOUT granting
 * liveness: the record keeps the state it already had. Used by rollback
 * paths that must record the allocation without activating it.
 */
export function bindProviderIdentity(
  lease: LeaseRecord,
  config: LeaseConfig,
  server: ProviderMachine,
  serverType: string,
): LeaseRecord {
  return { ...lease, ...providerIdentityFields(lease, config, server, serverType) } as LeaseRecord;
}

/**
 * The cleanup lease for a provider rollback: bind the identity and keep
 * the stored incarnation's state — a released incarnation stays
 * released, and only a record with no stored state becomes `active`.
 */
export function rollbackCleanupLease(
  base: LeaseRecord,
  latest: LeaseRecord | undefined,
  config: LeaseConfig,
  server: ProviderMachine,
  serverType: string,
): LeaseRecord {
  const bound = bindProviderIdentity(latest ?? base, config, server, serverType);
  bound.state = latest?.state ?? "active";
  return bound;
}

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
  return {
    ...lease,
    state: "active",
    ...providerIdentityFields(lease, config, server, serverType),
  } as LeaseRecord;
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

/**
 * Registered-lease expiry: the externally created lease is retired. Its
 * cleanup and runtime-adapter debt is cleared unless a delete is already
 * in flight, so maintenance cannot pick it up again.
 */
export function expiredRegisteredLease(lease: LeaseRecord, at: string): LeaseRecord {
  const next = { ...lease };
  next.state = "expired";
  next.updatedAt = at;
  next.endedAt = at;
  delete next.releaseDeletesServer;
  clearLeaseCleanupMetadata(next);
  if (!next.runtimeAdapterDeleteRequestedAt) {
    clearRuntimeAdapterDeleteMetadata(next);
  }
  delete next.cleanupStartedAt;
  delete next.cleanupClaimExpiresAt;
  return next;
}

/**
 * Expiry of a lease whose provider request never produced a resource:
 * the lease becomes terminal `failed`, and the dispatched request stays
 * visible as unresolved cleanup rather than disappearing with the TTL.
 */
export function failedUnprovisionedExpiryLease(lease: LeaseRecord, at: string): LeaseRecord {
  const next = { ...lease };
  next.state = "failed";
  next.updatedAt = at;
  next.endedAt = at;
  if (next.provisioningRequestStartedAt) next.provisioningResourceMayExist = true;
  next.cleanupFailedAt = at;
  next.cleanupError =
    "lease expired before provider returned a cloud resource; cleanup remains unresolved";
  return next;
}

/**
 * A provider resource returned after the lease ended: the record keeps
 * the allocation (it exists and must be cleaned up) while the lease
 * stays terminal, and a cleanup retry is scheduled.
 */
export function lateProviderResourceLease(
  lease: LeaseRecord,
  at: Date,
  retryDelayMs: number,
): void {
  if (lease.state === "provisioning") lease.state = "failed";
  lease.endedAt ??= lease.updatedAt;
  lease.releaseDeletesServer = true;
  lease.provisioningResourceMayExist = true;
  lease.provisioningFailureRetryable = false;
  delete lease.failureError;
  lease.cleanupError = "provider resource returned after the lease ended; cleanup pending";
  lease.cleanupRetryAt = new Date(at.getTime() + retryDelayMs).toISOString();
}

// ─── Recovery, reactivation, and workspace transitions ───────────────

/** Activation of a lease whose provider identity is already bound. */
export function activatedLease(lease: LeaseRecord, at: string): void {
  lease.state = "active";
  lease.updatedAt = at;
}

/** A provisioning attempt failed before a resource was confirmed. */
export function provisioningFailedLease(lease: LeaseRecord, at: string): void {
  lease.state = "failed";
  lease.endedAt = at;
}

/** Provisioning completed: the record becomes live and its recovery markers clear. */
export function finalizedProvisioningLease(lease: LeaseRecord): void {
  lease.state = "active";
  clearProvisioningRecoveryMetadata(lease);
}

/** Provider recovery failed: the lease is terminal. */
export function recoveryFailedLease(lease: LeaseRecord): void {
  lease.state = "failed";
}

/**
 * Workspace recovery outcome: a recovered ready workspace reactivates the
 * lease with its recovered host; anything else returns it to provisioning.
 */
export function recoveredWorkspaceLease(
  lease: LeaseRecord,
  input: { ready: boolean; host?: string | undefined },
): void {
  if (input.ready) {
    lease.state = "active";
    if (input.host) {
      lease.host = input.host;
    }
  } else {
    lease.state = "provisioning";
  }
}

/**
 * A provisioning attempt that left no resource behind: retryable failure,
 * with every recovery marker cleared so the next attempt starts clean.
 */
export function absentProvisioningLease(lease: LeaseRecord, at: string): void {
  lease.state = "failed";
  lease.provisioningResourceMayExist = false;
  lease.provisioningFailureRetryable = true;
  delete lease.provisioningRequestStartedAt;
  delete lease.provisioningCoordinatorVersion;
  delete lease.provisioningRequestSettledAt;
  delete lease.provisioningRecoveryObservedAt;
  delete lease.provisioningRecoveryMissingSince;
  lease.updatedAt = at;
}

/** Workspace provisioning deadline expired: terminal failure, no retry. */
export function expiredWorkspaceProvisioningLease(
  lease: LeaseRecord,
  input: { message: string; at: string },
): void {
  lease.state = "failed";
  lease.failureError = input.message;
  lease.provisioningFailureRetryable = false;
  lease.updatedAt = input.at;
  lease.endedAt = input.at;
}
