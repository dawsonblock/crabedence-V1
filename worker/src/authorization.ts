/**
 * Authorization decisions and the resolved actor context.
 *
 * Authentication (who the caller is: bearer tokens, device tokens,
 * GitHub grants, admin grants) lives in ./auth; identity labels
 * (owner/org resolution) live in ./http and ./org-identity. This module
 * owns what an authenticated caller may do — lease access roles, run
 * readability and writability, and the bridge-principal completeness
 * rule that gates every decision.
 *
 * Handlers resolve an ActorContext once with actorFromRequest and pass
 * it to these decisions instead of re-deriving identity inline. The
 * decisions are pure: they never touch storage, sockets, or the fleet
 * object graph, so they can be unit-tested directly.
 */
import { isAdminRequest } from "./auth";
import { requestOwner } from "./http";
import {
  isCurrentOrgKey,
  MISSING_ORG_KEY,
  requestOrg,
  requestOrgLabel,
  sameOrgIdentityKey,
} from "./org-identity";
import type { Env, LeaseRecord, LeaseShare, LeaseShareRole, RunRecord } from "./types";

/** The resolved security context of one request. */
export interface ActorContext {
  /** Stored and compared authorization identity. */
  owner: string;
  /** Canonical org key (see org-identity); the only org form that authorizes. */
  org: string;
  /** Public org label for responses — never used for authorization. */
  orgLabel: string;
  admin: boolean;
  auth: string;
}

/** Resolve the request's actor context once, at the handler boundary. */
export function actorFromRequest(
  request: Request,
  env: Pick<Env, "CRABBOX_DEFAULT_ORG">,
): ActorContext {
  return {
    owner: requestOwner(request),
    org: requestOrg(request, env),
    orgLabel: requestOrgLabel(request, env),
    admin: isAdminRequest(request),
    auth: request.headers.get("x-crabbox-auth") || "bearer",
  };
}

/** The principal subset every authorization decision consumes. */
export interface AuthorizationPrincipal {
  owner?: string;
  org?: string;
  admin?: boolean;
}

/**
 * A principal only authorizes when it is complete: owner and org are
 * strings and the org is a canonical key — an admin flag is the one
 * exception, because admins authorize without an org scope.
 */
export function completeBridgePrincipal(value: AuthorizationPrincipal): value is {
  owner: string;
  org: string;
  admin: boolean;
} {
  return (
    typeof value.owner === "string" &&
    typeof value.org === "string" &&
    typeof value.admin === "boolean" &&
    (value.admin || isCurrentOrgKey(value.org))
  );
}

export function normalizeShareUser(value: string | undefined): string {
  return (value ?? "").trim().toLowerCase();
}

export function sanitizeShareRole(value: string | undefined): LeaseShareRole | undefined {
  return value === "manage" || value === "use" ? value : undefined;
}

export type NormalizedLeaseShare = {
  users: Record<string, LeaseShareRole>;
  org?: LeaseShareRole;
  updatedAt?: string;
  updatedBy?: string;
};

export function normalizedLeaseShare(share: LeaseShare | undefined): NormalizedLeaseShare {
  const users: Record<string, LeaseShareRole> = {};
  for (const [rawUser, rawRole] of Object.entries(share?.users ?? {})) {
    const user = normalizeShareUser(rawUser);
    const role = sanitizeShareRole(rawRole);
    if (user && role) {
      users[user] = role;
    }
  }
  const role = sanitizeShareRole(share?.org);
  const normalized: NormalizedLeaseShare = { users };
  if (role) {
    normalized.org = role;
  }
  if (share?.updatedAt) {
    normalized.updatedAt = share.updatedAt;
  }
  if (share?.updatedBy) {
    normalized.updatedBy = share.updatedBy;
  }
  return normalized;
}

/**
 * The access role a complete principal holds on a lease. Legacy org
 * values are lossy and cannot safely prove any non-admin relationship,
 * including an otherwise explicit user share carried by an ambiguous
 * record.
 */
export function leaseAccessRoleForPrincipal(
  lease: LeaseRecord,
  principal: { owner: string; org: string; admin: boolean },
): "owner" | LeaseShareRole | undefined {
  if (principal.admin) {
    return "owner";
  }
  if (!isCurrentOrgKey(lease.org) || !isCurrentOrgKey(principal.org)) {
    return undefined;
  }
  const sameOrg = sameOrgIdentityKey(lease.org, principal.org);
  if (lease.owner === principal.owner && sameOrg) return "owner";
  const share = normalizedLeaseShare(lease.share);
  const userRole = share.users[normalizeShareUser(principal.owner)];
  const orgRole = sameOrg && lease.org !== MISSING_ORG_KEY ? share.org : undefined;
  if (userRole === "manage" || orgRole === "manage") {
    return "manage";
  }
  if (userRole === "use" || orgRole === "use") {
    return "use";
  }
  return undefined;
}

export function leaseManagerAuthorized(
  lease: LeaseRecord,
  principal: AuthorizationPrincipal,
): boolean {
  if (!completeBridgePrincipal(principal)) {
    return false;
  }
  const role = leaseAccessRoleForPrincipal(lease, principal);
  return role === "owner" || role === "manage";
}

export function leaseViewerAuthorized(
  lease: LeaseRecord,
  principal: AuthorizationPrincipal,
): boolean {
  if (!completeBridgePrincipal(principal)) {
    return false;
  }
  return leaseAccessRoleForPrincipal(lease, principal) !== undefined;
}

/** May this actor write the run? */
export function runWritableByPrincipal(run: RunRecord, principal: ActorContext): boolean {
  return principal.admin || (run.owner === principal.owner && run.org === principal.org);
}

/** May this actor read the run? */
export function runReadableByPrincipal(
  run: RunRecord,
  principal: ActorContext,
  lease?: LeaseRecord,
): boolean {
  if (runWritableByPrincipal(run, principal)) {
    return true;
  }
  return (
    run.leaseOwners?.some(
      (attribution) => attribution.owner === principal.owner && attribution.org === principal.org,
    ) ||
    (!run.leaseOwners?.length && lease?.owner === principal.owner && lease.org === principal.org)
  );
}

/**
 * May this bridge principal read the run? Unlike the request path, the
 * comparison is org-identity-aware: only canonical org keys authorize,
 * so an ambiguous legacy record can never widen access.
 */
export function runReadableToPrincipal(
  run: RunRecord,
  principal: AuthorizationPrincipal,
  lease?: LeaseRecord,
): boolean {
  if (principal.admin) {
    return true;
  }
  const owner = principal.owner;
  const org = principal.org;
  if (typeof owner !== "string" || !isCurrentOrgKey(org)) {
    return false;
  }
  return Boolean(
    (run.owner === owner && sameOrgIdentityKey(run.org, org)) ||
    run.leaseOwners?.some(
      (attribution) => attribution.owner === owner && sameOrgIdentityKey(attribution.org, org),
    ) ||
    (!run.leaseOwners?.length && lease?.owner === owner && sameOrgIdentityKey(lease.org, org)),
  );
}
