/**
 * Fleet vocabulary shared by the coordinator and the provider adapters:
 * error types, provider-access helpers, and diagnostic redaction. Extracted
 * from fleet.ts so both sides can import it without a module cycle.
 */
import { leaseConfig, validCIDRs } from "./config";
import type { ProviderAccessContext } from "./fleet-providers";
import { errorMessage } from "./http";
import { isRegisteredLease, leaseIsLive } from "./lease-lifecycle";
import type { Env, LeaseRecord, Provider } from "./types";
import { coordinatorProviderRegistry } from "./types";

export function coordinatorErrorMessage(env: Env, error: unknown): string {
  return errorMessage(error, coordinatorDiagnosticSecrets(env));
}

export function coordinatorDiagnosticSecrets(env: Env): Array<string | undefined> {
  return [
    ...coordinatorProviderRegistry.flatMap((provider) =>
      provider.requiredSecrets.map((name) => env[name]),
    ),
    env.AWS_SESSION_TOKEN,
    env.CRABBOX_RUNTIME_ADAPTER_TOKEN,
    env.CRABBOX_SHARED_TOKEN,
    env.CRABBOX_ADMIN_TOKEN,
    env.CRABBOX_SESSION_SECRET,
    env.CRABBOX_GITHUB_CLIENT_SECRET,
    env.CRABBOX_WORKSPACE_SSH_PRIVATE_KEY,
    env.CRABBOX_TRUSTED_PROXY_SECRET,
    env.CRABBOX_TAILSCALE_CLIENT_SECRET,
    env.CRABBOX_ARTIFACTS_ACCESS_KEY_ID,
    env.CRABBOX_ARTIFACTS_SECRET_ACCESS_KEY,
    env.CRABBOX_ARTIFACTS_SESSION_TOKEN,
  ];
}

export interface WorkspaceRecord {
  id: string;
  leaseID: string;
  owner: string;
  org: string;
  profile: string;
  repo: string;
  branch: string;
  command: string;
  provider: Provider;
  class: string;
  desktop: boolean;
  desktopCapabilityVersion?: 1;
  ttlSeconds: number;
  idleTimeoutSeconds: number;
  createdAt: string;
  updatedAt: string;
  prewarm?: boolean;
  sshHostKeySha256?: string;
  provisionClaim?: string;
  provisionClaimExpiresAt?: string;
  reconcileAfter?: string;
  recoveryMisses?: number;
  releaseRequestedAt?: string;
  error?: string;
}

export class ProviderCleanupManualResolutionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProviderCleanupManualResolutionError";
  }
}

export const createAttemptCanceledMessage = "create attempt was canceled before completion";

export class CreateAttemptCanceledError extends Error {
  constructor() {
    super(createAttemptCanceledMessage);
  }
}

export interface ProviderReadinessCheck {
  status: string;
  check: string;
  message?: string;
  details?: Record<string, string>;
}

export class ImageCapabilityMismatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ImageCapabilityMismatchError";
  }
}

export function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

export function azureProviderScope(
  value: string | undefined,
): { subscription: string; resourceGroup: string } | undefined {
  const match = /^\/subscriptions\/([^/]+)\/resourceGroups\/([^/]+)$/i.exec(value?.trim() ?? "");
  if (!match?.[1] || !match[2]) return undefined;
  return { subscription: match[1], resourceGroup: match[2] };
}

export function providerImageResourceName(
  provider: Provider,
  name: string,
  leaseID: string,
): string {
  if (provider === "aws") {
    return name;
  }
  const allowed = provider === "gcp" ? /[^a-z0-9-]/g : /[^a-z0-9_.-]/g;
  const normalized = name.trim().toLowerCase().replaceAll(allowed, "-");
  const trimmed =
    provider === "gcp"
      ? normalized
          .replaceAll(/^[^a-z]+/g, "")
          .replaceAll(/-+/g, "-")
          .replaceAll(/-+$/g, "")
      : normalized
          .replaceAll(/^[^a-z]+/g, "")
          .replaceAll(/-+/g, "-")
          .replaceAll(/[-.]+$/g, "");
  const fallback = leaseID.toLowerCase().replaceAll(/[^a-z0-9-]/g, "-");
  const maxLength = provider === "gcp" ? 63 : 80;
  const truncated = (trimmed || `checkpoint-${fallback}`).slice(0, maxLength);
  return provider === "gcp"
    ? truncated.replaceAll(/-+$/g, "")
    : truncated.replaceAll(/[-.]+$/g, "");
}

export function requestSourceCIDRs(request: Request): string[] {
  const sourceIP = request.headers.get("cf-connecting-ip") ?? "";
  if (!sourceIP) {
    return [];
  }
  const cidr = sourceIP.includes(":") ? `${sourceIP}/128` : `${sourceIP}/32`;
  return validCIDRs([cidr]);
}

export function replaceProviderAccessState(
  leases: LeaseRecord[],
  lease: LeaseRecord,
): LeaseRecord[] {
  let replaced = false;
  const next = leases.map((candidate) => {
    if (candidate.id !== lease.id) {
      return candidate;
    }
    replaced = true;
    return lease;
  });
  if (!replaced) {
    next.push(lease);
  }
  return next;
}

export function envFlagDisabled(value: string | undefined): boolean {
  return ["0", "false", "no", "off"].includes((value || "").trim().toLowerCase());
}

export function uniqueNonEmpty(values: Array<string | undefined>): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    const normalized = (value || "").trim();
    if (normalized && !seen.has(normalized)) {
      seen.add(normalized);
      out.push(normalized);
    }
  }
  return out;
}

export function awsLeaseSSHSourceCIDRs(
  config: Pick<ReturnType<typeof leaseConfig>, "awsSSHCIDRs" | "awsSSHCIDRsPinned">,
  context: ProviderAccessContext,
): string[] {
  const configuredCIDRs = uniqueNonEmpty(validCIDRs(config.awsSSHCIDRs));
  if (config.awsSSHCIDRsPinned) {
    return configuredCIDRs;
  }
  return uniqueNonEmpty([...configuredCIDRs, ...validCIDRs(context.requestSourceCIDRs)]);
}

export function awsGlobalSSHSourceCIDRs(env: Env): string[] {
  return uniqueNonEmpty(validCIDRs((env.CRABBOX_AWS_SSH_CIDRS ?? "").split(",")));
}

// A refresh owns only dynamic CIDRs from address families represented by the incoming request.

export function withLeaseSSHSourceCIDRs(
  lease: LeaseRecord,
  cidrs: string[],
  complete: boolean,
): LeaseRecord {
  if (cidrs.length === 0 && !complete) {
    return lease;
  }
  return {
    ...lease,
    network: {
      ...lease.network,
      sshSourceCIDRs: uniqueNonEmpty(cidrs),
      sshSourceCIDRsComplete: complete,
    },
  };
}

export function leaseOwnsAWSSSHAccess(lease: LeaseRecord): boolean {
  return (
    lease.provider === "aws" &&
    !isRegisteredLease(lease) &&
    !lease.network?.awsPrivate &&
    (leaseIsLive(lease) || lease.releaseDeletesServer === false)
  );
}
