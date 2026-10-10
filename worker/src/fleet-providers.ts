import { sha256Hex } from "./auth";
import {
  EC2SpotClient,
  awsConfiguredSecurityGroupID,
  awsManagedSecurityGroupName,
  awsLaunchCandidates,
  awsPrivateWorkspaceConfig,
  awsProvisioningErrorCategory,
  awsRegionCandidates,
  awsLeaseImageIdentity,
  isAWSInstanceNotFoundError,
  isRetryableAWSProvisioningError,
  isAWSSecurityGroupRuleLimitError,
} from "./aws";
import type { AWSPrivateWorkspaceConfig } from "./aws";
import { sanitizeAWSRegion } from "./aws-region";
import { AzureClient, azureSnapshotNotFound } from "./azure";
import type { AzureDeferredCleanupRequest } from "./azure";
/**
 * Cloud provider adapters: the provider-facing boundary between the fleet
 * coordinator and the per-provider client modules (aws.ts, azure.ts, gcp.ts,
 * hetzner.ts, daytona.ts). Extracted from fleet.ts.
 */
import { AzureResumableProvisioning } from "./azure-provisioning";
import { CheckpointError, pinCheckpointPromotion, unpinCheckpointPromotion } from "./checkpoints";
import {
  assertAzureWindowsARM64Image,
  awsPromotedAMIConfigKey,
  azureLocationFor,
  leaseConfig,
  normalizeArchitecture,
  validCIDRs,
  workspaceProviderKeyPrefix,
} from "./config";
import type { LeaseConfig } from "./config";
import type { CoordinatorStorage, CoordinatorStorageView } from "./coordinator-runtime";
import { DaytonaClient, daytonaAccessNeedsRefresh, isDaytonaNotFound } from "./daytona";
import type { DaytonaSSHEndpoint } from "./daytona";
import type { ProviderReadinessCheck, WorkspaceRecord } from "./fleet-shared";
import {
  CreateAttemptCanceledError,
  ImageCapabilityMismatchError,
  ProviderCleanupManualResolutionError,
  awsGlobalSSHSourceCIDRs,
  awsLeaseSSHSourceCIDRs,
  azureProviderScope,
  coordinatorErrorMessage,
  envFlagDisabled,
  leaseOwnsAWSSSHAccess,
  providerImageResourceName,
  replaceProviderAccessState,
  shellQuote,
  uniqueNonEmpty,
  withLeaseSSHSourceCIDRs,
} from "./fleet-shared";
import {
  GCPClient,
  gcpMachineImageNotFound,
  gcpProviderLabelValue,
  gcpReadyPoolImageScope,
  gcpReadyPoolImageScopeSupported,
  gcpSnapshotNotFound,
} from "./gcp";
import { HetznerClient } from "./hetzner";
import { confirmHetznerServerCleanup, hetznerKeyOnlyCleanupID } from "./hetzner-cleanup";
import { json, readJson } from "./http";
import {
  catalogOnlyImageRequested,
  hasImageRequirements,
  imageSatisfiesRequirements,
  InvalidImageCapabilitiesError,
  normalizeImageCapabilities,
  normalizeImageVariantSelectors,
} from "./image-capabilities";
import { defaultOSImage, normalizeOSImage } from "./os-image";
import { providerKeyForLease } from "./provider-key";
import { providerLabelsOwnedByLease, providerMachineOwnedByLease } from "./provider-labels";
import type { ProviderResumableProvisioning } from "./provider-provisioning";
import {
  ProviderProvisioningCleanupError,
  ProviderResourceUnresolvedError,
  providerProvisioningCleanupClaim,
  validateProviderProvisioningCleanupClaim,
} from "./provider-provisioning";
import type { ProviderProvisioningCleanupClaim } from "./provider-provisioning";
import { ProvisioningAttemptHistory } from "./provisioning-attempts";
import { validLeaseID } from "./slug";
import type {
  CapacityHint,
  CoordinatorCheckpointRecord,
  CoordinatorCheckpointScope,
  Env,
  LeaseRecord,
  ProviderCleanupEvidence,
  LeaseRequest,
  ImageCapabilities,
  ImageVariantSelectors,
  Provider,
  ProviderFastSnapshotRestore,
  ProviderCheckpointOwnership,
  LeaseImageIdentity,
  LeaseProvisioningTiming,
  ProviderImage,
  ProviderMachine,
  ProvisioningAttempt,
  ReadyPoolEntry,
  ReadyPoolImageIdentity,
  PromotedImageRecord,
  TargetOS,
} from "./types";

export const privateAWSWorkspaceWorkRoot = "/work/crabbox";

export function createdAWSImageKey(imageID: string): string {
  return `image:aws:created:${imageID}`;
}

export const awsImageDeletionClaimVersion = 1;

export interface AWSImageDeletionClaim {
  version: typeof awsImageDeletionClaimVersion;
  imageID: string;
  metadata: ProviderImage;
  snapshotIDs: string[];
  phase: "claimed" | "provider-deleted";
  claimedAt: string;
  providerDeletedAt?: string;
}

export function awsImageDeletionClaimKey(imageID: string): string {
  return `image:aws:deletion:${encodeURIComponent(imageID)}`;
}

export function validAWSImageDeletionClaim(
  value: unknown,
  imageID: string,
): value is AWSImageDeletionClaim {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const claim = value as Partial<AWSImageDeletionClaim>;
  return (
    claim.version === awsImageDeletionClaimVersion &&
    claim.imageID === imageID &&
    claim.metadata?.id === imageID &&
    claim.metadata.provider === "aws" &&
    Array.isArray(claim.snapshotIDs) &&
    claim.snapshotIDs.every((snapshotID) => typeof snapshotID === "string" && snapshotID !== "") &&
    (claim.phase === "claimed" || claim.phase === "provider-deleted") &&
    typeof claim.claimedAt === "string"
  );
}

export function awsImageDeletionSnapshotIDs(image: ProviderImage): string[] {
  return [
    ...new Set((image.snapshots ?? []).map((snapshotID) => snapshotID.trim()).filter(Boolean)),
  ];
}

export function awsImageDeletionMetadata(
  imageID: string,
  described: ProviderImage,
  stored?: Partial<ProviderImage>,
): ProviderImage {
  const merged = mergeAWSImageMetadata(described, stored);
  const snapshots = awsImageDeletionSnapshotIDs(described);
  const metadata: ProviderImage = {
    id: imageID,
    name: merged.name,
    state: merged.state,
    provider: "aws",
    kind: merged.kind ?? (imageID.startsWith("snap-") ? "aws-ebs-snapshot" : "aws-ami"),
    resourceID: imageID,
    snapshots,
  };
  const region = sanitizeAWSRegion(merged.region ?? "");
  if (region) metadata.region = region;
  if (merged.target) metadata.target = merged.target;
  if (merged.os) metadata.os = merged.os;
  if (merged.windowsMode) metadata.windowsMode = merged.windowsMode;
  if (merged.serverType) metadata.serverType = merged.serverType;
  if (merged.architecture) metadata.architecture = merged.architecture;
  if (merged.capabilities) metadata.capabilities = structuredClone(merged.capabilities);
  return metadata;
}

export function createdProviderImageKey(provider: Provider, imageID: string): string {
  return `image:${provider}:created:${encodeURIComponent(imageID)}`;
}

export async function checkpointCreatedImageMetadata(
  storage: ProviderStateStorage | undefined,
  checkpoint: CoordinatorCheckpointRecord,
): Promise<ProviderImage> {
  const image = checkpoint.image;
  const metadata = image
    ? await storage?.get<ProviderImage>(createdProviderImageKey(checkpoint.provider, image.id))
    : undefined;
  if (
    !image ||
    !metadata ||
    metadata.provider !== checkpoint.provider ||
    metadata.id !== image.id ||
    metadata.kind !== image.kind ||
    metadata.immutableID !== image.immutableID ||
    metadata.region !== checkpoint.scope.region ||
    !/^[a-f0-9]{64}$/.test(metadata.checkpointOwnershipHash ?? "") ||
    metadata.checkpointSourceLeaseID !== checkpoint.leaseID
  ) {
    throw new CheckpointError(
      "checkpoint_source_mismatch",
      "checkpoint trusted provider creation identity or ownership evidence is missing or changed",
    );
  }
  return metadata;
}

export function promotedAzureImageKey(
  image: Pick<ProviderImage, "target" | "architecture" | "region" | "serverType"> & {
    os?: string;
  },
): string {
  const target = image.target ?? "linux";
  const architecture = image.architecture ?? "amd64";
  const os = target === "linux" ? (image.os ?? defaultOSImage) : "";
  return [
    "image",
    "azure",
    "promoted",
    target,
    sanitizePromotedAWSImageKeyPart(architecture),
    sanitizePromotedAWSImageKeyPart(image.serverType ?? ""),
    sanitizePromotedAWSImageKeyPart(os),
    sanitizePromotedAWSImageKeyPart((image.region ?? "").toLowerCase()),
  ].join(":");
}

export async function storeCreatedProviderImage(
  storage: ProviderStateStorage,
  provider: Provider,
  image: ProviderImage,
): Promise<void> {
  await storage.put(createdProviderImageKey(provider, image.id), image);
  if (image.resourceID && image.resourceID !== image.id) {
    await storage.put(createdProviderImageKey(provider, image.resourceID), image);
  }
}

export function legacyPromotedAWSImageKey(): string {
  return promotedAWSImagePrefix();
}

export function legacyPromotedAWSImageCompatible(
  image: Pick<ProviderImage, "architecture">,
): boolean {
  return !image.architecture || image.architecture === "x86_64";
}

export function promotedAWSLinuxOSImageKey(
  image: Pick<ProviderImage, "architecture" | "os">,
): string {
  const architecture = image.architecture ?? awsImageArchitectureForTarget("linux", "");
  return `image:aws:promoted:linux:${architecture}:${sanitizePromotedAWSImageKeyPart(image.os ?? "")}`;
}

export function promotedAWSImagePrefix(): string {
  return "image:aws:promoted";
}

export function promotedAWSImageCatalogPrefix(
  image: Pick<ProviderImage, "target" | "architecture" | "region" | "serverType"> & {
    os?: string;
  },
): string {
  const scope = promotedAWSImageKey(image).slice(`${promotedAWSImagePrefix()}:`.length);
  return `image:aws:catalog:${scope}:`;
}

export function promotedAWSImageCatalogKey(image: PromotedImageRecord): string {
  return `${promotedAWSImageCatalogPrefix(image)}${encodeURIComponent(image.id)}`;
}

export function promotedAWSImageVariantPrefix(
  image: Pick<ProviderImage, "target" | "architecture" | "region" | "serverType"> & {
    os?: string;
  },
): string {
  const scope = promotedAWSImageKey(image).slice(`${promotedAWSImagePrefix()}:`.length);
  return `image:aws:variant:${scope}:`;
}

export function promotedAWSImageVariantKey(image: PromotedImageRecord): string {
  return `${promotedAWSImageVariantPrefix(image)}${encodeURIComponent(image.id)}`;
}

export function promotionVersionMap(
  values: string[],
  label: string,
): Record<string, string> | undefined {
  const versions = Object.create(null) as Record<string, string>;
  for (const value of values) {
    const separator = value.indexOf("=");
    const name = (separator > 0 ? value.slice(0, separator) : value).trim().toLowerCase();
    const version = (separator > 0 ? value.slice(separator + 1) : "").trim();
    if (Object.hasOwn(versions, name) && versions[name] !== version) {
      throw new InvalidImageCapabilitiesError(`${label} declares conflicting versions for ${name}`);
    }
    versions[name] = version;
  }
  return values.length > 0 ? versions : undefined;
}

export function mergePromotionVersions(
  inventory: Record<string, string> | undefined,
  selectors: Record<string, string> | undefined,
  inventoryLabel: string,
  selectorLabel: string,
): Record<string, string> | undefined {
  for (const [name, version] of Object.entries(selectors ?? {})) {
    const inventoryVersion = inventory?.[name];
    if (inventoryVersion !== undefined && inventoryVersion !== version) {
      throw new InvalidImageCapabilitiesError(
        `${inventoryLabel} and ${selectorLabel} declare conflicting versions for ${name}`,
      );
    }
  }
  if (!inventory && !selectors) return undefined;
  return { ...inventory, ...selectors };
}

export function promotedAWSImageKey(
  image: Pick<ProviderImage, "target" | "architecture" | "region" | "serverType"> & {
    os?: string;
  },
): string {
  const target = image.target ?? "linux";
  const architecture = image.architecture ?? awsImageArchitectureForTarget(target, "");
  const region = sanitizeAWSRegion(image.region ?? "");
  if (target === "macos") {
    return `image:aws:promoted:${target}:${architecture}:${sanitizePromotedAWSImageKeyPart(image.serverType ?? "")}:${region}`;
  }
  if (target === "linux" && image.os) {
    return `image:aws:promoted:${target}:${architecture}:${sanitizePromotedAWSImageKeyPart(image.os)}:${region}`;
  }
  return `image:aws:promoted:${target}:${architecture}:${region}`;
}

export function legacyScopedPromotedAWSImageKey(
  image: Pick<ProviderImage, "target" | "architecture" | "region">,
): string {
  const target = image.target ?? "linux";
  const architecture = image.architecture ?? awsImageArchitectureForTarget(target, "");
  const region = sanitizeAWSRegion(image.region ?? "");
  return `image:aws:promoted:${target}:${architecture}:${region}`;
}

export function sanitizePromotedAWSImageKeyPart(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replaceAll(/[^a-z0-9._-]/g, "");
}

export function enrichAWSImage(image: ProviderImage, lease: LeaseRecord): ProviderImage {
  const metadata: Partial<ProviderImage> = {};
  if (lease.target) {
    metadata.target = lease.target;
  }
  if (lease.windowsMode) {
    metadata.windowsMode = lease.windowsMode;
  }
  if (lease.os) {
    metadata.os = lease.os;
  }
  if (lease.serverType) {
    metadata.serverType = lease.serverType;
  }
  const region = image.region ?? lease.region;
  if (region !== undefined && region !== "") {
    metadata.region = region;
  }
  return mergeAWSImageMetadata(image, metadata);
}

export function mergeAWSImageMetadata(
  image: ProviderImage,
  metadata?: Partial<ProviderImage>,
): ProviderImage {
  const target = normalizeAWSImageTarget(metadata?.target ?? image.target ?? "linux") ?? "linux";
  const serverType = metadata?.serverType ?? image.serverType ?? "";
  const result: ProviderImage = {
    ...metadata,
    ...image,
    target,
    architecture:
      metadata?.architecture ??
      image.architecture ??
      awsImageArchitectureForTarget(target, serverType),
  };
  const windowsMode = metadata?.windowsMode ?? image.windowsMode;
  if (windowsMode !== undefined) {
    result.windowsMode = windowsMode;
  }
  if (serverType) {
    result.serverType = serverType;
  }
  const imageRegion = image.region;
  const metadataRegion = metadata?.region;
  if (imageRegion !== undefined && imageRegion !== "") {
    result.region = imageRegion;
  } else if (metadataRegion !== undefined && metadataRegion !== "") {
    result.region = metadataRegion;
  }
  return result;
}

export function awsConfiguredImageIdentity(
  config: LeaseConfig,
  env: Pick<Env, "CRABBOX_AWS_AMI">,
): LeaseImageIdentity | undefined {
  if (config.awsSnapshot) {
    return {
      id: config.awsSnapshot,
      source: "snapshot",
      provider: "aws",
      kind: "aws-ami",
      region: config.awsRegion,
    };
  }
  const explicitImageID = config.awsAMI || env.CRABBOX_AWS_AMI?.trim() || "";
  if (explicitImageID && !config.awsUseStockImage) {
    return {
      id: explicitImageID,
      source: "explicit",
      provider: "aws",
      kind: "aws-ami",
      region: config.awsRegion,
    };
  }
  return undefined;
}

export function azureLeaseImageIdentity(
  config: LeaseConfig,
  imageID: string,
  region: string,
): LeaseImageIdentity | undefined {
  if (config.selectedImage) {
    return { ...config.selectedImage, region };
  }
  if (config.azureSnapshot) {
    return {
      id: imageID,
      source: "snapshot",
      provider: "azure",
      kind: "azure-os-disk-snapshot",
      region,
    };
  }
  return undefined;
}

export function normalizeAzureImageTarget(value: string | undefined): TargetOS | undefined {
  switch ((value ?? "").trim().toLowerCase()) {
    case "":
    case "linux":
    case "ubuntu":
      return "linux";
    case "windows":
    case "win":
      return "windows";
    default:
      return undefined;
  }
}

export function azureImageScopeMismatch(
  field: string,
  requested: string,
  recorded: string,
): Response {
  return json(
    {
      error: "image_scope_mismatch",
      message: `Azure snapshot ${field} ${recorded} does not match requested ${requested}`,
    },
    { status: 409 },
  );
}

export function normalizeAWSImageTarget(value: string | undefined): TargetOS | undefined {
  switch ((value ?? "").trim().toLowerCase()) {
    case "":
    case "linux":
    case "ubuntu":
      return "linux";
    case "mac":
    case "macos":
    case "darwin":
    case "osx":
      return "macos";
    case "win":
    case "windows":
      return "windows";
    default:
      return undefined;
  }
}

export function awsImageArchitectureForTarget(target: TargetOS, serverType: string): string {
  if (target === "macos") {
    return serverType.startsWith("mac1.") ? "x86_64_mac" : "arm64_mac";
  }
  return "x86_64";
}

export function awsImageArchitectureForLease(
  target: TargetOS,
  serverType: string,
  architecture?: string,
): string {
  if (target === "linux" && architecture === "arm64") {
    return "arm64";
  }
  return awsImageArchitectureForTarget(target, serverType);
}

export function boolFromUnknown(value: unknown): boolean {
  if (value === true) return true;
  if (value === false || value === undefined || value === null) return false;
  const normalized = String(value).trim().toLowerCase();
  return ["1", "true", "yes", "on"].includes(normalized);
}

export function fastSnapshotRestoreAZs(
  inputZones: string[] | undefined,
  url: URL,
  region: string,
  env: Pick<Env, "CRABBOX_AWS_FAST_SNAPSHOT_RESTORE_AZS" | "CRABBOX_CAPACITY_AVAILABILITY_ZONES">,
): string[] {
  const zones = [
    ...(inputZones ?? []),
    ...url.searchParams.getAll("fsrAz"),
    ...splitCommaList(url.searchParams.get("fsrAzs") ?? ""),
    ...splitCommaList(env.CRABBOX_AWS_FAST_SNAPSHOT_RESTORE_AZS ?? ""),
    ...splitCommaList(env.CRABBOX_CAPACITY_AVAILABILITY_ZONES ?? ""),
  ];
  return [...new Set(zones.map((zone) => zone.trim()).filter((zone) => validAWSAZ(zone, region)))];
}

export function fastSnapshotRestoreStatusAZs(url: URL, region: string): string[] {
  const zones = [
    ...url.searchParams.getAll("fsrAz"),
    ...url.searchParams.getAll("az"),
    ...splitCommaList(url.searchParams.get("fsrAzs") ?? ""),
    ...splitCommaList(url.searchParams.get("azs") ?? ""),
  ];
  return [...new Set(zones.map((zone) => zone.trim()).filter((zone) => validAWSAZ(zone, region)))];
}

export function splitCommaList(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export function validAWSAZ(zone: string, region: string): boolean {
  if (!/^[a-z]{2}-[a-z-]+-[0-9][a-z]$/.test(zone)) {
    return false;
  }
  return region === "" || zone.startsWith(region);
}

export function privateAWSWorkspaceLeaseFields(
  workspace: WorkspaceRecord,
  policy: AWSPrivateWorkspaceConfig,
): Partial<LeaseRequest> {
  return {
    serverType: policy.instanceTypes[0]!,
    serverTypeExplicit: true,
    awsRegion: policy.region,
    awsSGID: policy.securityGroupID,
    awsSubnetID: policy.subnetID,
    awsProfile: policy.instanceProfile,
    awsRootGB: policy.rootGB,
    awsInstanceTypes: policy.instanceTypes,
    awsPrivate: true,
    awsRequireSSM: true,
    awsSSMBootstrapCommand: workspaceSSMBootstrapCommand(workspace),
    awsSSMLogGroup: policy.ssmLogGroup,
    capacity: {
      market: policy.market,
      fallback: "none",
      regions: [policy.region],
      hints: false,
    },
    sshUser: "crabbox",
    sshFallbackPorts: [],
    workRoot: privateAWSWorkspaceWorkRoot,
  };
}

export function privateAWSWorkspaceCapability(
  policy: AWSPrivateWorkspaceConfig | undefined,
  env: Env,
): ProviderWorkspaceCapability {
  const requiredPolicy = (): AWSPrivateWorkspaceConfig => {
    if (!policy) {
      throw new Error("private AWS workspace policy is unavailable");
    }
    return policy;
  };
  return {
    requiresCommand: true,
    supportsDesktop: false,
    supportsPrewarm: false,
    leaseRequestFields: (workspace) => privateAWSWorkspaceLeaseFields(workspace, requiredPolicy()),
    recoveryLeaseRequestFields: (workspace, server) => {
      const activePolicy = requiredPolicy();
      return {
        ...privateAWSWorkspaceLeaseFields(workspace, activePolicy),
        serverType: server.serverType,
        serverTypeExplicit: true,
        awsUseStockImage: true,
      };
    },
    recoveredReady: (server) => server.awsSSMCommandStatus === "Success",
    recoveredHost: () => "",
    applyRecoveredEvidence: (lease, config, server) => {
      if (server.awsSSMCommandID) {
        lease.awsSSMCommandID = server.awsSSMCommandID;
      }
      if (server.awsSSMCommandStatus) {
        lease.awsSSMCommandStatus = server.awsSSMCommandStatus;
      }
      lease.awsSSMLogGroup = config.awsSSMLogGroup;
    },
    bootstrapEvidence: (lease, status) => ({
      transport: "ssm",
      status:
        lease?.awsSSMCommandStatus ??
        (status === "ready" ? "Success" : status === "failed" ? "Failed" : "Pending"),
      ...(lease?.awsSSMCommandID ? { commandId: lease.awsSSMCommandID } : {}),
      ...(lease?.awsSSMLogGroup?.trim() || env.CRABBOX_WORKSPACE_AWS_SSM_LOG_GROUP?.trim()
        ? {
            logGroup:
              lease?.awsSSMLogGroup?.trim() || env.CRABBOX_WORKSPACE_AWS_SSM_LOG_GROUP?.trim(),
          }
        : {}),
    }),
    log: (event, fields) =>
      privateAWSWorkspaceLifecycleLog(event, {
        ...(event === "create_accepted"
          ? {
              region: requiredPolicy().region,
              instance_type: requiredPolicy().instanceTypes[0],
            }
          : {}),
        ...fields,
      }),
  };
}

export function workspaceSSMBootstrapCommand(workspace: WorkspaceRecord): string {
  const workspaceParent = `${privateAWSWorkspaceWorkRoot}/workspaces`;
  const workspaceRoot = `${workspaceParent}/${workspace.id}`;
  const serviceName = "crabbox-workspace.service";
  const startScript = "/usr/local/lib/crabbox/workspace-start";
  const successMarker = "/var/lib/crabbox/workspace-bootstrap-success";
  const branch = workspace.branch.trim() || "main";
  const command = workspace.command.trim();
  if (!command) {
    throw new Error("private AWS workspaces require an explicit command");
  }
  const setup = [
    "set -euo pipefail",
    "exec 9>/var/lock/crabbox-workspace-bootstrap.lock",
    "flock -x -w 600 9",
    `if test -f ${shellQuote(successMarker)} && systemctl is-active --quiet ${shellQuote(serviceName)}; then`,
    `  systemctl show --no-pager --property=ActiveState,SubState,Result,ExecMainStatus ${shellQuote(serviceName)}`,
    "  exit 0",
    "fi",
    `for workspace_ancestor in /work ${shellQuote(privateAWSWorkspaceWorkRoot)} ${shellQuote(workspaceParent)}; do`,
    '  test -d "$workspace_ancestor"',
    '  test ! -L "$workspace_ancestor"',
    '  test "$(stat -c %U:%G "$workspace_ancestor")" = root:root',
    "done",
    `test ! -L ${shellQuote(workspaceRoot)}`,
  ];
  if (workspace.repo) {
    const repoURL = `https://github.com/${workspace.repo}.git`;
    const cloneTemplate = `${workspaceRoot}.clone.XXXXXX`;
    setup.push(
      `if ! runuser -u crabbox -- git -C ${shellQuote(workspaceRoot)} rev-parse --verify 'HEAD^{commit}' >/dev/null 2>&1; then`,
      `  clone_root=$(mktemp -d ${shellQuote(cloneTemplate)})`,
      '  chown crabbox:crabbox "$clone_root"',
      `  if ! runuser -u crabbox -- git clone --quiet --depth=1 --branch ${shellQuote(branch)} ${shellQuote(repoURL)} "$clone_root" >/dev/null 2>&1; then`,
      '    rm -rf "$clone_root"',
      "    exit 1",
      "  fi",
      `  rm -rf ${shellQuote(workspaceRoot)}`,
      `  mv "$clone_root" ${shellQuote(workspaceRoot)}`,
      "fi",
    );
  } else {
    setup.push(`install -d -m 0755 -o crabbox -g crabbox ${shellQuote(workspaceRoot)}`);
  }
  const runner = [
    "#!/usr/bin/env bash",
    "set -euo pipefail",
    `cd ${shellQuote(workspaceRoot)}`,
    `exec /bin/bash -lc ${shellQuote(command)}`,
    "",
  ].join("\n");
  const unit = [
    "[Unit]",
    "Description=Crabbox private workspace command",
    "Wants=network-online.target",
    "After=network-online.target",
    "",
    "[Service]",
    "Type=simple",
    "User=crabbox",
    `WorkingDirectory=${workspaceRoot}`,
    `ExecStart=${startScript}`,
    "Restart=on-failure",
    "RestartSec=5",
    "StandardOutput=journal",
    "StandardError=journal",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    "",
  ].join("\n");
  setup.push(
    `install -d -m 0755 ${shellQuote(startScript.slice(0, startScript.lastIndexOf("/")))}`,
    `printf %s ${shellQuote(runner)} > ${shellQuote(startScript)}`,
    `chmod 0755 ${shellQuote(startScript)}`,
    `printf %s ${shellQuote(unit)} > ${shellQuote(`/etc/systemd/system/${serviceName}`)}`,
    "systemctl daemon-reload",
    `systemctl enable --now ${shellQuote(serviceName)}`,
    `if ! timeout 60 bash -c ${shellQuote(`until systemctl is-active --quiet ${serviceName}; do systemctl is-failed --quiet ${serviceName} && exit 1; sleep 1; done`)}; then`,
    `  systemctl show --no-pager --property=ActiveState,SubState,Result,ExecMainStatus ${shellQuote(serviceName)} || true`,
    "  exit 1",
    "fi",
    `systemctl show --no-pager --property=ActiveState,SubState,Result,ExecMainStatus ${shellQuote(serviceName)}`,
    `touch ${shellQuote(successMarker)}`,
  );
  return setup.join("\n");
}

export function privateAWSWorkspaceLifecycleLog(
  event: "create_accepted" | "ready" | "recovered_ready" | "delete_requested" | "terminated",
  fields: Record<string, string | undefined>,
): void {
  console.info(
    JSON.stringify({
      component: "crabbox_private_aws_workspace",
      event,
      ...Object.fromEntries(
        Object.entries(fields).filter(([, value]) => value !== undefined && value !== ""),
      ),
    }),
  );
}

export async function ownedProviderMachineForRelease(
  provider: Extract<Provider, "aws" | "azure" | "gcp">,
  lease: LeaseRecord,
  findServer: (id: string) => Promise<ProviderMachine | undefined>,
  options: {
    labelValue?: (value: string) => string;
  } = {},
): Promise<ProviderMachine | undefined> {
  const machine = await findServer(lease.cloudID);
  if (!machine) return undefined;
  if (!providerMachineOwnedByLease(machine, lease, provider, options.labelValue)) {
    throw new Error(
      `refusing to delete ${provider} resource ${lease.cloudID}: ownership does not match lease ${lease.id}`,
    );
  }
  return machine;
}

export function unsupportedProviderImageLifecycle(provider: Provider) {
  return () => Promise.reject(new Error(`${provider} images are not supported`));
}

export function noStoredImageMetadata(): Promise<ProviderImage | undefined> {
  return Promise.resolve(undefined);
}

export function passthroughProviderImage(image: ProviderImage): ProviderImage {
  return image;
}

export function allowProviderImageDelete(): Promise<undefined> {
  return Promise.resolve(undefined);
}

export function leaseUsesCanonicalProviderKey(
  lease: Pick<LeaseRecord, "id" | "providerKey" | "providerKeyCleanupOwned">,
): boolean {
  return (
    lease.providerKeyCleanupOwned === true &&
    validLeaseID(lease.id) &&
    lease.providerKey === providerKeyForLease(lease.id)
  );
}

export function capacityHints(
  env: Env,
  config: ReturnType<typeof leaseConfig>,
  lease: LeaseRecord,
  attempts: ProvisioningAttempt[],
): CapacityHint[] {
  if (!config.capacityHints || envFlagDisabled(env.CRABBOX_CAPACITY_HINTS)) {
    return [];
  }
  const hints: CapacityHint[] = [];
  const provider = lease.provider === "azure" ? "azure" : "aws";
  const providerName = provider === "azure" ? "Azure" : "AWS";
  const selectedRegion =
    lease.region || (provider === "azure" ? config.azureLocation : config.awsRegion);
  const selectedMarket = lease.market || config.capacityMarket;
  const attemptedRegions = uniqueNonEmpty(attempts.map((attempt) => attempt.region));
  const failedRegions = attemptedRegions.filter((region) => region !== selectedRegion);
  if (selectedRegion && failedRegions.length > 0) {
    hints.push({
      code: `${provider}_capacity_routed`,
      message: `${providerName} launch routed to ${selectedRegion} after failed attempts in ${failedRegions.join(", ")}`,
      action: `Keep multiple capacity regions configured and avoid pinning a single ${providerName} region during capacity pressure.`,
      region: selectedRegion,
      market: selectedMarket,
      class: config.class,
      serverType: lease.serverType,
      regionsTried: uniqueNonEmpty([...attemptedRegions, selectedRegion]),
    });
  }
  if (attempts.some((attempt) => attempt.category === "quota")) {
    hints.push({
      code: `${provider}_quota_pressure`,
      message: `${providerName} quota rejected at least one ${config.class} candidate before selecting ${lease.serverType}`,
      action:
        provider === "azure"
          ? "Use a smaller class or request more Azure vCPU quota for the affected regions."
          : "Use a smaller class or request more EC2 Standard Spot/On-Demand vCPU quota for the affected regions.",
      region: selectedRegion,
      market: selectedMarket,
      class: config.class,
      serverType: lease.serverType,
      regionsTried: uniqueNonEmpty([...attemptedRegions, selectedRegion]),
    });
  }
  if (
    selectedMarket === "on-demand" &&
    attempts.some((attempt) => (attempt.market || "spot") === "spot")
  ) {
    hints.push({
      code: `${provider}_on_demand_fallback`,
      message: `${providerName} launch used on-demand after spot capacity attempts for ${config.class}`,
      action:
        "Keep on-demand fallback for reliability, or switch back to spot when cost matters more than launch success.",
      region: selectedRegion,
      market: selectedMarket,
      class: config.class,
      serverType: lease.serverType,
      regionsTried: uniqueNonEmpty([...attemptedRegions, selectedRegion]),
    });
  }
  if (capacityLargeClasses(env).includes(config.class)) {
    hints.push({
      code: "capacity_large_class",
      message: `class=${config.class} is configured as a high-pressure capacity class`,
      action:
        "Use a smaller class unless the workload is explicitly CPU-bound or this large class was requested intentionally.",
      region: selectedRegion,
      market: selectedMarket,
      class: config.class,
      serverType: lease.serverType,
    });
  }
  return hints;
}

export function capacityLargeClasses(env: Env): string[] {
  return uniqueNonEmpty((env.CRABBOX_CAPACITY_LARGE_CLASSES || "beast").split(","));
}

// A refresh owns only dynamic CIDRs from address families represented by the incoming request.
export function refreshedAWSSSHSourceCIDRs(lease: LeaseRecord, incomingCIDRs: string[]): string[] {
  const pinnedCIDRs = uniqueNonEmpty(validCIDRs(lease.network?.sshPinnedSourceCIDRs ?? []));
  if (pinnedCIDRs.length > 0) {
    return pinnedCIDRs;
  }
  const incoming = uniqueNonEmpty(validCIDRs(incomingCIDRs));
  const refreshedFamilies = new Set(incoming.map((cidr) => (cidr.includes(":") ? "ipv6" : "ipv4")));
  const retainedDynamicCIDRs = uniqueNonEmpty(
    validCIDRs(lease.network?.sshSourceCIDRs ?? []),
  ).filter((cidr) => !refreshedFamilies.has(cidr.includes(":") ? "ipv6" : "ipv4"));
  return uniqueNonEmpty([...retainedDynamicCIDRs, ...incoming]);
}

export function awsCreateSSHSourceCIDRs(
  config: LeaseConfig,
  lease: LeaseRecord,
  context: ProviderAccessContext,
  env: Env,
  providerRegion: string,
): string[] {
  const targetKey = awsIngressAccessTargetKey(
    lease,
    lease.region || config.awsRegion,
    awsLeaseSSHPorts(lease),
    env,
  );
  const targetLeases = replaceProviderAccessState(context.activeLeases, lease).filter(
    (candidate) =>
      leaseOwnsAWSSSHAccess(candidate) &&
      awsIngressAccessTargetKey(
        candidate,
        candidate.region || providerRegion,
        awsLeaseSSHPorts(candidate),
        env,
      ) === targetKey,
  );
  return activeAWSSSHSourceCIDRs(targetLeases, awsGlobalSSHSourceCIDRs(env));
}

export function awsIngressAccessTargetKey(
  lease: LeaseRecord,
  region: string,
  ports: string[],
  env: Env,
): string {
  const workspaceManaged = lease.providerKey.startsWith(workspaceProviderKeyPrefix);
  const securityGroupID =
    lease.network?.awsSecurityGroupID ||
    (workspaceManaged ? "" : env.CRABBOX_AWS_SECURITY_GROUP_ID || "");
  const subnetID = lease.network?.awsSubnetID || env.CRABBOX_AWS_SUBNET_ID || "";
  const securityGroupName = lease.network?.awsSecurityGroupName;
  const group = securityGroupID
    ? `sg:${securityGroupID}`
    : securityGroupName
      ? `managed:${subnetID}:${securityGroupName}`
      : `auto:${subnetID}`;
  return [region, group, ...ports.toSorted()].join("\u0000");
}

export function awsIngressGroupMetadataUnknown(lease: LeaseRecord, env: Env): boolean {
  return (
    !lease.network?.awsSecurityGroupID &&
    !lease.network?.awsSecurityGroupName &&
    (lease.providerKey.startsWith(workspaceProviderKeyPrefix) || !env.CRABBOX_AWS_SECURITY_GROUP_ID)
  );
}

export function awsIngressPortScopeKey(region: string, port: string): string {
  return [region, port].join("\u0000");
}

export function awsLeaseSSHPorts(lease: LeaseRecord): string[] {
  return uniqueNonEmpty([lease.sshPort, ...(lease.sshFallbackPorts ?? [])]);
}

export function activeAWSSSHSourceCIDRs(leases: LeaseRecord[], cidrs: string[]): string[] {
  return uniqueNonEmpty([
    ...leases.flatMap((lease) =>
      leaseOwnsAWSSSHAccess(lease) ? (lease.network?.sshSourceCIDRs ?? []) : [],
    ),
    ...cidrs,
  ]);
}

export function hasUnknownActiveAWSSSHSource(leases: LeaseRecord[]): boolean {
  return leases.some(
    (lease) =>
      leaseOwnsAWSSSHAccess(lease) &&
      (lease.network?.sshSourceCIDRs?.length ?? 0) === 0 &&
      !lease.network?.sshSourceCIDRsComplete,
  );
}

export interface CloudProvider {
  resumableProvisioning?(): ProviderResumableProvisioning;
  readyPoolImageIdentity?(lease: LeaseRecord): ReadyPoolImageIdentity | undefined;
  observeReadyPoolImageIdentity?(lease: LeaseRecord): Promise<LeaseImageIdentity | undefined>;
  supportsReadyPoolImageIdentity?(identity: ReadyPoolImageIdentity): boolean;
  listCrabboxServers(): Promise<ProviderMachine[]>;
  listReconciliationResources?(): Promise<ProviderMachine[]>;
  workspaceCapability?(
    lease?: LeaseRecord,
    purpose?: "operate" | "observe",
  ): ProviderWorkspaceCapability | undefined;
  supportsSSHHostKeyInjection(config: ReturnType<typeof leaseConfig>): boolean;
  restrictedLeaseRequestFields?(input: LeaseRequest): string[];
  ownershipLabelValue?(value: string): string;
  recoveryIsAuthoritative?: true;
  recoverUnboundProvisioningResource?(lease: LeaseRecord): Promise<ProviderMachine | undefined>;
  observeLegacyCleanupIdentity?(
    lease: LeaseRecord,
    context?: ProviderReleaseContext,
  ): Promise<{ providerResourceID: string } | undefined>;
  recoverServer?(lease: LeaseRecord): Promise<ProviderMachine | undefined>;
  resumeRecoveredServer?(
    config: ReturnType<typeof leaseConfig>,
    lease: LeaseRecord,
    server: ProviderMachine,
  ): Promise<ProviderMachine>;
  findServerByLease?(leaseID: string): Promise<ProviderMachine | undefined>;
  getServer?(id: string): Promise<ProviderMachine>;
  prepareLeaseConfig?(
    config: ReturnType<typeof leaseConfig>,
  ): Promise<ReturnType<typeof leaseConfig>>;
  prepareLeaseCreate?(
    config: ReturnType<typeof leaseConfig>,
    lease: LeaseRecord,
    context: ProviderAccessContext,
  ): Promise<ProviderLeaseCreatePreparation>;
  refreshLeaseAccess?(
    lease: LeaseRecord,
    context: ProviderAccessContext,
  ): Promise<LeaseRecord | void>;
  refreshLeaseAccessForResolution?(lease: LeaseRecord): Promise<LeaseRecord | void>;
  reconcileLeaseAccess?(lease: LeaseRecord, context: ProviderAccessContext): Promise<void>;
  createServerWithFallback(
    config: ReturnType<typeof leaseConfig>,
    leaseID: string,
    slug: string,
    owner: string,
    provisioning?: ProviderProvisioningContext,
  ): Promise<{
    server: ProviderMachine;
    serverType: string;
    market?: string;
    attempts?: ProvisioningAttempt[];
    image?: LeaseImageIdentity;
    provisioningTiming?: LeaseProvisioningTiming;
  }>;
  finalizeLeaseCreate?(
    config: ReturnType<typeof leaseConfig>,
    lease: LeaseRecord,
    server: ProviderMachine,
    attempts: ProvisioningAttempt[],
  ): Promise<ProviderLeaseCreateFinalization>;
  releaseLease(lease: LeaseRecord, context?: ProviderReleaseContext): Promise<void>;
  deleteServer(id: string): Promise<void>;
  deleteOwnedServer?(lease: LeaseRecord): Promise<void>;
  inspectCleanup?(lease: LeaseRecord): Promise<unknown>;
  supportsNativeImages(): boolean;
  nativeImagesUnsupportedMessage(): string;
  defaultImageStrategy(lease: LeaseRecord): "image" | "disk-snapshot";
  validateLeaseImageStrategy(
    lease: LeaseRecord,
    strategy: "image" | "disk-snapshot",
  ): string | undefined;
  createLeaseImage(
    lease: LeaseRecord,
    name: string,
    noReboot: boolean,
    strategy: "image" | "disk-snapshot",
  ): Promise<ProviderImage>;
  checkpointScope?(lease: LeaseRecord): Promise<CoordinatorCheckpointScope>;
  validateCheckpointLeaseScope?(checkpoint: CoordinatorCheckpointRecord): Promise<void>;
  validateCheckpointImage?(checkpoint: CoordinatorCheckpointRecord): Promise<void>;
  createCheckpointImage?(
    lease: LeaseRecord,
    name: string,
    noReboot: boolean,
    strategy: "image" | "disk-snapshot",
    ownership: ProviderCheckpointOwnership,
    scope: CoordinatorCheckpointScope,
  ): Promise<ProviderImage>;
  recoverCheckpointImage?(
    checkpoint: CoordinatorCheckpointRecord,
  ): Promise<ProviderImage | undefined>;
  deleteCheckpointImage?(checkpoint: CoordinatorCheckpointRecord): Promise<void>;
  getImage(imageID: string, kind?: string): Promise<ProviderImage>;
  deleteImage(imageID: string, kind?: string, metadata?: ProviderImage): Promise<void>;
  retireCatalogImage?(imageID: string, region?: string): Promise<number>;
  retirePromotedImage?(imageID: string, region?: string): Promise<number>;
  storedImageMetadata(imageID: string): Promise<ProviderImage | undefined>;
  storedImageDeleteMetadata?(imageID: string): Promise<ProviderImage | undefined>;
  decorateImage(image: ProviderImage, metadata?: Partial<ProviderImage>): ProviderImage;
  validateDeleteImage(
    imageID: string,
    metadata?: Partial<ProviderImage>,
  ): Promise<{ status: number; body: Record<string, unknown> } | undefined>;
  promoteImage?(
    imageID: string,
    metadata: ProviderImage | undefined,
    request: Request,
    url: URL,
    checkpoint?: Pick<CoordinatorCheckpointRecord, "id" | "generation">,
  ): Promise<Response | { image: ProviderImage }>;
  fastSnapshotRestoreForImage?(
    imageID: string,
    metadata: ProviderImage | undefined,
    url: URL,
  ): Promise<
    Response | { image: ProviderImage; fastSnapshotRestores: ProviderFastSnapshotRestore[] }
  >;
  enableFastSnapshotRestore?(
    snapshotIDs: string[],
    availabilityZones: string[],
  ): Promise<ProviderFastSnapshotRestore[]>;
  fastSnapshotRestoreStatus?(
    snapshotIDs: string[],
    availabilityZones?: string[],
  ): Promise<ProviderFastSnapshotRestore[]>;
  deleteSSHKey(name: string, leaseID: string): Promise<void>;
  hourlyPriceUSD(
    serverType: string,
    config: ReturnType<typeof leaseConfig>,
  ): Promise<number | undefined>;
}

type ProviderWorkspaceLifecycleEvent =
  | "create_accepted"
  | "ready"
  | "recovered_ready"
  | "delete_requested"
  | "terminated";

export interface ProviderWorkspaceCapability {
  requiresCommand: boolean;
  supportsDesktop: boolean;
  supportsPrewarm: boolean;
  leaseRequestFields(workspace: WorkspaceRecord): Partial<LeaseRequest>;
  recoveryLeaseRequestFields(
    workspace: WorkspaceRecord,
    server: ProviderMachine,
  ): Partial<LeaseRequest>;
  recoveredReady(server: ProviderMachine): boolean;
  recoveredHost(server: ProviderMachine): string;
  applyRecoveredEvidence(
    lease: LeaseRecord,
    config: ReturnType<typeof leaseConfig>,
    server: ProviderMachine,
  ): void;
  bootstrapEvidence(lease: LeaseRecord | undefined, status: string): Record<string, unknown>;
  log(event: ProviderWorkspaceLifecycleEvent, fields: Record<string, string | undefined>): void;
}

type ProviderStateStorage = CoordinatorStorage;
type ProviderStateStorageView = CoordinatorStorageView;

export interface ProviderAccessContext {
  requestSourceCIDRs: string[];
  activeLeases: LeaseRecord[];
}

export interface ProviderReleaseContext {
  resourceIdentity?: string;
  assertCleanupOwner?: () => Promise<void>;
  saveCleanupEvidence?: (evidence: ProviderCleanupEvidence) => Promise<void>;
}

export interface ProviderLeaseCreatePreparation {
  config: ReturnType<typeof leaseConfig>;
  lease: LeaseRecord;
  provisioning?: ProviderProvisioningContext;
}

interface ProviderLeaseCreateFinalization {
  config: ReturnType<typeof leaseConfig>;
  lease: LeaseRecord;
}

export interface ProviderProvisioningContext {
  providerScope?: string;
  sshIngressReconcile?: "authoritative" | "additive";
  allowEmptySSHIngress?: boolean;
  publishAccessBeforeProvisioning?: boolean;
  onTargetAttempt?: (target: ProviderProvisioningTarget) => Promise<void>;
  onResourceCreated?: (claim: ProviderProvisioningCleanupClaim) => Promise<boolean>;
  withLeaseAccess?: <T>(
    target: ProviderProvisioningTarget,
    operation: (lease: LeaseRecord, context: ProviderAccessContext) => Promise<T>,
  ) => Promise<T>;
}

export interface ProviderProvisioningTarget {
  region?: string;
}

export class HetznerProvider implements CloudProvider {
  private clientValue?: HetznerClient;

  constructor(private readonly env: Env) {}

  private get client(): HetznerClient {
    this.clientValue ??= new HetznerClient(this.env);
    return this.clientValue;
  }

  async listCrabboxServers(): Promise<ProviderMachine[]> {
    const servers = await this.client.listCrabboxServers();
    return servers.map((server) => this.client.toMachine(server));
  }

  supportsSSHHostKeyInjection(config: ReturnType<typeof leaseConfig>): boolean {
    return config.target === "linux";
  }

  async findServerByLease(leaseID: string): Promise<ProviderMachine | undefined> {
    const server = await this.client.findServerByLease(leaseID);
    return server ? this.client.toMachine(server) : undefined;
  }

  async createServerWithFallback(
    config: ReturnType<typeof leaseConfig>,
    leaseID: string,
    slug: string,
    owner: string,
  ): Promise<{
    server: ProviderMachine;
    serverType: string;
    market?: string;
    attempts?: ProvisioningAttempt[];
  }> {
    const { server, serverType, providerKey } = await this.client.createServerWithFallback(
      config,
      leaseID,
      slug,
      owner,
    );
    return { server: { ...this.client.toMachine(server), providerKey }, serverType };
  }

  async deleteServer(id: string): Promise<void> {
    await this.client.deleteServer(Number(id));
  }

  async finalizeLeaseCreate(
    config: ReturnType<typeof leaseConfig>,
    lease: LeaseRecord,
    server: ProviderMachine,
  ): Promise<ProviderLeaseCreateFinalization> {
    const providerKey = server.providerKey?.trim() || config.providerKey;
    const providerKeyCleanupOwned = providerKey === providerKeyForLease(lease.id);
    return {
      config: { ...config, providerKey },
      lease: { ...lease, providerKey, providerKeyCleanupOwned },
    };
  }

  async releaseLease(lease: LeaseRecord, context?: ProviderReleaseContext): Promise<void> {
    const keyOnlyID = hetznerKeyOnlyCleanupID(lease);
    if (keyOnlyID !== undefined) {
      if (!context?.assertCleanupOwner)
        throw new Error("Hetzner key cleanup requires a current cleanup owner");
      const deadline = Date.now() + 60_000;
      await this.client.deleteSSHKeyByID(keyOnlyID, deadline, context.assertCleanupOwner);
      return;
    }
    if (!context?.saveCleanupEvidence)
      throw new Error("Hetzner cleanup requires durable evidence storage");
    if (!context.assertCleanupOwner)
      throw new Error("Hetzner key cleanup requires a current cleanup owner");
    const deadline = Date.now() + 60_000;
    await confirmHetznerServerCleanup(this.client, lease, context.saveCleanupEvidence, deadline);
    if (lease.providerKeyCleanupPending) {
      const providerKeyID = Number(lease.providerKeyCleanupID);
      if (!Number.isSafeInteger(providerKeyID) || providerKeyID <= 0) {
        throw new Error("invalid pending Hetzner SSH key cleanup id");
      }
      await this.client.deleteSSHKeyByID(providerKeyID, deadline, context.assertCleanupOwner);
      return;
    }
    if (leaseUsesCanonicalProviderKey(lease)) {
      await this.deleteSSHKey(lease.providerKey, lease.id, deadline, context.assertCleanupOwner);
    }
  }

  supportsNativeImages(): boolean {
    return false;
  }

  nativeImagesUnsupportedMessage(): string {
    return "native images are supported for AWS, Azure, and GCP leases";
  }

  defaultImageStrategy(): "image" | "disk-snapshot" {
    return "disk-snapshot";
  }

  validateLeaseImageStrategy(): string | undefined {
    return undefined;
  }

  createLeaseImage = unsupportedProviderImageLifecycle("hetzner");
  getImage = unsupportedProviderImageLifecycle("hetzner");
  deleteImage = unsupportedProviderImageLifecycle("hetzner");
  storedImageMetadata = noStoredImageMetadata;
  decorateImage = passthroughProviderImage;
  validateDeleteImage = allowProviderImageDelete;

  async deleteSSHKey(
    name: string,
    leaseID: string,
    deadline?: number,
    beforeDelete?: () => Promise<void>,
  ): Promise<void> {
    await this.client.deleteSSHKey(name, leaseID, deadline, beforeDelete);
  }

  hourlyPriceUSD(
    serverType: string,
    config: ReturnType<typeof leaseConfig>,
  ): Promise<number | undefined> {
    return this.client.hourlyPriceUSD(serverType, config.location);
  }
}

function withProvisioningPhases(
  timing: Omit<LeaseProvisioningTiming, "phases">,
): LeaseProvisioningTiming {
  const totalMs = Number.isSafeInteger(timing.totalMs) && timing.totalMs > 0 ? timing.totalMs : 0;
  const phases: NonNullable<LeaseProvisioningTiming["phases"]> = [];
  let remaining = totalMs;
  const append = (name: NonNullable<LeaseProvisioningTiming["phases"]>[number]["name"], ms = 0) => {
    if (!Number.isSafeInteger(ms) || ms <= 0 || ms > remaining) return;
    phases.push({ name, ms });
    remaining -= ms;
  };
  append("request", timing.requestMs);
  append("network_ready", timing.networkReadyMs);
  append("bootstrap", timing.bootstrapMs);
  append("unattributed", remaining);
  return { ...timing, totalMs, phases };
}

export class AzureProvider implements CloudProvider {
  private clientValue?: AzureClient;

  resumableProvisioning(): ProviderResumableProvisioning {
    return new AzureResumableProvisioning(this.env, undefined, this.storage);
  }

  constructor(
    private readonly env: Env,
    private readonly deferredCleanup?: (request: AzureDeferredCleanupRequest) => Promise<void>,
    private readonly storage?: ProviderStateStorage,
    private readonly location?: string,
  ) {}

  private get client(): AzureClient {
    this.clientValue ??= new AzureClient(this.env, {
      ...(this.location ? { location: this.location } : {}),
      ...(this.deferredCleanup ? { deferredCleanup: this.deferredCleanup } : {}),
      ...(this.storage ? { ownedDeleteClaimStorage: this.storage } : {}),
    });
    return this.clientValue;
  }

  restrictedLeaseRequestFields(input: LeaseRequest): string[] {
    return [input.azureImage ? "azureImage" : "", input.azureOSDisk ? "azureOSDisk" : ""].filter(
      Boolean,
    );
  }

  listCrabboxServers(): Promise<ProviderMachine[]> {
    return this.client.listCrabboxServers();
  }

  listReconciliationResources(): Promise<ProviderMachine[]> {
    return this.client.listReconciliationResources();
  }

  supportsSSHHostKeyInjection(config: ReturnType<typeof leaseConfig>): boolean {
    return config.target === "linux" && !config.azureSnapshot;
  }

  getServer(id: string): Promise<ProviderMachine> {
    return this.client.getServer(id);
  }

  findServer(id: string): Promise<ProviderMachine | undefined> {
    return this.client.findServer(id);
  }

  recoverServer(lease: LeaseRecord): Promise<ProviderMachine | undefined> {
    const scope = azureProviderScope(lease.providerScope);
    if (!scope) {
      return Promise.reject(
        new Error(
          `refusing to recover Azure lease ${lease.id}: canonical provider scope was not persisted`,
        ),
      );
    }
    const recoveryLocation = lease.region?.trim() || this.location?.trim();
    return new AzureClient(this.env, {
      ...(recoveryLocation ? { location: recoveryLocation } : {}),
      subscription: scope.subscription,
      resourceGroup: scope.resourceGroup,
      ...(this.deferredCleanup ? { deferredCleanup: this.deferredCleanup } : {}),
      ...(this.storage ? { ownedDeleteClaimStorage: this.storage } : {}),
    }).recoverServerForLease(lease);
  }

  async prepareLeaseConfig(
    config: ReturnType<typeof leaseConfig>,
  ): Promise<ReturnType<typeof leaseConfig>> {
    const located = config.azureLocation
      ? config
      : { ...config, azureLocation: azureLocationFor(this.env, "") };
    if (located.azureSnapshot) {
      return {
        ...located,
        selectedImage: {
          id: located.azureSnapshot,
          source: "snapshot",
          provider: "azure",
          kind: "azure-os-disk-snapshot",
          region: located.azureLocation,
        },
      };
    }
    if (this.storage && !located.azureImageExplicit && located.azureOSDisk === "managed") {
      const promoted = await this.storage.get<PromotedImageRecord>(
        promotedAzureImageKey({
          target: located.target,
          architecture: located.architecture,
          serverType: located.serverType,
          os: located.os,
          region: located.azureLocation,
        }),
      );
      const snapshotID = promoted?.resourceID ?? promoted?.id;
      if (promoted && snapshotID) {
        return {
          ...located,
          azureSnapshot: snapshotID,
          selectedImage: {
            id: promoted.id,
            source: "promoted",
            provider: "azure",
            kind: promoted.kind ?? "azure-os-disk-snapshot",
            region: promoted.region ?? located.azureLocation,
            promotedAt: promoted.promotedAt,
            ...(snapshotID !== promoted.id ? { sourceID: snapshotID } : {}),
          },
        };
      }
    }
    assertAzureWindowsARM64Image(located);
    return located;
  }

  prepareLeaseCreate(
    config: ReturnType<typeof leaseConfig>,
    lease: LeaseRecord,
  ): Promise<ProviderLeaseCreatePreparation> {
    return Promise.resolve({
      config,
      lease: { ...lease, providerScope: this.client.providerScope() },
    });
  }

  createServerWithFallback(
    config: ReturnType<typeof leaseConfig>,
    leaseID: string,
    slug: string,
    owner: string,
  ): Promise<{
    server: ProviderMachine;
    serverType: string;
    market?: string;
    attempts?: ProvisioningAttempt[];
    image?: LeaseImageIdentity;
    provisioningTiming?: LeaseProvisioningTiming;
  }> {
    const startedAt = Date.now();
    return this.client.createServerWithFallback(config, leaseID, slug, owner).then((result) => {
      const image = azureLeaseImageIdentity(
        config,
        config.azureSnapshot || this.client.resolvedImageForConfig(config),
        result.server.region || config.azureLocation,
      );
      return {
        ...result,
        ...(image ? { image } : {}),
        provisioningTiming: withProvisioningPhases({
          requestMs: Date.now() - startedAt,
          totalMs: Date.now() - startedAt,
        }),
      };
    });
  }

  deleteServer(id: string): Promise<void> {
    return this.client.deleteServer(id);
  }

  inspectCleanup(lease: LeaseRecord): ReturnType<AzureClient["inspectOwnedCleanup"]> {
    const scope = azureProviderScope(lease.providerScope);
    if (!scope) {
      throw new Error("Azure cleanup inspection requires the original provider scope");
    }
    return new AzureClient(this.env, {
      ...(lease.region ? { location: lease.region } : {}),
      subscription: scope.subscription,
      resourceGroup: scope.resourceGroup,
      ...(this.storage ? { ownedDeleteClaimStorage: this.storage } : {}),
    }).inspectOwnedCleanup(lease);
  }

  deleteOwnedServer(lease: LeaseRecord, context?: ProviderReleaseContext): Promise<void> {
    const scope = azureProviderScope(lease.providerScope);
    if (!scope) {
      return Promise.reject(
        new ProviderCleanupManualResolutionError(
          `refusing to delete Azure lease ${lease.id}: canonical provider scope was not persisted`,
        ),
      );
    }
    const client = new AzureClient(this.env, {
      ...(this.location ? { location: this.location } : {}),
      ...(this.deferredCleanup ? { deferredCleanup: this.deferredCleanup } : {}),
      subscription: scope.subscription,
      resourceGroup: scope.resourceGroup,
      ...(this.storage ? { ownedDeleteClaimStorage: this.storage } : {}),
    });
    return context?.resourceIdentity === undefined
      ? client.deleteOwnedServer(lease)
      : client.deleteOwnedServer(lease, { resourceIdentity: context.resourceIdentity });
  }

  async finalizeLeaseCreate(
    config: ReturnType<typeof leaseConfig>,
    lease: LeaseRecord,
    server: ProviderMachine,
    attempts: ProvisioningAttempt[],
  ): Promise<ProviderLeaseCreateFinalization> {
    const region = server.region || config.azureLocation;
    const nextConfig = region ? { ...config, azureLocation: region } : config;
    const nextLease: LeaseRecord = {
      ...lease,
      region,
      providerScope: this.client.providerScope(),
    };
    const hints = capacityHints(this.env, nextConfig, nextLease, attempts);
    if (hints.length > 0) {
      nextLease.capacityHints = hints;
    }
    return { config: nextConfig, lease: nextLease };
  }

  async releaseLease(lease: LeaseRecord, context?: ProviderReleaseContext): Promise<void> {
    if (context === undefined) {
      await this.deleteOwnedServer(lease);
      return;
    }
    await this.deleteOwnedServer(lease, context);
  }

  supportsNativeImages(): boolean {
    return true;
  }

  nativeImagesUnsupportedMessage(): string {
    return "native images are supported for AWS, Azure, and GCP leases";
  }

  defaultImageStrategy(): "image" | "disk-snapshot" {
    return "disk-snapshot";
  }

  validateLeaseImageStrategy(
    _lease: LeaseRecord,
    strategy: "image" | "disk-snapshot",
  ): string | undefined {
    return strategy === "image"
      ? "Azure managed images require a stopped/generalized source VM; use disk-snapshot checkpoints for active Azure leases"
      : undefined;
  }

  async createLeaseImage(
    lease: LeaseRecord,
    name: string,
    _noReboot: boolean,
    _strategy: "image" | "disk-snapshot",
  ): Promise<ProviderImage> {
    const image = await this.client.createDiskSnapshot(
      lease.cloudID,
      providerImageResourceName("azure", name, lease.id),
    );
    const region = image.region ?? lease.region;
    const enriched: ProviderImage = {
      ...image,
      provider: "azure",
      serverType: lease.serverType,
    };
    if (region) {
      enriched.region = region;
    }
    if (this.storage) {
      await storeCreatedProviderImage(this.storage, "azure", enriched);
    }
    return enriched;
  }

  async checkpointScope(lease: LeaseRecord): Promise<CoordinatorCheckpointScope> {
    const scope = azureProviderScope(lease.providerScope);
    const region = lease.region?.trim().toLowerCase();
    if (
      !scope ||
      !region ||
      this.client.providerScope().toLowerCase() !== lease.providerScope?.toLowerCase()
    ) {
      throw new CheckpointError(
        "checkpoint_source_mismatch",
        "Azure source lease has no exact subscription, resource group, and location",
      );
    }
    return { region, subscriptionID: scope.subscription, resourceGroup: scope.resourceGroup };
  }

  async validateCheckpointLeaseScope(checkpoint: CoordinatorCheckpointRecord): Promise<void> {
    const expected = `/subscriptions/${checkpoint.scope.subscriptionID}/resourceGroups/${checkpoint.scope.resourceGroup}`;
    if (this.client.providerScope().toLowerCase() !== expected.toLowerCase()) {
      throw new CheckpointError(
        "checkpoint_source_mismatch",
        "Azure checkpoint lease subscription or resource group does not match durable ownership",
      );
    }
  }

  async validateCheckpointImage(checkpoint: CoordinatorCheckpointRecord): Promise<void> {
    const metadata = await checkpointCreatedImageMetadata(this.storage, checkpoint);
    const image = checkpoint.image!;
    const expected = `/subscriptions/${checkpoint.scope.subscriptionID}/resourceGroups/${checkpoint.scope.resourceGroup}/providers/Microsoft.Compute/snapshots/${image.id}`;
    if (
      metadata.resourceID?.toLowerCase() !== image.resourceID.toLowerCase() ||
      image.resourceID.toLowerCase() !== expected.toLowerCase()
    ) {
      throw new CheckpointError(
        "checkpoint_source_mismatch",
        "Azure checkpoint snapshot durable resource scope does not match its source lease",
      );
    }
    let current: ProviderImage;
    try {
      current = await this.client.getImage(image.id, image.kind);
    } catch (error) {
      if (!azureSnapshotNotFound(error, image.resourceID)) throw error;
      throw new CheckpointError(
        "checkpoint_source_mismatch",
        "Azure checkpoint snapshot no longer exists",
      );
    }
    if (
      current.provider !== "azure" ||
      current.kind !== image.kind ||
      current.resourceID?.toLowerCase() !== image.resourceID.toLowerCase() ||
      current.immutableID !== image.immutableID ||
      current.region !== checkpoint.scope.region ||
      current.checkpointOwnershipHash !== metadata.checkpointOwnershipHash ||
      current.checkpointSourceLeaseID !== checkpoint.leaseID
    ) {
      throw new CheckpointError(
        "checkpoint_source_mismatch",
        "Azure checkpoint snapshot identity, location, or ownership evidence has changed",
      );
    }
  }

  async createCheckpointImage(
    lease: LeaseRecord,
    name: string,
    _noReboot: boolean,
    _strategy: "image" | "disk-snapshot",
    ownership: ProviderCheckpointOwnership,
    _scope: CoordinatorCheckpointScope,
  ): Promise<ProviderImage> {
    await this.client.createDiskSnapshot(lease.cloudID, name, ownership);
    const image = await this.client.getImage(name, "azure-os-disk-snapshot");
    const enriched: ProviderImage = {
      ...image,
      provider: "azure",
      ...(image.region ? { region: image.region.toLowerCase() } : {}),
      serverType: lease.serverType,
    };
    return enriched;
  }

  async recoverCheckpointImage(
    checkpoint: CoordinatorCheckpointRecord,
  ): Promise<ProviderImage | undefined> {
    if (!checkpoint.createClaim) return undefined;
    await this.validateCheckpointLeaseScope(checkpoint);
    try {
      const image = await this.client.getImage(
        checkpoint.createClaim.resourceName,
        "azure-os-disk-snapshot",
      );
      if (
        image.checkpointOwnershipHash !== checkpoint.createClaim.tokenHash ||
        image.checkpointSourceLeaseID !== checkpoint.leaseID
      ) {
        throw new CheckpointError(
          "checkpoint_source_mismatch",
          "existing Azure snapshot does not match the exact checkpoint ownership claim",
        );
      }
      return image;
    } catch (error) {
      const expected = `/subscriptions/${checkpoint.scope.subscriptionID}/resourceGroups/${checkpoint.scope.resourceGroup}/providers/Microsoft.Compute/snapshots/${checkpoint.createClaim.resourceName}`;
      if (azureSnapshotNotFound(error, expected)) return undefined;
      throw error;
    }
  }

  async deleteCheckpointImage(checkpoint: CoordinatorCheckpointRecord): Promise<void> {
    const image = checkpoint.image;
    const expectedScope = `/subscriptions/${checkpoint.scope.subscriptionID}/resourceGroups/${checkpoint.scope.resourceGroup}`;
    if (!image || this.client.providerScope().toLowerCase() !== expectedScope.toLowerCase()) {
      throw new CheckpointError(
        "checkpoint_source_mismatch",
        "Azure checkpoint subscription or resource group does not match its durable ownership",
      );
    }
    let current: ProviderImage | undefined;
    try {
      current = await this.client.getImage(image.id, image.kind);
    } catch (error) {
      if (!azureSnapshotNotFound(error, image.resourceID)) throw error;
    }
    if (current) {
      if (
        current.resourceID?.toLowerCase() !== image.resourceID.toLowerCase() ||
        current.immutableID !== image.immutableID ||
        current.region?.toLowerCase() !== checkpoint.scope.region.toLowerCase()
      ) {
        throw new CheckpointError(
          "checkpoint_source_mismatch",
          "Azure checkpoint snapshot immutable identity or location has changed",
        );
      }
      await this.client.deleteImage(image.resourceID, image.kind);
      try {
        await this.client.getImage(image.id, image.kind);
        throw new CheckpointError(
          "checkpoint_delete_failed",
          "Azure checkpoint snapshot remains present after deletion",
        );
      } catch (error) {
        if (!azureSnapshotNotFound(error, image.resourceID)) throw error;
      }
    }
  }

  getImage(imageID: string, kind?: string): Promise<ProviderImage> {
    return this.client.getImage(imageID, kind);
  }

  async deleteImage(imageID: string, kind?: string): Promise<void> {
    await this.client.deleteImage(imageID, kind);
    const storage = this.storage;
    if (!storage) return;
    const promoted = await storage.list<PromotedImageRecord>({
      prefix: "image:azure:promoted:",
    });
    await Promise.all(
      [...promoted]
        .filter(
          ([, image]) =>
            image.id === imageID || image.resourceID === imageID || image.name === imageID,
        )
        .map(([key]) => storage.delete(key)),
    );
  }

  storedImageMetadata(imageID: string): Promise<ProviderImage | undefined> {
    return (
      this.storage?.get<ProviderImage>(createdProviderImageKey("azure", imageID)) ??
      Promise.resolve(undefined)
    );
  }
  decorateImage = passthroughProviderImage;
  validateDeleteImage = allowProviderImageDelete;

  async promoteImage(
    imageID: string,
    known: ProviderImage | undefined,
    request: Request,
    url: URL,
    checkpoint?: Pick<CoordinatorCheckpointRecord, "id" | "generation">,
  ): Promise<Response | { image: ProviderImage }> {
    if (!this.storage) {
      return json(
        {
          error: "image_catalog_unavailable",
          message: "Azure image catalog storage is unavailable",
        },
        { status: 503 },
      );
    }
    const input: {
      target?: string;
      os?: string;
      region?: string;
      architecture?: string;
      serverType?: string;
      catalogOnly?: unknown;
    } = await readJson<{
      target?: string;
      os?: string;
      region?: string;
      architecture?: string;
      serverType?: string;
      catalogOnly?: unknown;
    }>(request).catch(() => ({}));
    const catalogOnly = boolFromUnknown(url.searchParams.get("catalogOnly") ?? input.catalogOnly);
    if (catalogOnly) {
      return json(
        {
          error: "unsupported_provider",
          message: "catalog-only image promotion is AWS-only",
        },
        { status: 400 },
      );
    }
    if (!known) {
      return json(
        {
          error: "image_not_owned",
          message: "Azure promotion requires a Crabbox-created OS disk snapshot",
        },
        { status: 409 },
      );
    }
    const image = known;
    if (image.kind !== "azure-os-disk-snapshot") {
      return json(
        {
          error: "invalid_image_kind",
          message: "Azure promotion requires a Crabbox-created OS disk snapshot",
        },
        { status: 409 },
      );
    }
    if (!["available", "ready", "succeeded", "completed"].includes(image.state.toLowerCase())) {
      return json(
        { error: "image_not_available", message: `image ${imageID} is ${image.state}` },
        { status: 409 },
      );
    }
    const requestedTargetValue = input.target ?? url.searchParams.get("target") ?? undefined;
    const requestedTarget = requestedTargetValue
      ? normalizeAzureImageTarget(requestedTargetValue)
      : undefined;
    if (requestedTargetValue && !requestedTarget) {
      return json(
        { error: "invalid_target", message: "Azure image target must be linux or windows" },
        { status: 400 },
      );
    }
    const imageTarget = image.target ? normalizeAzureImageTarget(image.target) : undefined;
    const target = requestedTarget ?? imageTarget ?? "linux";
    if (requestedTarget && imageTarget && requestedTarget !== imageTarget) {
      return azureImageScopeMismatch("target", requestedTarget, imageTarget);
    }
    const requestedRegion = (input.region ?? url.searchParams.get("region") ?? "").trim();
    const imageRegion = (image.region ?? "").trim();
    if (
      requestedRegion &&
      imageRegion &&
      requestedRegion.toLowerCase() !== imageRegion.toLowerCase()
    ) {
      return azureImageScopeMismatch("region", requestedRegion, imageRegion);
    }
    const rawRegion = requestedRegion || imageRegion || this.location || "";
    const region = rawRegion.trim().toLowerCase();
    if (!region) {
      return json(
        { error: "invalid_region", message: "Azure image promotion requires a location" },
        { status: 400 },
      );
    }
    const requestedArchitectureValue =
      input.architecture ?? url.searchParams.get("architecture") ?? undefined;
    let requestedArchitecture: ReturnType<typeof normalizeArchitecture> | undefined;
    let imageArchitecture: ReturnType<typeof normalizeArchitecture> | undefined;
    try {
      requestedArchitecture = requestedArchitectureValue
        ? normalizeArchitecture(requestedArchitectureValue)
        : undefined;
      imageArchitecture = image.architecture
        ? normalizeArchitecture(image.architecture)
        : undefined;
    } catch (error) {
      return json(
        { error: "invalid_architecture", message: coordinatorErrorMessage(this.env, error) },
        { status: 400 },
      );
    }
    if (requestedArchitecture && imageArchitecture && requestedArchitecture !== imageArchitecture) {
      return azureImageScopeMismatch("architecture", requestedArchitecture, imageArchitecture);
    }
    const requestedServerType = (
      input.serverType ??
      url.searchParams.get("serverType") ??
      ""
    ).trim();
    const imageServerType = (image.serverType ?? "").trim();
    if (
      requestedServerType &&
      imageServerType &&
      requestedServerType.toLowerCase() !== imageServerType.toLowerCase()
    ) {
      return azureImageScopeMismatch("serverType", requestedServerType, imageServerType);
    }
    const serverType = imageServerType || requestedServerType;
    if (!serverType) {
      return json(
        {
          error: "invalid_image_scope",
          message: "Azure image promotion requires the source VM size or --type",
        },
        { status: 409 },
      );
    }
    let os: string | undefined;
    if (target === "linux") {
      try {
        const requestedOSValue = input.os ?? url.searchParams.get("os") ?? undefined;
        const requestedOS = requestedOSValue ? normalizeOSImage(requestedOSValue) : undefined;
        const imageOS = image.os ? normalizeOSImage(image.os) : undefined;
        if (requestedOS && imageOS && requestedOS !== imageOS) {
          return azureImageScopeMismatch("os", requestedOS, imageOS);
        }
        os = requestedOS ?? imageOS ?? defaultOSImage;
      } catch (error) {
        return json(
          { error: "invalid_os", message: coordinatorErrorMessage(this.env, error) },
          { status: 400 },
        );
      }
    }
    const promoted: PromotedImageRecord = {
      ...image,
      provider: "azure",
      target,
      ...(os ? { os } : {}),
      region,
      architecture: requestedArchitecture ?? imageArchitecture ?? "amd64",
      serverType,
      promotedAt: new Date().toISOString(),
    };
    await imageCatalogTransaction(this.storage, async (transaction) => {
      const key = promotedAzureImageKey(promoted);
      const previous = await transaction.get<PromotedImageRecord>(key);
      if (
        previous &&
        (previous.id !== promoted.id || previous.resourceID !== promoted.resourceID)
      ) {
        await unpinCheckpointPromotion(transaction, "azure", previous, key);
      }
      await transaction.put(key, promoted);
      await pinCheckpointPromotion(transaction, "azure", promoted, key, checkpoint);
    });
    return { image: promoted };
  }

  async retirePromotedImage(imageID: string, region?: string): Promise<number> {
    if (!this.storage) throw new Error("Azure image catalog storage is unavailable");
    return await imageCatalogTransaction(this.storage, async (transaction) => {
      const records = await transaction.list<PromotedImageRecord>({
        prefix: "image:azure:promoted:",
      });
      const matching = [...records].filter(
        ([, image]) =>
          (image.id === imageID || image.resourceID === imageID) &&
          (!region || image.region?.toLowerCase() === region.toLowerCase()),
      );
      await matching.reduce(async (previous, [key, image]) => {
        await previous;
        await unpinCheckpointPromotion(transaction, "azure", image, key);
        await transaction.delete(key);
      }, Promise.resolve());
      return matching.length;
    });
  }

  async deleteSSHKey(): Promise<void> {
    // Azure stores the SSH public key inline on the VM; nothing to clean up.
  }

  hourlyPriceUSD(): Promise<number | undefined> {
    return Promise.resolve(undefined);
  }
}

export class GCPProvider implements CloudProvider {
  readonly recoveryIsAuthoritative = true;

  private clientValue?: GCPClient;

  constructor(
    private readonly env: Env,
    private readonly storage?: ProviderStateStorage,
    private readonly zone?: string,
    private readonly project?: string,
  ) {}

  private get client(): GCPClient {
    this.clientValue ??= new GCPClient(this.env, this.zone, this.project);
    return this.clientValue;
  }

  readyPoolImageIdentity(lease: LeaseRecord): ReadyPoolImageIdentity | undefined {
    const image = lease.image;
    if (
      lease.provider !== "gcp" ||
      !image ||
      image.provider !== "gcp" ||
      !lease.providerProject ||
      lease.providerProject.trim() !== lease.providerProject ||
      !/^[0-9]+$/.test(image.id)
    ) {
      return undefined;
    }
    const scope = gcpReadyPoolImageScope(image.sourceID, image.kind);
    return scope ? { provider: "gcp", scope, id: image.id } : undefined;
  }

  supportsReadyPoolImageIdentity(identity: ReadyPoolImageIdentity): boolean {
    return (
      identity.provider === "gcp" &&
      /^[0-9]+$/.test(identity.id) &&
      gcpReadyPoolImageScopeSupported(identity.scope)
    );
  }

  restrictedLeaseRequestFields(input: LeaseRequest): string[] {
    return [
      input.gcpProject ? "gcpProject" : "",
      input.gcpImage ? "gcpImage" : "",
      input.gcpNetwork ? "gcpNetwork" : "",
      input.gcpSubnet ? "gcpSubnet" : "",
      input.gcpTags?.length ? "gcpTags" : "",
      input.gcpServiceAccount ? "gcpServiceAccount" : "",
    ].filter(Boolean);
  }

  ownershipLabelValue(value: string): string {
    return gcpProviderLabelValue(value);
  }

  listCrabboxServers(): Promise<ProviderMachine[]> {
    return this.client.listCrabboxServers();
  }

  supportsSSHHostKeyInjection(config: ReturnType<typeof leaseConfig>): boolean {
    return config.target === "linux";
  }

  getServer(id: string): Promise<ProviderMachine> {
    return this.client.getServer(id);
  }

  findServer(id: string): Promise<ProviderMachine | undefined> {
    return this.client.findServer(id);
  }

  recoverServer(lease: LeaseRecord): Promise<ProviderMachine | undefined> {
    return this.client.recoverServerForLease(lease);
  }

  recoverUnboundProvisioningResource(lease: LeaseRecord): Promise<ProviderMachine | undefined> {
    return this.client.recoverUnboundProvisioningResource(lease);
  }

  async prepareLeaseConfig(
    config: ReturnType<typeof leaseConfig>,
  ): Promise<ReturnType<typeof leaseConfig>> {
    if (config.gcpProject) {
      return config;
    }
    return {
      ...config,
      gcpProject: this.env.CRABBOX_GCP_PROJECT?.trim() || this.env.GCP_PROJECT_ID?.trim() || "",
    };
  }

  observeReadyPoolImageIdentity(lease: LeaseRecord): Promise<LeaseImageIdentity | undefined> {
    return this.client.observeReadyPoolImageIdentity(lease);
  }

  observeLegacyCleanupIdentity(
    lease: LeaseRecord,
    context?: ProviderReleaseContext,
  ): Promise<{ providerResourceID: string } | undefined> {
    return this.client.observeLegacyCleanupIdentity(lease, context);
  }

  prepareLeaseCreate(
    config: ReturnType<typeof leaseConfig>,
    lease: LeaseRecord,
  ): Promise<ProviderLeaseCreatePreparation> {
    return Promise.resolve({ config, lease, provisioning: {} });
  }

  createServerWithFallback(
    config: ReturnType<typeof leaseConfig>,
    leaseID: string,
    slug: string,
    owner: string,
    provisioning?: ProviderProvisioningContext,
  ): Promise<{
    server: ProviderMachine;
    serverType: string;
    market?: string;
    attempts?: ProvisioningAttempt[];
  }> {
    return this.client.createServerWithFallback(config, leaseID, slug, owner, provisioning);
  }

  deleteServer(id: string): Promise<void> {
    return this.client.deleteServer(id);
  }

  async finalizeLeaseCreate(
    config: ReturnType<typeof leaseConfig>,
    lease: LeaseRecord,
    server: ProviderMachine,
  ): Promise<ProviderLeaseCreateFinalization> {
    return {
      config,
      lease: {
        ...lease,
        region: server.region ?? config.gcpZone,
        providerProject: config.gcpProject,
      },
    };
  }

  async releaseLease(lease: LeaseRecord): Promise<void> {
    if (
      !lease.providerResourceID ||
      lease.providerResourceID !== lease.providerResourceID.trim() ||
      !/^[0-9]+$/.test(lease.providerResourceID)
    ) {
      throw new ProviderResourceUnresolvedError(
        `refusing to delete GCP instance ${lease.cloudID}: lease ${lease.id} has no numeric resource id`,
      );
    }
    const machine = await ownedProviderMachineForRelease(
      "gcp",
      lease,
      (id) => this.findServer(id),
      { labelValue: gcpProviderLabelValue },
    );
    if (!machine) return;
    if (machine.providerResourceID !== lease.providerResourceID) {
      throw new ProviderResourceUnresolvedError(
        `refusing to delete GCP instance ${lease.cloudID}: numeric resource id does not match lease ${lease.id}`,
      );
    }
    await this.deleteServer(lease.cloudID);
  }

  supportsNativeImages(): boolean {
    return true;
  }

  nativeImagesUnsupportedMessage(): string {
    return "native images are supported for AWS, Azure, and GCP leases";
  }

  defaultImageStrategy(): "image" | "disk-snapshot" {
    return "disk-snapshot";
  }

  validateLeaseImageStrategy(): string | undefined {
    return undefined;
  }

  async createLeaseImage(
    lease: LeaseRecord,
    name: string,
    _noReboot: boolean,
    strategy: "image" | "disk-snapshot",
  ): Promise<ProviderImage> {
    const image =
      strategy === "image"
        ? await this.client.createImage(
            lease.cloudID,
            providerImageResourceName("gcp", name, lease.id),
          )
        : await this.client.createDiskSnapshot(
            lease.cloudID,
            providerImageResourceName("gcp", name, lease.id),
          );
    const region = image.region ?? lease.region;
    const project = image.project ?? lease.providerProject ?? this.project;
    const enriched: ProviderImage = {
      ...image,
      provider: "gcp",
    };
    if (region) {
      enriched.region = region;
    }
    if (project) {
      enriched.project = project;
    }
    if (this.storage) {
      await storeCreatedProviderImage(this.storage, "gcp", enriched);
    }
    return enriched;
  }

  async checkpointScope(lease: LeaseRecord): Promise<CoordinatorCheckpointScope> {
    const project = lease.providerProject?.trim();
    const region = lease.region?.trim();
    if (!project || !region || this.client.project !== project || this.client.zone !== region) {
      throw new CheckpointError(
        "checkpoint_source_mismatch",
        "GCP source lease has no exact project and source zone",
      );
    }
    return { region, project };
  }

  async validateCheckpointLeaseScope(checkpoint: CoordinatorCheckpointRecord): Promise<void> {
    if (
      this.client.project !== checkpoint.scope.project ||
      this.client.zone !== checkpoint.scope.region
    ) {
      throw new CheckpointError(
        "checkpoint_source_mismatch",
        "GCP checkpoint lease project or zone does not match durable ownership",
      );
    }
  }

  async validateCheckpointImage(checkpoint: CoordinatorCheckpointRecord): Promise<void> {
    const metadata = await checkpointCreatedImageMetadata(this.storage, checkpoint);
    const image = checkpoint.image!;
    const collection =
      image.kind === "gcp-disk-snapshot"
        ? "snapshots"
        : image.kind === "gcp-machine-image"
          ? "machineImages"
          : "";
    const expected = `projects/${checkpoint.scope.project}/global/${collection}/${image.id}`;
    if (
      !collection ||
      metadata.project !== checkpoint.scope.project ||
      metadata.resourceID !== image.resourceID ||
      (image.resourceID !== expected && !image.resourceID.endsWith(`/${expected}`))
    ) {
      throw new CheckpointError(
        "checkpoint_source_mismatch",
        "GCP checkpoint durable resource kind or project does not match its source lease",
      );
    }
    let current: ProviderImage;
    try {
      current = await this.client.getImage(image.id, image.kind);
    } catch (error) {
      const missing =
        image.kind === "gcp-machine-image"
          ? gcpMachineImageNotFound(error, checkpoint.scope.project!, image.id)
          : gcpSnapshotNotFound(error, checkpoint.scope.project!, image.id);
      if (!missing) throw error;
      throw new CheckpointError(
        "checkpoint_source_mismatch",
        "GCP checkpoint source resource no longer exists",
      );
    }
    if (
      current.provider !== "gcp" ||
      current.id !== image.id ||
      current.kind !== image.kind ||
      current.project !== checkpoint.scope.project ||
      current.region !== checkpoint.scope.region ||
      current.resourceID !== image.resourceID ||
      current.immutableID !== image.immutableID ||
      current.checkpointOwnershipHash !== metadata.checkpointOwnershipHash ||
      current.checkpointSourceLeaseID !== checkpoint.leaseID
    ) {
      throw new CheckpointError(
        "checkpoint_source_mismatch",
        "GCP checkpoint resource identity, project, zone, or ownership evidence has changed",
      );
    }
  }

  async createCheckpointImage(
    lease: LeaseRecord,
    name: string,
    _noReboot: boolean,
    strategy: "image" | "disk-snapshot",
    ownership: ProviderCheckpointOwnership,
    _scope: CoordinatorCheckpointScope,
  ): Promise<ProviderImage> {
    const created =
      strategy === "image"
        ? await this.client.createImage(lease.cloudID, name, ownership)
        : await this.client.createDiskSnapshot(lease.cloudID, name, ownership);
    const image = await this.client.getImage(created.id, created.kind);
    const enriched: ProviderImage = {
      ...image,
      provider: "gcp",
    };
    return enriched;
  }

  async recoverCheckpointImage(
    checkpoint: CoordinatorCheckpointRecord,
  ): Promise<ProviderImage | undefined> {
    if (!checkpoint.createClaim) return undefined;
    const kind = checkpoint.strategy === "image" ? "gcp-machine-image" : "gcp-disk-snapshot";
    try {
      const image = await this.client.getImage(checkpoint.createClaim.resourceName, kind);
      if (
        image.checkpointOwnershipHash !== checkpoint.createClaim.tokenHash ||
        image.checkpointSourceLeaseID !== checkpoint.leaseID
      ) {
        throw new CheckpointError(
          "checkpoint_source_mismatch",
          "existing GCP resource does not match the exact checkpoint ownership claim",
        );
      }
      return image;
    } catch (error) {
      const missing =
        kind === "gcp-machine-image"
          ? gcpMachineImageNotFound(
              error,
              checkpoint.scope.project!,
              checkpoint.createClaim.resourceName,
            )
          : gcpSnapshotNotFound(
              error,
              checkpoint.scope.project!,
              checkpoint.createClaim.resourceName,
            );
      if (missing) return undefined;
      throw error;
    }
  }

  async deleteCheckpointImage(checkpoint: CoordinatorCheckpointRecord): Promise<void> {
    const image = checkpoint.image;
    if (
      !image ||
      this.client.project !== checkpoint.scope.project ||
      this.client.zone !== checkpoint.scope.region
    ) {
      throw new CheckpointError(
        "checkpoint_source_mismatch",
        "GCP checkpoint project or source zone does not match its durable ownership",
      );
    }
    const missing = (error: unknown): boolean =>
      image.kind === "gcp-machine-image"
        ? gcpMachineImageNotFound(error, checkpoint.scope.project!, image.id)
        : gcpSnapshotNotFound(error, checkpoint.scope.project!, image.id);
    let current: ProviderImage | undefined;
    try {
      current = await this.client.getImage(image.id, image.kind);
    } catch (error) {
      if (!missing(error)) throw error;
    }
    if (current) {
      if (
        current.project !== checkpoint.scope.project ||
        current.resourceID !== image.resourceID ||
        current.immutableID !== image.immutableID
      ) {
        throw new CheckpointError(
          "checkpoint_source_mismatch",
          "GCP checkpoint resource numeric identity or project has changed",
        );
      }
      await this.client.deleteImage(image.id, image.kind);
      try {
        await this.client.getImage(image.id, image.kind);
        throw new CheckpointError(
          "checkpoint_delete_failed",
          "GCP checkpoint resource remains present after deletion",
        );
      } catch (error) {
        if (!missing(error)) throw error;
      }
    }
  }

  getImage(imageID: string, kind?: string): Promise<ProviderImage> {
    return this.client.getImage(imageID, kind);
  }

  deleteImage(imageID: string, kind?: string): Promise<void> {
    return this.client.deleteImage(imageID, kind);
  }

  storedImageMetadata(imageID: string): Promise<ProviderImage | undefined> {
    return (
      this.storage?.get<ProviderImage>(createdProviderImageKey("gcp", imageID)) ??
      Promise.resolve(undefined)
    );
  }
  decorateImage = passthroughProviderImage;
  validateDeleteImage = allowProviderImageDelete;

  deleteSSHKey(): Promise<void> {
    return this.client.deleteSSHKey();
  }

  hourlyPriceUSD(): Promise<number | undefined> {
    return this.client.hourlyPriceUSD();
  }
}

export class DaytonaProvider implements CloudProvider {
  readonly recoveryIsAuthoritative = true;
  private clientValue?: DaytonaClient;
  private readonly pendingAccess = new Map<string, DaytonaSSHEndpoint>();

  constructor(private readonly env: Env) {}

  private get client(): DaytonaClient {
    this.clientValue ??= new DaytonaClient(this.env);
    return this.clientValue;
  }

  listCrabboxServers(): Promise<ProviderMachine[]> {
    return this.client.listCrabboxServers();
  }

  async readinessChecks(): Promise<ProviderReadinessCheck[]> {
    const details = {
      api: "list",
      mutation: "false",
      client_auth: "crabbox",
      control_plane: "coordinator",
      data_plane: "ssh-rsync",
      snapshot: this.env.CRABBOX_DAYTONA_SNAPSHOT?.trim() ? "configured" : "account-default",
    };
    try {
      const servers = await this.client.listCrabboxServers();
      return [
        {
          status: "ok",
          check: "daytona-fallback",
          message: `auth=ready control_plane=ready inventory=ready leases=${servers.length} mutation=false`,
          details: { ...details, leases: String(servers.length) },
        },
      ];
    } catch (error) {
      return [
        {
          status: "failed",
          check: "daytona-fallback",
          message: `auth_or_control_plane=failed mutation=false ${coordinatorErrorMessage(this.env, error)}`,
          details,
        },
      ];
    }
  }

  supportsSSHHostKeyInjection(): boolean {
    return false;
  }

  getServer(id: string): Promise<ProviderMachine> {
    return this.client.getServer(id);
  }

  async recoverServer(lease: LeaseRecord): Promise<ProviderMachine | undefined> {
    try {
      return await this.client.getOwnedServer(lease);
    } catch (error) {
      if (isDaytonaNotFound(error)) return undefined;
      throw error;
    }
  }

  async prepareLeaseCreate(
    config: LeaseConfig,
    lease: LeaseRecord,
  ): Promise<ProviderLeaseCreatePreparation> {
    const providerScope = await this.client.providerScope();
    return { config, lease: { ...lease, providerScope } };
  }

  prepareLeaseConfig(
    config: ReturnType<typeof leaseConfig>,
  ): Promise<ReturnType<typeof leaseConfig>> {
    return Promise.resolve({
      ...config,
      serverType: this.client.snapshot || "default",
      sshUser: this.client.user,
      sshPort: "22",
      sshFallbackPorts: [],
      workRoot: this.client.workRoot,
    });
  }

  async createServerWithFallback(
    config: ReturnType<typeof leaseConfig>,
    leaseID: string,
    slug: string,
    owner: string,
    provisioning?: ProviderProvisioningContext,
  ): Promise<{ server: ProviderMachine; serverType: string }> {
    const providerScope = await this.client.providerScope();
    let server: ProviderMachine;
    try {
      server = await this.client.createServer(config, leaseID, slug, owner);
    } catch (error) {
      throw new ProviderResourceUnresolvedError(
        `Daytona creation unresolved for lease ${leaseID}: ${coordinatorErrorMessage(this.env, error)}; no authoritative sandbox UUID received. Native TTL was requested, but deletion is unobserved; inspect the original allocation context before resolving cleanup`,
        { cause: error },
      );
    }
    const claim = validateProviderProvisioningCleanupClaim(
      { provider: "daytona", cloudID: server.cloudID, serverID: server.id, providerScope },
      "daytona",
    );
    if (!claim) {
      throw new ProviderResourceUnresolvedError(
        `Daytona creation unresolved for lease ${leaseID}: create returned no valid sandbox UUID; native TTL was requested, but deletion is unobserved`,
      );
    }
    try {
      const continueReadiness = await provisioning?.onResourceCreated?.(claim);
      if (continueReadiness === false) {
        return { server, serverType: this.client.snapshot || server.serverType || "default" };
      }
      const ready = await this.client.waitForStarted(server.cloudID, config.ttlSeconds);
      if ((await provisioning?.onResourceCreated?.(claim)) === false) {
        return { server: ready, serverType: this.client.snapshot || ready.serverType || "default" };
      }
      const access = await this.client.createSSHAccess(ready.cloudID, {
        expiresAt: new Date(Date.now() + config.ttlSeconds * 1_000).toISOString(),
      });
      this.pendingAccess.set(ready.cloudID, access);
      return {
        server: { ...ready, host: access.host },
        serverType: this.client.snapshot || ready.serverType || "default",
      };
    } catch (error) {
      if (error instanceof ProviderResourceUnresolvedError) throw error;
      // The coordinator owns rollback and current retain/delete intent. A returned
      // UUID is durable before readiness, so restart or release cannot orphan it.
      throw new ProviderProvisioningCleanupError(
        `${coordinatorErrorMessage(this.env, error)}; Daytona sandbox ${server.cloudID} cleanup remains pending`,
        claim,
        error,
      );
    }
  }

  async finalizeLeaseCreate(
    config: ReturnType<typeof leaseConfig>,
    lease: LeaseRecord,
    server: ProviderMachine,
  ): Promise<ProviderLeaseCreateFinalization> {
    const access =
      this.pendingAccess.get(server.cloudID) ??
      (await this.client.createSSHAccess(server.cloudID, lease));
    this.pendingAccess.delete(server.cloudID);
    return {
      config,
      lease: {
        ...lease,
        host: access.host,
        sshUser: access.user,
        sshPort: access.port,
        sshFallbackPorts: [],
        providerAccessExpiresAt: access.expiresAt,
        workRoot: this.client.workRoot,
        ...(server.region ? { region: server.region } : {}),
      },
    };
  }

  async refreshLeaseAccessForResolution(lease: LeaseRecord): Promise<LeaseRecord | void> {
    if (!daytonaAccessNeedsRefresh(lease)) return;
    await this.client.getOwnedServer(lease);
    const access = await this.client.createSSHAccess(lease.cloudID, lease);
    return {
      ...lease,
      host: access.host,
      sshUser: access.user,
      sshPort: access.port,
      sshFallbackPorts: [],
      providerAccessExpiresAt: access.expiresAt,
    };
  }

  async releaseLease(lease: LeaseRecord): Promise<void> {
    this.pendingAccess.delete(lease.cloudID);
    await this.client.deleteOwnedServer(lease);
  }

  async deleteServer(id: string): Promise<void> {
    throw new ProviderResourceUnresolvedError(
      `Daytona sandbox ${id} requires its retained lease and original allocation context for deletion`,
    );
  }

  supportsNativeImages(): boolean {
    return false;
  }

  nativeImagesUnsupportedMessage(): string {
    return "Daytona sandboxes are selected through the coordinator snapshot configuration";
  }

  defaultImageStrategy(): "image" | "disk-snapshot" {
    return "disk-snapshot";
  }

  validateLeaseImageStrategy(): string | undefined {
    return undefined;
  }

  createLeaseImage = unsupportedProviderImageLifecycle("daytona");
  getImage = unsupportedProviderImageLifecycle("daytona");
  deleteImage = unsupportedProviderImageLifecycle("daytona");
  storedImageMetadata = noStoredImageMetadata;
  decorateImage = passthroughProviderImage;
  validateDeleteImage = allowProviderImageDelete;

  deleteSSHKey(): Promise<void> {
    return Promise.resolve();
  }

  hourlyPriceUSD(): Promise<number | undefined> {
    return Promise.resolve(undefined);
  }
}

function awsCheckpointResourceAbsent(message: string, resourceID: string): boolean {
  const snapshot = resourceID.startsWith("snap-");
  return (
    message.includes(snapshot ? "InvalidSnapshot.NotFound" : "InvalidAMIID.NotFound") ||
    message === `aws ${snapshot ? "snapshot" : "image"} not found: ${resourceID}`
  );
}

export class AWSProvider implements CloudProvider {
  private clientValue?: EC2SpotClient;
  private readonly region: string;

  constructor(
    private readonly env: Env,
    region: string,
    private readonly storage: ProviderStateStorage,
  ) {
    this.region = region;
  }

  private get client(): EC2SpotClient {
    this.clientValue ??= new EC2SpotClient(this.env, this.region);
    return this.clientValue;
  }

  readyPoolImageIdentity(lease: LeaseRecord): ReadyPoolImageIdentity | undefined {
    const image = lease.image;
    const region = lease.region;
    if (
      lease.provider !== "aws" ||
      !image ||
      image.provider !== "aws" ||
      image.kind !== "aws-ami" ||
      !region ||
      image.region !== region
    ) {
      return undefined;
    }
    const identity = { provider: "aws", scope: region, id: image.id };
    return this.supportsReadyPoolImageIdentity(identity) ? identity : undefined;
  }

  supportsReadyPoolImageIdentity(identity: ReadyPoolImageIdentity): boolean {
    if (identity.provider !== "aws" || !/^ami-[0-9a-f]{8,17}$/.test(identity.id)) return false;
    try {
      return sanitizeAWSRegion(identity.scope) === identity.scope;
    } catch {
      return false;
    }
  }

  workspaceCapability(
    lease?: LeaseRecord,
    purpose: "operate" | "observe" = "operate",
  ): ProviderWorkspaceCapability | undefined {
    if (lease && lease.network?.awsPrivate !== true) {
      return undefined;
    }
    let policy: AWSPrivateWorkspaceConfig | undefined;
    try {
      policy = awsPrivateWorkspaceConfig(this.env);
    } catch (error) {
      if (purpose !== "observe" || !lease?.network?.awsPrivate) {
        throw error;
      }
    }
    if (!policy) {
      if (lease?.network?.awsPrivate) {
        if (purpose === "observe") {
          return privateAWSWorkspaceCapability(undefined, this.env);
        }
        throw new Error("private AWS workspace recovery policy is unavailable");
      }
      return undefined;
    }
    return privateAWSWorkspaceCapability(policy, this.env);
  }

  restrictedLeaseRequestFields(input: LeaseRequest): string[] {
    return [
      input.awsAMI ? "awsAMI" : "",
      input.awsSGID ? "awsSGID" : "",
      input.awsSubnetID ? "awsSubnetID" : "",
      input.awsProfile ? "awsProfile" : "",
      input.awsInstanceTypes?.length ? "awsInstanceTypes" : "",
      input.awsPrivate ? "awsPrivate" : "",
      input.awsRequireSSM ? "awsRequireSSM" : "",
      input.awsSSMBootstrapCommand ? "awsSSMBootstrapCommand" : "",
      input.awsSSMLogGroup ? "awsSSMLogGroup" : "",
    ].filter(Boolean);
  }

  listCrabboxServers(): Promise<ProviderMachine[]> {
    return this.client.listCrabboxServers();
  }

  supportsSSHHostKeyInjection(config: ReturnType<typeof leaseConfig>): boolean {
    return config.target === "linux" && !config.awsPrivate;
  }

  getServer(id: string): Promise<ProviderMachine> {
    return this.client.getServer(id);
  }

  findServer(id: string): Promise<ProviderMachine | undefined> {
    return this.client.findServer(id);
  }

  async recoverServer(lease: LeaseRecord): Promise<ProviderMachine | undefined> {
    if (lease.network?.awsPrivate) {
      if (lease.cloudID) {
        const server = await this.findServer(lease.cloudID);
        return server && providerMachineOwnedByLease(server, lease, "aws") ? server : undefined;
      }
      const server = await this.client.findWorkspaceServerByLease(lease.id);
      return server && providerLabelsOwnedByLease(server.labels, lease, "aws") ? server : undefined;
    }
    if (!lease.cloudID) return undefined;
    const server = await this.findServer(lease.cloudID);
    return server && providerMachineOwnedByLease(server, lease, "aws") ? server : undefined;
  }

  async resumeRecoveredServer(
    config: ReturnType<typeof leaseConfig>,
    lease: LeaseRecord,
    server: ProviderMachine,
  ): Promise<ProviderMachine> {
    if (!config.awsPrivate) return server;
    const region = server.region || config.awsRegion;
    const client = region === this.region ? this.client : new EC2SpotClient(this.env, region);
    try {
      const expectedGroups = [config.awsSGID].filter(Boolean).toSorted();
      const profileSuffix = `:instance-profile/${config.awsProfile}`;
      if (
        !["pending", "running"].includes(server.status) ||
        region !== config.awsRegion ||
        !config.awsInstanceTypes.includes(server.serverType) ||
        Boolean(server.host) ||
        (server.awsIPv6Addresses?.length ?? 0) > 0 ||
        Boolean(server.awsKeyName) ||
        server.awsSubnetID !== config.awsSubnetID ||
        JSON.stringify(server.awsSecurityGroupIDs ?? []) !== JSON.stringify(expectedGroups) ||
        !server.awsInstanceProfileARN?.endsWith(profileSuffix) ||
        server.awsMetadataHttpEndpoint !== "enabled" ||
        server.awsMetadataHttpTokens !== "required" ||
        server.awsMetadataHttpPutResponseHopLimit !== 1 ||
        server.awsMetadataInstanceTags !== "disabled"
      ) {
        throw new Error("recovered AWS private workspace is outside deployment policy");
      }
      await client.assertPrivateWorkspaceRootVolume(server, lease.id, config.awsRootGB);
      await client.waitForSSMOnline(server.cloudID);
      const bootstrap = await client.runSSMBootstrap(
        server.cloudID,
        lease.id,
        config.awsSSMBootstrapCommand,
        config.awsSSMLogGroup,
      );
      return {
        ...server,
        region,
        host: "",
        awsSSMCommandID: bootstrap.commandID,
        awsSSMCommandStatus: bootstrap.status,
      };
    } catch (error) {
      const resumeMessage = error instanceof Error ? error.message : String(error);
      try {
        await client.terminateServerAndWait(server.cloudID);
      } catch (cleanupError) {
        const cleanupMessage =
          cleanupError instanceof Error ? cleanupError.message : String(cleanupError);
        throw new ProviderProvisioningCleanupError(
          `${resumeMessage}; cleanup failed for recovered AWS instance ${server.cloudID}: ${cleanupMessage}`,
          {
            provider: "aws",
            cloudID: server.cloudID,
            region,
            serverID: server.id,
          },
          cleanupError,
        );
      }
      throw new Error(
        `${resumeMessage}; crabbox_aws_stale_instance_cleaned; deleted recovered AWS instance ${server.cloudID}`,
        { cause: error },
      );
    }
  }

  async prepareLeaseConfig(
    config: ReturnType<typeof leaseConfig>,
  ): Promise<ReturnType<typeof leaseConfig>> {
    if (
      config.awsAMI ||
      this.env.CRABBOX_AWS_AMI?.trim() ||
      config.awsSnapshot ||
      config.awsUseStockImage ||
      config.providerKey.startsWith(workspaceProviderKeyPrefix)
    ) {
      if (hasImageRequirements(config.imageRequirements)) {
        throw new ImageCapabilityMismatchError(
          "image capability requirements cannot be verified for an explicit or stock image source",
        );
      }
      const selectedImage = awsConfiguredImageIdentity(config, this.env);
      return { ...config, ...(selectedImage ? { selectedImage } : {}) };
    }
    if (config.target === "macos") {
      const awsPromotedAMIs = await this.promotedImagesForFallback(config);
      if (
        hasImageRequirements(config.imageRequirements) &&
        Object.keys(awsPromotedAMIs).length === 0
      ) {
        throw new ImageCapabilityMismatchError(
          "no promoted AWS macOS image satisfies the requested image capabilities",
        );
      }
      return { ...config, awsPromotedAMIs };
    }
    if (hasImageRequirements(config.imageRequirements)) {
      const awsPromotedAMIs = await this.promotedImagesForFallback(config);
      if (Object.keys(awsPromotedAMIs).length === 0) {
        throw new ImageCapabilityMismatchError(
          `no promoted AWS ${config.target} image satisfies the requested image capabilities`,
        );
      }
      return { ...config, awsAMI: "", awsPromotedAMIs };
    }
    const promoted = await this.promotedImage(config);
    return {
      ...config,
      awsAMI: promoted?.id ?? "",
      ...(promoted
        ? {
            selectedImage: {
              id: promoted.id,
              source: "promoted" as const,
              provider: "aws" as const,
              kind: promoted.kind ?? "aws-ami",
              region: promoted.region ?? config.awsRegion,
              promotedAt: promoted.promotedAt,
            },
          }
        : {}),
      ...(promoted?.region ? { awsRegion: promoted.region } : {}),
    };
  }

  async prepareLeaseCreate(
    config: ReturnType<typeof leaseConfig>,
    lease: LeaseRecord,
    context: ProviderAccessContext,
  ): Promise<ProviderLeaseCreatePreparation> {
    if (config.target === "macos") {
      const identity = await this.client.verifiedIdentity();
      if (!/^\d{12}$/.test(identity.account)) {
        throw new Error("AWS Mac host ownership requires an authenticated 12-digit account ID");
      }
      lease = { ...lease, providerScope: `aws:account:${identity.account}` };
    }
    if (config.awsPrivate) {
      const policy = awsPrivateWorkspaceConfig(this.env);
      if (
        !policy ||
        !config.awsSubnetID ||
        !config.awsSGID ||
        !config.awsProfile ||
        config.awsInstanceTypes.length === 0 ||
        !config.awsSSMBootstrapCommand ||
        !config.awsSSMLogGroup ||
        !config.awsRequireSSM ||
        !config.awsUseStockImage ||
        config.awsRegion !== policy.region ||
        config.awsSubnetID !== policy.subnetID ||
        config.awsSGID !== policy.securityGroupID ||
        config.awsProfile !== policy.instanceProfile ||
        config.awsRootGB !== policy.rootGB ||
        config.awsSSMLogGroup !== policy.ssmLogGroup ||
        config.capacityMarket !== policy.market ||
        config.capacityFallback !== "none" ||
        config.capacityRegions.length !== 1 ||
        config.capacityRegions[0] !== policy.region ||
        !policy.instanceTypes.includes(config.serverType) ||
        config.awsInstanceTypes.some((instanceType) => !policy.instanceTypes.includes(instanceType))
      ) {
        throw new Error("private AWS workspace policy is incomplete or outside deployment limits");
      }
      const nextLease: LeaseRecord = {
        ...lease,
        awsSSMLogGroup: config.awsSSMLogGroup,
        network: {
          ...lease.network,
          awsPrivate: true,
          awsSecurityGroupID: config.awsSGID,
          awsSubnetID: config.awsSubnetID,
        },
      };
      return {
        config: { ...config, awsSSHCIDRs: [] },
        lease: nextLease,
        provisioning: {
          allowEmptySSHIngress: true,
          publishAccessBeforeProvisioning: false,
        },
      };
    }
    const sourceCIDRs = awsLeaseSSHSourceCIDRs(config, context);
    const globalCIDRs = awsGlobalSSHSourceCIDRs(this.env);
    const nextLeaseWithSources = withLeaseSSHSourceCIDRs(
      lease,
      sourceCIDRs,
      sourceCIDRs.length > 0 || globalCIDRs.length > 0,
    );
    const configuredSecurityGroupID = awsConfiguredSecurityGroupID(config, this.env);
    const managedSecurityGroupName = `${awsManagedSecurityGroupName(config)}-${(
      await sha256Hex(`${lease.org}\0${lease.owner}`)
    ).slice(0, 12)}`;
    const nextLease: LeaseRecord = {
      ...nextLeaseWithSources,
      network: {
        ...nextLeaseWithSources.network,
        ...(config.awsSSHCIDRsPinned ? { sshPinnedSourceCIDRs: config.awsSSHCIDRs } : {}),
        ...(configuredSecurityGroupID
          ? { awsSecurityGroupID: configuredSecurityGroupID }
          : { awsSecurityGroupName: managedSecurityGroupName }),
        ...(config.awsSubnetID ? { awsSubnetID: config.awsSubnetID } : {}),
      },
    };
    return {
      config: {
        ...config,
        awsSGName: configuredSecurityGroupID ? "" : managedSecurityGroupName,
        awsSSHCIDRs: awsCreateSSHSourceCIDRs(config, nextLease, context, this.env, this.region),
      },
      lease: nextLease,
      provisioning: {
        // Creates overlap outside the coordinator queue. Only serialized refreshes may prune.
        sshIngressReconcile: "additive",
        publishAccessBeforeProvisioning: true,
      },
    };
  }

  async refreshLeaseAccess(
    lease: LeaseRecord,
    context: ProviderAccessContext,
  ): Promise<LeaseRecord | void> {
    if (lease.network?.awsPrivate) return;
    if (lease.state !== "active") {
      return;
    }
    const sourceCIDRs = validCIDRs(context.requestSourceCIDRs);
    const nextLease =
      sourceCIDRs.length > 0
        ? withLeaseSSHSourceCIDRs(lease, refreshedAWSSSHSourceCIDRs(lease, sourceCIDRs), true)
        : lease;
    const activeLeases = replaceProviderAccessState(context.activeLeases, nextLease);
    try {
      await this.reconcileLeaseAccess(nextLease, { ...context, activeLeases });
    } catch (error) {
      console.warn(
        `refresh AWS SSH ingress failed for ${lease.id}: ${coordinatorErrorMessage(this.env, error)}`,
      );
    }
    return nextLease;
  }

  async reconcileLeaseAccess(lease: LeaseRecord, context: ProviderAccessContext): Promise<void> {
    if (lease.network?.awsPrivate) return;
    const globalCIDRs = awsGlobalSSHSourceCIDRs(this.env);
    const accessLeases = context.activeLeases.filter(leaseOwnsAWSSSHAccess);
    const targets = new Map<string, { lease: LeaseRecord; port: string; region: string }>();
    const targetScopes = new Map<string, { identities: Set<string>; hasUnknownGroup: boolean }>();
    for (const candidate of [lease, ...accessLeases]) {
      const region = candidate.region || this.region;
      for (const port of awsLeaseSSHPorts(candidate)) {
        const key = awsIngressAccessTargetKey(candidate, region, [port], this.env);
        if (!targets.has(key)) {
          targets.set(key, { lease: candidate, port, region });
        }
        const scopeKey = awsIngressPortScopeKey(region, port);
        const scope = targetScopes.get(scopeKey) ?? {
          identities: new Set<string>(),
          hasUnknownGroup: false,
        };
        scope.identities.add(key);
        scope.hasUnknownGroup ||= awsIngressGroupMetadataUnknown(candidate, this.env);
        targetScopes.set(scopeKey, scope);
      }
    }
    const ambiguousTargetScopes = new Set(
      [...targetScopes]
        .filter(([, scope]) => scope.hasUnknownGroup && scope.identities.size > 1)
        .map(([scopeKey]) => scopeKey),
    );
    for (const [targetKey, target] of targets) {
      const targetLease = target.lease;
      const targetLeases = accessLeases.filter((candidate) => {
        const region = candidate.region || this.region;
        return (
          awsLeaseSSHPorts(candidate).includes(target.port) &&
          awsIngressAccessTargetKey(candidate, region, [target.port], this.env) === targetKey
        );
      });
      const cidrs = activeAWSSSHSourceCIDRs(targetLeases, globalCIDRs);
      const reconcile =
        ambiguousTargetScopes.has(awsIngressPortScopeKey(target.region, target.port)) ||
        hasUnknownActiveAWSSSHSource(targetLeases)
          ? "additive"
          : "authoritative";
      const config = {
        ...leaseConfig({
          provider: "aws",
          target: targetLease.target,
          windowsMode: targetLease.windowsMode ?? "normal",
          class: targetLease.class,
          serverType: targetLease.serverType,
          awsSSHCIDRs: cidrs,
          ...(targetLease.network?.awsSecurityGroupID
            ? { awsSGID: targetLease.network.awsSecurityGroupID }
            : {}),
          ...(targetLease.network?.awsSubnetID
            ? { awsSubnetID: targetLease.network.awsSubnetID }
            : {}),
          capacity: { market: targetLease.market === "spot" ? "spot" : "on-demand" },
          providerKey: targetLease.providerKey,
          sshUser: targetLease.sshUser,
          sshPort: target.port,
          sshFallbackPorts: [],
          sshPublicKey: "ssh-ed25519 ingress-reconcile",
          workRoot: targetLease.workRoot,
          ...(targetLease.hostId || targetLease.hostID
            ? { hostId: targetLease.hostId || targetLease.hostID }
            : {}),
        }),
        awsSGName: targetLease.network?.awsSecurityGroupName ?? "",
      };
      const { region } = target;
      const client = region === this.region ? this.client : new EC2SpotClient(this.env, region);
      // oxlint-disable-next-line eslint/no-await-in-loop -- each regional shared group is distinct.
      await client.refreshSSHIngress(
        { ...config, awsRegion: region },
        { reconcile, allowEmpty: true },
      );
    }
  }

  async createServerWithFallback(
    config: ReturnType<typeof leaseConfig>,
    leaseID: string,
    slug: string,
    owner: string,
    provisioning?: ProviderProvisioningContext,
  ): Promise<{
    server: ProviderMachine;
    serverType: string;
    market?: string;
    attempts?: ProvisioningAttempt[];
    image?: LeaseImageIdentity;
    provisioningTiming?: LeaseProvisioningTiming;
  }> {
    const regions = awsRegionCandidates(config, this.env, this.region);
    const withLeaseAccess = provisioning?.withLeaseAccess;
    const totalStartedAt = Date.now();
    const history = new ProvisioningAttemptHistory();
    const ingressOptions =
      provisioning?.sshIngressReconcile === undefined && !provisioning?.allowEmptySSHIngress
        ? undefined
        : {
            ...(provisioning?.sshIngressReconcile
              ? { reconcile: provisioning.sshIngressReconcile }
              : {}),
            ...(provisioning?.allowEmptySSHIngress ? { allowEmpty: true } : {}),
          };
    for (const region of regions) {
      const client = region === this.region ? this.client : new EC2SpotClient(this.env, region);
      let allocated:
        | {
            serverType: string;
            market: string | undefined;
            attempts: ProvisioningAttempt[] | undefined;
          }
        | undefined;
      try {
        // Record only regions whose provisioning path is about to mutate provider state.
        // oxlint-disable-next-line eslint/no-await-in-loop -- region fallback is intentionally ordered.
        await provisioning?.onTargetAttempt?.({ region });
        const requestStartedAt = Date.now();
        const { server, serverType, market, attempts, imageID } =
          // oxlint-disable-next-line eslint/no-await-in-loop -- region fallback must preserve ordered capacity preference.
          await client.createServerWithFallback(
            { ...config, awsRegion: region },
            leaseID,
            slug,
            owner,
            {
              ...ingressOptions,
              // Only ingress writes hold the fence; image, instance and address waits do not.
              ...(!config.awsPrivate && withLeaseAccess
                ? {
                    withIngress: (apply: (cidrs: string[]) => Promise<string>) =>
                      withLeaseAccess({ region }, async (lease, context) => {
                        const cidrs = awsCreateSSHSourceCIDRs(
                          { ...config, awsRegion: region },
                          lease,
                          context,
                          this.env,
                          this.region,
                        );
                        try {
                          return await apply(cidrs);
                        } catch (error) {
                          if (
                            !isAWSSecurityGroupRuleLimitError(
                              coordinatorErrorMessage(this.env, error),
                            )
                          ) {
                            throw error;
                          }
                          await this.reconcileLeaseAccess(lease, context);
                          return apply(cidrs);
                        }
                      }),
                  }
                : {}),
            },
          );
        allocated = { serverType, market, attempts };
        const requestMs = Date.now() - requestStartedAt;
        const networkReadyStartedAt = Date.now();
        let bootstrapMs = 0;
        const claim: ProviderProvisioningCleanupClaim = {
          provider: "aws",
          cloudID: server.cloudID,
          serverID: server.id,
          region,
          ...(provisioning?.providerScope ? { providerScope: provisioning.providerScope } : {}),
        };
        const onResourceCreated = provisioning?.onResourceCreated;
        const publishResource = onResourceCreated
          ? async (readinessError?: unknown) => {
              try {
                return await onResourceCreated(claim);
              } catch (error) {
                if (error instanceof ProviderResourceUnresolvedError) throw error;
                const message = coordinatorErrorMessage(this.env, error);
                const cause =
                  readinessError === undefined
                    ? error
                    : new AggregateError([readinessError, error], message, {
                        cause: readinessError,
                      });
                throw new ProviderProvisioningCleanupError(message, claim, cause);
              }
            }
          : undefined;
        const checkReadiness = publishResource
          ? async () => {
              if (!(await publishResource())) throw new CreateAttemptCanceledError();
            }
          : undefined;
        let readyServer = server;
        try {
          // oxlint-disable-next-line eslint/no-await-in-loop -- publish the allocation before readiness can perform provider I/O.
          await checkReadiness?.();
          // oxlint-disable-next-line eslint/no-await-in-loop -- wait on the region that created the instance.
          readyServer = await client.waitForServerIP(
            server.cloudID,
            config.awsPrivate,
            checkReadiness,
          );
          if (config.awsRequireSSM) {
            // oxlint-disable-next-line eslint/no-await-in-loop -- private readiness belongs to the selected region.
            await client.waitForSSMOnline(server.cloudID, checkReadiness);
            const bootstrapStartedAt = Date.now();
            // oxlint-disable-next-line eslint/no-await-in-loop -- bootstrap must finish before the lease becomes active.
            const bootstrap = await client.runSSMBootstrap(
              server.cloudID,
              leaseID,
              config.awsSSMBootstrapCommand,
              config.awsSSMLogGroup,
              checkReadiness,
            );
            bootstrapMs = Date.now() - bootstrapStartedAt;
            readyServer = {
              ...readyServer,
              host: "",
              awsSSMCommandID: bootstrap.commandID,
              awsSSMCommandStatus: bootstrap.status,
            };
          }
        } catch (error) {
          if (error instanceof ProviderResourceUnresolvedError) throw error;
          // Publication failures already carry the allocation; retrying publication could lose that evidence.
          if (providerProvisioningCleanupClaim(error)) throw error;
          const waitMessage = error instanceof Error ? error.message : String(error);
          if (publishResource) {
            // The published owner decides current retain/delete intent; readiness never deletes behind it.
            if (
              !(error instanceof CreateAttemptCanceledError) &&
              // oxlint-disable-next-line eslint/no-await-in-loop -- revalidate retain/delete intent after the failed provider read.
              (await publishResource(error))
            ) {
              throw new ProviderProvisioningCleanupError(waitMessage, claim, error);
            }
            readyServer = server;
          } else {
            try {
              if (config.awsPrivate) {
                // oxlint-disable-next-line eslint/no-await-in-loop -- clean up the exact instance before any fallback.
                await client.terminateServerAndWait(server.cloudID);
              } else {
                // oxlint-disable-next-line eslint/no-await-in-loop -- clean up the exact instance before any fallback.
                await client.deleteServer(server.cloudID);
              }
            } catch (deleteError) {
              const deleteMessage =
                deleteError instanceof Error ? deleteError.message : String(deleteError);
              throw new ProviderProvisioningCleanupError(
                `${waitMessage}; cleanup failed for AWS instance ${server.cloudID}: ${deleteMessage}`,
                claim,
                deleteError,
              );
            }
            throw new Error(
              `${waitMessage}; crabbox_aws_stale_instance_cleaned; deleted AWS instance ${server.cloudID} after readiness failure`,
              { cause: error },
            );
          }
        }
        const result: {
          server: ProviderMachine;
          serverType: string;
          market?: string;
          attempts?: ProvisioningAttempt[];
          image?: LeaseImageIdentity;
          provisioningTiming?: LeaseProvisioningTiming;
        } = {
          server: { ...readyServer, region },
          serverType,
          image: awsLeaseImageIdentity(config, imageID, region),
          provisioningTiming: withProvisioningPhases({
            requestMs,
            networkReadyMs: Date.now() - networkReadyStartedAt - bootstrapMs,
            ...(bootstrapMs > 0 ? { bootstrapMs } : {}),
            totalMs: Date.now() - totalStartedAt,
          }),
        };
        if (market) {
          result.market = market;
        }
        return { ...result, ...history.result(attempts) };
      } catch (error) {
        // Keep cancellation typed so the create owner records cleanup debt before
        // returning its terminal response, even after an earlier regional failure.
        if (
          error instanceof CreateAttemptCanceledError ||
          providerProvisioningCleanupClaim(error) ||
          error instanceof ProviderResourceUnresolvedError
        ) {
          throw error;
        }
        const message = error instanceof Error ? error.message : String(error);
        history.recordFailure(
          error,
          {
            region,
            serverType: allocated?.serverType ?? config.serverType,
            market: allocated?.market ?? config.capacityMarket,
            category: awsProvisioningErrorCategory(message) || "region",
            message: `region ${region}: ${message}`,
          },
          `${region}: ${message}`,
          allocated?.attempts,
        );
        if (!isRetryableAWSRegionProvisioningError(message)) {
          break;
        }
      }
    }
    throw history.error();
  }

  async deleteServer(id: string): Promise<void> {
    await this.client.deleteServer(id);
  }

  async finalizeLeaseCreate(
    config: ReturnType<typeof leaseConfig>,
    lease: LeaseRecord,
    server: ProviderMachine,
    attempts: ProvisioningAttempt[],
  ): Promise<ProviderLeaseCreateFinalization> {
    const nextConfig = server.region ? { ...config, awsRegion: server.region } : config;
    const nextLease: LeaseRecord = {
      ...lease,
      region: server.region ?? nextConfig.awsRegion,
      providerKeyCleanupOwned: lease.providerKey === providerKeyForLease(lease.id),
      ...(server.awsSSMCommandID ? { awsSSMCommandID: server.awsSSMCommandID } : {}),
      ...(server.awsSSMCommandStatus ? { awsSSMCommandStatus: server.awsSSMCommandStatus } : {}),
      ...(config.awsPrivate ? { awsSSMLogGroup: config.awsSSMLogGroup } : {}),
    };
    const hints = capacityHints(this.env, nextConfig, nextLease, attempts);
    if (hints.length > 0) {
      nextLease.capacityHints = hints;
    }
    return { config: nextConfig, lease: nextLease };
  }

  async releaseLease(lease: LeaseRecord): Promise<void> {
    const unsettledAllocation = Boolean(
      lease.provisioningRequestStartedAt || lease.provisioningResourceMayExist,
    );
    // A new EC2 allocation can be absent from reads before its ID propagates.
    const server = await ownedProviderMachineForRelease("aws", lease, (id) =>
      unsettledAllocation ? this.client.waitForServerVisibility(id) : this.findServer(id),
    );
    try {
      if (server) {
        if (lease.network?.awsPrivate) {
          await this.client.terminateServerAndWait(lease.cloudID);
        } else {
          await this.deleteServer(lease.cloudID);
        }
      }
    } catch (error) {
      const message = coordinatorErrorMessage(this.env, error);
      if (unsettledAllocation || !isAWSInstanceNotFoundError(message)) {
        throw error;
      }
      console.warn(
        `AWS lease cleanup found missing instance lease=${lease.id} cloud=${lease.cloudID}: ${message}`,
      );
    }
    if (lease.network?.awsPrivate) {
      privateAWSWorkspaceLifecycleLog("terminated", {
        lease_id: lease.id,
        cloud_id: lease.cloudID,
        region: lease.region,
      });
    }
    if (leaseUsesCanonicalProviderKey(lease)) {
      await this.deleteSSHKey(lease.providerKey, lease.id);
    }
  }

  supportsNativeImages(): boolean {
    return true;
  }

  nativeImagesUnsupportedMessage(): string {
    return "native images are supported for AWS, Azure, and GCP leases";
  }

  defaultImageStrategy(): "image" | "disk-snapshot" {
    return "image";
  }

  validateLeaseImageStrategy(): string | undefined {
    return undefined;
  }

  async createLeaseImage(
    lease: LeaseRecord,
    name: string,
    noReboot: boolean,
    strategy: "image" | "disk-snapshot",
  ): Promise<ProviderImage> {
    const image =
      strategy === "image"
        ? await this.client.createImage(lease.cloudID, name, noReboot)
        : await this.client.createDiskSnapshot(lease.cloudID, name);
    const enriched = enrichAWSImage(image, lease);
    await this.storage.put(createdAWSImageKey(enriched.id), enriched);
    await storeCreatedProviderImage(this.storage, "aws", enriched);
    return enriched;
  }

  async checkpointScope(lease: LeaseRecord): Promise<CoordinatorCheckpointScope> {
    const region = lease.region?.trim();
    if (!region || region !== this.region) {
      throw new CheckpointError(
        "checkpoint_source_mismatch",
        "AWS source lease has no exact provider region",
      );
    }
    const identity = await this.client.verifiedIdentity();
    if (!/^\d{12}$/.test(identity.account) || identity.region !== region) {
      throw new CheckpointError(
        "checkpoint_source_mismatch",
        "AWS source lease account could not be verified",
      );
    }
    return { region, accountID: identity.account };
  }

  async validateCheckpointLeaseScope(checkpoint: CoordinatorCheckpointRecord): Promise<void> {
    const identity = await this.client.verifiedIdentity();
    if (
      identity.account !== checkpoint.scope.accountID ||
      identity.region !== checkpoint.scope.region
    ) {
      throw new CheckpointError(
        "checkpoint_source_mismatch",
        "AWS checkpoint lease account or region does not match durable ownership",
      );
    }
  }

  async validateCheckpointImage(checkpoint: CoordinatorCheckpointRecord): Promise<void> {
    const metadata = await checkpointCreatedImageMetadata(this.storage, checkpoint);
    const image = checkpoint.image!;
    if (
      metadata.resourceID !== image.resourceID ||
      metadata.accountID !== checkpoint.scope.accountID ||
      (image.kind !== "aws-ami" && image.kind !== "aws-ebs-snapshot")
    ) {
      throw new CheckpointError(
        "checkpoint_source_mismatch",
        "AWS checkpoint durable resource identity or account does not match its source lease",
      );
    }
    const describe = async (imageID: string): Promise<ProviderImage> => {
      try {
        return await this.client.getImage(imageID);
      } catch (error) {
        const message = coordinatorErrorMessage(this.env, error);
        if (!awsCheckpointResourceAbsent(message, imageID)) {
          throw error;
        }
        throw new CheckpointError(
          "checkpoint_source_mismatch",
          "AWS checkpoint source image or backing snapshot no longer exists",
        );
      }
    };
    const current = await describe(image.id);
    const snapshots = [...new Set(current.snapshots ?? [])].toSorted();
    const expectedSnapshots = [...new Set(image.snapshotIDs)].toSorted();
    if (
      current.provider !== "aws" ||
      current.id !== image.id ||
      current.kind !== image.kind ||
      current.resourceID !== image.resourceID ||
      current.immutableID !== image.immutableID ||
      current.accountID !== checkpoint.scope.accountID ||
      current.region !== checkpoint.scope.region ||
      current.checkpointOwnershipHash !== metadata.checkpointOwnershipHash ||
      current.checkpointSourceLeaseID !== checkpoint.leaseID ||
      snapshots.length !== expectedSnapshots.length ||
      snapshots.some((snapshot, index) => snapshot !== expectedSnapshots[index]) ||
      (image.kind === "aws-ami" && snapshots.length === 0)
    ) {
      throw new CheckpointError(
        "checkpoint_source_mismatch",
        "AWS checkpoint image identity, account, backing snapshots, or ownership evidence has changed",
      );
    }
    if (image.kind !== "aws-ami") return;
    await Promise.all(
      snapshots.map(async (snapshotID) => {
        const snapshot = await describe(snapshotID);
        if (
          snapshot.provider !== "aws" ||
          snapshot.id !== snapshotID ||
          snapshot.kind !== "aws-ebs-snapshot" ||
          snapshot.resourceID !== snapshotID ||
          snapshot.immutableID !== snapshotID ||
          snapshot.accountID !== checkpoint.scope.accountID ||
          snapshot.region !== checkpoint.scope.region ||
          snapshot.checkpointOwnershipHash !== metadata.checkpointOwnershipHash ||
          snapshot.checkpointSourceLeaseID !== checkpoint.leaseID
        ) {
          throw new CheckpointError(
            "checkpoint_source_mismatch",
            "AWS checkpoint AMI backing snapshot identity or ownership evidence has changed",
          );
        }
      }),
    );
  }

  async createCheckpointImage(
    lease: LeaseRecord,
    name: string,
    noReboot: boolean,
    strategy: "image" | "disk-snapshot",
    ownership: ProviderCheckpointOwnership,
    scope: CoordinatorCheckpointScope,
  ): Promise<ProviderImage> {
    const created =
      strategy === "image"
        ? await this.client.createImage(lease.cloudID, name, noReboot, ownership)
        : await this.client.createDiskSnapshot(lease.cloudID, name, ownership);
    const image = await this.client.getImage(created.id);
    if (image.kind === "aws-ami") {
      const described = image;
      if (
        described.id !== created.id ||
        described.accountID !== scope.accountID ||
        described.checkpointOwnershipHash !== ownership.tokenHash ||
        described.checkpointSourceLeaseID !== ownership.sourceLeaseID ||
        !(described.snapshots ?? []).length
      ) {
        throw new CheckpointError(
          "checkpoint_source_mismatch",
          "AWS checkpoint AMI or its exact backing snapshots could not be verified",
        );
      }
      await Promise.all(
        described.snapshots!.map(async (snapshotID) => {
          const snapshot = await this.client.getImage(snapshotID);
          if (
            snapshot.id !== snapshotID ||
            snapshot.accountID !== scope.accountID ||
            snapshot.checkpointOwnershipHash !== ownership.tokenHash ||
            snapshot.checkpointSourceLeaseID !== ownership.sourceLeaseID
          ) {
            throw new CheckpointError(
              "checkpoint_source_mismatch",
              "AWS checkpoint AMI backing snapshot ownership could not be verified",
            );
          }
        }),
      );
    }
    if (
      image.id !== created.id ||
      image.accountID !== scope.accountID ||
      image.checkpointOwnershipHash !== ownership.tokenHash ||
      image.checkpointSourceLeaseID !== ownership.sourceLeaseID
    ) {
      throw new CheckpointError(
        "checkpoint_source_mismatch",
        "AWS checkpoint provider ownership could not be verified from a fresh read",
      );
    }
    const enriched = {
      ...enrichAWSImage(image, lease),
      immutableID: image.id,
      accountID: scope.accountID!,
    };
    return enriched;
  }

  async recoverCheckpointImage(
    checkpoint: CoordinatorCheckpointRecord,
  ): Promise<ProviderImage | undefined> {
    if (!checkpoint.createClaim) return undefined;
    const identity = await this.client.verifiedIdentity();
    if (
      identity.account !== checkpoint.scope.accountID ||
      identity.region !== checkpoint.scope.region
    ) {
      throw new CheckpointError(
        "checkpoint_source_mismatch",
        "AWS checkpoint recovery account or region has changed",
      );
    }
    const image = await this.client.findCheckpointImage(
      checkpoint.createClaim.resourceName,
      checkpoint.strategy,
      {
        checkpointID: checkpoint.id,
        tokenHash: checkpoint.createClaim.tokenHash,
        sourceLeaseID: checkpoint.leaseID,
      },
    );
    if (!image) return undefined;
    if (image.accountID && image.accountID !== identity.account) {
      throw new CheckpointError(
        "checkpoint_source_mismatch",
        "AWS checkpoint recovery returned an image from another account",
      );
    }
    if (image.kind === "aws-ami") {
      if (!(image.snapshots ?? []).length) {
        throw new CheckpointError(
          "checkpoint_source_mismatch",
          "recovered AWS checkpoint AMI has no verified backing snapshots",
        );
      }
      await Promise.all(
        image.snapshots!.map(async (snapshotID) => {
          const snapshot = await this.client.getImage(snapshotID);
          if (
            snapshot.accountID !== identity.account ||
            snapshot.checkpointOwnershipHash !== checkpoint.createClaim!.tokenHash ||
            snapshot.checkpointSourceLeaseID !== checkpoint.leaseID
          ) {
            throw new CheckpointError(
              "checkpoint_source_mismatch",
              "recovered AWS checkpoint backing snapshot ownership does not match",
            );
          }
        }),
      );
    }
    return { ...image, accountID: identity.account };
  }

  async deleteCheckpointImage(checkpoint: CoordinatorCheckpointRecord): Promise<void> {
    const image = checkpoint.image;
    if (!image)
      throw new CheckpointError(
        "checkpoint_source_mismatch",
        "AWS checkpoint resource identity is missing",
      );
    const identity = await this.client.verifiedIdentity();
    if (
      identity.account !== checkpoint.scope.accountID ||
      identity.region !== checkpoint.scope.region
    ) {
      throw new CheckpointError(
        "checkpoint_source_mismatch",
        "AWS checkpoint deletion account or region has changed",
      );
    }
    let claim = await this.imageDeletionClaim(image.id);
    if (!claim) {
      let described: ProviderImage;
      try {
        described = await this.client.getImage(image.id);
      } catch (error) {
        const message = coordinatorErrorMessage(this.env, error);
        if (awsCheckpointResourceAbsent(message, image.id)) {
          if (image.kind === "aws-ami" && image.snapshotIDs.length === 0) {
            throw new CheckpointError(
              "checkpoint_delete_failed",
              "AWS AMI is absent but its backing snapshot identities were never recorded",
            );
          }
          described = {
            id: image.id,
            name: checkpoint.name,
            state: "missing",
            provider: "aws",
            kind: image.kind,
            region: checkpoint.scope.region,
            resourceID: image.resourceID,
            immutableID: image.immutableID,
            accountID: checkpoint.scope.accountID,
            snapshots: image.snapshotIDs,
          };
        } else {
          throw error;
        }
      }
      if (
        described.id !== image.id ||
        described.immutableID !== image.immutableID ||
        (described.accountID && described.accountID !== checkpoint.scope.accountID)
      ) {
        throw new CheckpointError(
          "checkpoint_source_mismatch",
          "AWS checkpoint provider resource identity has changed",
        );
      }
      claim = {
        version: awsImageDeletionClaimVersion,
        imageID: image.id,
        metadata: awsImageDeletionMetadata(image.id, described, {
          ...described,
          snapshots: [...new Set([...image.snapshotIDs, ...(described.snapshots ?? [])])],
        }),
        snapshotIDs: [...new Set([...image.snapshotIDs, ...(described.snapshots ?? [])])],
        phase: "claimed",
        claimedAt: new Date().toISOString(),
      };
      await this.storage.put(awsImageDeletionClaimKey(image.id), claim);
    }
    if (claim.phase !== "provider-deleted") {
      await this.client.deleteImage(image.id, claim.snapshotIDs);
      const resourceIDs = [...new Set([image.id, ...claim.snapshotIDs])];
      await Promise.all(
        resourceIDs.map(async (resourceID) => {
          try {
            await this.client.getImage(resourceID);
            throw new CheckpointError(
              "checkpoint_delete_failed",
              `AWS checkpoint resource ${resourceID} remains present after deletion`,
            );
          } catch (error) {
            const message = coordinatorErrorMessage(this.env, error);
            if (!awsCheckpointResourceAbsent(message, resourceID)) throw error;
          }
        }),
      );
      await this.storage.put(awsImageDeletionClaimKey(image.id), {
        ...claim,
        phase: "provider-deleted",
        providerDeletedAt: new Date().toISOString(),
      } satisfies AWSImageDeletionClaim);
    }
  }

  getImage(imageID: string): Promise<ProviderImage> {
    return this.client.getImage(imageID);
  }

  enableFastSnapshotRestore(
    snapshotIDs: string[],
    availabilityZones: string[],
  ): Promise<ProviderFastSnapshotRestore[]> {
    return this.client.enableFastSnapshotRestore(snapshotIDs, availabilityZones);
  }

  fastSnapshotRestoreStatus(
    snapshotIDs: string[],
    availabilityZones?: string[],
  ): Promise<ProviderFastSnapshotRestore[]> {
    return this.client.fastSnapshotRestoreStatus(snapshotIDs, availabilityZones);
  }

  async deleteImage(imageID: string, _kind?: string, metadata?: ProviderImage): Promise<void> {
    let claim = await this.imageDeletionClaim(imageID);
    if (!claim) {
      const described = await this.client.getImage(imageID);
      claim = {
        version: awsImageDeletionClaimVersion,
        imageID,
        metadata: awsImageDeletionMetadata(imageID, described, metadata),
        snapshotIDs: awsImageDeletionSnapshotIDs(described),
        phase: "claimed",
        claimedAt: new Date().toISOString(),
      };
      await this.storage.put(awsImageDeletionClaimKey(imageID), claim);
    }
    if (claim.phase !== "provider-deleted") {
      await this.client.deleteImage(imageID, claim.snapshotIDs);
      claim = {
        ...claim,
        phase: "provider-deleted",
        providerDeletedAt: new Date().toISOString(),
      };
      await this.storage.put(awsImageDeletionClaimKey(imageID), claim);
    }
    await this.deleteMatchingImageRecords("image:aws:created:", imageID, this.region);
    await this.deleteMatchingImageRecords(promotedAWSImagePrefix(), imageID, this.region);
    await imageCatalogTransaction(this.storage, async (transaction) => {
      await deletePromotedAWSImageRecords(
        transaction,
        imageID,
        ["image:aws:catalog:", "image:aws:variant:"],
        { region: this.region },
      );
      await transaction.delete(awsImageDeletionClaimKey(imageID));
    });
  }

  retireCatalogImage(imageID: string, region?: string): Promise<number> {
    return imageCatalogTransaction(
      this.storage,
      async (transaction) =>
        await deletePromotedAWSImageRecords(
          transaction,
          imageID,
          ["image:aws:variant:"],
          region ? { region } : {},
        ),
    );
  }

  retirePromotedImage(imageID: string, region?: string): Promise<number> {
    return imageCatalogTransaction(
      this.storage,
      async (transaction) =>
        await deletePromotedAWSImageRecords(
          transaction,
          imageID,
          ["image:aws:catalog:", "image:aws:variant:", "image:aws:promoted"],
          region ? { region } : {},
        ),
    );
  }

  async storedImageMetadata(imageID: string): Promise<ProviderImage | undefined> {
    const promoted = await this.promotedImagesByID(imageID);
    const currentPromoted = promoted.find((image) => image.region === this.region);
    if (currentPromoted) return currentPromoted;
    const created =
      (await this.storage.get<ProviderImage>(createdAWSImageKey(imageID))) ??
      (await this.storage.get<ProviderImage>(createdProviderImageKey("aws", imageID))) ??
      (await this.imageDeletionClaim(imageID))?.metadata;
    if (created?.region === this.region) return created;
    const variants = await this.variantImagesByID(imageID);
    return (
      variants.find((image) => image.region === this.region) ??
      promoted[0] ??
      created ??
      variants[0]
    );
  }

  async storedImageDeleteMetadata(imageID: string): Promise<ProviderImage | undefined> {
    const promoted = await this.promotedImageByID(imageID);
    if (promoted) return promoted;
    const created =
      (await this.storage.get<ProviderImage>(createdAWSImageKey(imageID))) ??
      (await this.storage.get<ProviderImage>(createdProviderImageKey("aws", imageID))) ??
      (await this.imageDeletionClaim(imageID))?.metadata;
    return created?.region === this.region ? created : undefined;
  }

  decorateImage(image: ProviderImage, metadata?: Partial<ProviderImage>): ProviderImage {
    return mergeAWSImageMetadata(image, metadata);
  }

  async validateDeleteImage(
    imageID: string,
    metadata?: Partial<ProviderImage>,
  ): Promise<{ status: number; body: Record<string, unknown> } | undefined> {
    if (await this.imageDeletionClaim(imageID)) {
      return undefined;
    }
    if (metadata?.id === imageID && "promotedAt" in metadata) {
      return {
        status: 409,
        body: {
          error: "image_promoted",
          message: `image ${imageID} is the promoted AWS image; promote another image before deleting it`,
        },
      };
    }
    return undefined;
  }

  private async imageDeletionClaim(imageID: string): Promise<AWSImageDeletionClaim | undefined> {
    const claim = await this.storage.get<unknown>(awsImageDeletionClaimKey(imageID));
    return validAWSImageDeletionClaim(claim, imageID) ? claim : undefined;
  }

  private async deleteMatchingImageRecords(
    prefix: string,
    imageID: string,
    region?: string,
  ): Promise<void> {
    const records = await this.storage.list<ProviderImage>({ prefix });
    for (const [key, image] of records) {
      if (image.id !== imageID && image.resourceID !== imageID) continue;
      if (region !== undefined && image.region !== region) continue;
      // oxlint-disable-next-line eslint/no-await-in-loop -- ordered deletes leave a retryable durable prefix boundary.
      await this.storage.delete(key);
    }
  }

  async fastSnapshotRestoreForImage(
    imageID: string,
    metadata: ProviderImage | undefined,
    url: URL,
  ): Promise<
    Response | { image: ProviderImage; fastSnapshotRestores: ProviderFastSnapshotRestore[] }
  > {
    const rawRegion = url.searchParams.get("region") ?? metadata?.region ?? "";
    const imageRegion = rawRegion ? sanitizeAWSRegion(rawRegion) : "";
    if (rawRegion && !imageRegion) {
      return json(
        { error: "invalid_region", message: "region must be an AWS region name" },
        { status: 400 },
      );
    }
    const region = imageRegion || this.region;
    const provider =
      region === this.region ? this : new AWSProvider(this.env, region, this.storage);
    const image = mergeAWSImageMetadata(await provider.getImage(imageID), metadata);
    const snapshots = image.snapshots ?? [];
    if (snapshots.length === 0) {
      return json(
        {
          error: "image_snapshots_missing",
          message: `image ${imageID} has no EBS snapshots to describe for Fast Snapshot Restore`,
        },
        { status: 409 },
      );
    }
    const availabilityZones = fastSnapshotRestoreStatusAZs(url, image.region ?? imageRegion);
    const fastSnapshotRestores = await provider.fastSnapshotRestoreStatus(
      snapshots,
      availabilityZones,
    );
    const imageWithStatus = { ...image, fastSnapshotRestores };
    return {
      image: imageWithStatus,
      fastSnapshotRestores: imageWithStatus.fastSnapshotRestores ?? [],
    };
  }

  async promoteImage(
    imageID: string,
    known: ProviderImage | undefined,
    request: Request,
    url: URL,
    checkpoint?: Pick<CoordinatorCheckpointRecord, "id" | "generation">,
  ): Promise<Response | { image: ProviderImage }> {
    const input: {
      target?: string;
      os?: string;
      region?: string;
      serverType?: string;
      architecture?: string;
      capabilities?: ImageCapabilities;
      catalogOnly?: unknown;
      variantSelectors?: ImageVariantSelectors;
      fastSnapshotRestore?: unknown;
      fastSnapshotRestoreAvailabilityZones?: string[];
    } = await readJson<{
      target?: string;
      os?: string;
      region?: string;
      serverType?: string;
      architecture?: string;
      capabilities?: ImageCapabilities;
      catalogOnly?: unknown;
      variantSelectors?: ImageVariantSelectors;
      fastSnapshotRestore?: unknown;
      fastSnapshotRestoreAvailabilityZones?: string[];
    }>(request).catch(() => ({}));
    const requestedRegion = input.region ?? url.searchParams.get("region") ?? "";
    const requestedImageRegion = requestedRegion ? sanitizeAWSRegion(requestedRegion) : "";
    if (requestedRegion && !requestedImageRegion) {
      return json(
        { error: "invalid_region", message: "region must be an AWS region name" },
        { status: 400 },
      );
    }
    const historyRegion =
      requestedImageRegion || sanitizeAWSRegion(known?.region ?? "") || this.region;
    const cataloged = await this.promotedImageMetadataByID(imageID, historyRegion, known);
    const prior: (ProviderImage & Partial<PromotedImageRecord>) | undefined = cataloged
      ? { ...(known?.region === historyRegion ? known : {}), ...cataloged }
      : known?.region === historyRegion
        ? known
        : undefined;
    const target = normalizeAWSImageTarget(
      input.target ?? url.searchParams.get("target") ?? prior?.target ?? "linux",
    );
    if (!target) {
      return json(
        { error: "invalid_target", message: "target must be linux, macos, or windows" },
        { status: 400 },
      );
    }
    let imageOS: string | undefined;
    if (target === "linux") {
      const requestedOS = input.os ?? url.searchParams.get("os");
      const fallbackOS = prior ? (prior.os ?? "ubuntu:24.04") : defaultOSImage;
      try {
        imageOS = normalizeOSImage(requestedOS ?? fallbackOS);
      } catch (error) {
        return json(
          { error: "invalid_os", message: coordinatorErrorMessage(this.env, error) },
          { status: 400 },
        );
      }
    }
    const rawRegion = requestedRegion || prior?.region || known?.region || "";
    const imageRegion = sanitizeAWSRegion(rawRegion);
    const {
      catalogOnly: _priorCatalogOnly,
      variantSelectors: _priorVariantSelectors,
      ...priorMetadata
    } = prior ?? {};
    void _priorCatalogOnly;
    void _priorVariantSelectors;
    const metadata: Partial<ProviderImage> = { ...priorMetadata, target, region: imageRegion };
    const serverType = input.serverType ?? url.searchParams.get("serverType") ?? prior?.serverType;
    if (serverType) {
      metadata.serverType = serverType;
    }
    const architecture =
      input.architecture ?? url.searchParams.get("architecture") ?? prior?.architecture;
    if (architecture) {
      metadata.architecture = architecture;
    }
    let declaredCapabilities: ImageCapabilities | undefined;
    let declaredSDKs: Record<string, string> | undefined;
    let declaredRuntimes: Record<string, string> | undefined;
    let variantSelectors: ImageVariantSelectors | undefined;
    try {
      declaredCapabilities = normalizeImageCapabilities({
        ...input.capabilities,
        osVersion: input.capabilities?.osVersion ?? url.searchParams.get("osVersion") ?? undefined,
        sdks:
          input.capabilities?.sdks ??
          promotionVersionMap(url.searchParams.getAll("sdk"), "sdk") ??
          undefined,
        runtimes:
          input.capabilities?.runtimes ??
          promotionVersionMap(url.searchParams.getAll("runtime"), "runtime") ??
          undefined,
        browser:
          input.capabilities?.browser ??
          (url.searchParams.has("browser")
            ? boolFromUnknown(url.searchParams.get("browser"))
            : undefined),
        webview2:
          input.capabilities?.webview2 ??
          (url.searchParams.has("webview2")
            ? boolFromUnknown(url.searchParams.get("webview2"))
            : undefined),
        desktop:
          input.capabilities?.desktop ??
          (url.searchParams.has("desktop")
            ? boolFromUnknown(url.searchParams.get("desktop"))
            : undefined),
      });
      variantSelectors = normalizeImageVariantSelectors(input.variantSelectors);
      declaredSDKs = mergePromotionVersions(
        declaredCapabilities?.sdks,
        variantSelectors?.sdks,
        "sdk",
        "variantSelectors.sdks",
      );
      declaredRuntimes = mergePromotionVersions(
        declaredCapabilities?.runtimes,
        variantSelectors?.runtimes,
        "runtime",
        "variantSelectors.runtimes",
      );
    } catch (error) {
      return json(
        { error: "invalid_image_capabilities", message: coordinatorErrorMessage(this.env, error) },
        { status: 400 },
      );
    }
    const accumulatedCapabilities = (
      priorCapabilities: ImageCapabilities | undefined,
    ): ImageCapabilities | undefined =>
      normalizeImageCapabilities({
        ...priorCapabilities,
        ...declaredCapabilities,
        osVersion: declaredCapabilities?.osVersion ?? priorCapabilities?.osVersion,
        sdks: declaredSDKs
          ? { ...priorCapabilities?.sdks, ...declaredSDKs }
          : priorCapabilities?.sdks,
        runtimes: declaredRuntimes
          ? { ...priorCapabilities?.runtimes, ...declaredRuntimes }
          : priorCapabilities?.runtimes,
        browser: declaredCapabilities?.browser ?? priorCapabilities?.browser,
        webview2: declaredCapabilities?.webview2 ?? priorCapabilities?.webview2,
        desktop: declaredCapabilities?.desktop ?? priorCapabilities?.desktop,
      });
    const catalogOnly = boolFromUnknown(url.searchParams.get("catalogOnly") ?? input.catalogOnly);
    if (catalogOnly && !variantSelectors) {
      return json(
        {
          error: "catalog_only_variant_selectors_required",
          message: "catalog-only image promotion requires at least one variant selector",
        },
        { status: 400 },
      );
    }
    if (!catalogOnly && variantSelectors) {
      return json(
        {
          error: "variant_selectors_require_catalog_only",
          message: "variant selectors require catalog-only image promotion",
        },
        { status: 400 },
      );
    }
    const fastSnapshotRestore = boolFromUnknown(
      input.fastSnapshotRestore ?? url.searchParams.get("fastSnapshotRestore"),
    );
    const fastSnapshotRestoreAvailabilityZones = fastSnapshotRestore
      ? fastSnapshotRestoreAZs(
          input.fastSnapshotRestoreAvailabilityZones,
          url,
          imageRegion,
          this.env,
        )
      : [];
    if (fastSnapshotRestore && fastSnapshotRestoreAvailabilityZones.length === 0) {
      return json(
        {
          error: "invalid_fast_snapshot_restore_zones",
          message:
            "Fast Snapshot Restore promotion requires at least one availability zone via fsrAz, fastSnapshotRestoreAvailabilityZones, CRABBOX_AWS_FAST_SNAPSHOT_RESTORE_AZS, or CRABBOX_CAPACITY_AVAILABILITY_ZONES",
        },
        { status: 400 },
      );
    }
    const region = imageRegion || this.region;
    const provider =
      region === this.region ? this : new AWSProvider(this.env, region, this.storage);
    const image = mergeAWSImageMetadata(await provider.getImage(imageID), metadata);
    if (image.state !== "available") {
      return json(
        { error: "image_not_available", message: `image ${imageID} is ${image.state}` },
        { status: 409 },
      );
    }
    if (target === "macos" && !image.serverType) {
      return json(
        { error: "invalid_server_type", message: "macOS AWS image promotion requires serverType" },
        { status: 400 },
      );
    }
    if (fastSnapshotRestoreAvailabilityZones.length > 0 && (image.snapshots ?? []).length === 0) {
      return json(
        {
          error: "image_snapshots_missing",
          message: `image ${imageID} has no EBS snapshots to enable for Fast Snapshot Restore`,
        },
        { status: 409 },
      );
    }
    const effectiveRegion = sanitizeAWSRegion(image.region ?? imageRegion) || region;
    const preflightCataloged = await this.promotedImageMetadataByID(
      imageID,
      effectiveRegion,
      known,
    );
    const preflightPrior = preflightCataloged
      ? { ...(known?.region === effectiveRegion ? known : {}), ...preflightCataloged }
      : known?.region === effectiveRegion
        ? known
        : undefined;
    try {
      accumulatedCapabilities(preflightPrior?.capabilities);
    } catch (error) {
      return json(
        { error: "invalid_image_capabilities", message: coordinatorErrorMessage(this.env, error) },
        { status: 400 },
      );
    }
    const fastSnapshotRestores =
      fastSnapshotRestoreAvailabilityZones.length > 0
        ? await provider.enableFastSnapshotRestore(
            image.snapshots ?? [],
            fastSnapshotRestoreAvailabilityZones,
          )
        : undefined;
    const { capabilities: _providerCapabilities, ...validatedImage } = image;
    void _providerCapabilities;
    try {
      const promoted = await imageCatalogTransaction(this.storage, async (transaction) => {
        const currentCataloged = await this.promotedImageMetadataByID(
          imageID,
          effectiveRegion,
          known,
          transaction,
        );
        const currentPrior: (ProviderImage & Partial<PromotedImageRecord>) | undefined =
          currentCataloged
            ? { ...(known?.region === effectiveRegion ? known : {}), ...currentCataloged }
            : known?.region === effectiveRegion
              ? known
              : undefined;
        const capabilities = accumulatedCapabilities(currentPrior?.capabilities);
        const next: PromotedImageRecord = {
          ...validatedImage,
          ...(fastSnapshotRestores ? { fastSnapshotRestores } : {}),
          target,
          ...(imageOS ? { os: imageOS } : {}),
          region: effectiveRegion,
          architecture:
            image.architecture ?? awsImageArchitectureForTarget(target, image.serverType ?? ""),
          promotedAt: new Date().toISOString(),
          ...(capabilities ? { capabilities } : {}),
          ...(catalogOnly && variantSelectors ? { catalogOnly: true, variantSelectors } : {}),
        };
        await deletePromotedAWSImageRecords(transaction, imageID, ["image:aws:variant:"], {
          region: effectiveRegion,
        });
        const publish = async (key: string): Promise<void> => {
          const previous = await transaction.get<PromotedImageRecord>(key);
          if (previous && (previous.id !== next.id || previous.region !== next.region)) {
            await unpinCheckpointPromotion(transaction, "aws", previous, key);
          }
          await transaction.put(key, next);
          await pinCheckpointPromotion(transaction, "aws", next, key, checkpoint);
        };
        if (catalogOnly) {
          await publish(promotedAWSImageVariantKey(next));
          return next;
        }
        await publish(promotedAWSImageCatalogKey(next));
        if (target === "linux" && next.os) {
          await publish(promotedAWSLinuxOSImageKey(next));
        }
        if (
          target === "linux" &&
          (!next.os || next.os === "ubuntu:24.04") &&
          legacyPromotedAWSImageCompatible(next)
        ) {
          await publish(legacyPromotedAWSImageKey());
        }
        await publish(promotedAWSImageKey(next));
        return next;
      });
      return { image: promoted };
    } catch (error) {
      if (error instanceof InvalidImageCapabilitiesError) {
        return json(
          {
            error: "invalid_image_capabilities",
            message: coordinatorErrorMessage(this.env, error),
          },
          { status: 400 },
        );
      }
      throw error;
    }
  }

  async deleteSSHKey(name: string, leaseID: string): Promise<void> {
    await this.client.deleteSSHKey(name, leaseID);
  }

  hourlyPriceUSD(
    serverType: string,
    config: ReturnType<typeof leaseConfig>,
  ): Promise<number | undefined> {
    // EC2 spot history is not an on-demand quote. Let cost accounting use an
    // explicit override or its conservative AWS fallback for on-demand leases.
    if (config.capacityMarket === "on-demand") return Promise.resolve(undefined);
    const region = config.awsRegion || this.region;
    const client = region === this.region ? this.client : new EC2SpotClient(this.env, region);
    return client.hourlySpotPriceUSD(serverType);
  }

  private async promotedImage(config: {
    target: TargetOS;
    architecture?: string;
    os?: string;
    serverType: string;
    awsRegion: string;
    imageRequirements: LeaseConfig["imageRequirements"];
  }): Promise<PromotedImageRecord | undefined> {
    const architecture = awsImageArchitectureForLease(
      config.target,
      config.serverType,
      config.architecture,
    );
    if (hasImageRequirements(config.imageRequirements)) {
      const imageScope = {
        target: config.target,
        ...(config.os ? { os: config.os } : {}),
        architecture,
        serverType: config.serverType,
        region: config.awsRegion,
      };
      const [selected, catalog, variants] = await Promise.all([
        this.storage.get<PromotedImageRecord>(promotedAWSImageKey(imageScope)),
        this.storage.list<PromotedImageRecord>({
          prefix: promotedAWSImageCatalogPrefix(imageScope),
        }),
        this.storage.list<PromotedImageRecord>({
          prefix: promotedAWSImageVariantPrefix(imageScope),
        }),
      ]);
      const candidates = [
        ...[selected, ...catalog.values()]
          .filter((image): image is PromotedImageRecord => Boolean(image))
          .map((image) => ({ image, variant: false })),
        ...[...variants.values()].map((image) => ({ image, variant: true })),
      ];
      return candidates
        .filter(({ image }) =>
          imageSatisfiesRequirements(image.capabilities, config.imageRequirements),
        )
        .filter(
          ({ image, variant }) =>
            !variant || catalogOnlyImageRequested(image.variantSelectors, config.imageRequirements),
        )
        .toSorted(
          (left, right) =>
            right.image.promotedAt.localeCompare(left.image.promotedAt) ||
            left.image.id.localeCompare(right.image.id),
        )[0]?.image;
    }
    const scoped = await this.storage.get<PromotedImageRecord>(
      promotedAWSImageKey({
        target: config.target,
        ...(config.os ? { os: config.os } : {}),
        architecture,
        serverType: config.serverType,
        region: config.awsRegion,
      }),
    );
    if (scoped) {
      return scoped;
    }
    if (config.target === "macos") {
      return this.storage.get<PromotedImageRecord>(
        legacyScopedPromotedAWSImageKey({
          target: config.target,
          architecture,
          region: config.awsRegion,
        }),
      );
    }
    if (config.target !== "linux") {
      return scoped;
    }
    if (config.os) {
      const osScoped = await this.storage.get<PromotedImageRecord>(
        promotedAWSLinuxOSImageKey({
          os: config.os,
          architecture,
        }),
      );
      if (osScoped) {
        return osScoped;
      }
    }
    if ((!config.os || config.os === "ubuntu:24.04") && architecture === "x86_64") {
      const legacy = await this.storage.get<PromotedImageRecord>(legacyPromotedAWSImageKey());
      if (legacy && legacyPromotedAWSImageCompatible(legacy)) {
        return legacy;
      }
    }
    return undefined;
  }

  private async promotedImagesForFallback(config: LeaseConfig): Promise<Record<string, string>> {
    const out: Record<string, string> = {};
    for (const region of awsRegionCandidates(config, this.env, config.awsRegion)) {
      for (const serverType of awsLaunchCandidates(config)) {
        // oxlint-disable-next-line eslint/no-await-in-loop -- storage reads preserve deterministic fallback key construction.
        const promoted = await this.promotedImage({
          target: config.target,
          architecture: config.architecture,
          os: config.os,
          serverType,
          awsRegion: region,
          imageRequirements: config.imageRequirements,
        });
        if (promoted?.id) {
          out[awsPromotedAMIConfigKey(region, serverType)] = promoted.id;
        }
      }
    }
    return out;
  }

  private async promotedImageByID(imageID: string): Promise<PromotedImageRecord | undefined> {
    const matches = await this.promotedImagesByID(imageID);
    return matches.find((image) => image.region === this.region);
  }

  private async promotedImagesByID(imageID: string): Promise<PromotedImageRecord[]> {
    const promoted = await this.storage.list<PromotedImageRecord>({
      prefix: promotedAWSImagePrefix(),
    });
    return [...promoted.values()].filter((image) => image.id === imageID);
  }

  private async variantImagesByID(imageID: string): Promise<PromotedImageRecord[]> {
    const variants = await this.storage.list<PromotedImageRecord>({ prefix: "image:aws:variant:" });
    return [...variants.values()].filter((image) => image.id === imageID);
  }

  private async promotedImageMetadataByID(
    imageID: string,
    region: string,
    known?: ProviderImage,
    storage: ProviderStateStorageView = this.storage,
  ): Promise<PromotedImageRecord | undefined> {
    const [catalog, variants] = await Promise.all([
      storage.list<PromotedImageRecord>({ prefix: "image:aws:catalog:" }),
      storage.list<PromotedImageRecord>({ prefix: "image:aws:variant:" }),
    ]);
    const matches = [
      ...[...catalog.values()]
        .filter((image) => image.id === imageID && image.region === region)
        .map((image) => ({ image, variant: false })),
      ...[...variants.values()]
        .filter((image) => image.id === imageID && image.region === region)
        .map((image) => ({ image, variant: true })),
    ];
    if (known?.region === region && typeof (known as PromotedImageRecord).promotedAt === "string") {
      const knownPromotion = known as PromotedImageRecord;
      const alreadyCataloged = matches.some(
        ({ image, variant }) =>
          !variant &&
          image.promotedAt === knownPromotion.promotedAt &&
          image.target === knownPromotion.target &&
          image.region === knownPromotion.region,
      );
      if (!alreadyCataloged) matches.push({ image: knownPromotion, variant: false });
    }
    return mergedPromotedAWSImageHistory(matches);
  }
}

async function deletePromotedAWSImageRecords(
  storage: ProviderStateStorageView,
  imageID: string,
  prefixes: string[],
  options: { region?: string } = {},
): Promise<number> {
  const catalogs = await Promise.all(
    prefixes.map(async (prefix) => await storage.list<PromotedImageRecord>({ prefix })),
  );
  const entries = catalogs.flatMap((catalog) =>
    [...catalog.entries()].filter(
      ([, image]) =>
        image.id === imageID && (options.region === undefined || image.region === options.region),
    ),
  );
  await entries.reduce(async (pending, [key, image]) => {
    await pending;
    await unpinCheckpointPromotion(storage, "aws", image, key);
    await storage.delete(key);
  }, Promise.resolve());
  return entries.length;
}

async function imageCatalogTransaction<T>(
  storage: ProviderStateStorage,
  callback: (transaction: ProviderStateStorageView) => Promise<T>,
): Promise<T> {
  if (typeof storage.transaction !== "function") {
    throw new Error("transactional image catalog storage is required");
  }
  return storage.transaction(callback);
}

function mergedPromotedAWSImageHistory(
  records: Array<{ image: PromotedImageRecord; variant: boolean }>,
): PromotedImageRecord | undefined {
  const ordered = records.toSorted(
    (left, right) =>
      left.image.promotedAt.localeCompare(right.image.promotedAt) ||
      Number(left.variant) - Number(right.variant) ||
      left.image.id.localeCompare(right.image.id),
  );
  const latest = ordered.at(-1);
  if (!latest) return undefined;
  const capabilities = ordered.reduce<ImageCapabilities | undefined>(
    (inventory, { image }) => mergeImageCapabilityInventory(inventory, image.capabilities),
    undefined,
  );
  return { ...latest.image, ...(capabilities ? { capabilities } : {}) };
}

function mergeImageCapabilityInventory(
  inventory: ImageCapabilities | undefined,
  additions: ImageCapabilities | undefined,
): ImageCapabilities | undefined {
  if (!additions) return inventory;
  return {
    ...inventory,
    ...additions,
    ...(inventory?.sdks || additions.sdks
      ? { sdks: { ...inventory?.sdks, ...additions.sdks } }
      : {}),
    ...(inventory?.runtimes || additions.runtimes
      ? { runtimes: { ...inventory?.runtimes, ...additions.runtimes } }
      : {}),
  };
}

function isRetryableAWSRegionProvisioningError(message: string): boolean {
  return (
    isRetryableAWSProvisioningError(message) ||
    message.includes("quota ") ||
    message.includes("capacity")
  );
}

export function redactReadyPoolEntry(entry: ReadyPoolEntry): ReadyPoolEntry {
  const { borrowToken: _borrowToken, ...redacted } = entry;
  void _borrowToken;
  return redacted;
}
