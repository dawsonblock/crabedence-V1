import { vi } from "vitest";

import { NodeCoordinatorRuntime } from "../node/node-runtime";
import { AsyncMutex, fleetRequestQueue } from "../node/server-support";
import { routeCoordinatorRequest } from "../src/coordinator-entry";
import type { CoordinatorLock } from "../src/coordinator-runtime";
import { FleetCoordinator, FleetDurableObject } from "../src/fleet";
import { orgKeyForLabel } from "../src/org-identity";
import type { Env, LeaseRecord, ProviderMachine } from "../src/types";
import { ProvisioningTestStorage } from "./provisioning-fixtures";

/**
 * Shared coordinator contract harness.
 *
 * The same `FleetCoordinator` contract is exercised through two runtime legs:
 *
 * - "cloudflare": `FleetDurableObject` over a `DurableObjectState` stub, which
 *   is what `worker/src/index.ts` serves through `routeCoordinatorRequest`.
 * - "node": `NodeCoordinatorRuntime` + `AsyncMutex` dispatch, matching
 *   `worker/node/server.ts` (`fleetRequestQueue` + lifecycle mutex). With a
 *   mocked `pg`/`pg-boss` (see `coordinator-parity.test.ts`) the storage is a
 *   serializable in-memory view; with a real `databaseURL` and no module mocks
 *   the same fixture drives the PostgreSQL-backed runtime.
 *
 * `restart()` discards the runtime and coordinator but keeps storage, modeling
 * a process restart (or, against a real database, a new process on the same
 * PostgreSQL cluster).
 */

export type CoordinatorParityKind = "cloudflare" | "node";

export interface CoordinatorParityNodeMocks {
  // The declaring test file owns the vi.mock module factories; the fixture only
  // sees the mutable cells those factories read.
  storage: unknown;
  boss: unknown;
}

export interface ParityProviderCalls {
  created: string[];
  released: LeaseRecord[];
  deleted: string[];
  deletedSSHKeys: string[];
}

type ParityProviders = ConstructorParameters<typeof FleetCoordinator>[2];

const parityLabelValue = (value: string): string =>
  value
    .trim()
    .replaceAll(/[^a-zA-Z0-9_.-]/g, "_")
    .slice(0, 63)
    .replaceAll(/^[_.-]+|[_.-]+$/g, "") || "unknown";

export function parityMachine(
  lease: Pick<LeaseRecord, "id" | "provider" | "slug"> & { owner?: string },
): ProviderMachine {
  const provider = lease.provider ?? "hetzner";
  return {
    provider,
    id: 4242,
    cloudID: `parity-${lease.id}`,
    name: `crabbox-${lease.slug ?? lease.id}`,
    status: "running",
    serverType: "cx23",
    host: "192.0.2.10",
    labels: {
      crabbox: "true",
      created_by: "crabbox",
      lease: lease.id,
      owner: parityLabelValue(lease.owner ?? "alice@example.com"),
      provider,
      slug: parityLabelValue(lease.slug ?? "parity-lease"),
    },
  };
}

export interface ParityProviderBehavior {
  recoverServer?: (
    lease: LeaseRecord,
  ) => Promise<ProviderMachine | undefined> | ProviderMachine | undefined;
  recoverUnboundProvisioningResource?: (
    lease: LeaseRecord,
  ) => Promise<ProviderMachine | undefined> | ProviderMachine | undefined;
}

export function parityProvider(calls: ParityProviderCalls, behavior: ParityProviderBehavior = {}) {
  const machine = (leaseID: string) =>
    parityMachine({ id: leaseID, provider: "hetzner", slug: "parity-lease" });
  return {
    attachStorage() {},
    async listCrabboxServers() {
      return [] as ProviderMachine[];
    },
    async findServerByLease(leaseID: string) {
      return calls.deleted.includes(`parity-${leaseID}`) ? undefined : machine(leaseID);
    },
    supportsSSHHostKeyInjection() {
      return true;
    },
    restrictedLeaseRequestFields() {
      return [] as string[];
    },
    async createServerWithFallback(_config: unknown, leaseID: string, slug: string, owner: string) {
      calls.created.push(leaseID);
      return {
        server: parityMachine({ id: leaseID, provider: "hetzner", slug, owner }),
        serverType: "cx23",
      };
    },
    ...(behavior.recoverServer
      ? {
          async recoverServer(lease: LeaseRecord) {
            return await behavior.recoverServer?.(lease);
          },
        }
      : {}),
    ...(behavior.recoverUnboundProvisioningResource
      ? {
          async recoverUnboundProvisioningResource(lease: LeaseRecord) {
            return await behavior.recoverUnboundProvisioningResource?.(lease);
          },
        }
      : {}),
    async releaseLease(lease: LeaseRecord) {
      calls.released.push(structuredClone(lease));
      calls.deleted.push(lease.cloudID);
    },
    async deleteServer(id: string) {
      calls.deleted.push(id);
    },
    async deleteSSHKey(name: string) {
      calls.deletedSSHKeys.push(name);
    },
    async hourlyPriceUSD() {
      return 1;
    },
    supportsNativeImages() {
      return false;
    },
    nativeImagesUnsupportedMessage() {
      return "native images are unsupported by the parity provider";
    },
    defaultImageStrategy() {
      return "disk-snapshot" as const;
    },
    validateLeaseImageStrategy() {
      return undefined;
    },
    async createLeaseImage(lease: LeaseRecord, name: string) {
      return {
        id: `parity-image-${name}`,
        name,
        state: "available",
        provider: lease.provider,
        kind: "aws-ebs-snapshot",
        region: lease.region ?? "eu-west-1",
        resourceID: `parity-image-${name}`,
        immutableID: `parity-image-${name}`,
        snapshots: [`parity-image-${name}`],
      };
    },
    async checkpointScope() {
      return { region: "eu-west-1", accountID: "123456789012" };
    },
    async validateCheckpointLeaseScope() {},
    async validateCheckpointImage() {},
    async createCheckpointImage(
      lease: LeaseRecord,
      name: string,
      _noReboot: boolean,
      strategy: "image" | "disk-snapshot",
      ownership: { tokenHash: string; sourceLeaseID: string },
    ) {
      const id = strategy === "image" ? `ami-${name}` : `snap-${name}`;
      return {
        id,
        name,
        state: "available",
        provider: lease.provider,
        kind: strategy === "image" ? "aws-ami" : "aws-ebs-snapshot",
        region: lease.region ?? "eu-west-1",
        accountID: "123456789012",
        resourceID: id,
        immutableID: id,
        checkpointOwnershipHash: ownership.tokenHash,
        checkpointSourceLeaseID: ownership.sourceLeaseID,
        snapshots: [id],
      };
    },
    async deleteCheckpointImage() {},
    async getImage(imageID: string) {
      return {
        id: imageID,
        name: imageID,
        state: "available",
        provider: "aws",
        kind: "aws-ebs-snapshot",
        region: "eu-west-1",
        accountID: "123456789012",
        resourceID: imageID,
        immutableID: imageID,
        snapshots: [imageID],
      };
    },
    async deleteImage() {},
    async storedImageMetadata() {
      return undefined;
    },
    decorateImage(image: never) {
      return image;
    },
    async validateDeleteImage() {
      return undefined;
    },
  };
}

export class ParityStorage extends ProvisioningTestStorage {
  private coordinatorLockHeld = false;
  private lockLostCallbacks: Array<() => void> = [];

  // NodeCoordinatorRuntime drives these PostgresCoordinatorStorage lifecycle
  // methods; initialize/ready are no-ops so committed state survives restarts.
  async initialize(): Promise<void> {}
  async ready(): Promise<void> {}

  async close(): Promise<void> {
    // Storage close models a dead session: the coordinator lease is freed.
    this.coordinatorLockHeld = false;
  }

  async acquireCoordinatorLock(): Promise<CoordinatorLock | undefined> {
    if (this.coordinatorLockHeld) return undefined;
    this.coordinatorLockHeld = true;
    const release = async () => {
      this.coordinatorLockHeld = false;
      this.lockLostCallbacks = [];
    };
    return {
      release,
      onLost: (callback: () => void) => {
        this.lockLostCallbacks.push(callback);
      },
    };
  }

  /** Simulate the advisory-lock session dying (network drop, DB restart). */
  simulateLockLost(): void {
    const callbacks = this.lockLostCallbacks;
    this.lockLostCallbacks = [];
    this.coordinatorLockHeld = false;
    for (const callback of callbacks) callback();
  }
}

export interface ParityBossJobs {
  on: ReturnType<typeof vi.fn>;
  start: ReturnType<typeof vi.fn>;
  stop: ReturnType<typeof vi.fn>;
  createQueue: ReturnType<typeof vi.fn>;
  work: ReturnType<typeof vi.fn>;
  schedule: ReturnType<typeof vi.fn>;
  send: ReturnType<typeof vi.fn>;
  deleteQueuedJobs: ReturnType<typeof vi.fn>;
}

export function parityBossJobs(): ParityBossJobs {
  return {
    on: vi.fn<(...args: unknown[]) => void>(),
    start: vi.fn<() => Promise<void>>(async () => {}),
    stop: vi.fn<() => Promise<void>>(async () => {}),
    createQueue: vi.fn<(...args: unknown[]) => Promise<void>>(async () => {}),
    work: vi.fn<(...args: unknown[]) => Promise<string>>(async () => "parity-worker"),
    schedule: vi.fn<(...args: unknown[]) => Promise<void>>(async () => {}),
    send: vi.fn<(...args: unknown[]) => Promise<string>>(async () => "parity-job"),
    deleteQueuedJobs: vi.fn<(...args: unknown[]) => Promise<void>>(async () => {}),
  };
}

export interface ParityFixtureOptions {
  env?: Partial<Env>;
  providers?: ParityProviders;
  storage?: ParityStorage;
  nodeMocks?: CoordinatorParityNodeMocks;
  databaseURL?: string;
}

export interface ParityHandle {
  kind: CoordinatorParityKind;
  /** The storage the current runtime is actually backed by. */
  readonly storage: import("../src/coordinator-runtime").CoordinatorStorage;
  env: Env;
  fleet: FleetCoordinator;
  /** The live runtime object (present on the node leg). */
  runtime?: NodeCoordinatorRuntime;
  jobs?: ParityBossJobs;
  /** Full entry path: `routeCoordinatorRequest` + runtime-correct dispatch. */
  fetch: (request: Request) => Promise<Response>;
  /** Runtime dispatch only (auth headers must already be in place). */
  dispatch: (request: Request) => Promise<Response>;
  request: (
    method: string,
    path: string,
    init?: { headers?: Record<string, string>; body?: unknown; auth?: boolean },
  ) => Request;
  seed: (key: string, value: unknown) => Promise<void>;
  stored: <T>(key: string) => Promise<T | undefined>;
  /** Run scheduled maintenance and drain runtime-owned maintenance tasks. */
  alarm: () => Promise<void>;
  /**
   * On the node leg, deliver an alarm the way production does: through the
   * handler `NodeCoordinatorRuntime` registered with pg-boss. Undefined on the
   * cloudflare leg (the DO alarm is invoked directly).
   */
  queueAlarm?: () => Promise<void>;
  /**
   * Rebuild the runtime + coordinator over the same storage. The default is an
   * orderly stop; `{ graceful: false }` simulates a crash: in-flight work is
   * dropped and the replacement process sees only committed state.
   */
  restart: (options?: { graceful?: boolean }) => Promise<ParityHandle>;
  stop: () => Promise<void>;
}

const parityEnv = (overrides: Partial<Env> = {}): Env =>
  ({
    CRABBOX_SHARED_TOKEN: "parity-shared-token",
    CRABBOX_SHARED_OWNER: "alice@example.com",
    CRABBOX_DEFAULT_ORG: "example-org",
    CRABBOX_ADMIN_TOKEN: "parity-admin-token",
    ...overrides,
  }) as Env;

export async function parityFixture(
  kind: CoordinatorParityKind,
  options: ParityFixtureOptions = {},
): Promise<ParityHandle> {
  const storage = options.storage ?? new ParityStorage();
  const env = parityEnv(options.env);
  const providers = options.providers ?? {};
  const maintenance = new Set<Promise<unknown>>();
  const track = (operation: Promise<unknown>) => {
    maintenance.add(operation);
    void operation.then(
      () => maintenance.delete(operation),
      () => maintenance.delete(operation),
    );
  };
  const drainMaintenance = async () => {
    while (maintenance.size > 0) {
      // oxlint-disable-next-line eslint/no-await-in-loop -- a completed pass can latch a follow-up pass.
      await Promise.allSettled(maintenance);
    }
  };

  const headers = (auth: boolean, extra: Record<string, string> = {}) => ({
    ...(auth ? { authorization: `Bearer ${env.CRABBOX_SHARED_TOKEN}` } : {}),
    ...extra,
  });
  const request: ParityHandle["request"] = (method, path, init = {}) =>
    new Request(`https://coordinator.test${path}`, {
      method,
      headers: {
        ...(init.body === undefined ? {} : { "content-type": "application/json" }),
        ...headers(init.auth !== false, init.headers ?? {}),
      },
      ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
    });

  if (kind === "cloudflare") {
    let durable: FleetDurableObject;
    const initializers: Promise<unknown>[] = [];
    const makeDurable = () =>
      new FleetDurableObject(
        {
          storage,
          getWebSockets: () => [],
          blockConcurrencyWhile<T>(callback: () => Promise<T>): Promise<T> {
            const initialized = callback();
            initializers.push(initialized);
            return initialized;
          },
          waitUntil(operation: Promise<unknown>): void {
            track(operation);
          },
        } as unknown as DurableObjectState,
        env,
        providers,
      );
    durable = makeDurable();
    let initialized = Promise.all(initializers.splice(0));
    // Constructor recovery (commitAndWake) snapshots storage; await it before the
    // caller seeds, or the recovery commit overwrites freshly written keys.
    await initialized;
    const dispatch = async (incoming: Request) => {
      await initialized;
      return durable.fetch(incoming);
    };
    const handle: ParityHandle = {
      kind,
      storage,
      env,
      get fleet() {
        return durable;
      },
      fetch: (incoming) =>
        routeCoordinatorRequest(incoming, env, async (prepared) => dispatch(prepared)),
      dispatch,
      request,
      seed: async (key, value) => {
        await storage.put(key, value);
      },
      stored: async (key) => await storage.get(key),
      alarm: async () => {
        await durable.alarm();
        await drainMaintenance();
      },
      restart: async (restartOptions = {}) => {
        if (restartOptions.graceful !== false) {
          await initialized;
          await drainMaintenance();
        }
        durable = makeDurable();
        initialized = Promise.all(initializers.splice(0));
        await initialized;
        return handle;
      },
      stop: async () => {
        await drainMaintenance();
      },
    };
    return handle;
  }

  const databaseURL = options.databaseURL ?? "postgresql://synthetic.invalid/parity";
  let node: NodeCoordinatorRuntime;
  let fleet: FleetCoordinator;
  let mutex: AsyncMutex;
  let jobs: ParityBossJobs | undefined;
  let queueAlarm: (() => Promise<void>) | undefined;
  const startNode = async () => {
    jobs = parityBossJobs();
    if (options.nodeMocks) {
      options.nodeMocks.storage = storage;
      options.nodeMocks.boss = jobs;
    }
    node = new NodeCoordinatorRuntime(databaseURL);
    mutex = new AsyncMutex();
    node.setOperationRunner((callback) => mutex.run(callback));
    const ownMaintenance = node.ownMaintenance.bind(node);
    node.ownMaintenance = (operation) => {
      track(operation);
      ownMaintenance(operation);
    };
    fleet = new FleetCoordinator(node, env, providers);
    await node.start(() => fleet.alarm());

    const alarmWork = jobs?.work.mock.calls.find((call) => call[0] === "coordinator-alarm");
    const alarmHandler = alarmWork?.[2] as ((jobs: unknown[]) => Promise<void>) | undefined;
    queueAlarm = alarmHandler ? async () => alarmHandler([]) : undefined;
  };
  const stopped = new WeakSet<NodeCoordinatorRuntime>();
  const stopCurrent = async () => {
    if (stopped.has(node)) return;
    stopped.add(node);
    await node.stop();
  };
  await startNode();
  const dispatch = async (incoming: Request) =>
    fleetRequestQueue(incoming) === "direct"
      ? fleet.fetch(incoming)
      : mutex.run(() => fleet.fetch(incoming));
  const handle: ParityHandle = {
    kind,
    get storage() {
      // With module mocks `node.storage` is the injected ParityStorage; without
      // them it is the real PostgresCoordinatorStorage over `databaseURL`.
      return node.storage;
    },
    env,
    get fleet() {
      return fleet;
    },
    get runtime() {
      return node;
    },
    get jobs() {
      return jobs;
    },
    fetch: (incoming) =>
      routeCoordinatorRequest(incoming, env, async (prepared) => dispatch(prepared)),
    dispatch,
    request,
    seed: async (key, value) => {
      await node.storage.put(key, value);
    },
    stored: async (key) => await node.storage.get(key),
    alarm: async () => {
      await fleet.alarm();
      await drainMaintenance();
    },
    get queueAlarm() {
      return queueAlarm
        ? async () => {
            await queueAlarm();
            await drainMaintenance();
          }
        : undefined;
    },
    restart: async (restartOptions = {}) => {
      if (restartOptions.graceful === false) {
        // Crash simulation: no drain, no boss stop. Closing storage models the
        // dead session (which is what frees a real advisory lock on crash).
        node.beginShutdown();
        await node.storage.close();
      } else {
        await stopCurrent();
      }
      await startNode();
      return handle;
    },
    stop: async () => {
      await stopCurrent();
    },
  };
  return handle;
}

export function parityLease(overrides: Partial<LeaseRecord> = {}): LeaseRecord {
  return {
    id: "cbx_parity000001",
    slug: "parity-lease",
    provider: "hetzner",
    cloudID: "parity-cbx_parity000001",
    owner: "alice@example.com",
    org: orgKeyForLabel("example-org"),
    profile: "default",
    class: "standard",
    serverType: "cx23",
    serverID: 4242,
    serverName: "crabbox-parity-lease",
    providerKey: "crabbox-parity",
    host: "192.0.2.10",
    sshUser: "crabbox",
    sshPort: "2222",
    workRoot: "/work",
    keep: false,
    ttlSeconds: 3600,
    estimatedHourlyUSD: 1,
    maxEstimatedUSD: 1,
    state: "active",
    createdAt: new Date(Date.now() - 60_000).toISOString(),
    updatedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    ...overrides,
  };
}
