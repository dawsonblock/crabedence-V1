import { afterEach, describe, expect, it, vi } from "vitest";

import type { BridgeTicketKind, LeaseBridgeTicketRecord } from "../src/bridge-tickets";
import type { LeaseRecord } from "../src/types";
import {
  parityFixture,
  parityLease,
  parityMachine,
  parityProvider,
  ParityStorage,
  type CoordinatorParityKind,
  type CoordinatorParityNodeMocks,
  type ParityProviderCalls,
} from "./coordinator-parity-fixture";

// The "node" leg runs the real NodeCoordinatorRuntime; only its PostgreSQL
// storage and pg-boss queue are substituted so the suite stays hermetic. A real
// DATABASE_URL leg is tracked separately (see docs/plan/portable-coordinator.md).
const nodeMocks = vi.hoisted(() => ({
  storage: undefined as unknown,
  boss: undefined as unknown,
}));
vi.mock("../node/postgres-storage", () => ({
  PostgresCoordinatorStorage: function () {
    return nodeMocks.storage;
  },
}));
vi.mock("pg-boss", () => ({
  PgBoss: function () {
    return nodeMocks.boss;
  },
}));

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  await Promise.all(cleanups.splice(0).map((cleanup) => cleanup()));
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

async function fixture(
  kind: CoordinatorParityKind,
  options: {
    env?: Record<string, string>;
    storage?: ParityStorage;
    providers?: Record<string, unknown>;
    behavior?: Parameters<typeof parityProvider>[1];
  } = {},
) {
  const calls: ParityProviderCalls = {
    created: [],
    released: [],
    deleted: [],
    deletedSSHKeys: [],
  };
  const handle = await parityFixture(kind, {
    env: options.env,
    storage: options.storage,
    nodeMocks: nodeMocks as CoordinatorParityNodeMocks,
    providers: {
      hetzner: parityProvider(calls, options.behavior) as never,
      ...options.providers,
    } as never,
  });
  cleanups.push(() => handle.stop());
  // Attach calls without spreading: handle getters (runtime/fleet/jobs) must
  // stay live so they follow restart() to the replacement runtime.
  (handle as unknown as { calls: ParityProviderCalls }).calls = calls;
  return handle as typeof handle & { calls: ParityProviderCalls };
}

const leaseCreateBody = {
  provider: "hetzner",
  target: "linux",
  serverType: "cx23",
  sshPublicKey: "ssh-ed25519 parity-contract",
};

async function createLease(
  f: Awaited<ReturnType<typeof fixture>>,
  body: Record<string, unknown> = {},
): Promise<LeaseRecord> {
  const create = await f.fetch(
    f.request("POST", "/v1/leases", { body: { ...leaseCreateBody, ...body } }),
  );
  expect(create.status).toBe(201);
  return ((await create.json()) as { lease: LeaseRecord }).lease;
}

const ticketCases = [
  {
    kind: "webvnc-agent",
    path: "webvnc",
    namespace: "webvnc-ticket:",
    prefix: "wvnc_",
    body: {},
  },
  {
    kind: "code-agent",
    path: "code",
    namespace: "code-ticket:",
    prefix: "code_",
    body: {},
  },
  {
    kind: "egress-host",
    path: "egress",
    namespace: "egress-ticket:",
    prefix: "egress_",
    body: { role: "host", sessionID: "parity_egress", allow: ["example.com"] },
  },
  {
    kind: "egress-client",
    path: "egress",
    namespace: "egress-ticket:",
    prefix: "egress_",
    body: { role: "client", sessionID: "parity_egress", allow: ["example.com"] },
  },
] satisfies {
  kind: BridgeTicketKind;
  path: string;
  namespace: string;
  prefix: string;
  body: object;
}[];

for (const kind of ["cloudflare", "node"] as const) {
  describe(`${kind} coordinator parity`, () => {
    it("serves health unauthenticated and rejects unauthenticated API access", async () => {
      const f = await fixture(kind);
      const health = await f.fetch(f.request("GET", "/v1/health", { auth: false }));
      expect(health.status).toBe(200);
      expect(await health.json()).toMatchObject({ ok: true });

      const unauthorized = await f.fetch(f.request("GET", "/v1/leases", { auth: false }));
      expect(unauthorized.status).toBe(401);
    });

    it("creates, reads, heartbeats, and releases a lease", async () => {
      const f = await fixture(kind);
      const lease = await createLease(f);
      expect(f.calls.created).toEqual([lease.id]);

      const inspect = await f.fetch(f.request("GET", `/v1/leases/${lease.id}`));
      expect(inspect.status).toBe(200);
      expect(await inspect.json()).toMatchObject({
        lease: { id: lease.id, state: "active" },
      });

      const heartbeat = await f.fetch(
        f.request("POST", `/v1/leases/${lease.id}/heartbeat`, {
          body: { idleTimeoutSeconds: 120 },
        }),
      );
      expect(heartbeat.status).toBe(200);
      expect(await heartbeat.json()).toMatchObject({
        lease: { id: lease.id, state: "active" },
      });

      const release = await f.fetch(
        f.request("POST", `/v1/leases/${lease.id}/release`, { body: { delete: true } }),
      );
      expect(release.status).toBe(200);
      expect(await f.stored<LeaseRecord>(`lease:${lease.id}`)).toMatchObject({
        state: expect.stringMatching(/released|expired/),
      });

      // Provider cleanup is claimed at release and completed by maintenance.
      await f.alarm();
      expect(f.calls.released.map((entry) => entry.id)).toContain(lease.id);
      expect(f.calls.deleted).toContain(lease.cloudID);
    });

    it("preserves leases, runs, and bridge tickets across a restart", async () => {
      const f = await fixture(kind);
      const lease = await createLease(f, { desktop: true, code: true });

      const run = await f.fetch(
        f.request("POST", "/v1/runs", {
          body: {
            provider: "hetzner",
            class: "standard",
            serverType: "cx23",
            command: ["pnpm", "test"],
          },
        }),
      );
      expect(run.status).toBe(201);
      const { run: created } = (await run.json()) as { run: { id: string } };

      const ticket = await f.fetch(
        f.request("POST", `/v1/leases/${lease.id}/webvnc/ticket`, { body: {} }),
      );
      expect(ticket.status).toBe(200);
      const { ticket: minted } = (await ticket.json()) as { ticket: string };

      await f.restart();

      const inspect = await f.fetch(f.request("GET", `/v1/leases/${lease.id}`));
      expect(inspect.status).toBe(200);
      expect(await inspect.json()).toMatchObject({
        lease: { id: lease.id, state: "active" },
      });

      const heartbeat = await f.fetch(
        f.request("POST", `/v1/leases/${lease.id}/heartbeat`, {
          body: { idleTimeoutSeconds: 120 },
        }),
      );
      expect(heartbeat.status).toBe(200);

      const runRecord = await f.fetch(f.request("GET", `/v1/runs/${created.id}`));
      expect(runRecord.status).toBe(200);

      expect(await f.stored(`webvnc-ticket:${minted}`)).toMatchObject({
        leaseID: lease.id,
      });

      const release = await f.fetch(
        f.request("POST", `/v1/leases/${lease.id}/release`, { body: { delete: true } }),
      );
      expect(release.status).toBe(200);
    });

    it("deletes expired resources after a restart without client traffic", async () => {
      const f = await fixture(kind);
      const lease = await createLease(f);

      // Expire the lease while the "process" is down.
      const stored = (await f.stored<LeaseRecord>(`lease:${lease.id}`))!;
      await f.seed(`lease:${lease.id}`, {
        ...stored,
        expiresAt: new Date(Date.now() - 1_000).toISOString(),
      });

      await f.restart();
      await f.alarm();

      const expired = await f.stored<LeaseRecord>(`lease:${lease.id}`);
      expect(expired?.state).not.toBe("active");
      expect(f.calls.released.map((entry) => entry.id)).toContain(lease.id);
      expect(f.calls.deleted).toContain(lease.cloudID);
    });

    it("keeps the active-lease limit under concurrent creates", async () => {
      const f = await fixture(kind, {
        env: { CRABBOX_MAX_ACTIVE_LEASES_PER_OWNER: "1" },
      });
      const [first, second] = await Promise.all([
        f.fetch(f.request("POST", "/v1/leases", { body: leaseCreateBody })),
        f.fetch(f.request("POST", "/v1/leases", { body: leaseCreateBody })),
      ]);
      const statuses = [first.status, second.status].toSorted((a, b) => a - b);
      expect(statuses).toEqual([201, 429]);
      expect(f.calls.created).toHaveLength(1);
    });

    it("preserves a lease across a crash restart", async () => {
      const f = await fixture(kind);
      const lease = await createLease(f);

      // SIGKILL-style restart: nothing is drained or gracefully stopped.
      await f.restart({ graceful: false });

      const inspect = await f.fetch(f.request("GET", `/v1/leases/${lease.id}`));
      expect(inspect.status).toBe(200);
      expect(await inspect.json()).toMatchObject({
        lease: { id: lease.id, state: "active" },
      });
      const heartbeat = await f.fetch(
        f.request("POST", `/v1/leases/${lease.id}/heartbeat`, {
          body: { idleTimeoutSeconds: 120 },
        }),
      );
      expect(heartbeat.status).toBe(200);
    });

    it("reconciles a lease stranded mid-provisioning by a dead coordinator", async () => {
      const f = await fixture(kind, {
        behavior: {
          recoverServer: (lease) =>
            parityMachine({
              id: lease.id,
              provider: "hetzner",
              slug: lease.slug ?? "parity-lease",
              owner: lease.owner,
            }),
        },
      });
      const lease = await createLease(f);
      const stored = (await f.stored<LeaseRecord>(`lease:${lease.id}`))!;

      // Model a create whose provider call settled but whose coordinator process
      // died before publishing the result: still provisioning, resource may exist.
      await f.seed(`lease:${lease.id}`, {
        ...stored,
        state: "provisioning",
        cloudID: "",
        provisioningRequestStartedAt: new Date(Date.now() - 60_000).toISOString(),
        provisioningRequestSettledAt: new Date(Date.now() - 30_000).toISOString(),
        provisioningRecoveryObservedAt: new Date(Date.now() - 3_600_000).toISOString(),
      });

      await f.restart();
      await f.alarm();

      const reconciled = await f.stored<LeaseRecord>(`lease:${lease.id}`);
      expect(reconciled?.state).not.toBe("provisioning");
      expect(reconciled?.cloudID).toBe(`parity-${lease.id}`);
    });

    it("delivers the scheduled alarm through the job queue", async () => {
      const f = await fixture(kind);
      const lease = await createLease(f);
      const stored = (await f.stored<LeaseRecord>(`lease:${lease.id}`))!;
      await f.seed(`lease:${lease.id}`, {
        ...stored,
        expiresAt: new Date(Date.now() - 1_000).toISOString(),
      });

      if (kind === "node" && f.queueAlarm) {
        // The production wake path: pg-boss delivers coordinator-alarm work.
        await f.queueAlarm();
      } else {
        await f.alarm();
      }

      const expired = await f.stored<LeaseRecord>(`lease:${lease.id}`);
      expect(expired?.state).not.toBe("active");
    });

    it.skipIf(kind === "cloudflare")(
      "refuses a second coordinator replica on the same database",
      async () => {
        const f = await fixture(kind);
        // DOs are intrinsic singletons; the node leg enforces the equivalent
        // contract with the storage-level coordinator lock.
        await expect(
          parityFixture("node", {
            nodeMocks: nodeMocks as CoordinatorParityNodeMocks,
            storage: f.storage as ParityStorage,
            providers: { hetzner: parityProvider(f.calls) as never },
          }),
        ).rejects.toThrow(/advisory lock|another instance/);
      },
    );

    it("serves the portal to an authenticated principal", async () => {
      const f = await fixture(kind);
      const portal = await f.fetch(f.request("GET", "/portal"));
      expect(portal.status).toBe(200);
      expect(portal.headers.get("content-type")).toContain("text/html");
    });

    it("records run events and survives a restart", async () => {
      const f = await fixture(kind);
      const create = await f.fetch(
        f.request("POST", "/v1/runs", {
          body: {
            provider: "hetzner",
            class: "standard",
            serverType: "cx23",
            command: ["pnpm", "test"],
          },
        }),
      );
      expect(create.status).toBe(201);
      const { run } = (await create.json()) as { run: { id: string; phase: string } };

      const event = await f.fetch(
        f.request("POST", `/v1/runs/${run.id}/events`, {
          body: { type: "stdout", stream: "stdout", data: "ok\n" },
        }),
      );
      expect(event.status).toBe(201);

      await f.restart();

      const finish = await f.fetch(
        f.request("POST", `/v1/runs/${run.id}/finish`, {
          body: { exitCode: 0, log: "ok\n" },
        }),
      );
      expect(finish.status).toBe(200);

      const events = await f.fetch(f.request("GET", `/v1/runs/${run.id}/events`));
      expect(events.status).toBe(200);
      const { events: recorded } = (await events.json()) as {
        events: Array<{ type: string }>;
      };
      expect(recorded.map((entry) => entry.type)).toEqual(
        expect.arrayContaining(["run.started", "stdout", "command.finished"]),
      );
    });

    it("creates, lists, and preserves a checkpoint across a restart", async () => {
      const awsCalls: ParityProviderCalls = {
        created: [],
        released: [],
        deleted: [],
        deletedSSHKeys: [],
      };
      const f = await fixture(kind, {
        providers: { aws: parityProvider(awsCalls) as never },
      });
      const lease = parityLease({
        id: "cbx_000000000008",
        provider: "aws",
        cloudID: "i-parity0001",
        region: "eu-west-1",
        keep: true,
      });
      await f.seed(`lease:${lease.id}`, lease);

      const create = await f.fetch(
        f.request("POST", "/v1/checkpoints", {
          body: {
            id: "chk_parity0001",
            leaseID: lease.id,
            name: "parity-checkpoint",
            strategy: "disk-snapshot",
            retention: { mode: "manual" },
            workdir: "/work/source",
            repo: { name: "my-app", head: "abc123" },
          },
        }),
      );
      expect(create.status).toBe(201);

      await f.restart();

      const list = await f.fetch(f.request("GET", "/v1/checkpoints"));
      expect(list.status).toBe(200);
      const { checkpoints } = (await list.json()) as {
        checkpoints: Array<{ id: string; state: string }>;
      };
      expect(checkpoints.map((entry) => entry.id)).toContain("chk_parity0001");
    });

    it("records usage accounting for the lease", async () => {
      const f = await fixture(kind);
      await createLease(f);

      const usage = await f.fetch(f.request("GET", "/v1/usage"));
      expect(usage.status).toBe(200);
      const { usage: report } = (await usage.json()) as {
        usage: {
          activeLeases: number;
          byProvider: Array<{ key: string; activeLeases: number }>;
        };
      };
      expect(report.activeLeases).toBe(1);
      expect(report.byProvider).toContainEqual(
        expect.objectContaining({ key: "hetzner", activeLeases: 1 }),
      );
    });

    it.each(ticketCases)("mints and durably stores $kind bridge tickets", async (item) => {
      const f = await fixture(kind);
      const lease = parityLease({
        id: "cbx_parity000007",
        desktop: true,
        code: true,
      });
      await f.seed(`lease:${lease.id}`, lease);

      const mint = await f.fetch(
        f.request("POST", `/v1/leases/${lease.id}/${item.path}/ticket`, {
          body: item.body,
        }),
      );
      expect(mint.status).toBe(200);
      const ticket = (await mint.json()) as {
        ticket: string;
        leaseID: string;
        expiresAt: string;
      };
      expect(ticket.ticket).toMatch(new RegExp(`^${item.prefix}[a-f0-9]{32}$`));
      expect(ticket.leaseID).toBe(lease.id);
      expect(
        await f.stored<LeaseBridgeTicketRecord>(`${item.namespace}${ticket.ticket}`),
      ).toMatchObject({
        leaseID: lease.id,
        owner: lease.owner,
      });
    });
  });
}
