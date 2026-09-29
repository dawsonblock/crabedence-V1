import { afterEach, describe, expect, it, vi } from "vitest";

import type { BridgeTicketKind, LeaseBridgeTicketRecord } from "../src/bridge-tickets";
import type { LeaseRecord, RunRecord } from "../src/types";
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

// Evidence parity helpers: build a spec-compliant RunEvidenceV1 (canonical
// sorted-key JSON, raw-hex digest) and a real Ed25519-signed v3 terminal
// receipt binding that digest, mirroring what the Go CLI submits.

function parityStableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(parityStableValue);
  if (!value || typeof value !== "object") return value ?? null;
  return Object.fromEntries(
    Object.entries(value)
      .toSorted(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, entry]) => [key, parityStableValue(entry)]),
  );
}

async function parityEvidenceDigest(evidence: Record<string, unknown>): Promise<string> {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(JSON.stringify(parityStableValue({ ...evidence, digest: "" })));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function parityPlainDigest(value: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", value));
  return `sha256:${[...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

async function parityPrefixedDigest(prefix: string, values: string[]): Promise<string> {
  const encoder = new TextEncoder();
  const parts = [encoder.encode(prefix)];
  for (const value of values) {
    const encoded = encoder.encode(value);
    const length = new Uint8Array(4);
    new DataView(length.buffer).setUint32(0, encoded.byteLength);
    parts.push(length, encoded);
  }
  const payload = new Uint8Array(parts.reduce((total, part) => total + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) {
    payload.set(part, offset);
    offset += part.byteLength;
  }
  return parityPlainDigest(payload);
}

async function parityEvidenceBundle(input: {
  run: Pick<RunRecord, "id" | "provider" | "command" | "startedAt">;
  exitCode?: number;
  syncMs?: number;
  commandMs?: number;
  log?: string;
}): Promise<{ evidence: Record<string, unknown>; receipt: Record<string, unknown> }> {
  const exitCode = input.exitCode ?? 0;
  const syncMs = input.syncMs ?? 200;
  const commandMs = input.commandMs ?? 800;
  const log = input.log ?? "ok\n";
  const evidence: Record<string, unknown> = {
    schema_version: 1,
    evidence_type: "run",
    provider: input.run.provider,
    run_id: input.run.id,
    exit_code: exitCode,
    run_status: exitCode === 0 ? "succeeded" : "failed",
    total_ms: syncMs + commandMs,
    command_ms: commandMs,
    sync_ms: syncMs,
  };
  evidence.digest = await parityEvidenceDigest(evidence);

  const started = new Date(input.run.startedAt);
  const ended = new Date(started.getTime() + syncMs + commandMs);
  const key = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", key.publicKey));
  const receipt: Record<string, unknown> = {
    schema_version: 3,
    receipt_type: "terminal",
    started_at: started.toISOString(),
    ended_at: ended.toISOString(),
    provider: input.run.provider,
    run_id: input.run.id,
    command: input.run.command.join(" "),
    command_sha256: await parityPrefixedDigest("crabbox-command-v1\0", input.run.command),
    exit_code: exitCode,
    sync_ms: syncMs,
    command_ms: commandMs,
    duration_ms: syncMs + commandMs,
    log_sha256: await parityPlainDigest(new TextEncoder().encode(log)),
    retained_log_sha256: await parityPlainDigest(new TextEncoder().encode(log)),
    log_truncated: false,
    evidence_sha256: evidence.digest,
    public_key: Buffer.from(publicKey).toString("base64"),
    signer: await parityPlainDigest(publicKey),
  };
  const fields = [
    "schema_version",
    "receipt_type",
    "started_at",
    "ended_at",
    "provider",
    "lease_id",
    "slug",
    "run_id",
    "command",
    "command_sha256",
    "exit_code",
    "sync_ms",
    "command_ms",
    "duration_ms",
    "log_sha256",
    "retained_log_sha256",
    "log_truncated",
    "evidence_sha256",
    "public_key",
    "signer",
  ];
  const encoder = new TextEncoder();
  const parts = [encoder.encode("crabbox-terminal-receipt-v3\0")];
  for (const field of fields) {
    const encoded = encoder.encode(String(receipt[field] ?? ""));
    const length = new Uint8Array(4);
    new DataView(length.buffer).setUint32(0, encoded.byteLength);
    parts.push(length, encoded);
  }
  const signing = new Uint8Array(parts.reduce((total, part) => total + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) {
    signing.set(part, offset);
    offset += part.byteLength;
  }
  receipt.signature = Buffer.from(
    await crypto.subtle.sign("Ed25519", key.privateKey, signing),
  ).toString("base64");
  return { evidence, receipt };
}

async function createRun(f: Awaited<ReturnType<typeof fixture>>): Promise<RunRecord> {
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
  return ((await create.json()) as { run: RunRecord }).run;
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

    // Evidence parity: the same authenticated RunEvidenceV1 + signed v3
    // receipt bundle must be accepted, stored, and rejected identically on
    // both the Cloudflare DO and Node backends.
    it("accepts a run finish with authenticated evidence and stores the bundle", async () => {
      const f = await fixture(kind);
      const run = await createRun(f);
      const bundle = await parityEvidenceBundle({ run });
      const finish = await f.fetch(
        f.request("POST", `/v1/runs/${run.id}/finish`, {
          body: {
            exitCode: 0,
            syncMs: 200,
            commandMs: 800,
            log: "ok\n",
            receipt: bundle.receipt,
            evidence: bundle.evidence,
          },
        }),
      );
      expect(finish.status).toBe(200);
      const stored = (await f.stored<RunRecord>(`run:${run.id}`))!;
      expect(stored.evidence).toEqual(bundle.evidence as never);
      expect(stored.terminalReceipt).toEqual(bundle.receipt as never);
      const receipt = await f.fetch(f.request("GET", `/v1/runs/${run.id}/receipt`));
      expect(receipt.status).toBe(200);
    });

    it("rejects a run finish with tampered evidence and fails closed", async () => {
      const f = await fixture(kind);
      const run = await createRun(f);
      const bundle = await parityEvidenceBundle({ run });
      const tampered = {
        ...bundle.evidence,
        total_ms: 999,
      };
      const finish = await f.fetch(
        f.request("POST", `/v1/runs/${run.id}/finish`, {
          body: {
            exitCode: 0,
            syncMs: 200,
            commandMs: 800,
            log: "ok\n",
            receipt: bundle.receipt,
            evidence: tampered,
          },
        }),
      );
      expect(finish.status).toBe(400);
      const stored = (await f.stored<RunRecord>(`run:${run.id}`))!;
      expect(stored.state).toBe("running");
      expect(stored.evidence).toBeUndefined();
    });

    it("rejects evidence submitted without a receipt binding", async () => {
      const f = await fixture(kind);
      const run = await createRun(f);
      const bundle = await parityEvidenceBundle({ run });
      const finish = await f.fetch(
        f.request("POST", `/v1/runs/${run.id}/finish`, {
          body: {
            exitCode: 0,
            syncMs: 200,
            commandMs: 800,
            log: "ok\n",
            evidence: bundle.evidence,
          },
        }),
      );
      expect(finish.status).toBe(400);
      const stored = (await f.stored<RunRecord>(`run:${run.id}`))!;
      expect(stored.state).toBe("running");
      expect(stored.evidence).toBeUndefined();
    });

    it("rejects evidence whose digest does not match the receipt binding", async () => {
      const f = await fixture(kind);
      const run = await createRun(f);
      const bundle = await parityEvidenceBundle({ run });
      // Fresh, internally-consistent evidence for a different outcome: its
      // digest is valid but does not match the receipt's signed binding.
      const other = await parityEvidenceBundle({ run, exitCode: 0, syncMs: 300 });
      const finish = await f.fetch(
        f.request("POST", `/v1/runs/${run.id}/finish`, {
          body: {
            exitCode: 0,
            syncMs: 200,
            commandMs: 800,
            log: "ok\n",
            receipt: bundle.receipt,
            evidence: other.evidence,
          },
        }),
      );
      expect(finish.status).toBe(400);
      const stored = (await f.stored<RunRecord>(`run:${run.id}`))!;
      expect(stored.state).toBe("running");
      expect(stored.evidence).toBeUndefined();
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

// Authority loss is a Node/PostgreSQL concern: only the advisory-lock backend
// can silently lose its session. The Cloudflare DO is an intrinsic singleton,
// so the same contract does not apply there. The fail-closed HTTP behavior
// lives in server.ts's request handler (exercised in node-runtime.test.ts);
// these tests cover the runtime-level authority-loss contract that both the
// server and the parity fixture can observe.
describe("node coordinator authority loss", () => {
  it("marks authority as lost when the advisory-lock session dies", async () => {
    const storage = new ParityStorage();
    const f = await fixture("node", { storage });
    expect(f.runtime?.lostAuthority()).toBe(false);

    storage.simulateLockLost();

    expect(f.runtime?.lostAuthority()).toBe(true);
  });

  it("invokes registered authority-lost callbacks exactly once", async () => {
    const storage = new ParityStorage();
    const f = await fixture("node", { storage });
    const calls: number[] = [];
    f.runtime?.onAuthorityLost(() => {
      calls.push(1);
    });

    // Repeated simulateLockLost() must not re-fire callbacks once authority is
    // already lost: the runtime is single-shot fail-closed.
    storage.simulateLockLost();
    storage.simulateLockLost();

    expect(f.runtime?.lostAuthority()).toBe(true);
    expect(calls).toHaveLength(1);
  });

  it("allows a replacement to acquire the lock after authority loss", async () => {
    const storage = new ParityStorage();
    const f = await fixture("node", { storage });
    expect(f.runtime?.lostAuthority()).toBe(false);

    // The original session dies. After the runtime drains, the lock is free.
    storage.simulateLockLost();
    await f.stop();

    // A fresh ParityStorage instance models a new process connecting to the
    // same database: the advisory lock is now available again.
    const replacement = new ParityStorage();
    const lock = await replacement.acquireCoordinatorLock();
    expect(lock).toBeDefined();
    await lock?.release();
  });

  it("keeps stop() idempotent when authority loss and orderly shutdown race", async () => {
    const storage = new ParityStorage();
    const f = await fixture("node", { storage });

    // Trigger authority loss, then immediately request an orderly stop. Both
    // paths must converge without double-release or thrown errors.
    storage.simulateLockLost();
    await f.stop();
    // A second stop (e.g. from afterEach cleanup) must be a no-op.
    await f.stop();
    expect(f.runtime?.lostAuthority()).toBe(true);
  });
});
