import { afterEach, describe, expect, it } from "vitest";

import type { LeaseRecord } from "../src/types";
import {
  parityFixture,
  parityProvider,
  type ParityProviderCalls,
} from "./coordinator-parity-fixture";

// Live coordinator parity: the same contract runs against the real
// NodeCoordinatorRuntime, PostgresCoordinatorStorage, and pg-boss. Requires a
// writable PostgreSQL database:
//
//   CRABBOX_TEST_DATABASE_URL=postgres://... npx vitest run test/coordinator-parity.live.test.ts
//
// This file intentionally declares no module mocks; `parityFixture("node")`
// constructs the production storage and job queue over `databaseURL`.
const databaseURL = process.env.CRABBOX_TEST_DATABASE_URL;
const runLive = databaseURL ? describe : describe.skip;

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  await Promise.all(cleanups.splice(0).map((cleanup) => cleanup()));
});

async function liveFixture() {
  const calls: ParityProviderCalls = {
    created: [],
    released: [],
    deleted: [],
    deletedSSHKeys: [],
  };
  const suffix = crypto.randomUUID().replaceAll("-", "").slice(0, 8);
  const handle = await parityFixture("node", {
    databaseURL,
    providers: { hetzner: parityProvider(calls) as never },
    env: { CRABBOX_DEFAULT_ORG: `parity-${suffix}` },
  });
  cleanups.push(() => handle.stop());
  (handle as unknown as { calls: ParityProviderCalls }).calls = calls;
  return handle as typeof handle & { calls: ParityProviderCalls };
}

runLive("postgres coordinator parity (live)", () => {
  it("creates, heartbeats, releases, and recovers across a restart", async () => {
    const f = await liveFixture();
    const create = await f.fetch(
      f.request("POST", "/v1/leases", {
        body: {
          provider: "hetzner",
          target: "linux",
          serverType: "cx23",
          sshPublicKey: "ssh-ed25519 parity-live",
        },
      }),
    );
    expect(create.status).toBe(201);
    const { lease } = (await create.json()) as { lease: LeaseRecord };

    const heartbeat = await f.fetch(
      f.request("POST", `/v1/leases/${lease.id}/heartbeat`, {
        body: { idleTimeoutSeconds: 120 },
      }),
    );
    expect(heartbeat.status).toBe(200);

    await f.restart();

    const inspect = await f.fetch(f.request("GET", `/v1/leases/${lease.id}`));
    expect(inspect.status).toBe(200);
    expect(await inspect.json()).toMatchObject({
      lease: { id: lease.id, state: "active" },
    });

    const release = await f.fetch(
      f.request("POST", `/v1/leases/${lease.id}/release`, { body: { delete: true } }),
    );
    expect(release.status).toBe(200);
    await f.alarm();
    expect(f.calls.released.map((entry) => entry.id)).toContain(lease.id);
  });

  it("deletes expired resources after a restart without client traffic", async () => {
    const f = await liveFixture();
    const create = await f.fetch(
      f.request("POST", "/v1/leases", {
        body: {
          provider: "hetzner",
          target: "linux",
          serverType: "cx23",
          sshPublicKey: "ssh-ed25519 parity-live-expiry",
        },
      }),
    );
    expect(create.status).toBe(201);
    const { lease } = (await create.json()) as { lease: LeaseRecord };

    const stored = await f.storage.get<LeaseRecord>(`lease:${lease.id}`);
    await f.storage.put(`lease:${lease.id}`, {
      ...stored!,
      expiresAt: new Date(Date.now() - 1_000).toISOString(),
    });

    await f.restart();
    await f.alarm();

    const expired = await f.storage.get<LeaseRecord>(`lease:${lease.id}`);
    expect(expired?.state).not.toBe("active");
    expect(f.calls.released.map((entry) => entry.id)).toContain(lease.id);
  });

  it("refuses a second replica while the first holds the advisory lock", async () => {
    const f = await liveFixture();
    await expect(
      parityFixture("node", {
        databaseURL,
        providers: { hetzner: parityProvider(f.calls) as never },
      }),
    ).rejects.toThrow(/advisory lock|another instance/);

    // A crashed holder frees the lock: the replacement may then start.
    await f.stop();
    const replacement = await liveFixture();
    const inspect = await replacement.fetch(replacement.request("GET", "/v1/leases"));
    expect(inspect.status).toBe(200);
  });

  it("detects advisory-lock session death and fails closed", async () => {
    const f = await liveFixture();
    // The coordinator is running and holding the advisory lock. Find
    // the PID of the lock-holding backend by querying pg_stat_activity
    // for the coordinator advisory lock query.
    const storage = f.storage as unknown as {
      pool: {
        query: (text: string, params?: unknown[]) => Promise<{ rows: Array<{ pid: number }> }>;
      };
    };
    const result = await storage.pool.query(
      `select pid from pg_stat_activity
       where query like '%pg_try_advisory_lock%'
         and state = 'idle'
       order by query_start desc
       limit 1`,
    );
    expect(result.rows.length).toBeGreaterThan(0);
    const pid = result.rows[0]!.pid;

    // Terminate the lock-holding backend. PostgreSQL will free the
    // advisory lock and emit an error/end event on the client connection.
    await storage.pool.query("select pg_terminate_backend($1)", [pid]);

    // The coordinator should detect authority loss and fail closed.
    // Wait for the authority-loss callback to fire (the node runtime
    // registers it on the lock's onLost callback).
    // Give the coordinator up to 5 seconds to detect the loss.
    const deadline = Date.now() + 5_000;
    let authorityLost = false;
    const runtime = f as unknown as { runtime?: { authorityLost: boolean } };
    while (Date.now() < deadline) {
      if (runtime.runtime?.authorityLost) {
        authorityLost = true;
        break;
      }
      // eslint-disable-next-line no-await-in-loop
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    expect(authorityLost, "coordinator should detect advisory-lock session death").toBe(true);

    // A replacement should be able to acquire the lock now that the
    // old session is dead and PostgreSQL has freed the advisory lock.
    const replacement = await liveFixture();
    const inspect = await replacement.fetch(replacement.request("GET", "/v1/leases"));
    expect(inspect.status).toBe(200);
    await replacement.stop();
  });
});
