import { afterEach, describe, expect, it, vi } from "vitest";

import { adminGrantVersion } from "../src/auth";
import type { LeaseRecord } from "../src/types";
import {
  parityFixture,
  parityLease,
  parityProvider,
  type CoordinatorParityNodeMocks,
  type ParityProviderCalls,
} from "./coordinator-parity-fixture";

// Socket-level parity for the node leg: `ws` is faked so the real
// NodeCoordinatorRuntime upgrade path (runWithUpgrade → createWebSocketUpgrade →
// acceptWebSocket → attachment + message handlers) is exercised end to end.
// The Cloudflare leg's socket contract is covered by bridge-tickets.test.ts
// (WebSocketPair and 101 responses do not exist in this environment).
interface ParityFakeSocket {
  readyState: number;
  readonly sent: string[];
  emit(event: string, ...args: unknown[]): boolean;
}

const wsState = vi.hoisted(() => ({
  sockets: [] as ParityFakeSocket[],
}));

vi.mock("ws", async () => {
  const { EventEmitter } = await import("node:events");
  class FakeSocket extends EventEmitter {
    static readonly OPEN = 1;
    static readonly CLOSED = 3;
    readyState = FakeSocket.OPEN;
    readonly sent: string[] = [];

    send(data: unknown): void {
      this.sent.push(String(data));
    }

    ping(): void {
      this.emit("pong");
    }

    close(code = 1000, reason: unknown = ""): void {
      this.readyState = FakeSocket.CLOSED;
      this.emit("close", code, Buffer.from(String(reason)));
    }

    terminate(): void {
      this.readyState = FakeSocket.CLOSED;
      this.emit("close", 1006, Buffer.from(""));
    }
  }
  class FakeWebSocketServer {
    handleUpgrade(
      _request: unknown,
      _socket: unknown,
      _head: unknown,
      callback: (socket: FakeSocket) => void,
    ): void {
      const socket = new FakeSocket();
      wsState.sockets.push(socket);
      callback(socket);
    }
  }
  return { WebSocket: FakeSocket, WebSocketServer: FakeWebSocketServer };
});

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
  wsState.sockets.length = 0;
});

async function nodeFixture() {
  const calls: ParityProviderCalls = {
    created: [],
    released: [],
    deleted: [],
    deletedSSHKeys: [],
  };
  const handle = await parityFixture("node", {
    nodeMocks: nodeMocks as CoordinatorParityNodeMocks,
    providers: { hetzner: parityProvider(calls) as never },
  });
  cleanups.push(() => handle.stop());
  (handle as unknown as { calls: ParityProviderCalls }).calls = calls;
  return handle as typeof handle & { calls: ParityProviderCalls };
}

async function connect(f: Awaited<ReturnType<typeof nodeFixture>>, path: string, ticket: string) {
  const context = {
    request: {},
    socket: {},
    head: Buffer.alloc(0),
    upgraded: false,
  };
  const request = f.request("GET", path, {
    auth: false,
    headers: {
      upgrade: "websocket",
      "x-crabbox-bridge-ticket": ticket,
      "x-crabbox-admin-grant-version": await adminGrantVersion(f.env),
    },
  });
  const response = await f.runtime!.runWithUpgrade(context, () => f.fetch(request));
  return { response, upgraded: context.upgraded };
}

const activeSockets = (f: Awaited<ReturnType<typeof nodeFixture>>) => [
  ...(f.runtime!.getWebSockets() as Iterable<unknown>),
];

describe("node coordinator socket parity", () => {
  it("redeems a WebVNC ticket into an accepted, attached, one-use socket", async () => {
    const f = await nodeFixture();
    const lease = parityLease({ id: "cbx_000000000007", desktop: true, code: true });
    await f.seed(`lease:${lease.id}`, lease);

    const mint = await f.fetch(
      f.request("POST", `/v1/leases/${lease.id}/webvnc/ticket`, { body: {} }),
    );
    expect(mint.status).toBe(200);
    const { ticket } = (await mint.json()) as { ticket: string };

    const first = await connect(f, `/v1/leases/${lease.id}/webvnc/agent`, ticket);
    expect(first.response.status).toBe(204);
    expect(first.upgraded).toBe(true);
    expect(wsState.sockets).toHaveLength(1);

    // The ticket is single-use and removed from storage.
    expect(await f.stored(`webvnc-ticket:${ticket}`)).toBeUndefined();
    const replay = await connect(f, `/v1/leases/${lease.id}/webvnc/agent`, ticket);
    expect(replay.response.status).toBe(401);
    expect(replay.upgraded).toBe(false);

    const socket = wsState.sockets[0]!;
    expect(activeSockets(f)).toContain(socket);
    expect(f.runtime!.socketAttachment(socket as unknown as WebSocket)).toMatchObject({
      kind: "webvnc-agent",
      leaseID: lease.id,
    });

    socket.emit("close", 1000, Buffer.from("done"));
    await new Promise((resolve) => setImmediate(resolve));
    expect(activeSockets(f)).not.toContain(socket);
  });

  it("keeps a minted ticket valid across a restart", async () => {
    const f = await nodeFixture();
    const lease = parityLease({ id: "cbx_000000000009", desktop: true, code: true });
    await f.seed(`lease:${lease.id}`, lease);

    const mint = await f.fetch(
      f.request("POST", `/v1/leases/${lease.id}/code/ticket`, { body: {} }),
    );
    expect(mint.status).toBe(200);
    const { ticket } = (await mint.json()) as { ticket: string };

    await f.restart();

    const connected = await connect(f, `/v1/leases/${lease.id}/code/agent`, ticket);
    expect(connected.response.status).toBe(204);
    expect(connected.upgraded).toBe(true);
    expect(await f.stored(`code-ticket:${ticket}`)).toBeUndefined();
  });

  it("closes bridge sockets on shutdown without dropping stored leases", async () => {
    const f = await nodeFixture();
    const lease = parityLease({ id: "cbx_00000000000a", desktop: true });
    await f.seed(`lease:${lease.id}`, lease);
    const mint = await f.fetch(
      f.request("POST", `/v1/leases/${lease.id}/webvnc/ticket`, { body: {} }),
    );
    const { ticket } = (await mint.json()) as { ticket: string };
    const connected = await connect(f, `/v1/leases/${lease.id}/webvnc/agent`, ticket);
    expect(connected.upgraded).toBe(true);

    await f.restart();

    // The replacement process owns the lease state; the old socket is gone.
    const stored = await f.stored<LeaseRecord>(`lease:${lease.id}`);
    expect(stored?.state).toBe("active");
    expect(wsState.sockets[0]!.readyState).toBe(3);
  });
});
