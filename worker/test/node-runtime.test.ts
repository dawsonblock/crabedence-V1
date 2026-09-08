import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";

import { beforeEach, describe, expect, it, vi } from "vitest";

import type { CoordinatorStorageView } from "../src/coordinator-runtime";
import { ProvisioningTestStorage } from "./provisioning-fixtures";

type OperationRunner = <T>(callback: () => Promise<T>) => Promise<T>;

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

const mocks = vi.hoisted(() => {
  const boss = {
    on: vi.fn<(...args: unknown[]) => unknown>(),
    start: vi.fn<() => Promise<void>>(async () => {}),
    stop: vi.fn<(...args: unknown[]) => Promise<void>>(async () => {}),
    createQueue: vi.fn<(...args: unknown[]) => Promise<void>>(async () => {}),
    work: vi.fn<(...args: unknown[]) => Promise<string>>(async () => "worker-id"),
    schedule: vi.fn<(...args: unknown[]) => Promise<void>>(async () => {}),
    send: vi.fn<(...args: unknown[]) => Promise<string>>(async () => "job-id"),
    deleteQueuedJobs: vi.fn<(...args: unknown[]) => Promise<void>>(async () => {}),
  };
  const storage = {
    transaction:
      vi.fn<
        (callback: (transaction: CoordinatorStorageView) => Promise<unknown>) => Promise<unknown>
      >(),
    list: vi.fn<(...args: unknown[]) => Promise<Map<string, unknown>>>(),
    initialize: vi.fn<() => Promise<void>>(async () => {}),
    close: vi.fn<() => Promise<void>>(async () => {}),
    get: vi.fn<(key: string) => Promise<unknown>>(async () => undefined),
    put: vi.fn<(key: string, value: unknown) => Promise<void>>(async () => {}),
    delete: vi.fn<(key: string) => Promise<void>>(async () => {}),
    take: vi.fn<(key: string) => Promise<unknown>>(async () => undefined),
    markAuthorityLost: vi.fn<() => void>(),
  };
  return { boss, storage };
});

vi.mock("pg-boss", () => ({
  PgBoss: function PgBoss() {
    return mocks.boss;
  },
}));

vi.mock("../node/postgres-storage", () => ({
  PostgresCoordinatorStorage: function PostgresCoordinatorStorage() {
    return mocks.storage;
  },
}));

import { NodeCoordinatorRuntime } from "../node/node-runtime";
import { AsyncMutex } from "../node/server-support";

describe("NodeCoordinatorRuntime", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    delete (mocks.storage as Record<string, unknown>)["acquireCoordinatorLock"];
    const storage = new ProvisioningTestStorage();
    mocks.storage.get.mockImplementation((key) => storage.get(key));
    mocks.storage.put.mockImplementation((key, value) => storage.put(key, value));
    mocks.storage.delete.mockImplementation((key) => storage.delete(key));
    mocks.storage.transaction.mockImplementation((callback) => storage.transaction(callback));
    mocks.storage.list.mockImplementation((options) =>
      storage.list(options as Parameters<CoordinatorStorageView["list"]>[0]),
    );
  });

  it("refuses to start when the coordinator lock is contended", async () => {
    const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");
    const storage = mocks.storage as typeof mocks.storage & {
      acquireCoordinatorLock: () => Promise<undefined>;
    };
    storage.acquireCoordinatorLock = vi.fn<() => Promise<undefined>>(async () => undefined);

    await expect(runtime.start(async () => {})).rejects.toThrow(/advisory lock/);
    expect(mocks.boss.start).not.toHaveBeenCalled();
  });

  it("releases the coordinator lock on stop", async () => {
    const release = vi.fn<() => Promise<void>>(async () => {});
    const storage = mocks.storage as typeof mocks.storage & {
      acquireCoordinatorLock: () => Promise<{ release(): Promise<void> }>;
    };
    storage.acquireCoordinatorLock = vi.fn<() => Promise<{ release(): Promise<void> }>>(
      async () => ({ release }),
    );
    const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");

    await runtime.start(async () => {});
    await runtime.stop();

    expect(release).toHaveBeenCalledTimes(1);
  });

  it("transitions through explicit lifecycle states", async () => {
    const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");
    expect(runtime.getLifecycleState()).toBe("idle");

    await runtime.start(async () => {});
    expect(runtime.getLifecycleState()).toBe("running");

    await runtime.stop();
    expect(runtime.getLifecycleState()).toBe("stopped");
  });

  it("transitions to stopped when the coordinator lock is contended", async () => {
    const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");
    const storage = mocks.storage as typeof mocks.storage & {
      acquireCoordinatorLock: () => Promise<undefined>;
    };
    storage.acquireCoordinatorLock = vi.fn<() => Promise<undefined>>(async () => undefined);

    await expect(runtime.start(async () => {})).rejects.toThrow(/advisory lock/);
    expect(runtime.getLifecycleState()).toBe("stopped");
  });

  it("transitions to stopped on startup failure", async () => {
    const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");
    mocks.boss.start.mockRejectedValueOnce(new Error("pg-boss start failed"));

    await expect(runtime.start(async () => {})).rejects.toThrow("pg-boss start failed");
    expect(runtime.getLifecycleState()).toBe("stopped");
  });

  it("handles authority loss during startup via abort controller", async () => {
    const release = vi.fn<() => Promise<void>>(async () => {});
    let onLostCallback: (() => void) | undefined;
    const storage = mocks.storage as typeof mocks.storage & {
      acquireCoordinatorLock: () => Promise<{
        release(): Promise<void>;
        onLost?: (callback: () => void) => void;
      }>;
    };
    storage.acquireCoordinatorLock = vi.fn<
      () => Promise<{
        release(): Promise<void>;
        onLost?: (callback: () => void) => void;
      }>
    >(async () => ({
      release,
      onLost: (callback: () => void) => {
        onLostCallback = callback;
      },
    }));

    // Make boss.start block so we can trigger authority loss mid-startup.
    let resolveBossStart: () => void;
    const bossStartPromise = new Promise<void>((resolve) => {
      resolveBossStart = resolve;
    });
    mocks.boss.start.mockReturnValueOnce(bossStartPromise);

    const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");
    const startPromise = runtime.start(async () => {});

    // Wait for the lock to be acquired (the onLost callback is registered).
    await vi.waitFor(() => expect(onLostCallback).toBeDefined());

    // Trigger authority loss during startup.
    onLostCallback!();

    // Resolve boss.start so the startup can proceed (it should abort).
    resolveBossStart!();

    await expect(startPromise).rejects.toThrow(/startup aborted|authority lost/);
    expect(runtime.getLifecycleState()).toBe("stopped");
    expect(runtime.lostAuthority()).toBe(true);
  });

  it("calls onAuthorityLost callback when authority is lost after startup", async () => {
    let onLostCallback: (() => void) | undefined;
    const release = vi.fn<() => Promise<void>>(async () => {});
    const storage = mocks.storage as typeof mocks.storage & {
      acquireCoordinatorLock: () => Promise<{
        release(): Promise<void>;
        onLost?: (callback: () => void) => void;
      }>;
    };
    storage.acquireCoordinatorLock = vi.fn<
      () => Promise<{
        release(): Promise<void>;
        onLost?: (callback: () => void) => void;
      }>
    >(async () => ({
      release,
      onLost: (callback: () => void) => {
        onLostCallback = callback;
      },
    }));

    const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");
    let callbackCalled = false;
    runtime.onAuthorityLost(() => {
      callbackCalled = true;
    });

    await runtime.start(async () => {});
    expect(runtime.getLifecycleState()).toBe("running");

    // Trigger authority loss after startup.
    onLostCallback!();

    expect(callbackCalled).toBe(true);
    expect(runtime.lostAuthority()).toBe(true);
    expect(runtime.getLifecycleState()).toBe("shutting-down");
  });

  it("allows an active alarm to enqueue one successor", async () => {
    const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");

    await runtime.start(async () => {});

    expect(mocks.boss.createQueue).toHaveBeenCalledWith(
      "coordinator-alarm",
      expect.objectContaining({ policy: "short" }),
    );
  });

  it("persists the scheduled alarm time across Node coordinator restarts", async () => {
    const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");
    mocks.storage.get.mockResolvedValueOnce(1234);

    await expect(runtime.getAlarm()).resolves.toBe(1234);
    await runtime.scheduleAlarm(5678);
    await expect(runtime.getAlarm()).resolves.toBe(5678);
    await runtime.clearAlarm();

    await expect(runtime.getAlarm()).resolves.toBeUndefined();
    expect(mocks.storage.transaction).toHaveBeenCalledTimes(2);
  });

  it("repairs a committed due marker with no queued job at startup and during slow maintenance", async () => {
    vi.useFakeTimers();
    const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");
    const at = Date.now();
    const due = `provisioning-due:${at.toString().padStart(16, "0")}:lease`;
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    mocks.boss.send.mockRejectedValueOnce(new Error("lost queue notification"));
    await runtime.commitAndWake(async (transaction) => {
      await transaction.put(due, { operationID: "lease", at });
    });
    await runtime.stop();
    const restarted = new NodeCoordinatorRuntime("postgresql://example.invalid/test");
    const ticks = vi.fn<() => Promise<void>>(async () => {
      await restarted.storage.delete(due);
    });
    restarted.registerProvisioningTick(ticks);
    await restarted.start(async () => {});
    expect(ticks).toHaveBeenCalledTimes(1);
    const maintenance = deferred<void>();
    restarted.ownMaintenance(maintenance.promise);
    await restarted.storage.put(due, { operationID: "lease", at: Date.now() });
    await vi.advanceTimersByTimeAsync(1000);
    expect(ticks).toHaveBeenCalledTimes(2);
    maintenance.resolve();
    await restarted.stop();
    log.mockRestore();
    vi.useRealTimers();
  });

  it("keeps scanning due work when the queue hint is stalled", async () => {
    vi.useFakeTimers();
    const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");
    const ticks = vi.fn<() => Promise<void>>(async () => {});
    runtime.registerProvisioningTick(ticks);
    await runtime.start(async () => {});
    const stalled = deferred<void>();
    mocks.boss.deleteQueuedJobs.mockImplementationOnce(() => stalled.promise);
    const at = Date.now();
    const committed = runtime.commitAndWake(async (transaction) => {
      await transaction.put(`provisioning-due:${at.toString().padStart(16, "0")}:lease`, {
        operationID: "lease",
        at,
      });
    });
    await vi.advanceTimersByTimeAsync(1000);
    await committed;
    expect(ticks).toHaveBeenCalled();
    stalled.resolve();
    await runtime.stop();
    vi.useRealTimers();
  });

  it("contains WebSocket message handler failures to the offending socket", async () => {
    const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");
    const socket = Object.assign(new EventEmitter(), {
      close: vi.fn<(code?: number, reason?: string) => void>(),
      terminate: vi.fn<() => void>(),
    });
    const errorLog = vi.spyOn(console, "error").mockImplementation(() => {});

    runtime.acceptWebSocket(socket as unknown as WebSocket, {}, [], {
      message: async () => {
        throw new Error("invalid peer frame");
      },
      close: vi.fn<(code: number, reason: string) => void>(),
      error: vi.fn<() => void>(),
    });
    socket.emit("message", Buffer.from("bad"), false);

    await vi.waitFor(() => {
      expect(socket.close).toHaveBeenCalledWith(1011, "coordinator handler failed");
    });
    expect(errorLog).toHaveBeenCalledWith(
      "coordinator websocket message handler failed",
      expect.any(Error),
    );
    errorLog.mockRestore();
  });

  it("accepts ephemeral sockets through the Node websocket runtime", async () => {
    const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");
    const socket = Object.assign(new EventEmitter(), {
      close: vi.fn<(code?: number, reason?: string) => void>(),
      terminate: vi.fn<() => void>(),
    });
    const message = vi.fn<() => Promise<void>>(async () => {});

    runtime.acceptEphemeralWebSocket(socket as unknown as WebSocket, {
      message,
      close: vi.fn<(code: number, reason: string) => void>(),
      error: vi.fn<() => void>(),
    });
    socket.emit("message", Buffer.from("terminal"), false);

    await vi.waitFor(() => {
      expect(message).toHaveBeenCalledWith("terminal");
    });
    expect((socket as unknown as { accept?: unknown }).accept).toBeUndefined();
  });

  it("delegates workspace terminal acceptance to the coordinator runtime", async () => {
    const source = await readFile(new URL("../src/fleet.ts", import.meta.url), "utf8");
    const start = source.indexOf("private async workspaceTerminal");
    const end = source.indexOf("private async connectWorkspaceTerminal", start);
    const terminalRoute = source.slice(start, end);

    expect(terminalRoute).toContain(
      "createWebSocketUpgrade({\n        maxPayload: workspaceTerminalMaxBufferedBytes",
    );
    expect(terminalRoute).toContain("return await this.state.runExclusive");
    expect(terminalRoute.indexOf("trackWorkspaceTerminal")).toBeLessThan(
      terminalRoute.indexOf("connectWorkspaceTerminal"),
    );
    expect(terminalRoute).not.toContain("socket.accept()");
  });

  it("defaults terminal bootstrap fields for persisted workspaces", async () => {
    const source = await readFile(new URL("../src/fleet.ts", import.meta.url), "utf8");
    const start = source.indexOf("function workspaceTerminalBootstrapCommand");
    const end = source.indexOf("function shellQuote", start);
    const bootstrap = source.slice(start, end);

    expect(bootstrap).toContain('workspace.branch?.trim() || "main"');
    expect(bootstrap).toContain('workspace.command?.trim() || "exec bash -l"');
    expect(bootstrap).not.toContain("checkout -B");
    expect(bootstrap).not.toContain("fetch --depth=1");
    expect(bootstrap).toContain("Workspace command exited with status %s");
    expect(bootstrap).toContain("exec bash -l");
  });

  it("bounds terminal input by bytes and queued frame count", async () => {
    const source = await readFile(new URL("../src/fleet.ts", import.meta.url), "utf8");
    const start = source.indexOf("private async connectWorkspaceTerminal");
    const end = source.indexOf("private trackWorkspaceTerminal", start);
    const terminal = source.slice(start, end);
    const sshStart = source.indexOf("async function connectWorkspaceSSH");
    const sshEnd = source.indexOf("async function readWorkspaceVNCPassword", sshStart);
    const ssh = source.slice(sshStart, sshEnd);

    expect(terminal).toContain("workspaceTerminalMaxBufferedFrames");
    expect(source).toContain("workspaceTerminalTransportMemoryBudgetBytes");
    expect(source).toContain("this.state.ephemeralWebSocketMaxPayloadBytes");
    expect(terminal).toContain("pending.length + queuedInputFrames");
    expect(terminal).toContain("queuedInputFrames -= 1");
    expect(terminal).toContain("if (length === 0) return");
    expect(ssh).toContain("observedHostKey = fingerprint");
    expect(ssh).toContain("return expectedHostKey === fingerprint");
    expect(ssh).toContain('cipher: ["aes128-ctr", "aes192-ctr", "aes256-ctr"]');
    expect(ssh).toContain('"hmac-sha2-256-etm@openssh.com"');
    expect(ssh).toContain('"hmac-sha2-512"');
    expect(ssh).toContain("workspaceTerminalSSHReadyTimeoutMs");
    expect(ssh).toContain("for (const port of ports)");
    expect(ssh).toContain("await new Promise<void>((resolve) => setTimeout(resolve, 2_000))");
    expect(terminal).not.toContain("!workspace.sshHostKeySha256");
  });

  it("lets code-agent replies bypass the lifecycle queue", async () => {
    const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");
    const socket = Object.assign(new EventEmitter(), {
      close: vi.fn<(code?: number, reason?: string) => void>(),
      terminate: vi.fn<() => void>(),
    });
    const operationRunner = vi.fn<OperationRunner>(
      async <T>(_callback: () => Promise<T>): Promise<T> => await new Promise<T>(() => {}),
    );
    const message = vi.fn<() => Promise<void>>(async () => {});
    runtime.setOperationRunner(operationRunner);

    runtime.acceptWebSocket(socket as unknown as WebSocket, { kind: "code-agent" }, [], {
      message,
      close: vi.fn<(code: number, reason: string) => void>(),
      error: vi.fn<() => void>(),
    });
    socket.emit("message", Buffer.from("{}"), false);

    await vi.waitFor(() => {
      expect(message).toHaveBeenCalledOnce();
    });
    expect(operationRunner).not.toHaveBeenCalled();
  });

  it("lets runtime-adapter replies bypass the lifecycle queue", async () => {
    const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");
    const socket = Object.assign(new EventEmitter(), {
      close: vi.fn<(code?: number, reason?: string) => void>(),
      terminate: vi.fn<() => void>(),
    });
    const operationRunner = vi.fn<OperationRunner>(
      async <T>(_callback: () => Promise<T>): Promise<T> => await new Promise<T>(() => {}),
    );
    const message = vi.fn<() => Promise<void>>(async () => {});
    runtime.setOperationRunner(operationRunner);

    runtime.acceptWebSocket(socket as unknown as WebSocket, { kind: "runtime-adapter-agent" }, [], {
      message,
      close: vi.fn<(code: number, reason: string) => void>(),
      error: vi.fn<() => void>(),
    });
    socket.emit("message", Buffer.from("{}"), false);

    await vi.waitFor(() => {
      expect(message).toHaveBeenCalledOnce();
    });
    expect(operationRunner).not.toHaveBeenCalled();
  });

  it.each([
    { kind: "control", payload: "{}", isBinary: false },
    { kind: "control", payload: '{"type":"subscribe"}', isBinary: false },
    { kind: "control", payload: '{"type":"heartbeat"', isBinary: false },
    { kind: "control", payload: '{"type":"heartbeat"}', isBinary: true },
    { kind: "unknown", payload: '{"type":"heartbeat"}', isBinary: false },
  ])(
    "serializes $kind messages ($payload, binary=$isBinary) with lifecycle operations",
    async ({ kind, payload, isBinary }) => {
      const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");
      const socket = Object.assign(new EventEmitter(), {
        close: vi.fn<(code?: number, reason?: string) => void>(),
        terminate: vi.fn<() => void>(),
      });
      const mutex = new AsyncMutex();
      const operationRunner = vi.fn<OperationRunner>((callback) => mutex.run(callback));
      runtime.setOperationRunner(operationRunner);
      const lifecycleDone = deferred<void>();
      const lifecycle = runtime.runExclusive(async () => lifecycleDone.promise);
      const message = vi.fn<() => Promise<void>>(async () => {});

      runtime.acceptWebSocket(socket as unknown as WebSocket, { kind }, [], {
        message,
        close: vi.fn<(code: number, reason: string) => void>(),
        error: vi.fn<() => void>(),
      });
      socket.emit("message", Buffer.from(payload), isBinary);

      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(message).not.toHaveBeenCalled();
      lifecycleDone.resolve();
      await lifecycle;

      await vi.waitFor(() => {
        expect(message).toHaveBeenCalledWith(
          isBinary ? Uint8Array.from(Buffer.from(payload)).buffer : payload,
        );
      });
      expect(operationRunner).toHaveBeenCalledTimes(2);
    },
  );

  it.each(["code-agent", "runtime-adapter-agent"])(
    "keeps %s data-plane close callbacks behind earlier messages",
    async (kind) => {
      const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");
      const socket = Object.assign(new EventEmitter(), {
        close: vi.fn<(code?: number, reason?: string) => void>(),
        terminate: vi.fn<() => void>(),
      });
      const order: string[] = [];
      const messageDone = deferred<void>();

      runtime.acceptWebSocket(socket as unknown as WebSocket, { kind }, [], {
        message: async () => {
          order.push("message");
          await messageDone.promise;
        },
        close: () => {
          order.push("close");
        },
        error: vi.fn<() => void>(),
      });
      socket.emit("message", Buffer.from('{"type":"heartbeat"}'), false);
      socket.emit("message", Buffer.from("{}"), false);
      socket.emit("close", 1000, Buffer.from("done"));

      await vi.waitFor(() => {
        expect(order).toEqual(["message"]);
      });
      messageDone.resolve();
      await vi.waitFor(() => {
        expect(order).toEqual(["message", "message", "close"]);
      });
    },
  );

  it.each(["code-agent", "runtime-adapter-agent", "control"])(
    "drains %s socket operations that own lifecycle transactions before stopping jobs and closing storage",
    async (kind) => {
      const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");
      const mutex = new AsyncMutex();
      runtime.setOperationRunner((callback) => mutex.run(callback));
      const messageDone = deferred<void>();
      const socket = new EventEmitter();
      const close = vi.fn<() => void>(() => {
        queueMicrotask(() => socket.emit("close", 1000, Buffer.from("shutdown")));
      });
      Object.assign(socket, {
        close,
        terminate: vi.fn<() => void>(),
        readyState: 1,
      });
      let heartbeatCompleted = false;
      const message = vi.fn<() => Promise<void>>(async () => {
        await runtime.runExclusive(async () => {
          await runtime.scheduleAlarm(Date.now() + 60_000);
        });
        heartbeatCompleted = true;
        await messageDone.promise;
      });

      runtime.acceptWebSocket(socket as unknown as WebSocket, { kind }, [], {
        message,
        close: vi.fn<(code: number, reason: string) => void>(),
        error: vi.fn<() => void>(),
      });
      socket.emit("message", Buffer.from('{"type":"heartbeat"}'), false);
      await vi.waitFor(() => expect(heartbeatCompleted).toBe(true));
      const followingLifecycle = vi.fn<() => Promise<void>>(async () => {});
      await runtime.runExclusive(followingLifecycle);
      await mutex.drain();
      expect(followingLifecycle).toHaveBeenCalledOnce();

      runtime.beginShutdown();
      expect(close).toHaveBeenCalledOnce();
      const stopped = runtime.stop();
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(mocks.boss.stop).not.toHaveBeenCalled();
      expect(mocks.storage.close).not.toHaveBeenCalled();
      messageDone.resolve();
      await stopped;
      await mutex.drain();

      expect(mocks.boss.send).toHaveBeenCalledWith(
        "coordinator-alarm",
        null,
        expect.objectContaining({ singletonKey: "fleet" }),
      );
      expect(mocks.boss.send.mock.invocationCallOrder.at(-1)).toBeLessThan(
        mocks.boss.stop.mock.invocationCallOrder.at(-1) ?? 0,
      );
      expect(mocks.storage.close).toHaveBeenCalledOnce();
    },
  );

  it("loses authority and fires callbacks when the advisory-lock session dies", async () => {
    let lostCallback: (() => void) | undefined;
    const release = vi.fn<() => Promise<void>>(async () => {});
    const storage = mocks.storage as typeof mocks.storage & {
      acquireCoordinatorLock: () => Promise<{
        release(): Promise<void>;
        onLost?(callback: () => void): void;
      }>;
    };
    storage.acquireCoordinatorLock = vi.fn<
      () => Promise<{
        release(): Promise<void>;
        onLost?(callback: () => void): void;
      }>
    >(async () => ({
      release,
      onLost: (callback: () => void) => {
        lostCallback = callback;
      },
    }));
    const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");
    const authorityLostCalls: number[] = [];
    runtime.onAuthorityLost(() => {
      authorityLostCalls.push(1);
    });

    await runtime.start(async () => {});
    expect(runtime.lostAuthority()).toBe(false);

    // Simulate the advisory-lock session dying.
    expect(lostCallback).toBeDefined();
    lostCallback!();

    expect(runtime.lostAuthority()).toBe(true);
    expect(authorityLostCalls).toHaveLength(1);

    // Repeated loss notifications must not re-fire (single-shot fail-closed).
    lostCallback!();
    expect(authorityLostCalls).toHaveLength(1);
  });

  it("stops itself when authority is lost and no callback is registered", async () => {
    let lostCallback: (() => void) | undefined;
    const release = vi.fn<() => Promise<void>>(async () => {});
    const storage = mocks.storage as typeof mocks.storage & {
      acquireCoordinatorLock: () => Promise<{
        release(): Promise<void>;
        onLost?(callback: () => void): void;
      }>;
    };
    storage.acquireCoordinatorLock = vi.fn<
      () => Promise<{
        release(): Promise<void>;
        onLost?(callback: () => void): void;
      }>
    >(async () => ({
      release,
      onLost: (callback: () => void) => {
        lostCallback = callback;
      },
    }));
    const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");
    // No onAuthorityLost callback registered: the runtime must stop itself.

    await runtime.start(async () => {});
    expect(runtime.lostAuthority()).toBe(false);

    lostCallback!();

    // The runtime should have begun stopping (boss.stop is called in stop()).
    await vi.waitFor(() => expect(mocks.boss.stop).toHaveBeenCalled());
    expect(runtime.lostAuthority()).toBe(true);
    expect(release).toHaveBeenCalled();
  });

  it("keeps stop() idempotent when authority loss and stop() race", async () => {
    let lostCallback: (() => void) | undefined;
    const release = vi.fn<() => Promise<void>>(async () => {});
    const storage = mocks.storage as typeof mocks.storage & {
      acquireCoordinatorLock: () => Promise<{
        release(): Promise<void>;
        onLost?(callback: () => void): void;
      }>;
    };
    storage.acquireCoordinatorLock = vi.fn<
      () => Promise<{
        release(): Promise<void>;
        onLost?(callback: () => void): void;
      }>
    >(async () => ({
      release,
      onLost: (callback: () => void) => {
        lostCallback = callback;
      },
    }));
    const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");
    let stopPromise: Promise<void> | undefined;
    runtime.onAuthorityLost(() => {
      // Server would call stop() here; we capture the promise to await it.
      stopPromise = runtime.stop();
    });

    await runtime.start(async () => {});

    // Trigger authority loss, then also call stop() directly.
    lostCallback!();
    await runtime.stop();
    // Wait for the callback's stop() to complete as well.
    await stopPromise;
    // Second stop must be a no-op.
    await runtime.stop();

    expect(runtime.lostAuthority()).toBe(true);
    // Lock released exactly once despite dual stop paths.
    expect(release).toHaveBeenCalledTimes(1);
    expect(mocks.storage.close).toHaveBeenCalledTimes(1);
  });

  it("ignores authority loss after orderly shutdown has begun", async () => {
    let lostCallback: (() => void) | undefined;
    const release = vi.fn<() => Promise<void>>(async () => {});
    const storage = mocks.storage as typeof mocks.storage & {
      acquireCoordinatorLock: () => Promise<{
        release(): Promise<void>;
        onLost?(callback: () => void): void;
      }>;
    };
    storage.acquireCoordinatorLock = vi.fn<
      () => Promise<{
        release(): Promise<void>;
        onLost?(callback: () => void): void;
      }>
    >(async () => ({
      release,
      onLost: (callback: () => void) => {
        lostCallback = callback;
      },
    }));
    const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");
    const authorityLostCalls: number[] = [];
    runtime.onAuthorityLost(() => {
      authorityLostCalls.push(1);
    });

    await runtime.start(async () => {});
    await runtime.stop();

    // A late loss notification after stop() must not fire callbacks.
    if (lostCallback) lostCallback();
    expect(authorityLostCalls).toHaveLength(0);
    // Lock released exactly once (by stop(), not by the late loss callback).
    expect(release).toHaveBeenCalledTimes(1);
  });
});

describe("NodeCoordinatorRuntime startup fault injection", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    delete (mocks.storage as Record<string, unknown>)["acquireCoordinatorLock"];
    const storage = new ProvisioningTestStorage();
    mocks.storage.get.mockImplementation((key) => storage.get(key));
    mocks.storage.put.mockImplementation((key, value) => storage.put(key, value));
    mocks.storage.delete.mockImplementation((key) => storage.delete(key));
    mocks.storage.transaction.mockImplementation((callback) => storage.transaction(callback));
    mocks.storage.list.mockImplementation((options) =>
      storage.list(options as Parameters<CoordinatorStorageView["list"]>[0]),
    );
  });

  function makeLock() {
    const release = vi.fn<() => Promise<void>>(async () => {});
    let onLostCallback: (() => void) | undefined;
    const onLost = (callback: () => void) => {
      onLostCallback = callback;
    };
    return {
      release,
      onLost,
      triggerLost: () => onLostCallback?.(),
      hasLostCallback: () => onLostCallback !== undefined,
    };
  }

  function setupLock() {
    const lock = makeLock();
    const storage = mocks.storage as typeof mocks.storage & {
      acquireCoordinatorLock: () => Promise<{
        release(): Promise<void>;
        onLost?: (callback: () => void) => void;
      }>;
    };
    storage.acquireCoordinatorLock = vi.fn<
      () => Promise<{
        release(): Promise<void>;
        onLost?: (callback: () => void) => void;
      }>
    >(async () => ({ release: lock.release, onLost: lock.onLost }));
    return lock;
  }

  const faultStages = [
    {
      name: "boss.start",
      setup: () => {
        mocks.boss.start.mockRejectedValueOnce(new Error("boss start failed"));
      },
    },
    {
      name: "createQueue",
      setup: () => {
        mocks.boss.createQueue.mockRejectedValueOnce(new Error("createQueue failed"));
      },
    },
    {
      name: "work registration",
      setup: () => {
        mocks.boss.work.mockRejectedValueOnce(new Error("work registration failed"));
      },
    },
    {
      name: "schedule",
      setup: () => {
        mocks.boss.schedule.mockRejectedValueOnce(new Error("schedule failed"));
      },
    },
    {
      name: "send startup reconciliation",
      setup: () => {
        mocks.boss.send.mockRejectedValueOnce(new Error("send failed"));
      },
    },
  ];

  for (const stage of faultStages) {
    it(`fails cleanly on startup fault at ${stage.name}`, async () => {
      const lock = setupLock();
      stage.setup();

      const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");
      await expect(runtime.start(async () => {})).rejects.toThrow();

      // Runtime state is deterministic: stopped.
      expect(runtime.getLifecycleState()).toBe("stopped");
      // Lock was released during cleanup.
      expect(lock.release).toHaveBeenCalledTimes(1);
      // pg-boss was stopped if it was started.
      if (stage.name !== "boss.start") {
        expect(mocks.boss.stop).toHaveBeenCalled();
      }
    });
  }

  for (const stage of faultStages) {
    it(`handles authority loss during startup at ${stage.name}`, async () => {
      const lock = setupLock();

      // Make the target stage's operation block so we can trigger
      // authority loss while it's pending. The abort check after the
      // stage will then catch the abort.
      let resolveStage: () => void;
      const stagePromise = new Promise<void>((resolve) => {
        resolveStage = resolve;
      });

      if (stage.name === "boss.start") {
        mocks.boss.start.mockReturnValueOnce(stagePromise);
      } else if (stage.name === "createQueue") {
        mocks.boss.createQueue.mockReturnValueOnce(stagePromise);
      } else if (stage.name === "work registration") {
        mocks.boss.work.mockReturnValueOnce(stagePromise.then(() => "worker-id"));
      } else if (stage.name === "schedule") {
        mocks.boss.schedule.mockReturnValueOnce(stagePromise);
      } else if (stage.name === "send startup reconciliation") {
        mocks.boss.send.mockReturnValueOnce(stagePromise.then(() => "job-id"));
      }

      const runtime = new NodeCoordinatorRuntime("postgresql://example.invalid/test");
      const startPromise = runtime.start(async () => {});

      // Wait for the lock to be acquired and the blocking stage to be
      // reached, then trigger authority loss and resolve the stage.
      await vi.waitFor(() => expect(lock.hasLostCallback()).toBe(true));
      // Give the runtime a tick to reach the blocking operation.
      await new Promise((resolve) => setTimeout(resolve, 10));
      lock.triggerLost();
      resolveStage!();

      await expect(startPromise).rejects.toThrow();
      expect(runtime.lostAuthority()).toBe(true);
      expect(runtime.getLifecycleState()).toBe("stopped");
      // Lock was released during cleanup.
      expect(lock.release).toHaveBeenCalledTimes(1);
    });
  }
});
