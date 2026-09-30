import { describe, expect, it } from "vitest";

import { orgKeyForLabel } from "../src/org-identity";
import {
  DurableObjectReadyPoolRepository,
  ReadyPoolTransitionRefused,
  readyPoolKey,
} from "../src/ready-pool-repository";
import type { ReadyPoolEntry } from "../src/types";

const acme = orgKeyForLabel("acme");

const entryFixture = (overrides: Partial<ReadyPoolEntry> = {}): ReadyPoolEntry =>
  ({
    key: "builders",
    leaseID: "lease-1",
    state: "ready",
    owner: "alice@example.com",
    org: acme,
    provider: "hetzner",
    target: "linux",
    class: "standard",
    serverType: "cx22",
    lastReadyAt: "2026-09-24T00:00:00.000Z",
    createdAt: "2026-09-24T00:00:00.000Z",
    updatedAt: "2026-09-24T00:00:00.000Z",
    expiresAt: "2026-09-24T02:00:00.000Z",
    ...overrides,
  }) as ReadyPoolEntry;

class MemoryStorage {
  readonly map = new Map<string, unknown>();
  private tail: Promise<unknown> = Promise.resolve();

  async get<T>(key: string): Promise<T | undefined> {
    return this.map.get(key) as T | undefined;
  }

  async put<T>(key: string, value: T): Promise<void> {
    this.map.set(key, value);
  }

  async delete(key: string): Promise<unknown> {
    return this.map.delete(key);
  }

  async list<T>(options: { prefix: string; limit?: number }): Promise<Map<string, T>> {
    const out = new Map<string, T>();
    for (const [key, value] of [...this.map.entries()].toSorted(([a], [b]) => a.localeCompare(b))) {
      if (!key.startsWith(options.prefix)) continue;
      out.set(key, value as T);
      if (options.limit !== undefined && out.size >= options.limit) break;
    }
    return out;
  }

  async transaction<T>(closure: (txn: MemoryStorage) => Promise<T>): Promise<T> {
    const predecessor = this.tail;
    let release!: () => void;
    this.tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await predecessor;
    try {
      return await closure(this);
    } finally {
      release();
    }
  }
}

const repositoryFor = (storage: MemoryStorage) =>
  new DurableObjectReadyPoolRepository(
    storage as unknown as ConstructorParameters<typeof DurableObjectReadyPoolRepository>[0],
  );

const borrowInput = (
  overrides: Partial<Parameters<ReturnType<typeof repositoryFor>["borrowEntry"]>[1]> = {},
) => ({
  typed: false,
  owner: "alice@example.com",
  token: "token-1",
  now: "2026-09-24T01:00:00.000Z",
  nowMs: Date.parse("2026-09-24T01:00:00.000Z"),
  heartbeat: true,
  leaseExpiresAt: "2026-09-24T02:00:00.000Z",
  ...overrides,
});

describe("DurableObjectReadyPoolRepository", () => {
  it("registers an entry and refuses a duplicate provision", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const entry = entryFixture();
    await repository.registerEntry(entry, false);
    expect(await repository.loadEntry(entry.key, entry.leaseID)).toMatchObject({ state: "ready" });

    // The lease is borrowed: a racing register must not create a duplicate.
    storage.map.set(readyPoolKey(entry.key, entry.leaseID), { ...entry, state: "busy" });
    await expect(
      repository.registerEntry(entryFixture({ createdAt: "2026-09-24T00:05:00.000Z" }), false),
    ).rejects.toThrow(ReadyPoolTransitionRefused);

    // Quarantined in the OTHER namespace: still refused.
    storage.map.set(readyPoolKey(entry.key, entry.leaseID), { ...entry, state: "ready" });
    storage.map.set(readyPoolKey(entry.key, entry.leaseID, true), {
      ...entry,
      state: "quarantined",
    });
    await expect(
      repository.registerEntry(entryFixture({ createdAt: "2026-09-24T00:06:00.000Z" }), false),
    ).rejects.toThrow(ReadyPoolTransitionRefused);
  });

  it("borrows a ready entry and refuses a stale view", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const entry = entryFixture();
    await repository.registerEntry(entry, false);

    const borrowed = await repository.borrowEntry(entry, borrowInput());
    expect(borrowed.state).toBe("busy");
    expect(borrowed.borrowToken).toBe("token-1");

    // The caller's view is now stale.
    await expect(repository.borrowEntry(entry, borrowInput())).rejects.toThrow(
      ReadyPoolTransitionRefused,
    );
  });

  it("refuses a borrow that races a retirement", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const entry = entryFixture();
    await repository.registerEntry(entry, false);

    // Two writers from the same ready view: the retirement commits first.
    const borrower = entryFixture();
    const retired = await repository.retireEntry(entry, {
      typed: false,
      kind: "quarantined",
      reason: "identity mismatch",
      at: "2026-09-24T01:00:00.000Z",
    });
    expect(retired.state).toBe("quarantined");
    await expect(repository.borrowEntry(borrower, borrowInput())).rejects.toThrow(
      ReadyPoolTransitionRefused,
    );
    // The quarantine survived: the borrow did not resurrect the entry.
    expect(await repository.loadEntry(entry.key, entry.leaseID)).toMatchObject({
      state: "quarantined",
    });
  });

  it("refuses a quarantine that races a borrow", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const entry = entryFixture();
    await repository.registerEntry(entry, false);

    const borrowed = await repository.borrowEntry(entry, borrowInput());
    expect(borrowed.state).toBe("busy");
    // A maintenance view still holding "ready" must not quarantine it.
    await expect(
      repository.retireEntry(entryFixture(), {
        typed: false,
        kind: "quarantined",
        reason: "borrow heartbeat expired",
        at: "2026-09-24T01:01:00.000Z",
      }),
    ).rejects.toThrow(ReadyPoolTransitionRefused);
  });

  it("refuses an eviction that races a return", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const entry = entryFixture();
    await repository.registerEntry(entry, false);
    const borrowed = await repository.borrowEntry(entry, borrowInput());

    const returned = await repository.returnEntry(borrowed, {
      typed: false,
      result: "ready",
      reason: undefined,
      now: "2026-09-24T01:05:00.000Z",
      leaseExpiresAt: "2026-09-24T02:00:00.000Z",
    });
    expect(returned.state).toBe("ready");
    expect(returned.failureCount).toBe(0);
    expect(returned.borrowToken).toBeUndefined();

    // The eviction view (still "busy") is refused rather than retiring a
    // freshly returned entry.
    await expect(
      repository.retireEntry(borrowed, {
        typed: false,
        kind: "stale",
        at: "2026-09-24T01:06:00.000Z",
      }),
    ).rejects.toThrow(ReadyPoolTransitionRefused);
    expect(await repository.loadEntry(entry.key, entry.leaseID)).toMatchObject({ state: "ready" });
  });

  it("refuses a transition from a replaced incarnation", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const first = entryFixture();
    await repository.registerEntry(first, false);
    // Re-registration replaces the incarnation (a new createdAt).
    const replacement = entryFixture({ createdAt: "2026-09-24T00:30:00.000Z" });
    storage.map.set(readyPoolKey(first.key, first.leaseID), replacement);

    await expect(repository.borrowEntry(first, borrowInput())).rejects.toThrow(
      ReadyPoolTransitionRefused,
    );
    expect(await repository.loadEntry(first.key, first.leaseID)).toMatchObject({
      createdAt: "2026-09-24T00:30:00.000Z",
    });
  });

  it("drains a quarantined entry, which is the documented way out", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const entry = entryFixture();
    await repository.registerEntry(entry, false);
    const quarantined = await repository.retireEntry(entry, {
      typed: false,
      kind: "quarantined",
      reason: "borrow heartbeat expired",
      at: "2026-09-24T01:00:00.000Z",
    });
    const drained = await repository.retireEntry(quarantined, {
      typed: false,
      kind: "draining",
      at: "2026-09-24T01:01:00.000Z",
    });
    expect(drained.state).toBe("draining");
  });

  it("serializes transitions so a paused writer cannot lose an update", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const entry = entryFixture();
    await repository.registerEntry(entry, false);

    let releaseRead!: () => void;
    const readObserved = new Promise<void>((resolve) => {
      releaseRead = resolve;
    });
    let unblockRead!: () => void;
    const readBlocked = new Promise<void>((resolve) => {
      unblockRead = resolve;
    });
    // Pause inside the first transition's transaction, after its read.
    let paused = false;
    const originalTransaction = storage.transaction.bind(storage);
    storage.transaction = async (closure) => {
      if (!paused) {
        paused = true;
        return originalTransaction(async (txn) => {
          releaseRead();
          await readBlocked;
          return closure(txn);
        });
      }
      return originalTransaction(closure);
    };

    const borrower = entryFixture();
    const retireView = entryFixture();
    const borrow = repository.borrowEntry(borrower, borrowInput());
    await readObserved;
    const retire = repository.retireEntry(retireView, {
      typed: false,
      kind: "stale",
      at: "2026-09-24T01:00:00.000Z",
    });
    unblockRead();

    const borrowed = await borrow;
    expect(borrowed.state).toBe("busy");
    await expect(retire).rejects.toThrow(ReadyPoolTransitionRefused);
    expect(await repository.loadEntry(entry.key, entry.leaseID)).toMatchObject({ state: "busy" });
  });
});

// A heartbeat is a same-state (`busy` -> `busy`) metadata update. Two
// heartbeats from the same stale view cannot be distinguished by state,
// so without a revision check the second silently rewinds the deadline.
describe("ready-pool same-state serialization", () => {
  it("refuses a same-state heartbeat instead of overwriting committed metadata", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const entry = entryFixture();
    await repository.registerEntry(entry, false);
    const borrowed = await repository.borrowEntry(entry, borrowInput());

    const writerA = structuredClone(borrowed);
    const writerB = structuredClone(borrowed);

    const a = await repository.heartbeatBorrow(writerA, {
      typed: false,
      now: "2026-09-24T01:01:00.000Z",
      nowMs: Date.parse("2026-09-24T01:01:00.000Z"),
    });
    expect(a.state).toBe("busy");
    expect(a.borrowHeartbeatAt).toBe("2026-09-24T01:01:00.000Z");

    await expect(
      repository.heartbeatBorrow(writerB, {
        typed: false,
        now: "2026-09-24T01:02:00.000Z",
        nowMs: Date.parse("2026-09-24T01:02:00.000Z"),
      }),
    ).rejects.toThrow(ReadyPoolTransitionRefused);

    const stored = await repository.loadEntry(entry.key, entry.leaseID);
    expect(stored?.borrowHeartbeatAt).toBe("2026-09-24T01:01:00.000Z");
  });

  it("refuses a same-state heartbeat paused across a commit", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const entry = entryFixture();
    await repository.registerEntry(entry, false);
    const borrowed = await repository.borrowEntry(entry, borrowInput());

    const writerA = structuredClone(borrowed);
    const writerB = structuredClone(borrowed);

    let releaseRead!: () => void;
    const readObserved = new Promise<void>((resolve) => {
      releaseRead = resolve;
    });
    let unblockRead!: () => void;
    const readBlocked = new Promise<void>((resolve) => {
      unblockRead = resolve;
    });
    let paused = false;
    const originalTransaction = storage.transaction.bind(storage);
    storage.transaction = async (closure) => {
      if (!paused) {
        paused = true;
        return originalTransaction(async (txn) => {
          releaseRead();
          await readBlocked;
          return closure(txn);
        });
      }
      return originalTransaction(closure);
    };

    const a = repository.heartbeatBorrow(writerA, {
      typed: false,
      now: "2026-09-24T01:01:00.000Z",
      nowMs: Date.parse("2026-09-24T01:01:00.000Z"),
    });
    await readObserved;
    const b = repository.heartbeatBorrow(writerB, {
      typed: false,
      now: "2026-09-24T01:02:00.000Z",
      nowMs: Date.parse("2026-09-24T01:02:00.000Z"),
    });
    unblockRead();

    await a;
    await expect(b).rejects.toThrow(ReadyPoolTransitionRefused);

    const stored = await repository.loadEntry(entry.key, entry.leaseID);
    expect(stored?.borrowHeartbeatAt).toBe("2026-09-24T01:01:00.000Z");
  });
});
