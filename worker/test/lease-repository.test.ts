import { describe, expect, it } from "vitest";

import type { LeaseConfig } from "../src/config";
import { rollbackCleanupLease } from "../src/lease-lifecycle";
import {
  DurableObjectLeaseRepository,
  LeaseTransitionRefused,
  leaseKey,
} from "../src/lease-repository";
import { orgKeyForLabel } from "../src/org-identity";
import type { LeaseRecord, ProviderMachine } from "../src/types";

const acme = orgKeyForLabel("acme");

const leaseFixture = (overrides: Partial<LeaseRecord> = {}): LeaseRecord =>
  ({
    id: "lease-1",
    provider: "hetzner",
    cloudID: "",
    owner: "alice@example.com",
    org: acme,
    state: "provisioning",
    lifecycle: "managed",
    createdAt: "2026-09-24T00:00:00.000Z",
    updatedAt: "2026-09-24T00:00:00.000Z",
    expiresAt: "2026-09-24T02:00:00.000Z",
    ...overrides,
  }) as LeaseRecord;

const configFixture = (overrides: Partial<LeaseConfig> = {}): LeaseConfig =>
  ({ provider: "hetzner", providerKey: "cbx-key", ...overrides }) as LeaseConfig;

const serverFixture = (overrides: Partial<ProviderMachine> = {}): ProviderMachine =>
  ({
    provider: "hetzner",
    id: 7,
    cloudID: "srv-7",
    name: "srv-7",
    status: "running",
    serverType: "cx22",
    host: "1.2.3.4",
    ...overrides,
  }) as ProviderMachine;

class MemoryStorage {
  readonly map = new Map<string, unknown>();
  /** Serializes transactions the way the durable-object storage does. */
  private tail: Promise<unknown> = Promise.resolve();
  async get<T>(key: string): Promise<T | undefined> {
    return this.map.get(key) as T | undefined;
  }

  async put<T>(key: string, value: T): Promise<void> {
    this.map.set(key, value);
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
  new DurableObjectLeaseRepository(
    storage as unknown as ConstructorParameters<typeof DurableObjectLeaseRepository>[0],
  );

describe("DurableObjectLeaseRepository", () => {
  it("loads a managed lease in the provisioning state", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const lease = leaseFixture();
    storage.map.set(leaseKey(lease.id), lease);
    const stored = await repository.loadLease(lease.id);
    expect(stored?.state).toBe("provisioning");
    expect(storage.map.has(leaseKey(lease.id))).toBe(true);
  });

  it("keeps the attempt generation when a reactivated lease is activated", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const lease = leaseFixture({
      createAttemptID: "attempt-1",
      createAttemptGeneration: "gen-9",
    } as Partial<LeaseRecord>);
    storage.map.set(leaseKey(lease.id), lease);
    const activated = await repository.activateLease(lease, { at: "2026-09-24T00:05:00.000Z" });
    expect(activated.state).toBe("active");
    expect(activated.createAttemptGeneration).toBe("gen-9");
    const stored = await repository.loadLease(lease.id);
    expect(stored?.state).toBe("active");
  });

  it("releases idempotently and keeps unresolved-creation debt", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const unresolved = leaseFixture({
      provisioningRequestStartedAt: "2026-09-24T00:10:00.000Z",
    } as Partial<LeaseRecord>);
    storage.map.set(leaseKey(unresolved.id), unresolved);
    const first = await repository.releaseLease(unresolved, { deleteServer: true });
    expect(first.state).toBe("released");
    expect(first.provisioningResourceMayExist).toBe(true);
    expect(first.releaseDeletesServer).toBe(true);

    const second = await repository.releaseLease(first, { deleteServer: true });
    expect(second.state).toBe("released");
    expect(second.releaseDeletesServer).toBe(first.releaseDeletesServer);
    const stored = await repository.loadLease(unresolved.id);
    expect(stored?.state).toBe("released");
  });

  it("records a queued release claim without losing the release intent", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const lease = leaseFixture({ state: "active", cloudID: "srv-1" });
    storage.map.set(leaseKey(lease.id), lease);
    const queuedAt = "2026-09-24T00:30:00.000Z";
    const queued = await repository.releaseLease(lease, {
      deleteServer: true,
      keep: true,
      cleanupClaim: { startedAt: queuedAt, expiresAt: queuedAt },
    });
    expect(queued.state).toBe("released");
    expect(queued.releaseDeletesServer).toBe(true);
    expect(queued.cleanupStartedAt).toBe(queuedAt);
    expect(queued.cleanupClaimExpiresAt).toBe(queuedAt);
    expect(queued.keep).toBe(true);
  });

  it("restores dispatch evidence for a release canceled before provider identity", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const lease = leaseFixture({
      provisioningRequestStartedAt: "2026-09-24T00:10:00.000Z",
      provisioningCoordinatorVersion: "v1",
    } as Partial<LeaseRecord>);
    storage.map.set(leaseKey(lease.id), lease);
    const released = await repository.releaseLease(lease, {
      deleteServer: true,
      keep: false,
      restoreDispatchEvidence: {
        provisioningRequestStartedAt: "2026-09-24T00:10:00.000Z",
        provisioningCoordinatorVersion: "v1",
      },
    });
    expect(released.state).toBe("released");
    expect(released.provisioningRequestStartedAt).toBe("2026-09-24T00:10:00.000Z");
    expect(released.provisioningResourceMayExist).toBe(true);
    expect(released.provisioningFailureRetryable).toBe(true);
  });

  it("records unresolved failure as explicit debt", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const lease = leaseFixture();
    storage.map.set(leaseKey(lease.id), lease);
    const failed = await repository.retainUnresolvedLease(lease, {
      message: "resource may exist",
      at: "2026-09-24T00:40:00.000Z",
    });
    expect(failed.state).toBe("failed");
    expect(failed.provisioningResourceMayExist).toBe(true);
    expect(failed.provisioningFailureRetryable).toBe(false);
    expect(failed.cleanupRetryAt).toBeUndefined();
  });

  it("expires a registered lease and an unprovisioned lease", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const registered = leaseFixture({ lifecycle: "registered", cloudID: "host-1" });
    const unprovisioned = leaseFixture({
      id: "lease-2",
      provisioningRequestStartedAt: "2026-09-24T00:10:00.000Z",
    } as Partial<LeaseRecord>);
    storage.map.set(leaseKey(registered.id), registered);
    storage.map.set(leaseKey(unprovisioned.id), unprovisioned);

    const expired = await repository.expireRegisteredLease(registered, {
      at: "2026-09-24T01:00:00.000Z",
    });
    expect(expired.state).toBe("expired");
    expect(expired.releaseDeletesServer).toBeUndefined();

    const failed = await repository.failUnprovisionedExpiredLease(unprovisioned, {
      at: "2026-09-24T01:00:00.000Z",
    });
    expect(failed.state).toBe("failed");
    expect(failed.provisioningResourceMayExist).toBe(true);
    expect(failed.cleanupError).toContain("expired before provider returned");
  });
});

describe("rollback cleanup lease", () => {
  it("keeps the stored incarnation's state and only activates when absent", () => {
    const base = leaseFixture({ state: "provisioning" });
    const released = leaseFixture({ state: "released" });
    expect(
      rollbackCleanupLease(base, released, configFixture(), serverFixture(), "cx22").state,
    ).toBe("released");
    expect(
      rollbackCleanupLease(
        base,
        leaseFixture({ state: "expired" }),
        configFixture(),
        serverFixture(),
        "cx22",
      ).state,
    ).toBe("expired");
    const withoutStored = rollbackCleanupLease(
      base,
      undefined,
      configFixture(),
      serverFixture(),
      "cx22",
    );
    expect(withoutStored.state).toBe("active");
    expect(withoutStored.cloudID).toBe("srv-7");
  });
});

describe("lease transition validation", () => {
  it("activates a lease whose provider identity is already bound", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const lease = leaseFixture();
    storage.map.set(leaseKey(lease.id), lease);
    const activated = await repository.activateLease(lease, { at: "2026-09-24T00:05:00.000Z" });
    expect(activated.state).toBe("active");
    expect(activated.updatedAt).toBe("2026-09-24T00:05:00.000Z");
    expect((await repository.loadLease(lease.id))?.state).toBe("active");
  });

  it("refuses a transition from a stale state", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const stale = leaseFixture();
    storage.map.set(leaseKey(stale.id), stale);
    // A caller holding this copy is stale the moment someone else moves
    // the record.
    const staleView = structuredClone(stale);
    await repository.activateLease(stale, { at: "2026-09-24T00:05:00.000Z" });
    await expect(
      repository.activateLease(staleView, { at: "2026-09-24T00:06:00.000Z" }),
    ).rejects.toThrow(LeaseTransitionRefused);
    expect((await repository.loadLease(stale.id))?.state).toBe("active");
  });

  it("refuses a transition from a stale incarnation", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const first = leaseFixture({ createAttemptGeneration: "gen-1" } as Partial<LeaseRecord>);
    storage.map.set(leaseKey(first.id), first);
    // A new create attempt replaces the incarnation.
    storage.map.set(leaseKey(first.id), {
      ...first,
      createAttemptGeneration: "gen-2",
      updatedAt: "2026-09-24T00:04:00.000Z",
    } as LeaseRecord);
    await expect(
      repository.activateLease(first, { at: "2026-09-24T00:05:00.000Z" }),
    ).rejects.toThrow(LeaseTransitionRefused);
  });

  it("refuses to resurrect a terminal lease", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const lease = leaseFixture({ state: "active", cloudID: "srv-1" });
    storage.map.set(leaseKey(lease.id), lease);
    const released = await repository.releaseLease(lease, { deleteServer: true });
    expect(released.state).toBe("released");
    // A terminal record may record release intent again (idempotent), but
    // it can never return to a live state.
    await expect(
      repository.activateLease(released, { at: "2026-09-24T00:05:00.000Z" }),
    ).rejects.toThrow(LeaseTransitionRefused);
    const again = await repository.releaseLease(released, { deleteServer: true });
    expect(again.state).toBe("released");
    expect((await repository.loadLease(lease.id))?.state).toBe("released");
  });

  it("refuses to transition a missing lease", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    await expect(
      repository.activateLease(leaseFixture(), { at: "2026-09-24T00:05:00.000Z" }),
    ).rejects.toThrow(LeaseTransitionRefused);
  });
});

// TestLeaseTransitionSerialization is the adversarial case: writer A
// pauses inside its transaction after reading; writer B submits a
// transition from the same stale view; A commits; B must be REFUSED
// rather than overwrite A's committed transition. Before the repository
// owned its own transaction, B could read before A's write and land after
// it — a silent lost update.
describe("lease transition serialization", () => {
  it("refuses a stale writer instead of overwriting a committed transition", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const record = leaseFixture({ state: "provisioning" });
    storage.map.set(leaseKey(record.id), record);

    const writerA = structuredClone(record);
    const writerB = structuredClone(record);

    let releaseRead!: () => void;
    const readObserved = new Promise<void>((resolve) => {
      releaseRead = resolve;
    });
    let unblockRead!: () => void;
    const readBlocked = new Promise<void>((resolve) => {
      unblockRead = resolve;
    });
    repository.afterTransactionRead = async () => {
      releaseRead();
      await readBlocked;
    };

    const a = repository.activateLease(writerA, { at: "2026-09-24T00:05:00.000Z" });
    await readObserved;
    const b = repository.releaseLease(writerB, { deleteServer: true });
    // Let A's transaction finish; B's is serialized behind it.
    unblockRead();

    const activated = await a;
    expect(activated.state).toBe("active");
    await expect(b).rejects.toThrow(LeaseTransitionRefused);

    // A's transition survived: B did not overwrite it.
    const stored = await repository.loadLease(record.id);
    expect(stored?.state).toBe("active");
    expect(stored?.updatedAt).toBe("2026-09-24T00:05:00.000Z");
  });
});

// A same-state transition (recording cleanup debt on a terminal record)
// changes metadata without changing state. A state comparison alone
// cannot distinguish the two writers, so without a revision check B
// silently overwrites A's committed metadata.
describe("lease same-state serialization", () => {
  it("refuses a same-state writer instead of overwriting committed metadata", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const record = leaseFixture({ state: "failed" });
    storage.map.set(leaseKey(record.id), record);

    const writerA = structuredClone(record);
    const writerB = structuredClone(record);

    const a = await repository.retainUnresolvedLease(writerA, {
      message: "resource may exist (A)",
      at: "2026-09-24T00:40:00.000Z",
    });
    expect(a.state).toBe("failed");
    expect(a.cleanupError).toBe("resource may exist (A)");

    await expect(
      repository.retainUnresolvedLease(writerB, {
        message: "resource may exist (B)",
        at: "2026-09-24T00:41:00.000Z",
      }),
    ).rejects.toThrow(LeaseTransitionRefused);

    const stored = await repository.loadLease(record.id);
    expect(stored?.state).toBe("failed");
    expect(stored?.cleanupError).toBe("resource may exist (A)");
  });

  it("refuses a same-state writer paused across a commit", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const record = leaseFixture({ state: "failed" });
    storage.map.set(leaseKey(record.id), record);

    const writerA = structuredClone(record);
    const writerB = structuredClone(record);

    let releaseRead!: () => void;
    const readObserved = new Promise<void>((resolve) => {
      releaseRead = resolve;
    });
    let unblockRead!: () => void;
    const readBlocked = new Promise<void>((resolve) => {
      unblockRead = resolve;
    });
    repository.afterTransactionRead = async () => {
      releaseRead();
      await readBlocked;
    };

    const a = repository.retainUnresolvedLease(writerA, {
      message: "resource may exist (A)",
      at: "2026-09-24T00:40:00.000Z",
    });
    await readObserved;
    const b = repository.retainUnresolvedLease(writerB, {
      message: "resource may exist (B)",
      at: "2026-09-24T00:41:00.000Z",
    });
    unblockRead();

    await a;
    await expect(b).rejects.toThrow(LeaseTransitionRefused);

    const stored = await repository.loadLease(record.id);
    expect(stored?.cleanupError).toBe("resource may exist (A)");
  });
});

// Cleanup-failure debt is transition input, applied to the reloaded
// record. A caller that mutates its own copy instead is ignored, so the
// two fleet.ts failure paths must express the debt here rather than by
// assigning fields on the record they pass in.
describe("lease cleanup-failure debt", () => {
  it("records deletion debt and the validity window from the input", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const record = leaseFixture({ state: "failed" });
    storage.map.set(leaseKey(record.id), record);

    const failed = await repository.retainUnresolvedLease(record, {
      message: "resource may exist",
      at: "2026-09-24T00:40:00.000Z",
      releaseDeletesServer: true,
      expiresAt: "2026-09-24T00:40:00.000Z",
    });
    expect(failed.releaseDeletesServer).toBe(true);
    expect(failed.expiresAt).toBe("2026-09-24T00:40:00.000Z");

    const stored = await repository.loadLease(record.id);
    expect(stored?.releaseDeletesServer).toBe(true);
    expect(stored?.expiresAt).toBe("2026-09-24T00:40:00.000Z");
  });

  it("ignores a caller-side edit the transition would discard", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const record = leaseFixture({ state: "failed" });
    storage.map.set(leaseKey(record.id), record);

    const caller = structuredClone(record);
    caller.releaseDeletesServer = true;
    const failed = await repository.retainUnresolvedLease(caller, {
      message: "resource may exist",
      at: "2026-09-24T00:40:00.000Z",
    });
    expect(failed.releaseDeletesServer).toBeUndefined();
  });

  it("carries the validity window but disclaims deletion debt on manual resolution", async () => {
    const storage = new MemoryStorage();
    const repository = repositoryFor(storage);
    const record = leaseFixture({ releaseDeletesServer: true });
    storage.map.set(leaseKey(record.id), record);

    const expired = await repository.expireLeaseForManualCleanup(record, {
      error: "manual resolution required",
      at: "2026-09-24T00:41:00.000Z",
      expiresAt: "2026-09-24T00:41:00.000Z",
    });
    expect(expired.state).toBe("expired");
    expect(expired.releaseDeletesServer).toBe(false);
    expect(expired.expiresAt).toBe("2026-09-24T00:41:00.000Z");
  });
});
