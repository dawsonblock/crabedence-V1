import { describe, expect, it } from "vitest";

import { orgKeyForLabel } from "../src/org-identity";
import {
  READY_POOL_BORROW_TIMEOUT_MS,
  READY_POOL_STATES,
  borrowedReadyPoolEntry,
  classifyReadyPoolBorrow,
  drainedReadyPoolEntry,
  heartbeatedReadyPoolEntry,
  isBorrowableReadyPoolState,
  isLegalReadyPoolTransition,
  isRetiredReadyPoolState,
  quarantinedReadyPoolEntry,
  readyPoolBorrowDeadline,
  returnedReadyPoolEntry,
  staleReadyPoolEntry,
  withoutReadyPoolBorrow,
} from "../src/ready-pool-lifecycle";
import type { LeaseRecord, ReadyPoolEntry, ReadyPoolState } from "../src/types";

const acme = orgKeyForLabel("acme");

const entryFixture = (overrides: Partial<ReadyPoolEntry> = {}): ReadyPoolEntry =>
  ({
    key: "acme:repo",
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

const leaseFixture = (overrides: Partial<LeaseRecord> = {}): LeaseRecord =>
  ({
    id: "lease-1",
    owner: "alice@example.com",
    org: acme,
    provider: "hetzner",
    state: "active",
    createdAt: "2026-09-24T00:00:00.000Z",
    updatedAt: "2026-09-24T00:00:00.000Z",
    expiresAt: "2026-09-24T02:00:00.000Z",
    ...overrides,
  }) as LeaseRecord;

const borrowContext = (overrides: Partial<Parameters<typeof classifyReadyPoolBorrow>[1]> = {}) => ({
  lease: leaseFixture(),
  nowMs: Date.parse("2026-09-24T01:00:00.000Z"),
  unavailableLeases: new Set<string>(),
  identityMatches: true,
  manageable: true,
  typed: false,
  ...overrides,
});

describe("ready pool state vocabulary", () => {
  it("classifies every state as borrowable or retired exactly once", () => {
    const rows = READY_POOL_STATES.map((state) => ({
      state,
      borrowable: isBorrowableReadyPoolState(state),
      retired: isRetiredReadyPoolState(state),
    }));
    expect(rows).toEqual([
      { state: "ready", borrowable: true, retired: false },
      { state: "busy", borrowable: false, retired: false },
      { state: "draining", borrowable: false, retired: true },
      { state: "quarantined", borrowable: false, retired: true },
      { state: "stale", borrowable: false, retired: true },
    ]);
  });

  it("permits exactly the transitions the lifecycle defines", () => {
    const allowed: Record<ReadyPoolState, ReadyPoolState[]> = {
      ready: ["busy", "draining", "quarantined", "stale"],
      busy: ["ready", "draining", "quarantined", "stale"],
      draining: ["quarantined", "stale"],
      quarantined: ["stale"],
      stale: [],
    };
    const rows = READY_POOL_STATES.flatMap((from) =>
      READY_POOL_STATES.map((to) => ({
        from,
        to,
        legal: isLegalReadyPoolTransition(from, to),
      })),
    );
    const expected = READY_POOL_STATES.flatMap((from) =>
      READY_POOL_STATES.map((to) => ({
        from,
        to,
        legal: from === to || allowed[from].includes(to),
      })),
    );
    expect(rows).toEqual(expected);
  });
});

describe("reuse decision", () => {
  it("borrows only a ready, available entry whose lease is active and unexpired", () => {
    expect(classifyReadyPoolBorrow(entryFixture(), borrowContext())).toBe("borrow");
  });

  const skips: Array<[string, Parameters<typeof classifyReadyPoolBorrow>[1]]> = [
    ["missing lease", borrowContext({ lease: undefined })],
    ["busy entry", borrowContext()],
    ["lease borrowed elsewhere", borrowContext({ unavailableLeases: new Set(["lease-1"]) })],
    ["released lease", borrowContext({ lease: leaseFixture({ state: "released" }) })],
    [
      "expired lease",
      borrowContext({ lease: leaseFixture({ expiresAt: "2026-09-24T00:30:00.000Z" }) }),
    ],
  ];
  it.each(skips)("skips: %s", (name, context) => {
    const entry = entryFixture(name === "busy entry" ? { state: "busy" } : {});
    expect(classifyReadyPoolBorrow(entry, context)).toBe("skip");
  });

  it("drains a typed entry whose identity no longer matches, before anything else", () => {
    expect(
      classifyReadyPoolBorrow(
        entryFixture(),
        borrowContext({ typed: true, identityMatches: false, manageable: false }),
      ),
    ).toBe("drain");
  });

  it("reports a manage-access refusal distinctly from a skip", () => {
    expect(classifyReadyPoolBorrow(entryFixture(), borrowContext({ manageable: false }))).toBe(
      "forbidden",
    );
  });

  it("reports the borrow deadline for heartbeat-required borrows", () => {
    expect(readyPoolBorrowDeadline(entryFixture())).toBeUndefined();
    const heartbeat = entryFixture({
      borrowHeartbeatRequired: true,
      borrowExpiresAt: "2026-09-24T01:05:00.000Z",
    } as Partial<ReadyPoolEntry>);
    expect(readyPoolBorrowDeadline(heartbeat)).toBe(Date.parse("2026-09-24T01:05:00.000Z"));
    const anchored = entryFixture({
      borrowHeartbeatRequired: true,
      borrowHeartbeatAt: "2026-09-24T01:00:00.000Z",
    } as Partial<ReadyPoolEntry>);
    expect(readyPoolBorrowDeadline(anchored)).toBe(
      Date.parse("2026-09-24T01:00:00.000Z") + READY_POOL_BORROW_TIMEOUT_MS,
    );
  });
});

describe("pool transitions", () => {
  it("borrows with a token and optional heartbeat", () => {
    const borrowed = borrowedReadyPoolEntry(entryFixture(), {
      owner: "alice@example.com",
      token: "token-1",
      now: "2026-09-24T01:00:00.000Z",
      nowMs: Date.parse("2026-09-24T01:00:00.000Z"),
      heartbeat: true,
      expiresAt: "2026-09-24T02:00:00.000Z",
    });
    expect(borrowed.state).toBe("busy");
    expect(borrowed.borrowedBy).toBe("alice@example.com");
    expect(borrowed.borrowToken).toBe("token-1");
    expect(borrowed.borrowHeartbeatRequired).toBe(true);
    expect(borrowed.borrowExpiresAt).toBe(
      new Date(Date.parse("2026-09-24T01:00:00.000Z") + READY_POOL_BORROW_TIMEOUT_MS).toISOString(),
    );
    const plain = borrowedReadyPoolEntry(entryFixture(), {
      owner: "alice@example.com",
      token: "token-2",
      now: "2026-09-24T01:00:00.000Z",
      nowMs: Date.parse("2026-09-24T01:00:00.000Z"),
      heartbeat: false,
      expiresAt: undefined,
    });
    expect(plain.borrowHeartbeatRequired).toBeUndefined();
  });

  it("returns a ready entry with a reset failure streak", () => {
    const busy = entryFixture({
      state: "busy",
      borrowToken: "t",
      borrowedBy: "alice@example.com",
      failureCount: 3,
    } as Partial<ReadyPoolEntry>);
    const returned = returnedReadyPoolEntry(busy, {
      state: "ready",
      reason: undefined,
      now: "2026-09-24T01:10:00.000Z",
      leaseExpiresAt: "2026-09-24T02:00:00.000Z",
    });
    expect(returned.state).toBe("ready");
    expect(returned.failureCount).toBe(0);
    expect(returned.lastReadyAt).toBe("2026-09-24T01:10:00.000Z");
    expect(returned.borrowToken).toBeUndefined();
    expect(returned.lastResult).toBe("ready");
  });

  it("counts a failed return and retires the entry", () => {
    const returned = returnedReadyPoolEntry(
      entryFixture({ failureCount: 1 } as Partial<ReadyPoolEntry>),
      {
        state: "draining",
        reason: "returned drained",
        now: "2026-09-24T01:10:00.000Z",
      },
    );
    expect(returned.state).toBe("draining");
    expect(returned.failureCount).toBe(2);
    expect(returned.lastResult).toBe("returned drained");
    expect(returned.lastReadyAt).toBe("2026-09-24T00:00:00.000Z");
  });

  it("retires entries as stale, quarantined, or draining and strips borrow metadata", () => {
    const busy = entryFixture({
      state: "busy",
      borrowToken: "t",
      borrowedBy: "alice@example.com",
      borrowedAt: "2026-09-24T00:30:00.000Z",
    } as Partial<ReadyPoolEntry>);
    const stale = staleReadyPoolEntry(busy, "2026-09-24T01:20:00.000Z");
    expect(stale.state).toBe("stale");
    expect(stale.lastResult).toBe("lease expired or missing");
    expect(stale.borrowToken).toBeUndefined();

    const quarantined = quarantinedReadyPoolEntry(busy, {
      reason: "borrow heartbeat expired",
      at: "2026-09-24T01:20:00.000Z",
    });
    expect(quarantined.state).toBe("quarantined");
    expect(quarantined.failureCount).toBe(1);
    expect(quarantined.borrowedBy).toBeUndefined();

    const drained = drainedReadyPoolEntry(busy, "2026-09-24T01:20:00.000Z");
    expect(drained.state).toBe("draining");
    expect(drained.lastResult).toBe("typed ready-pool lease image or architecture changed");
    expect(drained.borrowHeartbeatAt).toBeUndefined();
  });

  it("extends a borrow deadline on heartbeat without changing state", () => {
    const busy = entryFixture({ state: "busy", borrowToken: "t" } as Partial<ReadyPoolEntry>);
    const heartbeated = heartbeatedReadyPoolEntry(busy, {
      now: "2026-09-24T01:15:00.000Z",
      nowMs: Date.parse("2026-09-24T01:15:00.000Z"),
      leaseExpiresAt: "2026-09-24T02:00:00.000Z",
    });
    expect(heartbeated.state).toBe("busy");
    expect(heartbeated.borrowToken).toBe("t");
    expect(heartbeated.borrowHeartbeatAt).toBe("2026-09-24T01:15:00.000Z");
  });

  it("strips every borrow field", () => {
    const stripped = withoutReadyPoolBorrow(
      entryFixture({
        borrowedAt: "a",
        borrowedBy: "b",
        borrowHeartbeatRequired: true,
        borrowHeartbeatAt: "c",
        borrowExpiresAt: "d",
        borrowToken: "e",
      } as Partial<ReadyPoolEntry>),
    );
    expect(stripped.borrowedAt).toBeUndefined();
    expect(stripped.borrowedBy).toBeUndefined();
    expect(stripped.borrowHeartbeatRequired).toBeUndefined();
    expect(stripped.borrowHeartbeatAt).toBeUndefined();
    expect(stripped.borrowExpiresAt).toBeUndefined();
    expect(stripped.borrowToken).toBeUndefined();
  });
});
