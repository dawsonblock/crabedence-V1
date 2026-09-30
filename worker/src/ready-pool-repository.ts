/**
 * Ready-pool storage: the durable-object adapter behind the pool's
 * persistence contract, plus the pool storage-key layout.
 *
 * Every transition runs inside a storage transaction: reload the entry,
 * verify the caller's expectation (same incarnation, same state, and a
 * resulting state the lifecycle defines from there), apply the named
 * transition, and persist. A stale writer is refused rather than
 * overwriting a committed transition — the discipline the lease
 * repository has, built in from the start instead of added later.
 */
import {
  borrowedReadyPoolEntry,
  drainedReadyPoolEntry,
  heartbeatedReadyPoolEntry,
  isLegalReadyPoolTransition,
  quarantinedReadyPoolEntry,
  returnedReadyPoolEntry,
  staleReadyPoolEntry,
  type ReadyPoolState,
} from "./ready-pool-lifecycle";
import type { ReadyPoolEntry } from "./types";

export const readyPoolPrefix = "ready-pool:";
export const typedReadyPoolPrefix = "typed-ready-pool-v1:";

export function readyPoolKey(key: string, leaseID: string, typed = false): string {
  return `${typed ? typedReadyPoolPrefix : readyPoolPrefix}${key}:${leaseID}`;
}

/** The storage surface this module needs; the DO storage satisfies it. */
export interface ReadyPoolStorageView {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<unknown>;
  list<T>(options: { prefix: string; limit?: number }): Promise<Map<string, T>>;
}

/** The transactional surface the repository requires. */
export interface ReadyPoolRepositoryStorage extends ReadyPoolStorageView {
  transaction<T>(closure: (txn: ReadyPoolStorageView) => Promise<T>): Promise<T>;
}

/**
 * A transition the repository refused: the entry is not what the caller
 * believes it is, or the transition is not one the lifecycle defines from
 * its current state.
 */
export class ReadyPoolTransitionRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ReadyPoolTransitionRefused";
  }
}

/**
 * The immutable identity of one pool-entry incarnation. A lease
 * re-registered into the pool is a NEW incarnation: a caller holding the
 * previous entry must never transition the new one.
 */
export interface ReadyPoolIncarnation {
  key: string;
  leaseID: string;
  createdAt: string;
}

export function readyPoolIncarnation(entry: ReadyPoolEntry): ReadyPoolIncarnation {
  return { key: entry.key, leaseID: entry.leaseID, createdAt: entry.createdAt };
}

export function sameReadyPoolIncarnation(
  current: ReadyPoolEntry,
  expected: ReadyPoolIncarnation,
): boolean {
  return (
    current.key === expected.key &&
    current.leaseID === expected.leaseID &&
    current.createdAt === expected.createdAt
  );
}

export interface BorrowEntryInput {
  typed: boolean;
  owner: string;
  token: string;
  now: string;
  nowMs: number;
  heartbeat: boolean;
  leaseExpiresAt: string | undefined;
}

export interface HeartbeatEntryInput {
  typed: boolean;
  now: string;
  nowMs: number;
  leaseExpiresAt?: string | undefined;
}

export interface ReturnEntryInput {
  typed: boolean;
  /** The borrower's chosen outcome, in the route's own vocabulary. */
  result: ReadyPoolState;
  reason: string | undefined;
  now: string;
  leaseExpiresAt?: string | undefined;
}

export interface RetireEntryInput {
  typed: boolean;
  kind: "draining" | "quarantined" | "stale";
  reason?: string | undefined;
  at: string;
}

export interface ReadyPoolRepository {
  loadEntry(key: string, leaseID: string, typed?: boolean): Promise<ReadyPoolEntry | null>;
  /**
   * Register a ready entry. Refuses when the lease is already borrowed or
   * quarantined in EITHER namespace, so a duplicate provision cannot be
   * created by a racing register.
   */
  registerEntry(entry: ReadyPoolEntry, typed: boolean): Promise<ReadyPoolEntry>;
  borrowEntry(entry: ReadyPoolEntry, input: BorrowEntryInput): Promise<ReadyPoolEntry>;
  heartbeatBorrow(entry: ReadyPoolEntry, input: HeartbeatEntryInput): Promise<ReadyPoolEntry>;
  returnEntry(entry: ReadyPoolEntry, input: ReturnEntryInput): Promise<ReadyPoolEntry>;
  retireEntry(entry: ReadyPoolEntry, input: RetireEntryInput): Promise<ReadyPoolEntry>;
}

export class DurableObjectReadyPoolRepository implements ReadyPoolRepository {
  constructor(private readonly storage: ReadyPoolRepositoryStorage) {}

  /**
   * Run one transition inside a storage transaction: reload, verify the
   * caller's expectation (incarnation, state, and storage revision),
   * apply the named operation to the RELOADED entry, validate the
   * resulting state, and persist as one atomic unit.
   *
   * The operation is applied to the reloaded entry, never to the caller's
   * possibly stale copy, so a same-state update another writer committed
   * in the meantime is preserved. The revision check refuses a caller
   * superseded by a same-state write, which a state comparison alone
   * cannot detect.
   */
  private async transition(
    expected: ReadyPoolEntry,
    typed: boolean,
    operation: (current: ReadyPoolEntry) => ReadyPoolEntry,
  ): Promise<ReadyPoolEntry> {
    const storageKey = readyPoolKey(expected.key, expected.leaseID, typed);
    return this.storage.transaction(async (txn) => {
      const current = await txn.get<ReadyPoolEntry>(storageKey);
      if (!current) {
        throw new ReadyPoolTransitionRefused(`pool entry ${storageKey} is missing`);
      }
      if (!sameReadyPoolIncarnation(current, readyPoolIncarnation(expected))) {
        throw new ReadyPoolTransitionRefused(`pool entry ${storageKey} incarnation changed`);
      }
      if (current.state !== expected.state) {
        throw new ReadyPoolTransitionRefused(
          `pool entry ${storageKey} state changed from ${expected.state} to ${current.state}`,
        );
      }
      const currentRevision = current.storageRevision ?? 0;
      if (currentRevision !== (expected.storageRevision ?? 0)) {
        throw new ReadyPoolTransitionRefused(
          `pool entry ${storageKey} revision changed from ${expected.storageRevision ?? 0} to ${currentRevision}`,
        );
      }
      const next = operation(structuredClone(current));
      if (next.state !== current.state && !isLegalReadyPoolTransition(current.state, next.state)) {
        throw new ReadyPoolTransitionRefused(
          `pool entry ${storageKey} may not move from ${current.state} to ${next.state}`,
        );
      }
      next.storageRevision = currentRevision + 1;
      await txn.put(storageKey, next);
      return next;
    });
  }

  async loadEntry(key: string, leaseID: string, typed = false): Promise<ReadyPoolEntry | null> {
    return (await this.storage.get<ReadyPoolEntry>(readyPoolKey(key, leaseID, typed))) ?? null;
  }

  async registerEntry(entry: ReadyPoolEntry, typed: boolean): Promise<ReadyPoolEntry> {
    const storageKey = readyPoolKey(entry.key, entry.leaseID, typed);
    return this.storage.transaction(async (txn) => {
      const entries = [
        ...(await txn.list<ReadyPoolEntry>({ prefix: readyPoolPrefix })).values(),
        ...(await txn.list<ReadyPoolEntry>({ prefix: typedReadyPoolPrefix })).values(),
      ].filter((candidate) => candidate.leaseID === entry.leaseID);
      if (entries.some((candidate) => candidate.state === "busy")) {
        throw new ReadyPoolTransitionRefused("lease is currently borrowed from a ready pool");
      }
      if (entries.some((candidate) => candidate.state === "quarantined")) {
        throw new ReadyPoolTransitionRefused("quarantined leases must be drained");
      }
      await txn.put(storageKey, entry);
      return entry;
    });
  }

  async borrowEntry(entry: ReadyPoolEntry, input: BorrowEntryInput): Promise<ReadyPoolEntry> {
    const borrow = (target: ReadyPoolEntry) => {
      const borrowed = borrowedReadyPoolEntry(target, {
        owner: input.owner,
        token: input.token,
        now: input.now,
        nowMs: input.nowMs,
        heartbeat: input.heartbeat,
        expiresAt: input.leaseExpiresAt,
      });
      if (!input.heartbeat) {
        delete borrowed.borrowHeartbeatRequired;
        delete borrowed.borrowHeartbeatAt;
        delete borrowed.borrowExpiresAt;
      }
      return borrowed;
    };
    return this.transition(entry, input.typed, borrow);
  }

  async heartbeatBorrow(
    entry: ReadyPoolEntry,
    input: HeartbeatEntryInput,
  ): Promise<ReadyPoolEntry> {
    const beat = (target: ReadyPoolEntry) =>
      heartbeatedReadyPoolEntry(target, {
        now: input.now,
        nowMs: input.nowMs,
        leaseExpiresAt: input.leaseExpiresAt,
      });
    return this.transition(entry, input.typed, beat);
  }

  async returnEntry(entry: ReadyPoolEntry, input: ReturnEntryInput): Promise<ReadyPoolEntry> {
    const returned = (target: ReadyPoolEntry) =>
      returnedReadyPoolEntry(target, {
        state: input.result,
        reason: input.reason,
        now: input.now,
        leaseExpiresAt: input.leaseExpiresAt,
      });
    return this.transition(entry, input.typed, returned);
  }

  async retireEntry(entry: ReadyPoolEntry, input: RetireEntryInput): Promise<ReadyPoolEntry> {
    const retire = (target: ReadyPoolEntry) => {
      switch (input.kind) {
        case "draining":
          return drainedReadyPoolEntry(target, input.at);
        case "quarantined":
          return quarantinedReadyPoolEntry(target, { reason: input.reason ?? "", at: input.at });
        default:
          return staleReadyPoolEntry(target, input.at);
      }
    };
    return this.transition(entry, input.typed, retire);
  }
}
