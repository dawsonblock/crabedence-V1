/**
 * Ready-pool lifecycle: the rules that decide whether a prewarmed
 * provider instance may be reused, and how a pool entry changes state.
 *
 * States: `ready | busy | draining | quarantined | stale`. A `ready`
 * entry may be borrowed; `busy` means one borrower holds it; `draining`,
 * `quarantined`, and `stale` are retired from reuse, and `stale` is
 * terminal. There is no generic state setter: the only transitions are
 * the builders defined here.
 *
 * Layering: this module depends on the domain types only. It must not
 * import the fleet router, the storage layer, Cloudflare runtime
 * globals, HTTP routing code, or environment parsing — the pool
 * repository supplies persistence.
 */
import type { LeaseRecord, ReadyPoolEntry } from "./types";

export type ReadyPoolState = ReadyPoolEntry["state"];

export const READY_POOL_STATES: readonly ReadyPoolState[] = [
  "ready",
  "busy",
  "draining",
  "quarantined",
  "stale",
];

/** The state a newly registered pool entry starts in. */
export const INITIAL_READY_POOL_STATE: ReadyPoolState = "ready";

/** How long a borrow may go without a heartbeat before it expires. */
export const READY_POOL_BORROW_TIMEOUT_MS = 2 * 60_000;

/** Only a ready entry may be borrowed. */
export function isBorrowableReadyPoolState(state: ReadyPoolState): boolean {
  return state === "ready";
}

/** Retired entries are never reused; `stale` is terminal. */
export function isRetiredReadyPoolState(state: ReadyPoolState): boolean {
  return state !== "ready" && state !== "busy";
}

/** Whether a pool state change is one the lifecycle defines. */
export function isLegalReadyPoolTransition(from: ReadyPoolState, to: ReadyPoolState): boolean {
  if (from === to) {
    return true;
  }
  switch (from) {
    case "ready":
      return to === "busy" || to === "draining" || to === "quarantined" || to === "stale";
    case "busy":
      return to === "ready" || to === "draining" || to === "quarantined" || to === "stale";
    case "draining":
      return to === "quarantined" || to === "stale";
    case "quarantined":
      return to === "stale";
    default:
      return false;
  }
}

/**
 * The borrow decision for one candidate entry: reuse it, drain it because
 * its identity no longer matches the lease's image, refuse because the
 * requester may not manage the lease, or skip it.
 */
export type ReadyPoolBorrowDecision = "borrow" | "drain" | "forbidden" | "skip";

export interface ReadyPoolBorrowContext {
  lease: LeaseRecord | undefined;
  nowMs: number;
  /** Leases already borrowed or quarantined in the other namespace. */
  unavailableLeases: ReadonlySet<string>;
  /** Whether a typed borrow's identity still matches the lease's image. */
  identityMatches: boolean;
  /** Whether the requester may manage the lease. */
  manageable: boolean;
  typed: boolean;
}

export function classifyReadyPoolBorrow(
  entry: ReadyPoolEntry,
  context: ReadyPoolBorrowContext,
): ReadyPoolBorrowDecision {
  const lease = context.lease;
  if (
    !lease ||
    entry.state !== "ready" ||
    context.unavailableLeases.has(entry.leaseID) ||
    lease.state !== "active" ||
    Date.parse(lease.expiresAt) <= context.nowMs
  ) {
    return "skip";
  }
  if (context.typed && !context.identityMatches) {
    return "drain";
  }
  return context.manageable ? "borrow" : "forbidden";
}

/** The instant a heartbeat-required borrow expires. */
export function readyPoolBorrowDeadline(entry: ReadyPoolEntry): number | undefined {
  if (entry.borrowHeartbeatRequired !== true) {
    return undefined;
  }
  const explicit = Date.parse(entry.borrowExpiresAt ?? "");
  if (Number.isFinite(explicit)) {
    return explicit;
  }
  const anchor = Date.parse(entry.borrowHeartbeatAt ?? entry.borrowedAt ?? entry.updatedAt);
  return Number.isFinite(anchor) ? anchor + READY_POOL_BORROW_TIMEOUT_MS : Number.NEGATIVE_INFINITY;
}

/** The entry without any borrow metadata. */
export function withoutReadyPoolBorrow(entry: ReadyPoolEntry): ReadyPoolEntry {
  const {
    borrowedAt: _borrowedAt,
    borrowedBy: _borrowedBy,
    borrowHeartbeatRequired: _borrowHeartbeatRequired,
    borrowHeartbeatAt: _borrowHeartbeatAt,
    borrowExpiresAt: _borrowExpiresAt,
    borrowToken: _borrowToken,
    ...rest
  } = entry;
  void _borrowedAt;
  void _borrowedBy;
  void _borrowHeartbeatRequired;
  void _borrowHeartbeatAt;
  void _borrowExpiresAt;
  void _borrowToken;
  return rest;
}

// ─── Transitions ──────────────────────────────────────────────────────

export interface ReadyPoolBorrowInput {
  owner: string;
  token: string;
  now: string;
  nowMs: number;
  heartbeat: boolean;
  expiresAt: string | undefined;
}

/** Borrow: one requester takes the entry out of the pool. */
export function borrowedReadyPoolEntry(
  entry: ReadyPoolEntry,
  input: ReadyPoolBorrowInput,
): ReadyPoolEntry {
  const borrowed: ReadyPoolEntry = {
    ...entry,
    state: "busy",
    borrowedBy: input.owner,
    borrowedAt: input.now,
    borrowToken: input.token,
    lastUsedAt: input.now,
    updatedAt: input.now,
    expiresAt: input.expiresAt ?? entry.expiresAt,
  };
  if (input.heartbeat) {
    borrowed.borrowHeartbeatRequired = true;
    borrowed.borrowHeartbeatAt = input.now;
    borrowed.borrowExpiresAt = new Date(input.nowMs + READY_POOL_BORROW_TIMEOUT_MS).toISOString();
  }
  return borrowed;
}

/**
 * Return: the borrower hands the entry back. A `ready` return resets the
 * failure streak and refreshes `lastReadyAt`; a `drain` or `release`
 * return retires it, counting the failure.
 */
export function returnedReadyPoolEntry(
  current: ReadyPoolEntry,
  input: {
    state: ReadyPoolState;
    reason: string | undefined;
    now: string;
    leaseExpiresAt?: string | undefined;
  },
): ReadyPoolEntry {
  const failures = input.state === "ready" ? 0 : (current.failureCount ?? 0) + 1;
  const returned: ReadyPoolEntry = {
    ...withoutReadyPoolBorrow(current),
    state: input.state,
    lastResult: input.reason || input.state,
    failureCount: failures,
    updatedAt: input.now,
    expiresAt: input.leaseExpiresAt ?? current.expiresAt,
  };
  if (input.state === "ready") {
    returned.lastReadyAt = input.now;
  } else if (current.lastReadyAt) {
    returned.lastReadyAt = current.lastReadyAt;
  }
  return returned;
}

/** The lease behind an entry expired or disappeared: retire it as stale. */
export function staleReadyPoolEntry(entry: ReadyPoolEntry, at: string): ReadyPoolEntry {
  return {
    ...withoutReadyPoolBorrow(entry),
    state: "stale",
    updatedAt: at,
    lastResult: "lease expired or missing",
  };
}

/** Quarantine: the entry must not be reused until it is drained. */
export function quarantinedReadyPoolEntry(
  entry: ReadyPoolEntry,
  input: { reason: string; at: string },
): ReadyPoolEntry {
  return {
    ...withoutReadyPoolBorrow(entry),
    state: "quarantined",
    updatedAt: input.at,
    lastResult: input.reason,
    failureCount: (entry.failureCount ?? 0) + 1,
  };
}

/** Drain: the entry's image or architecture no longer matches its lease. */
export function drainedReadyPoolEntry(entry: ReadyPoolEntry, at: string): ReadyPoolEntry {
  return {
    ...withoutReadyPoolBorrow(entry),
    state: "draining",
    updatedAt: at,
    lastResult: "typed ready-pool lease image or architecture changed",
    failureCount: (entry.failureCount ?? 0) + 1,
  };
}

/**
 * Borrow heartbeat: the borrower proves it is still working, extending
 * the borrow deadline on the same entry.
 */
export function heartbeatedReadyPoolEntry(
  current: ReadyPoolEntry,
  input: { now: string; nowMs: number; leaseExpiresAt?: string | undefined },
): ReadyPoolEntry {
  return {
    ...current,
    borrowHeartbeatRequired: true,
    borrowHeartbeatAt: input.now,
    borrowExpiresAt: new Date(input.nowMs + READY_POOL_BORROW_TIMEOUT_MS).toISOString(),
    updatedAt: input.now,
    expiresAt: input.leaseExpiresAt ?? current.expiresAt,
  };
}
