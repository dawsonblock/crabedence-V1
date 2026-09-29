import { describe, expect, it } from "vitest";

import { orgKeyForLabel } from "../src/org-identity";
import {
  RunIDCollisionError,
  RunLifecycleService,
  applyRunEventSummary,
  buildTerminalRunUpdate,
  classifyTerminalRunAttempt,
  isTerminalRunState,
  newRunID,
  terminalRunStateForExitCode,
  terminalRunTimestamp,
  type RunRepository,
  type RunRepositoryStorage,
  type RunStorageView,
  type TerminalRunCommitInput,
} from "../src/run-lifecycle";
import {
  DurableObjectRunRepository,
  runEventKey,
  runGcKey,
  runKey,
  terminalAttemptKey,
} from "../src/run-repository";
import type { RunEventRecord, RunRecord } from "../src/types";

const acme = orgKeyForLabel("acme");

const terminalFingerprint = `sha256:${"a".repeat(64)}`;

const runFixture = (overrides: Partial<RunRecord> = {}): RunRecord =>
  ({
    id: "run-1",
    leaseID: "lease-1",
    owner: "alice@example.com",
    org: acme,
    provider: "hetzner",
    class: "standard",
    serverType: "cx22",
    command: ["echo", "hi"],
    state: "running",
    phase: "command",
    logBytes: 0,
    logTruncated: false,
    startedAt: "2026-09-24T00:00:00.000Z",
    lastEventAt: "2026-09-24T00:00:00.000Z",
    eventCount: 0,
    ...overrides,
  }) as RunRecord;

const commitInput = (
  binding: RunRecord,
  overrides: Partial<TerminalRunCommitInput> = {},
): TerminalRunCommitInput => ({
  runID: binding.id,
  fingerprint: terminalFingerprint,
  binding,
  exitCode: 0,
  syncMs: 10,
  commandMs: 20,
  log: { text: "hello", bytes: 5, truncated: false },
  now: new Date("2026-09-24T00:01:00.000Z"),
  ...overrides,
});

/** Minimal in-memory storage implementing the repository's contract. */
class MemoryStorage implements RunRepositoryStorage {
  readonly map = new Map<string, unknown>();
  failTransactions = false;
  /** Fail only the Nth transaction (1-based), for staged-flow crash tests. */
  failTransactionNumber: number | undefined;
  transactionCount = 0;

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

  async transaction<T>(closure: (txn: RunStorageView) => Promise<T>): Promise<T> {
    this.transactionCount += 1;
    if (this.failTransactions || this.failTransactionNumber === this.transactionCount) {
      throw new Error("storage transaction failed");
    }
    return closure(this);
  }

  async runExclusive<T>(closure: () => Promise<T>): Promise<T> {
    return closure();
  }
}

// ─── Transition matrix ────────────────────────────────────────────────

describe("run state machine", () => {
  const states: Array<RunRecord["state"]> = ["running", "succeeded", "failed"];

  it("classifies every (state, exit code) pair exactly once", () => {
    const rows = states.flatMap((state) =>
      [0, 1, 137].map((exitCode) => {
        const current = runFixture({
          state,
          terminalFinishSHA256: state === "running" ? undefined : terminalFingerprint,
        });
        return {
          state,
          exitCode,
          classification: classifyTerminalRunAttempt(current, terminalFingerprint, current),
          otherFingerprint: classifyTerminalRunAttempt(current, "sha256:bbbb", current),
          nextState:
            state === "running"
              ? buildTerminalRunUpdate(
                  current,
                  commitInput(current, { exitCode }),
                  "runlog:run-1:finish:aa:attempt:",
                ).next.state
              : undefined,
        };
      }),
    );
    // A running record proceeds to the exit code's terminal state; a
    // terminal record never transitions — the same fingerprint replays
    // and any other fingerprint conflicts.
    const expected = states.flatMap((state) =>
      [0, 1, 137].map((exitCode) => ({
        state,
        exitCode,
        classification: state === "running" ? "proceed" : "duplicate",
        otherFingerprint: state === "running" ? "proceed" : "conflict",
        nextState: state === "running" ? terminalRunStateForExitCode(exitCode) : undefined,
      })),
    );
    expect(rows).toEqual(expected);
  });

  it("reports a missing record as missing, never as a transition", () => {
    expect(classifyTerminalRunAttempt(null, terminalFingerprint, runFixture())).toBe("missing");
  });

  it("refuses a transition when the terminal binding does not match", () => {
    const stored = runFixture({ leaseID: "lease-1" });
    const rebound = runFixture({ leaseID: "lease-2" });
    expect(classifyTerminalRunAttempt(stored, terminalFingerprint, rebound)).toBe("conflict");
  });

  it("keeps the run running until a terminal state is committed", () => {
    const running = runFixture();
    expect(isTerminalRunState(running.state)).toBe(false);
    expect(terminalRunTimestamp(running)).toBeUndefined();
    expect(
      terminalRunTimestamp(runFixture({ state: "failed", endedAt: "2026-09-24T00:05:00.000Z" })),
    ).toBe(Date.parse("2026-09-24T00:05:00.000Z"));
  });
});

// ─── Event projection ─────────────────────────────────────────────────

describe("run event projection", () => {
  it("marks a running run failed on a run.failed event", () => {
    const run = runFixture();
    applyRunEventSummary(run, {
      runID: run.id,
      seq: 2,
      type: "run.failed",
      createdAt: "2026-09-24T00:02:00.000Z",
    } as RunEventRecord);
    expect(run.state).toBe("failed");
    expect(run.phase).toBe("failed");
    expect(run.endedAt).toBe("2026-09-24T00:02:00.000Z");
  });

  it("never rewrites committed terminal evidence with a late event", () => {
    const committed = runFixture({
      state: "succeeded",
      terminalFinishSHA256: terminalFingerprint,
      endedAt: "2026-09-24T00:01:00.000Z",
    });
    const before = { ...committed };
    applyRunEventSummary(committed, {
      runID: committed.id,
      seq: 9,
      type: "run.failed",
      createdAt: "2026-09-24T00:09:00.000Z",
    } as RunEventRecord);
    expect(committed).toEqual(before);
  });

  // A run.failed event terminalizes a run WITHOUT a terminal fingerprint,
  // so the fingerprint guard alone did not freeze it: a late event could
  // rewrite the failed run's projection — including its lease
  // attribution, which decides who may read the run's history.
  it("never rewrites a run.failed terminal either", () => {
    const failed = runFixture();
    applyRunEventSummary(failed, {
      runID: failed.id,
      seq: 2,
      type: "run.failed",
      createdAt: "2026-09-24T00:02:00.000Z",
    } as RunEventRecord);
    const before = { ...failed };
    expect(before.state).toBe("failed");

    applyRunEventSummary(failed, {
      runID: failed.id,
      seq: 3,
      type: "lease.created",
      phase: "leased",
      leaseID: "cbx_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      provider: "hetzner",
      createdAt: "2026-09-24T00:03:00.000Z",
    } as RunEventRecord);

    expect(failed).toEqual(before);
  });
});

// ─── Repository: replay, conflict, persistence order ──────────────────

const hostFor = (storage: MemoryStorage) => ({
  storage,
  runExclusive: <T>(closure: () => Promise<T>) => storage.runExclusive(closure),
});

describe("DurableObjectRunRepository", () => {
  it("creates the record and its started event atomically, or not at all", async () => {
    const storage = new MemoryStorage();
    const repository = new DurableObjectRunRepository(hostFor(storage));
    const run = runFixture();
    storage.failTransactions = true;
    await expect(repository.createRunningRun(run)).rejects.toThrow("storage transaction failed");
    storage.failTransactions = false;
    // A failed creation leaves nothing behind: no record, no orphan event.
    expect(await storage.get(runKey(run.id))).toBeUndefined();
    expect(await storage.get(runEventKey(run.id, 1))).toBeUndefined();
    expect(run.eventCount).toBe(0);
  });

  it("creates a running record and its started event", async () => {
    const storage = new MemoryStorage();
    const repository = new DurableObjectRunRepository(hostFor(storage));
    const run = runFixture();
    const event = await repository.createRunningRun(run);
    expect(event.type).toBe("run.started");
    expect(event.seq).toBe(1);
    const stored = (await storage.get(runKey(run.id))) as RunRecord;
    expect(stored.state).toBe("running");
    expect(stored.eventCount).toBe(1);
    expect(await storage.get(runEventKey(run.id, 1))).toEqual(event);
  });

  it("commits the terminal transition with its log and single terminal event", async () => {
    const storage = new MemoryStorage();
    const repository = new DurableObjectRunRepository(hostFor(storage));
    const run = runFixture();
    await repository.createRunningRun(run);
    const result = await repository.commitTerminalRun(commitInput(run, { exitCode: 0 }));
    expect(result.kind).toBe("committed");
    if (result.kind !== "committed") return;
    expect(result.run.state).toBe("succeeded");
    expect(result.event.type).toBe("command.finished");
    expect(result.event.seq).toBe(2);
    const stored = (await storage.get(runKey(run.id))) as RunRecord;
    expect(stored.terminalFinishSHA256).toBe(terminalFingerprint);
    expect(stored.terminalLogPrefix).toContain("runlog:run-1:finish:");
    const logKeys = [...storage.map.keys()].filter((key) =>
      key.startsWith(stored.terminalLogPrefix ?? ""),
    );
    expect(logKeys.length).toBe(1);
    expect(storage.map.get(logKeys[0]!)).toBe("hello");
  });

  it("replays a repeated finish instead of writing a second terminal effect", async () => {
    const storage = new MemoryStorage();
    const repository = new DurableObjectRunRepository(hostFor(storage));
    const run = runFixture();
    await repository.createRunningRun(run);
    const first = await repository.commitTerminalRun(commitInput(run, { exitCode: 0 }));
    expect(first.kind).toBe("committed");
    const committed = (await storage.get(runKey(run.id))) as RunRecord;

    const replay = await repository.commitTerminalRun(
      commitInput(run, { exitCode: 0, log: { text: "hello", bytes: 5, truncated: false } }),
    );
    expect(replay.kind).toBe("duplicate");
    if (replay.kind !== "duplicate") return;
    expect(replay.run.terminalFinishSHA256).toBe(terminalFingerprint);
    expect(replay.run.eventCount).toBe(committed.eventCount);
    expect(await storage.get(runKey(run.id))).toEqual(committed);
    // No second terminal event was written.
    expect(await storage.get(runEventKey(run.id, 3))).toBeUndefined();
  });

  it("rejects a conflicting finish without changing the committed record", async () => {
    const storage = new MemoryStorage();
    const repository = new DurableObjectRunRepository(hostFor(storage));
    const run = runFixture();
    await repository.createRunningRun(run);
    await repository.commitTerminalRun(commitInput(run, { exitCode: 0 }));
    const committed = (await storage.get(runKey(run.id))) as RunRecord;

    const conflict = await repository.commitTerminalRun(
      commitInput(run, { fingerprint: "sha256:cccc", exitCode: 1 }),
    );
    expect(conflict.kind).toBe("conflict");
    expect(await storage.get(runKey(run.id))).toEqual(committed);
  });

  it("rejects a rebound finish while the run is still running", async () => {
    const storage = new MemoryStorage();
    const repository = new DurableObjectRunRepository(hostFor(storage));
    const run = runFixture();
    await repository.createRunningRun(run);
    const rebound = runFixture({ leaseID: "lease-2" });
    const result = await repository.commitTerminalRun(commitInput(rebound, { binding: rebound }));
    expect(result.kind).toBe("conflict");
    const stored = (await storage.get(runKey(run.id))) as RunRecord;
    expect(stored.state).toBe("running");
  });

  it("leaves the run running and removes the terminal log when the commit fails", async () => {
    const storage = new MemoryStorage();
    const repository = new DurableObjectRunRepository(hostFor(storage));
    const run = runFixture();
    await repository.createRunningRun(run);
    storage.failTransactions = true;
    await expect(repository.commitTerminalRun(commitInput(run))).rejects.toThrow(
      "storage transaction failed",
    );
    storage.failTransactions = false;
    const stored = (await storage.get(runKey(run.id))) as RunRecord;
    expect(stored.state).toBe("running");
    expect(stored.terminalFinishSHA256).toBeUndefined();
    // The pre-written terminal log was cleaned up with the failed attempt.
    const finishKeys = [...storage.map.keys()].filter((key) =>
      key.startsWith("runlog:run-1:finish:"),
    );
    expect(finishKeys).toEqual([]);
  });

  it("prunes only terminal runs older than the cutoff, removing everything they own", async () => {
    const storage = new MemoryStorage();
    const repository = new DurableObjectRunRepository(hostFor(storage));
    const run = runFixture();
    await repository.createRunningRun(run);
    await repository.commitTerminalRun(
      commitInput(run, { now: new Date("2026-09-24T00:01:00.000Z") }),
    );

    // A cutoff before the run ended keeps it; a later one retires it.
    await repository.deleteTerminalRun(run.id, Date.parse("2026-09-24T00:00:30.000Z"));
    expect(await storage.get(runKey(run.id))).toBeDefined();

    await repository.deleteTerminalRun(run.id, Date.parse("2026-09-24T01:00:00.000Z"));
    expect(await storage.get(runKey(run.id))).toBeUndefined();
    const leftovers = [...storage.map.keys()].filter(
      (key) =>
        key.startsWith("runlog:run-1") ||
        key.startsWith("runevent:run-1") ||
        key.startsWith(attemptPrefix(run.id)),
    );
    expect(leftovers).toEqual([]);
  });

  it("never prunes a running run", async () => {
    const storage = new MemoryStorage();
    const repository = new DurableObjectRunRepository(hostFor(storage));
    const run = runFixture();
    await repository.createRunningRun(run);
    await repository.deleteTerminalRun(run.id, Date.now() + 60_000);
    expect(await storage.get(runKey(run.id))).toBeDefined();
  });
});

// ─── Terminal attempt staging (crash boundaries) ─────────────────────

const attemptPrefix = (runID: string) => `terminal-attempt:${runID}:`;

describe("terminal attempt staging", () => {
  it("reserves nothing when the attempt transaction fails", async () => {
    const storage = new MemoryStorage();
    const repository = new DurableObjectRunRepository(hostFor(storage));
    const run = runFixture();
    await repository.createRunningRun(run);
    storage.failTransactions = true;
    await expect(repository.commitTerminalRun(commitInput(run))).rejects.toThrow(
      "storage transaction failed",
    );
    storage.failTransactions = false;
    // No attempt, no log, no terminal state.
    expect((await storage.list({ prefix: attemptPrefix(run.id) })).size).toBe(0);
    expect((await storage.get(runKey(run.id))) as RunRecord).toMatchObject({ state: "running" });
  });

  it("recovers a reserved attempt and converges on one attempt per fingerprint", async () => {
    const storage = new MemoryStorage();
    const repository = new DurableObjectRunRepository(hostFor(storage));
    const run = runFixture();
    await repository.createRunningRun(run);

    // Crash after transaction A, before the log_written record: the
    // attempt is reserved and the retry converges on it.
    storage.failTransactionNumber = 3;
    await expect(repository.commitTerminalRun(commitInput(run))).rejects.toThrow(
      "storage transaction failed",
    );
    storage.failTransactionNumber = undefined;
    const reserved = await storage.list<{ state: string; logPrefix: string }>({
      prefix: attemptPrefix(run.id),
    });
    expect(reserved.size).toBe(1);
    const reservedAttempt = [...reserved.values()][0]!;
    expect(reservedAttempt.state).toBe("reserved");

    // The retry converges on the SAME attempt and the same log key.
    const committed = await repository.commitTerminalRun(commitInput(run));
    expect(committed.kind).toBe("committed");
    if (committed.kind !== "committed") return;
    expect(committed.run.terminalLogPrefix).toBe(reservedAttempt.logPrefix);
    const consumed = await storage.list<{ state: string }>({ prefix: attemptPrefix(run.id) });
    expect(consumed.size).toBe(1);
    expect([...consumed.values()][0]!.state).toBe("consumed");

    // A repeated finish converges: duplicate, still one attempt.
    const replay = await repository.commitTerminalRun(commitInput(run));
    expect(replay.kind).toBe("duplicate");
    expect((await storage.list({ prefix: attemptPrefix(run.id) })).size).toBe(1);
  });

  it("refuses to commit when the log bytes do not match the attempt digest", async () => {
    const storage = new MemoryStorage();
    const repository = new DurableObjectRunRepository(hostFor(storage));
    const run = runFixture();
    await repository.createRunningRun(run);
    // Crash before transaction B: the attempt is log_written and the run is
    // still running.
    storage.failTransactionNumber = 4;
    await expect(repository.commitTerminalRun(commitInput(run))).rejects.toThrow(
      "storage transaction failed",
    );
    storage.failTransactionNumber = undefined;
    const attempts = await storage.list<{ state: string; logPrefix: string }>({
      prefix: attemptPrefix(run.id),
    });
    const attempt = [...attempts.values()][0]!;
    expect(attempt.state).toBe("log_written");
    // Corrupt the immutable bytes: the commit must refuse rather than
    // reference a log it cannot verify.
    for (const logKey of [...storage.map.keys()].filter((candidate) =>
      candidate.startsWith(attempt.logPrefix),
    )) {
      storage.map.set(logKey, "corrupted");
    }
    const refused = await repository.commitTerminalRun(commitInput(run));
    expect(refused.kind).toBe("conflict");
    expect((await storage.get(runKey(run.id))) as RunRecord).toMatchObject({ state: "running" });
  });

  it("never sweeps a live finish log, retains the consumed attempt, and sweeps abandoned attempts with their bytes", async () => {
    const storage = new MemoryStorage();
    const repository = new DurableObjectRunRepository(hostFor(storage));

    // Live: a committed terminal run owns its log.
    const live = runFixture({ id: "run-live" });
    await repository.createRunningRun(live);
    const committed = await repository.commitTerminalRun(commitInput(live));
    expect(committed.kind).toBe("committed");
    if (committed.kind !== "committed") return;
    const livePrefix = committed.run.terminalLogPrefix!;

    // Abandoned: a finish that crashed before transaction B.
    const abandoned = runFixture({ id: "run-abandoned" });
    await repository.createRunningRun(abandoned);
    // Fail the abandoned run's terminal transaction (B), relative to the
    // transactions already consumed by the live run's commit.
    storage.failTransactionNumber = storage.transactionCount + 3;
    await expect(repository.commitTerminalRun(commitInput(abandoned))).rejects.toThrow(
      "storage transaction failed",
    );
    storage.failTransactionNumber = undefined;
    const abandonedAttempts = await storage.list<{ logPrefix: string }>({
      prefix: attemptPrefix(abandoned.id),
    });
    const abandonedPrefix = [...abandonedAttempts.values()][0]!.logPrefix;

    const swept = await repository.sweepTerminalAttempts(Date.now() + 60_000);
    expect(swept).toBe(1);

    // The abandoned attempt and its bytes are gone; the live log, the live
    // run's reference to it, AND the consumed attempt (the run's durable
    // digest anchor) all survive. A consumed attempt is retired only when
    // its run is deleted, so a valid terminal run never becomes
    // unverifiable through ordinary maintenance.
    expect((await storage.list({ prefix: attemptPrefix(abandoned.id) })).size).toBe(0);
    expect((await storage.list({ prefix: abandonedPrefix })).size).toBe(0);
    expect((await storage.get(runKey(live.id))) as RunRecord).toMatchObject({
      state: "succeeded",
      terminalLogPrefix: livePrefix,
    });
    expect((await storage.list({ prefix: livePrefix })).size).toBeGreaterThan(0);
    expect((await storage.list({ prefix: attemptPrefix(live.id) })).size).toBe(1);
  });

  it("never deletes a claimed attempt's bytes while a visible run references them", async () => {
    const storage = new MemoryStorage();
    const repository = new DurableObjectRunRepository(hostFor(storage));
    const run = runFixture();
    await repository.createRunningRun(run);
    const committed = await repository.commitTerminalRun(commitInput(run));
    expect(committed.kind).toBe("committed");
    const attemptKey = terminalAttemptKey(run.id, terminalFingerprint);
    const consumed = (await storage.get<{ state: string; logPrefix: string }>(attemptKey))!;
    expect(consumed.state).toBe("consumed");

    // Force the state the repository cannot produce — GC has claimed the
    // attempt while the run still references its log — and require the
    // sweep to refuse rather than delete a terminal run's evidence.
    storage.map.set(attemptKey, { ...consumed, state: "retiring" });
    expect(await repository.sweepTerminalAttempts(Date.now())).toBe(0);
    expect((await storage.get<{ state: string }>(attemptKey))!.state).toBe("retiring");
    expect((await storage.list({ prefix: consumed.logPrefix })).size).toBeGreaterThan(0);
    expect((await storage.get(runKey(run.id))) as RunRecord).toMatchObject({
      state: "succeeded",
      terminalLogPrefix: consumed.logPrefix,
    });
  });

  it("removes a consumed attempt only together with its run", async () => {
    const storage = new MemoryStorage();
    const repository = new DurableObjectRunRepository(hostFor(storage));
    const run = runFixture();
    await repository.createRunningRun(run);
    const committed = await repository.commitTerminalRun(commitInput(run));
    expect(committed.kind).toBe("committed");
    expect((await storage.list({ prefix: attemptPrefix(run.id) })).size).toBe(1);

    await repository.deleteTerminalRun(run.id, Date.parse("2026-09-24T01:00:00.000Z"));
    expect((await storage.list({ prefix: attemptPrefix(run.id) })).size).toBe(0);
  });

  it("refuses to commit a finish whose attempt garbage collection has claimed", async () => {
    const storage = new MemoryStorage();
    const repository = new DurableObjectRunRepository(hostFor(storage));
    const run = runFixture();
    await repository.createRunningRun(run);

    // Leave a log_written attempt: reserve, write bytes, then fail
    // transaction B so the run stays running (an abandoned attempt).
    storage.failTransactionNumber = storage.transactionCount + 3;
    await expect(repository.commitTerminalRun(commitInput(run))).rejects.toThrow(
      "storage transaction failed",
    );
    storage.failTransactionNumber = undefined;

    const attemptKey = terminalAttemptKey(run.id, terminalFingerprint);
    const abandoned = (await storage.get(attemptKey)) as { state: string };
    expect(abandoned.state).toBe("log_written");

    // GC claims the attempt. A commit racing it must refuse rather than
    // consume a log whose bytes GC is deleting.
    storage.map.set(attemptKey, { ...abandoned, state: "retiring" });
    const refused = await repository.commitTerminalRun(commitInput(run));
    expect(refused.kind).toBe("conflict");
    expect((await storage.get(runKey(run.id))) as RunRecord).toMatchObject({ state: "running" });
  });
});

// ─── Run ID collisions ────────────────────────────────────────────────

describe("run ID collisions", () => {
  it("mints 128-bit run IDs", () => {
    const first = newRunID();
    const second = newRunID();
    expect(first).toMatch(/^run_[0-9a-f]{32}$/u);
    expect(second).toMatch(/^run_[0-9a-f]{32}$/u);
    expect(first).not.toBe(second);
  });

  it("refuses a creation whose ID already owns a run, without overwriting it", async () => {
    const storage = new MemoryStorage();
    const repository = new DurableObjectRunRepository(hostFor(storage));
    const existing = runFixture({ id: "run_existing" });
    await repository.createRunningRun(existing);
    const stored = structuredClone(await storage.get(runKey(existing.id)));

    const colliding = runFixture({ id: "run_existing", command: ["other"] });
    await expect(repository.createRunningRun(colliding)).rejects.toThrow(RunIDCollisionError);

    // The existing record and its event survive untouched, and the
    // refused creation left nothing behind.
    expect(await storage.get(runKey(existing.id))).toEqual(stored);
    expect((await storage.list({ prefix: "runevent:run_existing:" })).size).toBe(1);
  });

  it("refuses a creation inside an in-flight retirement", async () => {
    const storage = new MemoryStorage();
    const repository = new DurableObjectRunRepository(hostFor(storage));
    storage.map.set(runGcKey("run_retiring"), {
      runID: "run_retiring",
      claimedAt: "2026-09-24T00:00:00.000Z",
    });

    // Creating under the tombstone's ID would let the resumed retirement
    // delete the new run's events, logs, and attempts.
    await expect(repository.createRunningRun(runFixture({ id: "run_retiring" }))).rejects.toThrow(
      RunIDCollisionError,
    );
    expect(await storage.get(runKey("run_retiring"))).toBeUndefined();
    expect(await storage.get(runGcKey("run_retiring"))).toBeDefined();
  });

  it("re-mints and retries through the lifecycle service", async () => {
    const storage = new MemoryStorage();
    const repository = new DurableObjectRunRepository(hostFor(storage));
    const service = new RunLifecycleService(repository);
    const existing = runFixture({ id: "run_existing" });
    await service.createRun(existing);

    const colliding = runFixture({ id: "run_existing" });
    const event = await service.createRun(colliding);
    expect(colliding.id).toMatch(/^run_[0-9a-f]{32}$/u);
    expect(colliding.id).not.toBe("run_existing");
    expect(event.runID).toBe(colliding.id);
    expect(await storage.get(runKey(colliding.id))).toBeDefined();
    // The original run still owns exactly one event.
    expect((await storage.list({ prefix: "runevent:run_existing:" })).size).toBe(1);
  });

  it("gives up after the bounded retries when creation keeps colliding", async () => {
    let calls = 0;
    const repository: RunRepository = {
      loadRun: async () => null,
      createRunningRun: async () => {
        calls += 1;
        throw new RunIDCollisionError("run_collision");
      },
      commitTerminalRun: async () => ({ kind: "missing" }),
      deleteTerminalRun: async () => {},
      resumeTerminalRunGc: async () => 0,
      sweepTerminalAttempts: async () => 0,
    };
    const service = new RunLifecycleService(repository);
    const run = runFixture();
    await expect(service.createRun(run)).rejects.toThrow(RunIDCollisionError);
    // Five attempts: the initial creation plus the bounded re-mints.
    expect(calls).toBe(5);
    expect(run.id).toMatch(/^run_[0-9a-f]{32}$/u);
  });
});
