import { describe, expect, it } from "vitest";

import { orgKeyForLabel } from "../src/org-identity";
import {
  applyRunEventSummary,
  buildTerminalRunUpdate,
  classifyTerminalRunAttempt,
  isTerminalRunState,
  terminalRunStateForExitCode,
  terminalRunTimestamp,
  type RunRepositoryStorage,
  type RunStorageView,
  type TerminalRunCommitInput,
} from "../src/run-lifecycle";
import { DurableObjectRunRepository, runEventKey, runKey } from "../src/run-repository";
import type { RunEventRecord, RunRecord } from "../src/types";

const acme = orgKeyForLabel("acme");

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
  fingerprint: "sha256:aaaa",
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
    if (this.failTransactions) throw new Error("storage transaction failed");
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
          terminalFinishSHA256: state === "running" ? undefined : "sha256:aaaa",
        });
        return {
          state,
          exitCode,
          classification: classifyTerminalRunAttempt(current, "sha256:aaaa", current),
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
    expect(classifyTerminalRunAttempt(null, "sha256:aaaa", runFixture())).toBe("missing");
  });

  it("refuses a transition when the terminal binding does not match", () => {
    const stored = runFixture({ leaseID: "lease-1" });
    const rebound = runFixture({ leaseID: "lease-2" });
    expect(classifyTerminalRunAttempt(stored, "sha256:aaaa", rebound)).toBe("conflict");
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
      terminalFinishSHA256: "sha256:aaaa",
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
});

// ─── Repository: replay, conflict, persistence order ──────────────────

const hostFor = (storage: MemoryStorage) => ({
  storage,
  runExclusive: <T>(closure: () => Promise<T>) => storage.runExclusive(closure),
});

describe("DurableObjectRunRepository", () => {
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
    expect(stored.terminalFinishSHA256).toBe("sha256:aaaa");
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
    expect(replay.run.terminalFinishSHA256).toBe("sha256:aaaa");
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
      (key) => key.startsWith("runlog:run-1") || key.startsWith("runevent:run-1"),
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
