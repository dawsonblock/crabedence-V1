import { describe, expect, it } from "vitest";

import { orgKeyForLabel } from "../src/org-identity";
import { runKey } from "../src/run-repository";
import {
  RunRetentionService,
  runPruneCursorKey,
  terminalRunRetentionMs,
} from "../src/run-retention";
import type { RunRecord } from "../src/types";

// The retention sweep is a bounded, resumable scan. These tests pin the
// properties that make it safe to run on every maintenance tick: it
// never exceeds its batch, it resumes from a durable cursor, and it
// still sweeps tombstones and abandoned attempts when the run scan
// finds nothing.

const acme = orgKeyForLabel("acme");

class FakeStorage {
  readonly map = new Map<string, unknown>();

  async get<T>(key: string): Promise<T | undefined> {
    return this.map.get(key) as T | undefined;
  }

  async put<T>(key: string, value: T): Promise<void> {
    this.map.set(key, value);
  }

  async delete(key: string): Promise<unknown> {
    return this.map.delete(key);
  }

  async list<T>(options: {
    prefix: string;
    limit?: number;
    startAfter?: string;
  }): Promise<Map<string, T>> {
    const out = new Map<string, T>();
    for (const [key, value] of [...this.map.entries()].toSorted(([a], [b]) => a.localeCompare(b))) {
      if (!key.startsWith(options.prefix)) continue;
      if (options.startAfter !== undefined && key <= options.startAfter) continue;
      out.set(key, value as T);
      if (options.limit !== undefined && out.size >= options.limit) break;
    }
    return out;
  }
}

function terminalRun(id: string, endedAt: string): RunRecord {
  return {
    id,
    leaseID: "lease-1",
    owner: "alice@example.com",
    org: acme,
    provider: "hetzner",
    class: "standard",
    serverType: "cx22",
    command: ["echo", "hi"],
    state: "succeeded",
    phase: "succeeded",
    logBytes: 0,
    logTruncated: false,
    startedAt: endedAt,
    endedAt,
    lastEventAt: endedAt,
    eventCount: 3,
  };
}

function retentionHarness(options: { retentionDays?: string } = {}) {
  const storage = new FakeStorage();
  const pruned: Array<{ runID: string; cutoff: number }> = [];
  let resumedGc = 0;
  let sweptAttempts = 0;
  const service = new RunRetentionService({
    storage,
    retentionDays: options.retentionDays,
    runs: {
      async pruneTerminalRun(runID: string, cutoff: number) {
        pruned.push({ runID, cutoff });
        await storage.delete(runKey(runID));
      },
      async resumeTerminalRunGc() {
        resumedGc += 1;
        return 0;
      },
      async sweepTerminalAttempts() {
        sweptAttempts += 1;
        return 0;
      },
    },
  });
  return {
    storage,
    service,
    pruned,
    counters: () => ({ resumedGc, sweptAttempts }),
  };
}

describe("run retention sweep", () => {
  it("deletes only terminal runs older than the window", async () => {
    const { storage, service, pruned } = retentionHarness({ retentionDays: "30" });
    const old = new Date(Date.now() - 40 * 24 * 60 * 60 * 1000).toISOString();
    const fresh = new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString();
    storage.map.set(runKey("run-old"), terminalRun("run-old", old));
    storage.map.set(runKey("run-fresh"), terminalRun("run-fresh", fresh));
    storage.map.set(runKey("run-live"), {
      ...terminalRun("run-live", old),
      state: "running",
      endedAt: undefined,
    });

    await service.pruneTerminalRuns();

    expect(pruned.map((entry) => entry.runID)).toEqual(["run-old"]);
    expect(storage.map.has(runKey("run-fresh"))).toBe(true);
    expect(storage.map.has(runKey("run-live"))).toBe(true);
  });

  it("sweeps tombstones and abandoned attempts even when the scan is empty", async () => {
    const { service, counters } = retentionHarness();
    await service.pruneTerminalRuns();
    expect(counters()).toEqual({ resumedGc: 1, sweptAttempts: 1 });
  });

  it("stops at the per-tick batch bound and resumes from the cursor", async () => {
    const { storage, service, pruned } = retentionHarness({ retentionDays: "1" });
    const old = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();
    for (let index = 0; index < 20; index += 1) {
      const id = `run-${String(index).padStart(3, "0")}`;
      storage.map.set(runKey(id), terminalRun(id, old));
    }

    await service.pruneTerminalRuns();
    expect(pruned).toHaveLength(16);
    // The cursor survives so the next tick continues where this one stopped.
    const cursor = await storage.get<string>(runPruneCursorKey);
    expect(cursor).toBe(runKey("run-015"));

    await service.pruneTerminalRuns();
    expect(pruned).toHaveLength(20);
    expect(await storage.get<string>(runPruneCursorKey)).toBeUndefined();
  });

  it("clears a stale cursor when the namespace is empty", async () => {
    const { storage, service } = retentionHarness();
    storage.map.set(runPruneCursorKey, runKey("run-gone"));

    await service.pruneTerminalRuns();

    expect(await storage.get<string>(runPruneCursorKey)).toBeUndefined();
  });

  it("bounds the configured window and defaults a malformed value", () => {
    const day = 24 * 60 * 60 * 1000;
    expect(terminalRunRetentionMs("7")).toBe(7 * day);
    expect(terminalRunRetentionMs("0")).toBe(30 * day);
    expect(terminalRunRetentionMs("not-a-number")).toBe(30 * day);
    expect(terminalRunRetentionMs("100000")).toBe(3650 * day);
  });
});
