/**
 * Run storage: the durable-object adapter behind the run lifecycle's
 * RunRepository contract, plus the storage-key and terminal-log layout
 * that belongs with it.
 *
 * The adapter is deliberately thin: the transition rules and the
 * record/event construction live in ./run-lifecycle, and the
 * classification is re-run inside the storage transaction so a
 * concurrent writer cannot be raced.
 */
import {
  buildTerminalRunUpdate,
  classifyTerminalRunAttempt,
  runStartedEvent,
  terminalRunTimestamp,
  type RunCommitResult,
  type RunRepository,
  type TerminalRunCommitInput,
} from "./run-lifecycle";
import type { RunEventRecord, RunRecord } from "./types";

// ─── Storage layout ───────────────────────────────────────────────────

export function runKey(runID: string): string {
  return `run:${runID}`;
}

export function runLogKey(runID: string): string {
  return `runlog:${runID}`;
}

export function runLogChunkPrefix(runID: string): string {
  return `runlog:${runID}:chunk:`;
}

export function runTerminalLogRoot(runID: string): string {
  return `runlog:${runID}:finish:`;
}

function runTerminalLogPrefix(runID: string, fingerprint: string, attemptID: string): string {
  return `${runTerminalLogRoot(runID)}${fingerprint.replace(/^sha256:/u, "")}:${attemptID}:`;
}

export function terminalRunLogValueKey(prefix: string): string {
  return `${prefix}value`;
}

export function terminalRunLogChunkPrefix(prefix: string): string {
  return `${prefix}chunk:`;
}

export function terminalRunLogChunkKey(prefix: string, index: number): string {
  return `${terminalRunLogChunkPrefix(prefix)}${String(index).padStart(6, "0")}`;
}

export function runEventPrefix(runID: string): string {
  return `runevent:${runID}:`;
}

export function runEventKey(runID: string, seq: number): string {
  return `${runEventPrefix(runID)}${String(seq).padStart(12, "0")}`;
}

// ─── Terminal log persistence ─────────────────────────────────────────

const runLogChunkBytes = 64 * 1024;
const prefixDeletePageSize = 128;
const textEncoder = new TextEncoder();
const runLogTextDecoder = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true });

/** The storage surface this module needs; the DO storage satisfies it. */
export interface RunStorageView {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<unknown>;
  list<T>(options: { prefix: string; limit?: number }): Promise<Map<string, T>>;
}

export async function writeTerminalRunLog(
  storage: RunStorageView,
  prefix: string,
  log: string,
): Promise<void> {
  if (textEncoder.encode(log).byteLength <= runLogChunkBytes) {
    await storage.put(terminalRunLogValueKey(prefix), log);
    return;
  }
  await Promise.all(
    splitRunLogByBytes(log).map((chunk, index) =>
      storage.put(terminalRunLogChunkKey(prefix, index), chunk),
    ),
  );
}

export async function deleteStoragePrefix(storage: RunStorageView, prefix: string): Promise<void> {
  for (;;) {
    // oxlint-disable-next-line eslint/no-await-in-loop -- deletion advances by removing each bounded first page.
    const page = await storage.list({ prefix, limit: prefixDeletePageSize });
    if (page.size === 0) return;
    // oxlint-disable-next-line eslint/no-await-in-loop -- finish each bounded delete batch before loading the next one.
    await Promise.all([...page.keys()].map((key) => storage.delete(key)));
    if (page.size < prefixDeletePageSize) return;
  }
}

function splitRunLogByBytes(log: string): string[] {
  const encoded = textEncoder.encode(log);
  const chunks: string[] = [];
  for (let start = 0; start < encoded.byteLength;) {
    let end = Math.min(start + runLogChunkBytes, encoded.byteLength);
    while (end < encoded.byteLength && (encoded[end]! & 0xc0) === 0x80) end--;
    chunks.push(runLogTextDecoder.decode(encoded.subarray(start, end)));
    start = end;
  }
  return chunks;
}

// ─── Repository adapter ───────────────────────────────────────────────

/** The durable-object storage surface the repository needs. */
export interface RunRepositoryStorage extends RunStorageView {
  transaction<T>(closure: (txn: RunStorageView) => Promise<T>): Promise<T>;
}

/** The host surface the repository needs; the coordinator runtime satisfies it. */
export interface RunRepositoryHost {
  readonly storage: RunRepositoryStorage;
  runExclusive<T>(closure: () => Promise<T>): Promise<T>;
}

export class DurableObjectRunRepository implements RunRepository {
  constructor(private readonly host: RunRepositoryHost) {}

  private get storage(): RunRepositoryStorage {
    return this.host.storage;
  }

  async loadRun(runID: string): Promise<RunRecord | null> {
    return (await this.storage.get<RunRecord>(runKey(runID))) ?? null;
  }

  /**
   * Persist a new running run and its `run.started` event, in the order
   * the coordinator has always used: the running record first, then the
   * event, then the record carrying the event counter.
   */
  async createRunningRun(run: RunRecord): Promise<RunEventRecord> {
    await this.storage.put(runKey(run.id), run);
    const now = new Date().toISOString();
    const seq = (run.eventCount ?? 0) + 1;
    const event = runStartedEvent(run.id, seq, now);
    run.eventCount = seq;
    run.lastEventAt = now;
    await this.storage.put(runEventKey(run.id, seq), event);
    await this.storage.put(runKey(run.id), run);
    return event;
  }

  /**
   * The terminal commit. The terminal log bytes are written BEFORE the
   * state transaction and removed again when the attempt does not
   * commit, so a crash never leaves a terminal record without its log
   * or a stray log without its record. The transaction re-classifies
   * against the current record, so a concurrent finish cannot be raced.
   */
  async commitTerminalRun(input: TerminalRunCommitInput): Promise<RunCommitResult> {
    const terminalLogPrefix = runTerminalLogPrefix(
      input.runID,
      input.fingerprint,
      crypto.randomUUID(),
    );
    let committed: RunCommitResult;
    try {
      await writeTerminalRunLog(this.storage, terminalLogPrefix, input.log.text);
      committed = await this.storage.transaction(async (storage) => {
        const current = await storage.get<RunRecord>(runKey(input.runID));
        if (!current) return { kind: "missing" as const };
        const classification = classifyTerminalRunAttempt(
          current,
          input.fingerprint,
          input.binding,
        );
        if (classification === "duplicate") {
          return { kind: "duplicate" as const, run: current };
        }
        if (classification === "conflict") {
          return { kind: "conflict" as const, run: current };
        }
        const { next, event } = buildTerminalRunUpdate(current, input, terminalLogPrefix);
        await storage.put(runEventKey(next.id, event.seq), event);
        await storage.put(runKey(next.id), next);
        return { kind: "committed" as const, run: next, event };
      });
    } catch (error) {
      await deleteStoragePrefix(this.storage, terminalLogPrefix).catch(() => undefined);
      throw error;
    }
    if (
      committed.kind !== "committed" &&
      (committed.kind === "missing" || committed.run.terminalLogPrefix !== terminalLogPrefix)
    ) {
      await deleteStoragePrefix(this.storage, terminalLogPrefix).catch(() => undefined);
    }
    return committed;
  }

  async deleteTerminalRun(runID: string, cutoff: number): Promise<void> {
    await this.host.runExclusive(async () => {
      const current = (await this.storage.get<RunRecord>(runKey(runID))) ?? null;
      const terminalAt = current ? terminalRunTimestamp(current) : undefined;
      if (!current || terminalAt === undefined || terminalAt > cutoff) {
        return;
      }
      await deleteStoragePrefix(this.storage, runEventPrefix(runID));
      if (current.terminalLogPrefix?.startsWith(runTerminalLogRoot(runID))) {
        await deleteStoragePrefix(this.storage, current.terminalLogPrefix);
      }
      await deleteStoragePrefix(this.storage, runLogChunkPrefix(runID));
      await this.storage.delete(runLogKey(runID));
      await this.storage.delete(runKey(runID));
    });
  }
}
