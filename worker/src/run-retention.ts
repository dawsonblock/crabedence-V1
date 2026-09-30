/**
 * Run retention: the maintenance sweep that retires terminal runs and
 * reclaims the storage they own.
 *
 * The sweep is a bounded, resumable scan, never a full-table operation:
 * it pages over `run:` records with a durable cursor, deletes at most
 * one batch of expired terminal runs per tick, and then finishes the
 * work that lives under its own prefixes — interrupted retirements
 * (tombstones) and abandoned terminalization attempts — which must be
 * swept even when the run scan finds nothing.
 *
 * Layering: this module owns the sweep's rules, cursor, and batching.
 * Deletion itself belongs to the run lifecycle/repository, and the host
 * supplies the storage surface. It must not import the fleet router,
 * HTTP routing code, or runtime globals.
 */
import { terminalRunTimestamp, type RunLifecycleService } from "./run-lifecycle";
import { runKey } from "./run-repository";
import type { RunRecord } from "./types";

/** The retention window when the deployment does not configure one. */
export const defaultTerminalRunRetentionDays = 30;

/** How many `run:` records one maintenance page scans. */
const storageRecordScanBatchSize = 128;

/** How many expired terminal runs one tick may delete. */
const terminalRunPruneBatchSize = 16;

/** The durable cursor that makes the scan resumable across ticks. */
export const runPruneCursorKey = "maintenance:run-prune-cursor";

/**
 * The configured retention window in milliseconds: at least one day,
 * at most ten years, defaulting when unset or malformed.
 */
export function terminalRunRetentionMs(value: string | undefined): number {
  const parsed = Number(value ?? "");
  const days =
    Number.isFinite(parsed) && parsed >= 1 ? Math.trunc(parsed) : defaultTerminalRunRetentionDays;
  return Math.min(days, 3650) * 24 * 60 * 60 * 1000;
}

/** The storage surface the sweep needs; durable-object storage satisfies it. */
export interface RunRetentionStorage {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<unknown>;
  list<T>(options: {
    prefix: string;
    limit?: number;
    startAfter?: string;
  }): Promise<Map<string, T>>;
}

/** The host surface the sweep needs. */
export interface RunRetentionHost {
  readonly storage: RunRetentionStorage;
  /** The run lifecycle, which owns terminal-run deletion and GC. */
  readonly runs: Pick<
    RunLifecycleService,
    "pruneTerminalRun" | "resumeTerminalRunGc" | "sweepTerminalAttempts"
  >;
  /** CRABBOX_RUN_RETENTION_DAYS as configured. */
  readonly retentionDays: string | undefined;
}

export class RunRetentionService {
  constructor(private readonly host: RunRetentionHost) {}

  /**
   * One retention tick: delete up to a batch of expired terminal runs,
   * then resume interrupted retirements and sweep abandoned attempts.
   * Every step is idempotent and resumable, so an interrupted tick is
   * finished by the next one.
   */
  async pruneTerminalRuns(): Promise<void> {
    const cutoff = Date.now() - terminalRunRetentionMs(this.host.retentionDays);
    const storedCursor = await this.host.storage.get<string>(runPruneCursorKey);
    const startAfter = storedCursor?.startsWith("run:") ? storedCursor : undefined;
    const page = await this.host.storage.list<RunRecord>({
      prefix: "run:",
      limit: storageRecordScanBatchSize,
      ...(startAfter ? { startAfter } : {}),
    });
    if (page.size === 0) {
      if (storedCursor !== undefined) {
        await this.host.storage.delete(runPruneCursorKey);
      }
    } else {
      let deleted = 0;
      let lastScanned: string | undefined;
      for (const [key, run] of page) {
        lastScanned = key;
        const terminalAt = terminalRunTimestamp(run);
        if (key === runKey(run.id) && terminalAt !== undefined && terminalAt <= cutoff) {
          // oxlint-disable-next-line eslint/no-await-in-loop -- each run and its artifacts are removed before advancing the maintenance cursor.
          await this.host.runs.pruneTerminalRun(run.id, cutoff);
          deleted += 1;
          if (deleted >= terminalRunPruneBatchSize) {
            break;
          }
        }
      }
      const pageEnd = [...page.keys()].at(-1);
      if (lastScanned && (lastScanned !== pageEnd || page.size === storageRecordScanBatchSize)) {
        await this.host.storage.put(runPruneCursorKey, lastScanned);
      } else {
        await this.host.storage.delete(runPruneCursorKey);
      }
    }
    // Interrupted retirements and abandoned attempts live under their own
    // prefixes, so they are swept even when the run scan found nothing.
    await this.host.runs.resumeTerminalRunGc();
    await this.host.runs.sweepTerminalAttempts(
      Date.now() - terminalRunRetentionMs(this.host.retentionDays),
    );
  }
}
