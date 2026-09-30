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
import { leaseKey } from "./lease-repository";
import {
  appendRunTelemetrySample,
  applyRunEventSummary,
  buildRunEvent,
  buildTerminalRunUpdate,
  classifyTerminalRunAttempt,
  RunIDCollisionError,
  runStartedEvent,
  RunTransitionRefused,
  terminalAttemptHasLog,
  terminalAttemptIsConsumed,
  terminalAttemptIsRetiring,
  terminalLogDigest,
  terminalRunTimestamp,
  type RunCommitResult,
  type RunEventTemplate,
  type RunRepository,
  type TerminalAttemptRecord,
  type TerminalAttemptState,
  type TerminalRunCommitInput,
} from "./run-lifecycle";
import { validLeaseID } from "./slug";
import type { LeaseRecord, LeaseTelemetry, RunEventRecord, RunRecord } from "./types";

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

/**
 * The finish-log prefix root one (run, fingerprint) attempt pair owns. The
 * attempt id extends it, but the root is the ownership proof: bytes under it
 * belong to this run's attempt for this fingerprint and nothing else, so GC
 * never has to trust a prefix that is merely under the same run.
 */
function terminalAttemptLogPrefixRoot(runID: string, fingerprint: string): string {
  return `${runTerminalLogRoot(runID)}${fingerprint.replace(/^sha256:/u, "")}:`;
}

function runTerminalLogPrefix(runID: string, fingerprint: string, attemptID: string): string {
  return `${terminalAttemptLogPrefixRoot(runID, fingerprint)}${attemptID}:`;
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

/** The durable terminalization attempt for one (run, fingerprint) pair. */
export function terminalAttemptKey(runID: string, fingerprint: string): string {
  return `terminal-attempt:${runID}:${fingerprint}`;
}

/** Every terminalization attempt that belongs to one run. */
export function terminalAttemptRunPrefix(runID: string): string {
  return `terminal-attempt:${runID}:`;
}

const terminalAttemptPrefix = "terminal-attempt:";

/**
 * The durable reservation of a run ID's namespace. A run ID owns every
 * key derived from it — its record, events, finish logs, and
 * terminalization attempts — so admission cannot be decided by looking
 * only at the two keys that happen to be visible today. The reservation
 * is written in the same transaction as the run and removed only after
 * everything the run owns is gone, which makes "the ID is taken" a
 * single-key fact instead of a scan over several prefixes.
 */
export function runNamespaceKey(runID: string): string {
  return `run-namespace:${runID}`;
}

/** The durable reservation record for one run ID's namespace. */
export interface RunNamespaceRecord {
  runID: string;
  reservedAt: string;
}

/** The durable cleanup tombstone for one terminal run being retired. */
export function runGcKey(runID: string): string {
  return `run-gc:${runID}`;
}

const runGcPrefix = "run-gc:";

/**
 * A durable cleanup tombstone for one terminal run. Retention writes it
 * and removes the visible run record in ONE transaction, then deletes the
 * run's subordinate data idempotently and removes the tombstone and the
 * namespace reservation together last. A crash therefore leaves either a
 * valid visible run or an invisible run with a tombstone naming exactly
 * what still has to be deleted — never a visible run whose terminal log
 * is already gone, and never leftover bytes with no ledger.
 */
export interface RunGcRecord {
  runID: string;
  /** The run's finish-log prefix, recorded only when it is the run's own. */
  terminalLogPrefix?: string;
  claimedAt: string;
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

/** Read the immutable finish-log bytes a reserved prefix holds. */
export async function readTerminalRunLog(storage: RunStorageView, prefix: string): Promise<string> {
  const chunks = await storage.list<string>({ prefix: terminalRunLogChunkPrefix(prefix) });
  if (chunks.size > 0) {
    return [...chunks.entries()]
      .toSorted(([left], [right]) => left.localeCompare(right))
      .map(([, chunk]) => chunk)
      .join("");
  }
  return (await storage.get<string>(terminalRunLogValueKey(prefix))) ?? "";
}

export async function deleteStoragePrefix(storage: RunStorageView, prefix: string): Promise<void> {
  if (prefix === "") {
    // An empty prefix lists the entire storage namespace; no caller may
    // delete without naming what it owns.
    throw new RunStorageIntegrityError("refusing to delete an empty storage prefix");
  }
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

// ─── Persisted-record validation ──────────────────────────────────────
//
// Every persisted record the repository obeys — a GC tombstone, a
// terminalization attempt — must first prove what it owns. The same
// proof applies on every path that touches the record's storage key or
// log prefix: deletion (GC), writing finish bytes, reading them back,
// and consuming the attempt. Corruption is refused, never obeyed, so a
// record that cannot prove its identity can neither redirect a write
// nor redirect a deletion.

/** A persisted record that cannot prove what it owns; the operation is refused. */
export class RunStorageIntegrityError extends Error {}

const sha256Pattern = /^sha256:[0-9a-f]{64}$/u;
const terminalAttemptStates: ReadonlySet<TerminalAttemptState> = new Set([
  "reserved",
  "log_written",
  "consumed",
  "retiring",
]);

function validTimestamp(value: string | undefined): boolean {
  return value !== undefined && Number.isFinite(Date.parse(value));
}

/**
 * Record that a run is attributed to a lease: the lease joins the run's
 * leaseIDs and its ownership joins leaseOwners, both idempotently. The
 * attribution is what read authorization compares against, so it is
 * applied to the record the transaction just reloaded — never to a
 * caller's copy.
 */
function applyLeaseAttribution(run: RunRecord, lease: LeaseRecord): void {
  if (!run.leaseIDs?.includes(lease.id)) {
    run.leaseIDs = [...(run.leaseIDs ?? []), lease.id];
  }
  if (
    !run.leaseOwners?.some(
      (attribution) => attribution.owner === lease.owner && attribution.org === lease.org,
    )
  ) {
    run.leaseOwners = [...(run.leaseOwners ?? []), { owner: lease.owner, org: lease.org }];
  }
}

/**
 * Prove a `run-gc:` tombstone owns exactly what it names before deleting
 * anything. GC deletes by prefix, so a corrupted record must fail closed
 * rather than redirect deletion at another run's namespace: an empty run
 * ID would name every run's events and attempts, and a foreign log prefix
 * could walk the whole storage namespace. The key comparison is the
 * identity proof — the record must be the one its own run ID derives.
 */
function validateRunGcRecord(key: string, record: RunGcRecord): void {
  if (record.runID === "" || key !== runGcKey(record.runID)) {
    throw new RunStorageIntegrityError(`run-gc record ${key} does not match its run ID`);
  }
  if (
    record.terminalLogPrefix !== undefined &&
    !record.terminalLogPrefix.startsWith(runTerminalLogRoot(record.runID))
  ) {
    throw new RunStorageIntegrityError(`run-gc record ${key} names a log outside its run`);
  }
  if (!validTimestamp(record.claimedAt)) {
    throw new RunStorageIntegrityError(`run-gc record ${key} has no valid claim time`);
  }
}

/**
 * The attempt-ID shape the repository mints: `crypto.randomUUID()`.
 *
 * Ownership must be EXACT. A prefix that merely starts inside the
 * fingerprint's root is not proof of anything: the bare root names every
 * attempt for the fingerprint, and a deeper path names someone else's
 * namespace — yet both would pass a `startsWith` check, and deletion is
 * prefix-based, so obeying either could delete a committed run's finish
 * log. The suffix is therefore required to be exactly one attempt ID of
 * the minted shape, followed by the terminal colon.
 */
const attemptIDPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;

/**
 * The proof for a terminalization attempt: the key must be the one its
 * (run ID, fingerprint) pair derives, the state must be one this
 * repository writes, and the log prefix must name EXACTLY one attempt
 * namespace — `root + <attempt ID> + ":"`, nothing else. It is applied
 * on every path that touches the attempt's storage key or log prefix:
 * claiming it for GC, writing its bytes, reading them back, and
 * consuming it. A record that cannot prove what it owns is refused.
 */
function validateTerminalAttemptRecord(key: string, attempt: TerminalAttemptRecord): void {
  if (
    attempt.runID === "" ||
    !sha256Pattern.test(attempt.fingerprint) ||
    key !== terminalAttemptKey(attempt.runID, attempt.fingerprint)
  ) {
    throw new RunStorageIntegrityError(`terminal attempt ${key} does not match its identity`);
  }
  if (!terminalAttemptStates.has(attempt.state)) {
    throw new RunStorageIntegrityError(`terminal attempt ${key} has an unknown state`);
  }
  const root = terminalAttemptLogPrefixRoot(attempt.runID, attempt.fingerprint);
  const attemptID =
    attempt.logPrefix.startsWith(root) && attempt.logPrefix.endsWith(":")
      ? attempt.logPrefix.slice(root.length, -1)
      : undefined;
  if (attemptID === undefined || !attemptIDPattern.test(attemptID)) {
    throw new RunStorageIntegrityError(
      `terminal attempt ${key} does not name exactly one attempt log`,
    );
  }
  if (!validTimestamp(attempt.reservedAt)) {
    throw new RunStorageIntegrityError(`terminal attempt ${key} has no valid reservation time`);
  }
  if (attempt.logDigest !== undefined && !sha256Pattern.test(attempt.logDigest)) {
    throw new RunStorageIntegrityError(`terminal attempt ${key} has an invalid log digest`);
  }
  if (attempt.logWrittenAt !== undefined && !validTimestamp(attempt.logWrittenAt)) {
    throw new RunStorageIntegrityError(`terminal attempt ${key} has no valid log-write time`);
  }
  if (attempt.consumedAt !== undefined && !validTimestamp(attempt.consumedAt)) {
    throw new RunStorageIntegrityError(`terminal attempt ${key} has no valid consumption time`);
  }
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
   * Create the run record, its initial event, and the sequence metadata in
   * ONE transaction: either all of it exists or none of it does. A crash
   * can therefore never leave a partially initialized audit record — the
   * record without its `run.started` event, or an event whose run has no
   * counter for it.
   */
  async createRunningRun(run: RunRecord): Promise<RunEventRecord> {
    const committed = await this.storage.transaction(async (txn) => {
      // Build the persisted record from a clone, so a transaction that
      // aborts (or retries) never leaves the caller holding a record the
      // durable state does not reflect.
      const next = structuredClone(run);
      // A run ID owns its namespace. Refuse an ID that is already a run,
      // an in-flight retirement tombstone, or a reserved namespace
      // instead of overwriting the existing record or being created
      // inside a retirement whose resume would delete the new run's
      // events, logs, and attempts. The reservation is the durable
      // answer for subordinate keys (events, finish logs, attempts) that
      // may outlive a hidden or partially retired run; the run and
      // tombstone checks cover records written before reservations
      // existed.
      if (
        (await txn.get<RunRecord>(runKey(next.id))) !== undefined ||
        (await txn.get<RunGcRecord>(runGcKey(next.id))) !== undefined ||
        (await txn.get<RunNamespaceRecord>(runNamespaceKey(next.id))) !== undefined
      ) {
        throw new RunIDCollisionError(next.id);
      }
      const now = new Date().toISOString();
      const seq = (next.eventCount ?? 0) + 1;
      const event = runStartedEvent(next.id, seq, now);
      next.eventCount = seq;
      next.lastEventAt = now;
      next.storageRevision = 1;
      await txn.put(runNamespaceKey(next.id), {
        runID: next.id,
        reservedAt: now,
      } satisfies RunNamespaceRecord);
      await txn.put(runKey(next.id), next);
      await txn.put(runEventKey(next.id, seq), event);
      return { event, seq, now };
    });
    // Publish the committed sequence back to the caller only AFTER the
    // commit: callers that keep using their record stay in sync, while an
    // aborted attempt leaves the caller's object untouched.
    run.eventCount = committed.seq;
    run.lastEventAt = committed.now;
    return committed.event;
  }

  /**
   * Append one run event, atomically: reload the record, allocate the
   * next sequence from the DURABLE event count, build the event, apply
   * its summary to the reloaded record, and commit the event and the
   * record together. The caller's copy is never written back — a writer
   * that loaded the run before another writer's commit re-derives from
   * the reloaded record instead of reverting it, which is what keeps a
   * late event from resurrecting a run whose terminal commit already
   * landed (the summary additionally refuses to touch committed
   * terminal evidence).
   *
   * Sequence allocation and the record write are one transaction, so
   * two appends cannot mint the same sequence or lose one another's
   * summary update — correctness no longer depends on an outer
   * scheduler serializing these calls.
   */
  async appendRunEvent(
    runID: string,
    template: RunEventTemplate,
  ): Promise<{ event: RunEventRecord; run: RunRecord }> {
    return this.storage.transaction(async (txn) => {
      const current = await txn.get<RunRecord>(runKey(runID));
      if (!current) {
        throw new RunTransitionRefused(`run ${runID} is missing`);
      }
      const next = structuredClone(current);
      const now = new Date().toISOString();
      const seq = (next.eventCount ?? 0) + 1;
      const event = buildRunEvent(next.id, seq, now, template);
      applyRunEventSummary(next, event);
      next.eventCount = seq;
      next.lastEventAt = now;
      // The event may have introduced a lease the run is not yet
      // attributed to; resolve the attribution from the lease record
      // inside the same transaction, so the run never points at a lease
      // whose ownership it does not carry.
      if (validLeaseID(next.leaseID) && !next.leaseIDs?.includes(next.leaseID)) {
        const lease = await txn.get<LeaseRecord>(leaseKey(next.leaseID));
        if (lease) {
          applyLeaseAttribution(next, lease);
        }
      }
      next.storageRevision = (current.storageRevision ?? 0) + 1;
      await txn.put(runEventKey(next.id, seq), event);
      await txn.put(runKey(next.id), next);
      return { event, run: next };
    });
  }

  /**
   * Append one telemetry sample, atomically: merge the sample into the
   * reloaded record so a concurrent append is preserved rather than
   * overwritten, and a stale caller cannot revert a newer summary.
   */
  async appendRunTelemetry(runID: string, sample: LeaseTelemetry): Promise<RunRecord> {
    return this.storage.transaction(async (txn) => {
      const current = await txn.get<RunRecord>(runKey(runID));
      if (!current) {
        throw new RunTransitionRefused(`run ${runID} is missing`);
      }
      const next = structuredClone(current);
      next.telemetry = appendRunTelemetrySample(next.telemetry, sample);
      next.storageRevision = (current.storageRevision ?? 0) + 1;
      await txn.put(runKey(next.id), next);
      return next;
    });
  }

  /**
   * Backfill the run's lease attribution from its own event log,
   * atomically. The event list and the reloaded record are read in the
   * same transaction, so the attribution written back is derived from
   * the durable events and applied to the durable record — a concurrent
   * commit between the caller's load and this write is preserved, not
   * reverted. The caller never writes the record itself.
   *
   * Returns the run's current lease for read authorization, resolved
   * only when the backfill actually ran: a run with complete
   * attribution is judged by its own leaseOwners, so handing back a
   * lease for it would widen a decision the attribution already
   * settled.
   */
  async backfillRunLeaseAttribution(
    runID: string,
  ): Promise<{ run: RunRecord; currentLease?: LeaseRecord } | null> {
    return this.storage.transaction(async (txn) => {
      const current = await txn.get<RunRecord>(runKey(runID));
      if (!current) {
        return null;
      }
      if (current.leaseIDs !== undefined && current.leaseOwners !== undefined) {
        return { run: current };
      }
      // The event log is the authority for which leases this run
      // references: every valid-format lease ID an event carries is
      // part of the run's leaseIDs, resolvable or not, so a reference
      // is never narrowed by a lease that has since been deleted.
      const events = await txn.list<RunEventRecord>({ prefix: runEventPrefix(runID) });
      const leaseIDs = new Set<string>(
        [...events.values()]
          .toSorted((a, b) => a.seq - b.seq)
          .map((event) => event.leaseID)
          .filter((leaseID): leaseID is string => Boolean(leaseID && validLeaseID(leaseID))),
      );
      if (validLeaseID(current.leaseID)) {
        leaseIDs.add(current.leaseID);
      }
      const attributions = new Map<string, { owner: string; org: string }>();
      let currentLease: LeaseRecord | undefined;
      for (const leaseID of leaseIDs) {
        // oxlint-disable-next-line eslint/no-await-in-loop -- each referenced lease is read inside the same transaction before the attribution is committed.
        const lease = await txn.get<LeaseRecord>(leaseKey(leaseID));
        if (!lease) continue;
        attributions.set(`${lease.owner}\u001f${lease.org}`, {
          owner: lease.owner,
          org: lease.org,
        });
        if (leaseID === current.leaseID) {
          currentLease = lease;
        }
      }
      const next = structuredClone(current);
      next.leaseIDs = [...leaseIDs];
      next.leaseOwners = [...attributions.values()];
      next.storageRevision = (current.storageRevision ?? 0) + 1;
      await txn.put(runKey(next.id), next);
      return currentLease === undefined ? { run: next } : { run: next, currentLease };
    });
  }

  /**
   * The terminal commit, staged through a durable attempt so a crash at
   * any boundary is recoverable rather than merely cleaned up:
   *   transaction A  reserve the attempt and its finish-log key
   *   (outside)      write the immutable finish-log bytes
   *   transaction    record log_written with the content digest
   *   transaction B  verify the bytes against that digest, then commit
   *                  the terminal record, its event, and mark the
   *                  attempt consumed — atomically
   *
   * The invariant: a terminal run references a finish log only if the
   * immutable bytes exist and their digest matches the durable attempt,
   * and an uncommitted attempt never makes the run appear terminal.
   * Repeating a finish converges on the same attempt (same fingerprint,
   * same log key) instead of creating a second one.
   *
   * Integrity: every loaded attempt must prove it owns its storage key
   * and its log prefix before this path writes, reads, or consumes it —
   * a corrupted record is refused rather than obeyed, so it can never
   * redirect finish bytes into another run's namespace.
   */
  async commitTerminalRun(input: TerminalRunCommitInput): Promise<RunCommitResult> {
    const attemptKey = terminalAttemptKey(input.runID, input.fingerprint);

    // ── Transaction A: reserve ────────────────────────────────────────
    const reservation = await this.storage.transaction(async (txn) => {
      const current = await txn.get<RunRecord>(runKey(input.runID));
      if (!current) return { kind: "missing" as const };
      const classification = classifyTerminalRunAttempt(current, input.fingerprint, input.binding);
      if (classification === "duplicate") return { kind: "duplicate" as const, run: current };
      if (classification === "conflict") return { kind: "conflict" as const, run: current };
      const existing = await txn.get<TerminalAttemptRecord>(attemptKey);
      if (existing) {
        // A persisted attempt must prove it owns the key it was loaded
        // from and the log prefix this path is about to write to. The
        // commit path obeys the same integrity model as GC: corruption
        // is refused, never carried into a write, a read, or a commit.
        validateTerminalAttemptRecord(attemptKey, existing);
        if (terminalAttemptIsConsumed(existing) || terminalAttemptIsRetiring(existing)) {
          // Consumed: the run already used this attempt and moved on.
          // Retiring: garbage collection owns it, and a new attempt must
          // not reuse a log key GC is about to delete.
          return { kind: "conflict" as const, run: current };
        }
        return { kind: "reserved" as const, attempt: existing };
      }
      const attempt: TerminalAttemptRecord = {
        runID: input.runID,
        fingerprint: input.fingerprint,
        state: "reserved",
        logPrefix: runTerminalLogPrefix(input.runID, input.fingerprint, crypto.randomUUID()),
        reservedAt: new Date().toISOString(),
      };
      await txn.put(attemptKey, attempt);
      return { kind: "reserved" as const, attempt };
    });
    if (reservation.kind !== "reserved") {
      return reservation;
    }
    let attempt = reservation.attempt;

    // ── Immutable bytes, then the digest ──────────────────────────────
    const logDigest = await terminalLogDigest(input.log.text);
    if (!terminalAttemptHasLog(attempt) || attempt.logDigest !== logDigest) {
      // Re-prove ownership immediately before the bytes are written: the
      // prefix came from a validated record, but this write is outside
      // any transaction, so the check cannot be deferred to the
      // log-write transaction that follows it.
      validateTerminalAttemptRecord(attemptKey, attempt);
      await writeTerminalRunLog(this.storage, attempt.logPrefix, input.log.text);
      const recorded = await this.storage.transaction(async (txn) => {
        const current = await txn.get<TerminalAttemptRecord>(attemptKey);
        if (!current || terminalAttemptIsConsumed(current) || terminalAttemptIsRetiring(current)) {
          return undefined;
        }
        // The reloaded record must prove the same ownership before the
        // digest is recorded against its prefix, or corruption could be
        // laundered into `log_written`.
        validateTerminalAttemptRecord(attemptKey, current);
        const next: TerminalAttemptRecord = {
          ...current,
          state: "log_written",
          logDigest,
          logWrittenAt: new Date().toISOString(),
        };
        await txn.put(attemptKey, next);
        return next;
      });
      if (!recorded) {
        // Someone consumed or replaced the attempt while the bytes were
        // being written; re-read the run rather than guessing.
        const current = await this.loadRun(input.runID);
        if (!current) return { kind: "missing" };
        const classification = classifyTerminalRunAttempt(
          current,
          input.fingerprint,
          input.binding,
        );
        if (classification === "duplicate") return { kind: "duplicate", run: current };
        return { kind: "conflict", run: current };
      }
      attempt = recorded;
    }

    // ── Transaction B: verify, then commit and consume ────────────────
    return this.storage.transaction(async (txn) => {
      const current = await txn.get<RunRecord>(runKey(input.runID));
      if (!current) return { kind: "missing" as const };
      const classification = classifyTerminalRunAttempt(current, input.fingerprint, input.binding);
      if (classification === "duplicate") return { kind: "duplicate" as const, run: current };
      if (classification === "conflict") return { kind: "conflict" as const, run: current };
      const durable = await txn.get<TerminalAttemptRecord>(attemptKey);
      if (!durable || !terminalAttemptHasLog(durable) || !durable.logDigest) {
        // The attempt did not survive to a promised log: refuse rather
        // than commit a record that would reference unverified bytes.
        return { kind: "conflict" as const, run: current };
      }
      // The record about to be consumed and referenced by the terminal
      // run must prove it owns its key and its log prefix — the run's
      // finish log reference is only as trustworthy as this proof.
      validateTerminalAttemptRecord(attemptKey, durable);
      // The bytes must exist and hash to the attempt's digest. This is the
      // invariant: no terminal record may reference an unverified log.
      const bytes = await readTerminalRunLog(txn, durable.logPrefix);
      if ((await terminalLogDigest(bytes)) !== durable.logDigest) {
        return { kind: "conflict" as const, run: current };
      }
      const { next, event } = buildTerminalRunUpdate(current, input, durable.logPrefix);
      next.storageRevision = (current.storageRevision ?? 0) + 1;
      await txn.put(runEventKey(next.id, event.seq), event);
      await txn.put(runKey(next.id), next);
      await txn.put(attemptKey, {
        ...durable,
        state: "consumed",
        consumedAt: new Date().toISOString(),
      } satisfies TerminalAttemptRecord);
      return { kind: "committed" as const, run: next, event };
    });
  }

  /**
   * Sweep terminalization attempts that are provably abandoned. An
   * attempt is LIVE — never swept, and neither are its bytes — while the
   * run references its log prefix, which is exactly what a committed
   * terminal run does. A consumed attempt whose run no longer exists
   * anchors nothing and is reclaimed like any other abandoned attempt.
   *
   * The abandon decision is a transaction of its own: it reloads the run
   * and the attempt together and claims the attempt (state `retiring`)
   * only if the run does not reference its log. A terminal commit that
   * runs after the claim sees `retiring` and refuses; one that commits
   * first makes the run reference the log, so the claim is refused. The
   * two outcomes cannot interleave into a run pointing at deleted bytes.
   *
   * `retiring` is a RESUMABLE state, not a terminal one: the claim is
   * committed before any bytes are deleted, so a crash right after the
   * claim — or a deletion that fails part-way — leaves the attempt as the
   * durable ledger for the bytes that remain. The next sweep resumes the
   * deletion instead of skipping the state forever, and the attempt
   * record is removed only once its bytes are gone. A failed deletion
   * therefore never orphans bytes behind a deleted ledger; the sweep
   * finishes the other attempts and then reports the failure, so the
   * retry that follows resumes from the durable claim.
   */
  async sweepTerminalAttempts(cutoff: number): Promise<number> {
    const attempts = await this.storage.list<TerminalAttemptRecord>({
      prefix: terminalAttemptPrefix,
    });
    let swept = 0;
    let firstFailure: unknown;
    for (const [key, attempt] of attempts) {
      let retired = false;
      try {
        // oxlint-disable-next-line eslint/no-await-in-loop -- each attempt is claimed and retired from its own freshly read state before the next is considered.
        retired = await this.sweepTerminalAttempt(key, attempt, cutoff);
      } catch (error) {
        // The attempt stays `retiring` (or unclaimed) and the failure is
        // reported after the others are considered: the ledger survives,
        // and the next sweep resumes the deletion.
        firstFailure ??= error;
      }
      if (retired) {
        swept += 1;
      }
    }
    if (firstFailure !== undefined) {
      throw firstFailure;
    }
    return swept;
  }

  /**
   * Claim one listed attempt if it is abandoned and old enough, then
   * retire it. A `retiring` attempt is already claimed — that is what
   * makes a crash mid-sweep recoverable — so it is resumed directly.
   * Either way the listed record must first prove it owns its storage key
   * and log prefix; a corrupted record is refused rather than obeyed.
   */
  private async sweepTerminalAttempt(
    key: string,
    listed: TerminalAttemptRecord,
    cutoff: number,
  ): Promise<boolean> {
    validateTerminalAttemptRecord(key, listed);
    let attempt = listed;
    if (!terminalAttemptIsRetiring(attempt)) {
      const reservedAt = Date.parse(attempt.reservedAt);
      if (reservedAt > cutoff) {
        return false;
      }
      const claimed = await this.storage.transaction(async (txn) => {
        const current = await txn.get<TerminalAttemptRecord>(key);
        if (!current || terminalAttemptIsRetiring(current)) {
          return undefined;
        }
        // The listed copy was validated before the transaction; the reloaded
        // record must prove the same ownership before it can be claimed, or
        // corruption could be laundered into the `retiring` state.
        validateTerminalAttemptRecord(key, current);
        const run = await txn.get<RunRecord>(runKey(current.runID));
        if (run?.terminalLogPrefix === current.logPrefix) {
          // Live: the run owns this log. Refuse the claim, so a commit
          // that just referenced it is never swept.
          return undefined;
        }
        const next: TerminalAttemptRecord = { ...current, state: "retiring" };
        await txn.put(key, next);
        return next;
      });
      if (!claimed) {
        return false;
      }
      attempt = claimed;
    }
    return this.retireTerminalAttempt(key, attempt);
  }

  /**
   * Delete an attempt GC owns: its bytes first, then the record. The
   * record is the durable ledger for those bytes, so a failure to delete
   * them leaves it in `retiring` and the next sweep resumes; bytes are
   * never orphaned behind a deleted ledger.
   */
  private async retireTerminalAttempt(
    key: string,
    attempt: TerminalAttemptRecord,
  ): Promise<boolean> {
    const run = await this.storage.get<RunRecord>(runKey(attempt.runID));
    if (run?.terminalLogPrefix === attempt.logPrefix) {
      // Unreachable through this repository — a terminal commit accepts
      // only a `log_written` attempt — but never delete bytes a visible
      // run references, even on a state that claims GC owns them.
      return false;
    }
    // GC now owns the attempt: deleting its bytes can no longer race a
    // commit, because the commit accepts only log_written attempts.
    await deleteStoragePrefix(this.storage, attempt.logPrefix);
    // Retire the attempt only after its bytes are gone.
    await this.storage.delete(key);
    return true;
  }

  /**
   * Retire a terminal run: hide it behind a durable tombstone in ONE
   * transaction, then delete everything it owns and the tombstone last.
   * The tombstone is the crash ledger — a resumed retirement re-runs the
   * idempotent deletions instead of guessing which of them survived.
   */
  async deleteTerminalRun(runID: string, cutoff: number): Promise<void> {
    await this.host.runExclusive(async () => {
      const claimed = await this.storage.transaction(async (txn) => {
        const current = await txn.get<RunRecord>(runKey(runID));
        const terminalAt = current ? terminalRunTimestamp(current) : undefined;
        if (!current || terminalAt === undefined || terminalAt > cutoff) {
          return undefined;
        }
        const record: RunGcRecord = {
          runID,
          claimedAt: new Date().toISOString(),
          ...(current.terminalLogPrefix?.startsWith(runTerminalLogRoot(runID))
            ? { terminalLogPrefix: current.terminalLogPrefix }
            : {}),
        };
        await txn.put(runGcKey(runID), record);
        await txn.delete(runKey(runID));
        return record;
      });
      if (!claimed) {
        return;
      }
      await this.retireTerminalRun(runGcKey(runID), claimed);
    });
  }

  /**
   * Finish every tombstoned retirement a crash interrupted. Each resume
   * is idempotent and keeps its tombstone on failure, so the pass can be
   * repeated until nothing is left; one failed resume does not stop the
   * others, and the failure is reported after they are considered.
   */
  async resumeTerminalRunGc(): Promise<number> {
    const pending = await this.storage.list<RunGcRecord>({ prefix: runGcPrefix });
    let resumed = 0;
    let firstFailure: unknown;
    for (const [key, record] of pending) {
      try {
        // oxlint-disable-next-line eslint/no-await-in-loop -- each tombstone is resumed from its own durable record before the next is considered.
        await this.retireTerminalRun(key, record);
        resumed += 1;
      } catch (error) {
        firstFailure ??= error;
      }
    }
    if (firstFailure !== undefined) {
      throw firstFailure;
    }
    return resumed;
  }

  /**
   * Delete a hidden run's subordinate data and then its tombstone. Every
   * step is idempotent and runs only once the tombstone exists, so a
   * crash anywhere here is resumed by the next pass. The tombstone is
   * validated against its storage key and its owned prefixes first, so a
   * corrupted record is refused rather than obeyed.
   */
  private async retireTerminalRun(key: string, record: RunGcRecord): Promise<void> {
    validateRunGcRecord(key, record);
    const { runID } = record;
    await deleteStoragePrefix(this.storage, runEventPrefix(runID));
    if (record.terminalLogPrefix) {
      await deleteStoragePrefix(this.storage, record.terminalLogPrefix);
    }
    await deleteStoragePrefix(this.storage, runLogChunkPrefix(runID));
    await this.storage.delete(runLogKey(runID));
    // The run's digest anchor is removed with it — never before it, so a
    // crash mid-deletion can leave an orphaned attempt but never a run
    // that references a deleted attempt.
    await deleteStoragePrefix(this.storage, terminalAttemptRunPrefix(runID));
    // The tombstone and the namespace reservation are the last things to
    // go, together: everything the run owned is already deleted, so a
    // crash before this point leaves a reservation that keeps refusing
    // the ID (fail closed), and a crash cannot leave either key behind
    // without the other. Only after this does the ID become admissible
    // again — with no subordinate keys left to orphan.
    await this.storage.transaction(async (txn) => {
      await txn.delete(key);
      await txn.delete(runNamespaceKey(runID));
    });
  }
}
