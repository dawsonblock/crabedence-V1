/**
 * Run lifecycle: the rules that decide how a coordinator run changes
 * state, and the service that applies them through a narrow repository.
 *
 * The run state machine is deliberately small — `running` →
 * `succeeded` | `failed` — and there is no generic state setter: the
 * only transitions are the ones defined here. Terminal evidence is
 * immutable: once a run carries a terminal fingerprint, no late event
 * and no repeated finish attempt may rewrite it.
 *
 * Layering: this module depends on the authorization decisions and the
 * domain types. It must not import the fleet router, the storage layer,
 * Cloudflare runtime globals, HTTP routing code, or environment
 * parsing — the repository adapter supplies persistence.
 */
import { runWritableByPrincipal, type ActorContext } from "./authorization";
import { sameTerminalRunBinding } from "./run-receipt";
import type {
  LeaseRecord,
  LeaseTelemetry,
  RunEventRecord,
  RunEvidenceV1,
  RunRecord,
  RunTelemetrySummary,
  TerminalRunReceipt,
  TestResultSummary,
} from "./types";

export type RunState = RunRecord["state"];

/** The state and phase a newly created run starts in. */
export const INITIAL_RUN_STATE: RunState = "running";
export const INITIAL_RUN_PHASE = "starting";

/**
 * The run ID a new run is minted with: `run_` plus 128 random bits.
 * Durable storage keys are derived from the ID, so the width is a
 * namespace guarantee, not cosmetics; creation additionally refuses an ID
 * that already owns storage (RunIDCollisionError), which the lifecycle
 * service resolves by re-minting.
 */
export function newRunID(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return `run_${[...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

/** A creation was refused because the run ID already owns storage. */
export class RunIDCollisionError extends Error {}

/**
 * An update the repository refused because the durable record is not
 * what the caller believes it is — a different incarnation, a missing
 * record, or a revision the caller's update cannot be applied to. The
 * caller reloads and re-derives rather than writing a stale copy back.
 */
export class RunTransitionRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RunTransitionRefused";
  }
}

/**
 * Everything a run event carries except the fields the repository
 * assigns from the durable record: the run ID, the sequence, and the
 * commit time. Callers bound and sanitize the caller-supplied fields;
 * identity and ordering come from the record itself.
 */
export type RunEventTemplate = Omit<RunEventRecord, "runID" | "seq" | "createdAt">;

/** Build one run event from a template, with the record-assigned fields. */
export function buildRunEvent(
  runID: string,
  seq: number,
  createdAt: string,
  template: RunEventTemplate,
): RunEventRecord {
  return { runID, seq, createdAt, ...template };
}

/** Terminal states are immutable; only `running` may transition. */
export function isTerminalRunState(state: RunState): boolean {
  return state !== "running";
}

/** The terminal state an exit code implies. */
export function terminalRunStateForExitCode(exitCode: number): RunState {
  return exitCode === 0 ? "succeeded" : "failed";
}

/** When a terminal run became terminal, for retention. */
export function terminalRunTimestamp(run: RunRecord): number | undefined {
  if (run.state === "running") {
    return undefined;
  }
  for (const value of [run.endedAt, run.lastEventAt, run.startedAt]) {
    const timestamp = Date.parse(value ?? "");
    if (Number.isFinite(timestamp)) {
      return timestamp;
    }
  }
  return undefined;
}

function phaseForRunEvent(event: RunEventRecord): string {
  switch (event.type) {
    case "leasing.started":
      return "leasing";
    case "lease.created":
      return "leased";
    case "bootstrap.waiting":
      return "bootstrap";
    case "sync.started":
      return "sync";
    case "sync.finished":
      return "synced";
    case "command.started":
    case "stdout":
    case "stderr":
      return "command";
    case "lease.released":
      return "released";
    default:
      return "";
  }
}

/**
 * Apply an event to the run summary. Late deliveries remain in the audit
 * trail without rewriting committed terminal evidence, and a
 * `run.failed` event is the one event-driven state transition: the run
 * becomes terminal `failed`.
 *
 * The projection freezes on EITHER terminal marker. A `/finish` commit
 * leaves a terminal fingerprint; a `run.failed` event terminalizes
 * without one. Guarding only on the fingerprint let a late event rewrite
 * a failed run's projection — phase, provider, lease attribution — which
 * is both a history-integrity and an authorization defect, since lease
 * attribution decides who may read the run. The event that terminalizes
 * still applies, because the record is `running` when it is projected.
 */
export function applyRunEventSummary(run: RunRecord, event: RunEventRecord): void {
  if (run.terminalFinishSHA256 || isTerminalRunState(run.state)) {
    return;
  }
  if (event.phase) {
    run.phase = event.phase;
  } else {
    const phase = phaseForRunEvent(event);
    if (phase) {
      run.phase = phase;
    }
  }
  if (event.leaseID) {
    run.leaseID = event.leaseID;
  }
  if (event.slug) {
    run.slug = event.slug;
  }
  if (event.provider) {
    run.provider = event.provider;
  }
  if (event.target) {
    run.target = event.target;
  }
  if (event.windowsMode) {
    run.windowsMode = event.windowsMode;
  }
  if (event.class) {
    run.class = event.class;
  }
  if (event.serverType) {
    run.serverType = event.serverType;
  }
  if (event.type === "run.failed") {
    run.state = "failed";
    run.phase = "failed";
    run.endedAt = event.createdAt;
  }
}

/**
 * The single terminal lifecycle event. Its fields are fixed by the
 * transition, so it needs no input sanitization.
 */
export function terminalRunEvent(
  runID: string,
  seq: number,
  createdAt: string,
  state: RunState,
  exitCode: number,
): RunEventRecord {
  return {
    runID,
    seq,
    type: "command.finished",
    phase: state,
    exitCode,
    createdAt,
  };
}

/** The run.started event, fixed by the creation transition. */
export function runStartedEvent(runID: string, seq: number, createdAt: string): RunEventRecord {
  return {
    runID,
    seq,
    type: "run.started",
    phase: "starting",
    createdAt,
  };
}

// ─── Run telemetry ───────────────────────────────────────────────────

/** The most recent telemetry samples one run retains. */
export const maxRunTelemetrySamples = 60;

/**
 * Keep the most recent `max` samples, one per capture time, in time
 * order. A sample without a capture time is dropped: it cannot be
 * ordered against the others, so retaining it would make the series
 * ambiguous.
 */
export function boundedTelemetrySamples(samples: LeaseTelemetry[], max: number): LeaseTelemetry[] {
  const byTime = new Map<string, LeaseTelemetry>();
  for (const sample of samples) {
    if (sample?.capturedAt) {
      byTime.set(sample.capturedAt, sample);
    }
  }
  return [...byTime.values()]
    .toSorted((left, right) => left.capturedAt.localeCompare(right.capturedAt))
    .slice(-max);
}

/**
 * Merge two telemetry summaries: the incoming summary's start/end win
 * (they are the later observation), and the sample series is the bounded
 * union of both, so a merge never drops a sample another writer
 * committed.
 */
export function mergeRunTelemetry(
  existing: RunTelemetrySummary | undefined,
  incoming: RunTelemetrySummary,
): RunTelemetrySummary {
  const telemetry: RunTelemetrySummary = {
    ...existing,
    ...incoming,
  };
  telemetry.samples = boundedTelemetrySamples(
    [
      ...((existing?.samples ?? []).filter(Boolean) as LeaseTelemetry[]),
      ...((incoming.samples ?? []).filter(Boolean) as LeaseTelemetry[]),
    ],
    maxRunTelemetrySamples,
  );
  if (telemetry.samples.length === 0) {
    delete telemetry.samples;
  }
  return telemetry;
}

/**
 * Append one telemetry sample to a run's summary: the first sample also
 * becomes the run's start reading, and the series stays bounded.
 */
export function appendRunTelemetrySample(
  telemetry: RunTelemetrySummary | undefined,
  sample: LeaseTelemetry,
): RunTelemetrySummary {
  const next: RunTelemetrySummary = { ...telemetry };
  next.samples = boundedTelemetrySamples([...(next.samples ?? []), sample], maxRunTelemetrySamples);
  if (!next.start) {
    next.start = sample;
  }
  return next;
}

/** The classification of one finish attempt against the current record. */
export type TerminalRunClassification = "missing" | "duplicate" | "conflict" | "proceed";

/**
 * Decide what a finish attempt means for the current record: a
 * repeated attempt carrying the same fingerprint replays the committed
 * result; a different fingerprint or a different terminal binding is a
 * conflict; only a running record bound to the same identity proceeds.
 */
export function classifyTerminalRunAttempt(
  current: RunRecord | null,
  requestedFingerprint: string,
  requestedBinding: RunRecord,
): TerminalRunClassification {
  if (!current) {
    return "missing";
  }
  if (isTerminalRunState(current.state)) {
    return current.terminalFinishSHA256 === requestedFingerprint ? "duplicate" : "conflict";
  }
  if (!sameTerminalRunBinding(current, requestedBinding)) {
    return "conflict";
  }
  return "proceed";
}

/** Everything a terminal transition needs, already verified. */
export interface TerminalRunCommitInput {
  runID: string;
  /** The terminal-finish fingerprint that identifies this attempt. */
  fingerprint: string;
  /** The run as loaded by the caller, for the terminal-binding check. */
  binding: RunRecord;
  exitCode: number;
  syncMs: number;
  commandMs: number;
  log: { text: string; bytes: number; truncated: boolean };
  blockedStage?: string | undefined;
  retryLikely?: string | undefined;
  /** Already bounded by the caller. */
  results?: TestResultSummary | undefined;
  /** Already sanitized and merged with the run's existing telemetry. */
  telemetry?: RunTelemetrySummary | undefined;
  receipt?: TerminalRunReceipt | undefined;
  evidence?: RunEvidenceV1 | undefined;
  now: Date;
}

/**
 * Build the terminal transition: the next record and its lifecycle
 * event. Pure — the repository persists both in one transaction.
 */
export function buildTerminalRunUpdate(
  current: RunRecord,
  input: TerminalRunCommitInput,
  terminalLogPrefix: string,
): { next: RunRecord; event: RunEventRecord } {
  const next = { ...current };
  next.exitCode = input.exitCode;
  next.syncMs = input.syncMs;
  next.commandMs = input.commandMs;
  next.state = terminalRunStateForExitCode(input.exitCode);
  next.phase = next.state;
  const endedAt = input.now.toISOString();
  next.endedAt = endedAt;
  const started = Date.parse(next.startedAt);
  const ended = Date.parse(endedAt);
  if (Number.isFinite(started) && Number.isFinite(ended)) {
    next.durationMs = ended - started;
  }
  next.logBytes = input.log.bytes;
  next.logTruncated = input.log.truncated;
  if (input.blockedStage) next.blockedStage = input.blockedStage;
  if (input.retryLikely) next.retryLikely = input.retryLikely;
  if (input.results) next.results = input.results;
  if (input.telemetry) {
    // Merge with the RELOADED record's summary, never replace it: a
    // telemetry append that committed between the caller's load and this
    // transaction must survive the terminal commit, exactly as an event
    // append does.
    next.telemetry = mergeRunTelemetry(current.telemetry, input.telemetry);
  }
  if (input.receipt) next.terminalReceipt = input.receipt;
  if (input.evidence) next.evidence = input.evidence;
  next.terminalFinishSHA256 = input.fingerprint;
  next.terminalLogPrefix = terminalLogPrefix;
  const seq = (next.eventCount ?? 0) + 1;
  const event = terminalRunEvent(next.id, seq, endedAt, next.state, exitCodeOf(next));
  next.eventCount = seq;
  next.lastEventAt = endedAt;
  return { next, event };
}

function exitCodeOf(run: RunRecord): number {
  return typeof run.exitCode === "number" && Number.isFinite(run.exitCode) ? run.exitCode : 1;
}

/** The outcome of one repository commit. */
export type RunCommitResult =
  | { kind: "missing" }
  | { kind: "duplicate"; run: RunRecord }
  | { kind: "conflict"; run: RunRecord }
  | { kind: "committed"; run: RunRecord; event: RunEventRecord };

/**
 * The narrow persistence contract the lifecycle service depends on.
 * Operations are semantic — there is deliberately no generic state
 * setter, and the terminal commit re-classifies inside its own
 * transaction, so a concurrent writer cannot be raced.
 */
export interface RunRepository {
  loadRun(runID: string): Promise<RunRecord | null>;
  /**
   * Persist the running record, its `run.started` event, and the
   * durable reservation of its ID namespace. An ID that already owns
   * storage — an existing run, an in-flight retirement tombstone, or a
   * reserved namespace — is refused with RunIDCollisionError, never
   * overwritten.
   */
  createRunningRun(run: RunRecord): Promise<RunEventRecord>;
  /**
   * Append one run event and apply its summary to the run, atomically.
   * The sequence is allocated from the durable record inside the
   * transaction, so concurrent appends cannot collide, and the summary
   * is applied to the reloaded record, so a late event can never write
   * a pre-terminal copy back over a committed terminal run. Returns the
   * committed event and the record it was applied to.
   */
  appendRunEvent(
    runID: string,
    template: RunEventTemplate,
  ): Promise<{ event: RunEventRecord; run: RunRecord }>;
  /**
   * Append one telemetry sample to the run's summary, atomically: the
   * sample is merged into the reloaded record, so a concurrent append
   * cannot be lost and a stale copy is never written back.
   */
  appendRunTelemetry(runID: string, sample: LeaseTelemetry): Promise<RunRecord>;
  /**
   * Backfill the run's lease attribution from its event log and the
   * referenced leases, atomically, and return the run's current lease
   * for read authorization. A run whose attribution is already present
   * is returned unchanged WITHOUT resolving the current lease: the
   * attribution alone settles readability, and handing back a lease
   * would widen a decision it already made.
   */
  backfillRunLeaseAttribution(
    runID: string,
  ): Promise<{ run: RunRecord; currentLease?: LeaseRecord } | null>;
  /** Persist the terminal transition atomically, or classify the attempt. */
  commitTerminalRun(input: TerminalRunCommitInput): Promise<RunCommitResult>;
  /** Remove a terminal run and everything it owns. */
  deleteTerminalRun(runID: string, cutoff: number): Promise<void>;
  /**
   * Finish terminal-run retirements a crash interrupted: each durable
   * cleanup tombstone is resumed and removed. Retention hides a run
   * behind its tombstone atomically, so an interrupted retirement is
   * never a visible run pointing at deleted data — only an invisible run
   * whose tombstone names the deletion that still has to happen.
   */
  resumeTerminalRunGc(): Promise<number>;
  /**
   * Remove terminalization attempts that are provably abandoned: an
   * attempt whose log the run does not reference, older than the cutoff.
   * A committed terminal run's log is never swept, and a consumed
   * attempt is retained until its run is deleted. The abandon decision is
   * claimed atomically (state `retiring`) so it cannot race a concurrent
   * terminal commit, and a claim survives a crash: the next sweep
   * resumes the deletion instead of skipping the state forever.
   */
  sweepTerminalAttempts(cutoff: number): Promise<number>;
}

/**
 * The lifecycle service: authorize, classify, persist through the
 * repository, and return a domain result. The fleet router consumes
 * this and never decides how a run changes state.
 */
export class RunLifecycleService {
  constructor(private readonly repository: RunRepository) {}

  /** Load a run and prove the actor may write it; null means not found. */
  async loadWritableRun(runID: string, actor: ActorContext): Promise<RunRecord | null> {
    const run = await this.repository.loadRun(runID);
    if (!run || !runWritableByPrincipal(run, actor)) {
      return null;
    }
    return run;
  }

  /**
   * Persist a new running run and its `run.started` event. A refused ID
   * collision is resolved by re-minting the run's ID and retrying, so the
   * caller's record always carries the persisted ID and a colliding
   * creation can never overwrite another run's namespace.
   */
  async createRun(run: RunRecord): Promise<RunEventRecord> {
    for (let attempt = 0; ; attempt += 1) {
      try {
        // oxlint-disable-next-line eslint/no-await-in-loop -- each attempt is one complete transaction that must settle before the ID is re-minted.
        return await this.repository.createRunningRun(run);
      } catch (error) {
        // The bound turns a pathological storage state into an error
        // instead of an endless loop.
        if (!(error instanceof RunIDCollisionError) || attempt >= 4) {
          throw error;
        }
        run.id = newRunID();
      }
    }
  }

  /** Classify a finish attempt against the current record (pre-check). */
  classifyFinishAttempt(run: RunRecord, fingerprint: string): TerminalRunClassification {
    return classifyTerminalRunAttempt(run, fingerprint, run);
  }

  /**
   * Append one run event. The event's caller-supplied fields are already
   * bounded; identity and sequence are assigned from the durable record
   * inside the repository transaction.
   */
  async appendRunEvent(
    runID: string,
    template: RunEventTemplate,
  ): Promise<{ event: RunEventRecord; run: RunRecord }> {
    return this.repository.appendRunEvent(runID, template);
  }

  /** Append one telemetry sample to the run's summary. */
  async appendRunTelemetry(runID: string, sample: LeaseTelemetry): Promise<RunRecord> {
    return this.repository.appendRunTelemetry(runID, sample);
  }

  /**
   * Backfill the run's lease attribution, resolving its current lease
   * only when the backfill actually ran (see the repository contract).
   */
  async ensureRunLeaseAttribution(
    runID: string,
  ): Promise<{ run: RunRecord; currentLease?: LeaseRecord } | null> {
    return this.repository.backfillRunLeaseAttribution(runID);
  }

  /** Commit the terminal transition through the repository. */
  async finalizeRun(input: TerminalRunCommitInput): Promise<RunCommitResult> {
    return this.repository.commitTerminalRun(input);
  }

  /** Retire a terminal run and everything it owns. */
  async pruneTerminalRun(runID: string, cutoff: number): Promise<void> {
    return this.repository.deleteTerminalRun(runID, cutoff);
  }

  /** Finish terminal-run retirements a crash interrupted. */
  async resumeTerminalRunGc(): Promise<number> {
    return this.repository.resumeTerminalRunGc();
  }

  /** Retire terminalization attempts that are provably abandoned. */
  async sweepTerminalAttempts(cutoff: number): Promise<number> {
    return this.repository.sweepTerminalAttempts(cutoff);
  }
}

// ─── Terminal attempts (finish-log ownership) ────────────────────────

/**
 * The progress of one terminalization attempt, tracked EXPLICITLY rather
 * than inferred from which artifacts happen to exist:
 *
 *   reserved     — the attempt owns a finish-log key, no bytes promised yet
 *   log_written  — the immutable finish-log bytes exist and their digest
 *                  is recorded on the attempt
 *   consumed     — the terminal run record references this log; the
 *                  attempt is the run's durable digest anchor and is
 *                  removed WITH the run, reclaimed alone only once the
 *                  run is gone
 *   retiring     — garbage collection has claimed the abandoned attempt;
 *                  the terminal commit must never consume it again, and
 *                  the claim is durable: after a crash the sweeper
 *                  resumes the deletion instead of skipping the state
 *                  forever, and the record is removed only once its
 *                  bytes are gone
 *
 * The invariant this exists to make checkable: a terminal run may
 * reference a finish log only if the immutable bytes exist and their
 * digest matches the durable attempt, and an uncommitted attempt may
 * never make the run appear terminal.
 *
 * A consumed attempt is deliberately NOT swept while its run exists: the
 * run's `terminalLogPrefix` and the attempt's `logDigest` are one durable
 * integrity unit, so removing the attempt alone would make a valid
 * terminal run unverifiable (the persistence qualification classifies
 * exactly that as impossible). Once the run is gone — retention removed
 * it, or a crash interrupted that removal — the attempt anchors nothing
 * and is reclaimed like any other abandoned attempt.
 */
export type TerminalAttemptState = "reserved" | "log_written" | "consumed" | "retiring";

export interface TerminalAttemptRecord {
  runID: string;
  fingerprint: string;
  state: TerminalAttemptState;
  /** The finish-log key prefix this attempt reserved (immutable). */
  logPrefix: string;
  /** The content digest of the finish-log bytes, recorded with log_written. */
  logDigest?: string;
  reservedAt: string;
  logWrittenAt?: string;
  consumedAt?: string;
}

/** Whether the attempt has promised immutable log bytes. */
export function terminalAttemptHasLog(attempt: TerminalAttemptRecord): boolean {
  return attempt.state === "log_written" || attempt.state === "consumed";
}

/** Whether the attempt's log is owned by a committed terminal run. */
export function terminalAttemptIsConsumed(attempt: TerminalAttemptRecord): boolean {
  return attempt.state === "consumed";
}

/** Whether garbage collection has claimed the attempt for retirement. */
export function terminalAttemptIsRetiring(attempt: TerminalAttemptRecord): boolean {
  return attempt.state === "retiring";
}

/** The SHA-256 of a finish log's bytes, in the fingerprint's format. */
export async function terminalLogDigest(bytes: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(bytes));
  const hex = [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return `sha256:${hex}`;
}
