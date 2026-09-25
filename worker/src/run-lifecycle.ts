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
 */
export function applyRunEventSummary(run: RunRecord, event: RunEventRecord): void {
  if (run.terminalFinishSHA256) {
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
  if (input.telemetry) next.telemetry = input.telemetry;
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
  /** Persist the running record, then its `run.started` event. */
  createRunningRun(run: RunRecord): Promise<RunEventRecord>;
  /** Persist the terminal transition atomically, or classify the attempt. */
  commitTerminalRun(input: TerminalRunCommitInput): Promise<RunCommitResult>;
  /** Remove a terminal run and everything it owns. */
  deleteTerminalRun(runID: string, cutoff: number): Promise<void>;
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

  /** Persist a new running run and its `run.started` event. */
  async createRun(run: RunRecord): Promise<RunEventRecord> {
    return this.repository.createRunningRun(run);
  }

  /** Classify a finish attempt against the current record (pre-check). */
  classifyFinishAttempt(run: RunRecord, fingerprint: string): TerminalRunClassification {
    return classifyTerminalRunAttempt(run, fingerprint, run);
  }

  /** Commit the terminal transition through the repository. */
  async finalizeRun(input: TerminalRunCommitInput): Promise<RunCommitResult> {
    return this.repository.commitTerminalRun(input);
  }

  /** Retire a terminal run and everything it owns. */
  async pruneTerminalRun(runID: string, cutoff: number): Promise<void> {
    return this.repository.deleteTerminalRun(runID, cutoff);
  }
}
