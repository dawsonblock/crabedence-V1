import type { RunEvidenceV1, RunRecord, TerminalRunReceipt } from "./types";

const terminalReceiptMaxBytes = 16 * 1024;
const terminalReceiptFieldMaxBytes = 4 * 1024;
const terminalReceiptIdentityMaxBytes = 256;
const terminalReceiptClockSkewMs = 30_000;
const terminalReceiptFields = [
  "schema_version",
  "receipt_type",
  "started_at",
  "ended_at",
  "provider",
  "lease_id",
  "slug",
  "run_id",
  "command",
  "command_sha256",
  "exit_code",
  "sync_ms",
  "command_ms",
  "duration_ms",
  "log_sha256",
  "retained_log_sha256",
  "log_truncated",
  "evidence_sha256",
  "public_key",
  "signer",
  "signature",
] as const;
const terminalReceiptSigningFields = terminalReceiptFields.filter((field) => field !== "signature");
const encoder = new TextEncoder();

export async function verifyTerminalReceipt(
  value: unknown,
  binding: {
    run: RunRecord;
    exitCode: number;
    syncMs: number;
    commandMs: number;
    log: string;
    logTruncated: boolean;
    observedAt: Date;
  },
): Promise<TerminalRunReceipt> {
  const receipt = parseTerminalReceipt(value);
  const startedAt = Date.parse(receipt.started_at);
  const endedAt = Date.parse(receipt.ended_at);
  if (
    !Number.isFinite(startedAt) ||
    !Number.isFinite(endedAt) ||
    endedAt < startedAt ||
    endedAt > binding.observedAt.getTime() + terminalReceiptClockSkewMs ||
    receipt.duration_ms !== endedAt - startedAt ||
    receipt.duration_ms < binding.syncMs + binding.commandMs
  ) {
    throw new Error("invalid terminal receipt timestamps");
  }
  if (
    startedAt !== Date.parse(binding.run.startedAt) ||
    receipt.provider !== binding.run.provider ||
    receipt.lease_id !== (binding.run.leaseID || undefined) ||
    receipt.slug !== (binding.run.slug || undefined) ||
    receipt.run_id !== binding.run.id ||
    receipt.exit_code !== binding.exitCode ||
    receipt.sync_ms !== binding.syncMs ||
    receipt.command_ms !== binding.commandMs ||
    receipt.log_truncated !== binding.logTruncated
  ) {
    throw new Error("terminal receipt run binding mismatch");
  }
  if (receipt.command_sha256 !== (await commandSHA256(binding.run.command))) {
    throw new Error("terminal receipt command binding mismatch");
  }
  const retainedDigest = await sha256Digest(encoder.encode(binding.log));
  if (
    receipt.retained_log_sha256 !== retainedDigest ||
    (!binding.logTruncated && receipt.log_sha256 !== retainedDigest)
  ) {
    throw new Error("terminal receipt log binding mismatch");
  }
  const publicKey = decodeBase64(receipt.public_key, 32, "public_key");
  if (receipt.signer !== (await sha256Digest(publicKey))) {
    throw new Error("terminal receipt signer mismatch");
  }
  const signature = decodeBase64(receipt.signature, 64, "signature");
  const key = await crypto.subtle.importKey("raw", publicKey, "Ed25519", false, ["verify"]);
  if (
    !(await crypto.subtle.verify("Ed25519", key, signature, terminalReceiptSigningBytes(receipt)))
  ) {
    throw new Error("terminal receipt signature mismatch");
  }
  return receipt;
}

export async function terminalFinishSHA256(input: {
  exitCode: number;
  syncMs: number;
  commandMs: number;
  log: string;
  logTruncated: boolean;
  blockedStage: string | undefined;
  retryLikely: string | undefined;
  results: unknown;
  telemetry: unknown;
  receipt: TerminalRunReceipt | undefined;
  evidence: RunEvidenceV1 | undefined;
}): Promise<string> {
  return sha256Digest(
    encoder.encode(
      JSON.stringify([
        input.exitCode,
        input.syncMs,
        input.commandMs,
        input.log,
        input.logTruncated,
        input.blockedStage ?? "",
        input.retryLikely ?? "",
        stableJSONValue(input.results),
        stableJSONValue(input.telemetry),
        stableJSONValue(input.receipt),
        stableJSONValue(input.evidence),
      ]),
    ),
  );
}

export function sameTerminalRunBinding(left: RunRecord, right: RunRecord): boolean {
  return (
    left.provider === right.provider &&
    left.leaseID === right.leaseID &&
    left.slug === right.slug &&
    left.startedAt === right.startedAt &&
    left.command.length === right.command.length &&
    left.command.every((argument, index) => argument === right.command[index])
  );
}

/**
 * validateRunEvidence checks that a RunEvidenceV1 record is structurally valid
 * and internally consistent. It verifies:
 * - schema_version and evidence_type
 * - digest correctness (SHA-256 over canonical JSON with digest set to "")
 * - status/exit_code consistency
 * - bounded field sizes
 * - run_id/lease_id/provider match the run when provided
 * - evidence_sha256 in the receipt (when present) matches the evidence digest
 *
 * Returns an Error if validation fails, undefined if the evidence is absent.
 */
export async function validateRunEvidence(
  evidence: unknown,
  binding: {
    runID: string;
    leaseID: string;
    provider: string;
    exitCode: number;
    receipt?: TerminalRunReceipt | undefined;
  },
): Promise<Error | undefined> {
  if (evidence === undefined || evidence === null) return undefined;
  if (typeof evidence !== "object" || Array.isArray(evidence)) {
    return new Error("evidence must be an object");
  }
  const ev = evidence as Record<string, unknown>;
  if (ev["schema_version"] !== 1) {
    return new Error("evidence schema_version must be 1");
  }
  if (ev["evidence_type"] !== "run") {
    return new Error("evidence evidence_type must be 'run'");
  }
  if (typeof ev["provider"] !== "string" || ev["provider"].length === 0) {
    return new Error("evidence provider is required");
  }
  if (ev["provider"] !== binding.provider) {
    return new Error("evidence provider does not match run provider");
  }
  if (typeof ev["run_id"] === "string" && ev["run_id"] !== binding.runID) {
    return new Error("evidence run_id does not match run");
  }
  if (typeof ev["lease_id"] === "string" && ev["lease_id"] !== binding.leaseID) {
    return new Error("evidence lease_id does not match run");
  }
  if (typeof ev["exit_code"] !== "number" || !Number.isFinite(ev["exit_code"])) {
    return new Error("evidence exit_code must be a finite number");
  }
  if (ev["exit_code"] !== binding.exitCode) {
    return new Error("evidence exit_code does not match finish exitCode");
  }
  if (typeof ev["run_status"] !== "string") {
    return new Error("evidence run_status is required");
  }
  const expectedStatus = binding.exitCode === 0 ? "succeeded" : "failed";
  if (
    ev["run_status"] !== expectedStatus &&
    ev["run_status"] !== "timed-out" &&
    ev["run_status"] !== "canceled"
  ) {
    return new Error(
      `evidence run_status ${ev["run_status"]} is inconsistent with exit_code ${binding.exitCode}`,
    );
  }
  if (
    typeof ev["digest"] !== "string" ||
    ev["digest"].length !== 71 ||
    !ev["digest"].startsWith("sha256:")
  ) {
    return new Error("evidence digest must be a sha256 digest");
  }
  // Verify digest: recompute SHA-256 over canonical JSON with digest set to "".
  const recomputed = await computeEvidenceDigest(ev);
  if (recomputed !== ev["digest"]) {
    return new Error("evidence digest mismatch");
  }
  // If the receipt binds evidence_sha256, verify it matches.
  if (binding.receipt?.evidence_sha256) {
    if (binding.receipt.evidence_sha256 !== ev["digest"]) {
      return new Error("evidence digest does not match receipt evidence_sha256");
    }
  }
  return undefined;
}

async function computeEvidenceDigest(ev: Record<string, unknown>): Promise<string> {
  const canonical = { ...ev, digest: "" };
  const stable = stableJSONValue(canonical);
  return sha256Digest(encoder.encode(JSON.stringify(stable)));
}

function stableJSONValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableJSONValue);
  if (!value || typeof value !== "object") return value ?? null;
  return Object.fromEntries(
    Object.entries(value)
      .toSorted(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => [key, stableJSONValue(entry)]),
  );
}

function parseTerminalReceipt(value: unknown): TerminalRunReceipt {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("terminal receipt must be an object");
  }
  if (encoder.encode(JSON.stringify(value)).byteLength > terminalReceiptMaxBytes) {
    throw new Error("terminal receipt is too large");
  }
  const record = value as Record<string, unknown>;
  const allowed = new Set<string>(terminalReceiptFields);
  if (Object.keys(record).some((field) => !allowed.has(field))) {
    throw new Error("terminal receipt has unknown fields");
  }
  for (const field of terminalReceiptFields) {
    if (
      (field === "lease_id" || field === "slug" || field === "evidence_sha256") &&
      record[field] === undefined
    )
      continue;
    if (record[field] === undefined) throw new Error(`terminal receipt is missing ${field}`);
  }
  const receipt = record as unknown as TerminalRunReceipt;
  if (
    (receipt.schema_version !== 2 && receipt.schema_version !== 3) ||
    receipt.receipt_type !== "terminal"
  ) {
    throw new Error("unsupported terminal receipt");
  }
  for (const field of [
    "started_at",
    "ended_at",
    "provider",
    "run_id",
    "command",
    "command_sha256",
    "log_sha256",
    "retained_log_sha256",
    "public_key",
    "signer",
    "signature",
  ] as const) {
    if (
      typeof receipt[field] !== "string" ||
      !receipt[field] ||
      encoder.encode(receipt[field]).byteLength > terminalReceiptFieldMaxBytes
    ) {
      throw new Error(`invalid terminal receipt ${field}`);
    }
  }
  for (const field of ["lease_id", "slug"] as const) {
    if (
      receipt[field] !== undefined &&
      (typeof receipt[field] !== "string" ||
        !receipt[field] ||
        encoder.encode(receipt[field]).byteLength > terminalReceiptIdentityMaxBytes)
    ) {
      throw new Error(`invalid terminal receipt ${field}`);
    }
  }
  for (const field of ["exit_code", "sync_ms", "command_ms", "duration_ms"] as const) {
    if (!Number.isSafeInteger(receipt[field]) || receipt[field] < 0) {
      throw new Error(`invalid terminal receipt ${field}`);
    }
  }
  if (typeof receipt.log_truncated !== "boolean") {
    throw new Error("invalid terminal receipt log_truncated");
  }
  for (const field of ["command_sha256", "log_sha256", "retained_log_sha256", "signer"] as const) {
    if (!/^sha256:[0-9a-f]{64}$/u.test(receipt[field])) {
      throw new Error(`invalid terminal receipt ${field}`);
    }
  }
  if (receipt.evidence_sha256 !== undefined && !/^[0-9a-f]{64}$/u.test(receipt.evidence_sha256)) {
    throw new Error("invalid terminal receipt evidence_sha256");
  }
  return receipt;
}

function terminalReceiptSigningBytes(receipt: TerminalRunReceipt): Uint8Array {
  // v2 receipts do not include evidence_sha256 in the signing payload.
  // v3+ receipts append evidence_sha256 before public_key/signer.
  const fields =
    receipt.schema_version >= 3
      ? terminalReceiptSigningFields
      : terminalReceiptSigningFields.filter((field) => field !== "evidence_sha256");
  const prefix =
    receipt.schema_version >= 3 ? "crabbox-terminal-receipt-v3\0" : "crabbox-terminal-receipt-v2\0";
  return lengthPrefixedPayload(
    prefix,
    fields.map((field) => String((receipt as unknown as Record<string, unknown>)[field] ?? "")),
  );
}

async function commandSHA256(command: string[]): Promise<string> {
  return sha256Digest(lengthPrefixedPayload("crabbox-command-v1\0", command));
}

function lengthPrefixedPayload(prefix: string, values: string[]): Uint8Array {
  const parts = [encoder.encode(prefix)];
  for (const entry of values) {
    const value = encoder.encode(entry);
    const length = new Uint8Array(4);
    new DataView(length.buffer).setUint32(0, value.byteLength);
    parts.push(length, value);
  }
  const payload = new Uint8Array(parts.reduce((total, part) => total + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) {
    payload.set(part, offset);
    offset += part.byteLength;
  }
  return payload;
}

async function sha256Digest(value: BufferSource): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", value));
  return `sha256:${[...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function decodeBase64(value: string, length: number, field: string): Uint8Array {
  try {
    const decoded = Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
    if (decoded.byteLength === length) return decoded;
  } catch {
    // Report one stable validation error below.
  }
  throw new Error(`invalid terminal receipt ${field}`);
}
