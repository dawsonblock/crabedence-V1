import { sha256Hex } from "./auth";
import type { CoordinatorStorage } from "./coordinator-runtime";

// Coordinator state migration between storage backends (for example Durable
// Object storage → PostgreSQL). The export document is versioned and hashed so
// an import can be validated before it mutates anything, applied in bounded
// transactions, reconciled after the fact, and compared against a pre-import
// baseline for rollback validation.

export const coordinatorExportKind = "crabbox-coordinator-export";
export const coordinatorExportVersion = 1;
export const coordinatorImportBatchSize = 1000;

export interface CoordinatorExportEntry {
  key: string;
  value: unknown;
  /** sha256 of the canonical JSON encoding of `value`. */
  sha256: string;
}

export interface CoordinatorStateExport {
  kind: typeof coordinatorExportKind;
  version: typeof coordinatorExportVersion;
  exportedAt: string;
  entryCount: number;
  /** sha256 over `<key>:<entry-sha256>` lines in key order. */
  digest: string;
  entries: CoordinatorExportEntry[];
}

export interface CoordinatorExportValidation {
  document?: CoordinatorStateExport;
  errors: string[];
}

export interface CoordinatorImportConflict {
  key: string;
  existingSha256: string;
  incomingSha256: string;
}

export interface CoordinatorImportPlan {
  errors: string[];
  total: number;
  writes: number;
  unchanged: number;
  conflicts: CoordinatorImportConflict[];
}

export interface CoordinatorImportOptions {
  /** Plan only: validate the document and compare keys without writing. */
  dryRun?: boolean;
  /** How to treat keys that already exist with different values. */
  onConflict?: "fail" | "skip" | "overwrite";
  /** Entries per transaction; bounds individual commit size. */
  batchSize?: number;
}

export interface CoordinatorImportResult extends CoordinatorImportPlan {
  applied: boolean;
  batches: number;
  written: number;
  skipped: number;
}

export interface CoordinatorImportVerification {
  ok: boolean;
  expected: number;
  present: number;
  missing: string[];
  mismatched: Array<{ key: string; expectedSha256: string; actualSha256: string }>;
  /** Keys present in the target that the export does not contain. */
  unexpected: string[];
}

export function canonicalCoordinatorJSON(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .toSorted(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
        .map(([key, entry]) => [key, canonicalize(entry)]),
    );
  }
  return value;
}

export async function exportCoordinatorState(
  storage: CoordinatorStorage,
): Promise<CoordinatorStateExport> {
  const records = await storage.list<unknown>();
  const entries: CoordinatorExportEntry[] = await Promise.all(
    [...records]
      .toSorted(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(async ([key, value]) => ({
        key,
        value,
        sha256: await sha256Hex(canonicalCoordinatorJSON(value)),
      })),
  );
  return {
    kind: coordinatorExportKind,
    version: coordinatorExportVersion,
    exportedAt: new Date().toISOString(),
    entryCount: entries.length,
    digest: await exportDigest(entries),
    entries,
  };
}

async function exportDigest(entries: CoordinatorExportEntry[]): Promise<string> {
  return sha256Hex(entries.map((entry) => `${entry.key}:${entry.sha256}`).join("\n"));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

export async function validateCoordinatorExport(
  document: unknown,
): Promise<CoordinatorExportValidation> {
  const errors: string[] = [];
  if (!isRecord(document)) {
    return { errors: ["export document is not an object"] };
  }
  if (document["kind"] !== coordinatorExportKind) {
    errors.push(`kind must be "${coordinatorExportKind}"`);
  }
  if (document["version"] !== coordinatorExportVersion) {
    errors.push(`unsupported export version ${JSON.stringify(document["version"])}`);
  }
  const rawEntries = document["entries"];
  if (!Array.isArray(rawEntries)) {
    errors.push("entries must be an array");
    return { errors };
  }
  const entries: CoordinatorExportEntry[] = [];
  const seen = new Set<string>();
  const checked: Array<{ error?: string; entry?: CoordinatorExportEntry }> = await Promise.all(
    rawEntries.map(async (entry, index) => {
      const label = `entries[${index}]`;
      if (!isRecord(entry) || typeof entry["key"] !== "string" || entry["key"].length === 0) {
        return { error: `${label} is missing a string key` };
      }
      if (seen.has(entry["key"])) {
        return { error: `${label} duplicates key ${entry["key"]}` };
      }
      if (typeof entry["sha256"] !== "string" || !/^[a-f0-9]{64}$/.test(entry["sha256"])) {
        return { error: `${label} has an invalid sha256` };
      }
      seen.add(entry["key"]);
      const sha256 = await sha256Hex(canonicalCoordinatorJSON(entry["value"]));
      if (sha256 !== entry["sha256"]) {
        return { error: `${label} value does not match its sha256` };
      }
      return { entry: { key: entry["key"], value: entry["value"], sha256: entry["sha256"] } };
    }),
  );
  for (const result of checked) {
    if (result.error) errors.push(result.error);
    else if (result.entry) entries.push(result.entry);
  }
  if (document["entryCount"] !== rawEntries.length) {
    errors.push("entryCount does not match entries length");
  }
  if (errors.length === 0) {
    const digest = await exportDigest(
      entries.toSorted((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0)),
    );
    if (document["digest"] !== digest) {
      errors.push("digest does not match entries");
    }
  }
  if (errors.length > 0) return { errors };
  return {
    document: {
      kind: coordinatorExportKind,
      version: coordinatorExportVersion,
      exportedAt: String(document["exportedAt"] ?? ""),
      entryCount: rawEntries.length,
      digest: String(document["digest"]),
      entries: entries.toSorted((left, right) =>
        left.key < right.key ? -1 : left.key > right.key ? 1 : 0,
      ),
    },
    errors: [],
  };
}

export async function planCoordinatorImport(
  document: CoordinatorStateExport,
  target: CoordinatorStorage,
): Promise<CoordinatorImportPlan> {
  const plan: CoordinatorImportPlan = {
    errors: [],
    total: document.entries.length,
    writes: 0,
    unchanged: 0,
    conflicts: [],
  };
  const classified = await Promise.all(
    document.entries.map(async (entry) => {
      const existing = await target.get(entry.key);
      if (existing === undefined) return { entry, kind: "write" as const };
      const existingSha256 = await sha256Hex(canonicalCoordinatorJSON(existing));
      if (existingSha256 === entry.sha256) return { entry, kind: "unchanged" as const };
      return { entry, kind: "conflict" as const, existingSha256 };
    }),
  );
  for (const result of classified) {
    if (result.kind === "write") plan.writes += 1;
    else if (result.kind === "unchanged") plan.unchanged += 1;
    else
      plan.conflicts.push({
        key: result.entry.key,
        existingSha256: result.existingSha256,
        incomingSha256: result.entry.sha256,
      });
  }
  return plan;
}

export async function importCoordinatorState(
  document: unknown,
  target: CoordinatorStorage,
  options: CoordinatorImportOptions = {},
): Promise<CoordinatorImportResult> {
  const validation = await validateCoordinatorExport(document);
  if (!validation.document) {
    return {
      errors: validation.errors,
      total: 0,
      writes: 0,
      unchanged: 0,
      conflicts: [],
      applied: false,
      batches: 0,
      written: 0,
      skipped: 0,
    };
  }
  const plan = await planCoordinatorImport(validation.document, target);
  const onConflict = options.onConflict ?? "fail";
  if (onConflict === "fail" && plan.conflicts.length > 0) {
    plan.errors.push(
      `import aborted: ${plan.conflicts.length} existing key(s) differ ` +
        `(first: ${plan.conflicts[0]!.key})`,
    );
    return { ...plan, applied: false, batches: 0, written: 0, skipped: 0 };
  }
  if (options.dryRun) {
    return { ...plan, applied: false, batches: 0, written: 0, skipped: 0 };
  }
  const conflictKeys = new Set(plan.conflicts.map((conflict) => conflict.key));
  const unchangedChecks = await Promise.all(
    validation.document.entries.map(async (entry) => {
      if (conflictKeys.has(entry.key)) return { key: entry.key, unchanged: false };
      const existing = await target.get(entry.key);
      const unchanged =
        existing !== undefined &&
        (await sha256Hex(canonicalCoordinatorJSON(existing))) === entry.sha256;
      return { key: entry.key, unchanged };
    }),
  );
  const unchangedKeys = new Set(
    unchangedChecks.filter((check) => check.unchanged).map((check) => check.key),
  );
  const pending = validation.document.entries.filter(
    (entry) =>
      !unchangedKeys.has(entry.key) && !(onConflict === "skip" && conflictKeys.has(entry.key)),
  );
  const batchSize = options.batchSize ?? coordinatorImportBatchSize;
  let written = 0;
  let batches = 0;
  for (let offset = 0; offset < pending.length; offset += batchSize) {
    const batch = pending.slice(offset, offset + batchSize);
    // oxlint-disable-next-line eslint/no-await-in-loop -- batches commit sequentially to bound each transaction.
    await target.transaction(async (transaction) => {
      await Promise.all(batch.map((entry) => transaction.put(entry.key, entry.value)));
    });
    written += batch.length;
    batches += 1;
  }
  return {
    ...plan,
    applied: true,
    batches,
    written,
    skipped: plan.total - written - plan.unchanged,
  };
}

export async function verifyCoordinatorImport(
  document: CoordinatorStateExport,
  target: CoordinatorStorage,
): Promise<CoordinatorImportVerification> {
  const result: CoordinatorImportVerification = {
    ok: true,
    expected: document.entries.length,
    present: 0,
    missing: [],
    mismatched: [],
    unexpected: [],
  };
  const exported = new Map(document.entries.map((entry) => [entry.key, entry.sha256]));
  const existing = await target.list<unknown>();
  for (const [key] of existing) {
    if (!exported.has(key)) result.unexpected.push(key);
  }
  const comparisons = await Promise.all(
    [...exported].map(async ([key, sha256]) => {
      const value = existing.get(key);
      if (value === undefined) return { key, sha256, status: "missing" as const };
      const actualSha256 = await sha256Hex(canonicalCoordinatorJSON(value));
      return {
        key,
        sha256,
        status: actualSha256 === sha256 ? ("present" as const) : ("mismatched" as const),
        actualSha256,
      };
    }),
  );
  for (const comparison of comparisons) {
    if (comparison.status === "missing") result.missing.push(comparison.key);
    else if (comparison.status === "mismatched") {
      result.present += 1;
      result.mismatched.push({
        key: comparison.key,
        expectedSha256: comparison.sha256,
        actualSha256: comparison.actualSha256,
      });
    } else {
      result.present += 1;
    }
  }
  // Extra keys in the target (runtime bookkeeping, pre-existing state) are
  // informational; reconciliation only requires every exported key to match.
  result.ok = result.missing.length === 0 && result.mismatched.length === 0;
  return result;
}
