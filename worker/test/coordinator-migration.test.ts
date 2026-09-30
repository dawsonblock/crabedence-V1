import { afterEach, describe, expect, it, vi } from "vitest";

import {
  exportCoordinatorState,
  importCoordinatorState,
  validateCoordinatorExport,
  verifyCoordinatorImport,
  type CoordinatorStateExport,
} from "../src/coordinator-migration";
import type { LeaseRecord } from "../src/types";
import {
  parityFixture,
  parityLease,
  parityProvider,
  ParityStorage,
  type CoordinatorParityNodeMocks,
  type ParityProviderCalls,
} from "./coordinator-parity-fixture";

const nodeMocks = vi.hoisted(() => ({
  storage: undefined as unknown,
  boss: undefined as unknown,
}));
vi.mock("../node/postgres-storage", () => ({
  PostgresCoordinatorStorage: function () {
    return nodeMocks.storage;
  },
}));
vi.mock("pg-boss", () => ({
  PgBoss: function () {
    return nodeMocks.boss;
  },
}));

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  await Promise.all(cleanups.splice(0).map((cleanup) => cleanup()));
  vi.restoreAllMocks();
});

async function sourceStorage() {
  const storage = new ParityStorage();
  await storage.put("lease:cbx_000000000001", parityLease({ id: "cbx_000000000001" }));
  await storage.put("run:run_1", { id: "run_1", state: "finished", exitCode: 0 });
  await storage.put("webvnc-ticket:t1", {
    leaseID: "cbx_000000000001",
    owner: "alice@example.com",
  });
  return storage;
}

describe("coordinator migration", () => {
  it("exports a versioned, hashed document and validates it", async () => {
    const storage = await sourceStorage();
    const document = await exportCoordinatorState(storage);

    expect(document.kind).toBe("crabbox-coordinator-export");
    expect(document.version).toBe(1);
    expect(document.entryCount).toBe(3);
    expect(document.entries.map((entry) => entry.key)).toEqual(
      document.entries.map((entry) => entry.key).toSorted(),
    );
    const validation = await validateCoordinatorExport(document);
    expect(validation.errors).toEqual([]);
    expect(validation.document?.digest).toBe(document.digest);
  });

  it("rejects tampered or malformed export documents", async () => {
    const storage = await sourceStorage();
    const document = await exportCoordinatorState(storage);

    const wrongKind = await validateCoordinatorExport({ ...document, kind: "other" });
    expect(wrongKind.errors.join(" ")).toContain("kind");

    const wrongVersion = await validateCoordinatorExport({ ...document, version: 2 });
    expect(wrongVersion.errors.join(" ")).toContain("version");

    const tampered = structuredClone(document);
    (tampered.entries[0]!.value as Record<string, unknown>)["tampered"] = true;
    const badHash = await validateCoordinatorExport(tampered);
    expect(badHash.errors.join(" ")).toContain("sha256");

    const badDigest = structuredClone(document);
    badDigest.digest = "0".repeat(64);
    const digestCheck = await validateCoordinatorExport(badDigest);
    expect(digestCheck.errors.join(" ")).toContain("digest");
  });

  it("dry-runs an import without writing, then applies it in a transaction", async () => {
    const source = await sourceStorage();
    const target = new ParityStorage();
    const document = await exportCoordinatorState(source);

    const dry = await importCoordinatorState(document, target, { dryRun: true });
    expect(dry.applied).toBe(false);
    expect(dry.writes).toBe(3);
    expect((await target.list()).size).toBe(0);

    const applied = await importCoordinatorState(document, target);
    expect(applied.applied).toBe(true);
    expect(applied.written).toBe(3);

    const verification = await verifyCoordinatorImport(document, target);
    expect(verification.ok).toBe(true);
  });

  it("reports conflicts and honors fail/skip/overwrite policies", async () => {
    const source = await sourceStorage();
    const target = new ParityStorage();
    await target.put("run:run_1", { id: "run_1", state: "different" });
    const document = await exportCoordinatorState(source);

    const fail = await importCoordinatorState(document, target);
    expect(fail.applied).toBe(false);
    expect(fail.conflicts.map((entry) => entry.key)).toEqual(["run:run_1"]);

    const skip = await importCoordinatorState(document, target, { onConflict: "skip" });
    expect(skip.applied).toBe(true);
    expect(await target.get<{ state: string }>("run:run_1")).toMatchObject({
      state: "different",
    });
    expect(await target.get("lease:cbx_000000000001")).toBeDefined();

    const overwrite = await importCoordinatorState(document, target, { onConflict: "overwrite" });
    expect(overwrite.applied).toBe(true);
    expect(await target.get<{ state: string }>("run:run_1")).toMatchObject({ state: "finished" });

    const verification = await verifyCoordinatorImport(document, target);
    expect(verification.ok).toBe(true);
  });

  it("detects missing, mismatched, and unexpected keys in verification", async () => {
    const source = await sourceStorage();
    const target = new ParityStorage();
    const document = await exportCoordinatorState(source);

    await target.put("run:run_1", { id: "run_1", state: "different" });
    await target.put("extra:key", { stray: true });

    const verification = await verifyCoordinatorImport(document, target);
    expect(verification.ok).toBe(false);
    expect(verification.missing).toEqual(
      expect.arrayContaining(["lease:cbx_000000000001", "webvnc-ticket:t1"]),
    );
    expect(verification.mismatched.map((entry) => entry.key)).toEqual(["run:run_1"]);
    // Extra target keys are reported but do not by themselves fail verification.
    expect(verification.unexpected).toEqual(["extra:key"]);
  });

  it("enforces planned state inside import transactions (TOCTOU)", async () => {
    // A TOCTOU gap exists when the pre-import plan reads target state outside
    // any transaction, and a concurrent writer changes that state before the
    // transactional write. The import must re-classify each entry inside the
    // transaction and apply the conflict policy there, not trust the plan.
    const source = await sourceStorage();
    const document = await exportCoordinatorState(source);

    // Target starts empty; the plan will classify all entries as "write".
    const target = new ParityStorage();
    // Inject a concurrent write between plan and commit: the transaction
    // callback writes a conflicting value before the import's own put.
    const originalTransaction = target.transaction.bind(target);
    let transactionCallCount = 0;
    target.transaction = vi.fn<
      (callback: (tx: typeof target) => Promise<unknown>) => Promise<unknown>
    >(async (callback: (tx: typeof target) => Promise<unknown>) => {
      transactionCallCount += 1;
      if (transactionCallCount === 1) {
        // Simulate a concurrent writer landing a conflicting value for run:run_1
        // just before the import's transaction opens (or inside it, before the
        // import's read). The in-transaction re-classification must detect this.
        await target.put("run:run_1", { id: "run_1", state: "raced" });
      }
      return originalTransaction(callback);
    }) as typeof target.transaction;

    // onConflict=fail: the in-transaction conflict must abort the import.
    const fail = await importCoordinatorState(document, target);
    expect(fail.applied).toBe(false);
    expect(fail.errors.join(" ")).toContain("run:run_1");
    // The raced value must be preserved (the transaction rolled back).
    expect(await target.get<{ state: string }>("run:run_1")).toMatchObject({ state: "raced" });

    // onConflict=skip: the in-transaction conflict must skip the raced key.
    const skip = await importCoordinatorState(document, target, { onConflict: "skip" });
    expect(skip.applied).toBe(true);
    expect(await target.get<{ state: string }>("run:run_1")).toMatchObject({ state: "raced" });
    // Non-conflicting keys should still be written.
    expect(await target.get("lease:cbx_000000000001")).toBeDefined();

    // onConflict=overwrite: the in-transaction conflict must overwrite.
    const overwrite = await importCoordinatorState(document, target, {
      onConflict: "overwrite",
    });
    expect(overwrite.applied).toBe(true);
    expect(await target.get<{ state: string }>("run:run_1")).toMatchObject({
      state: "finished",
    });
  });

  it("skips unchanged keys inside import transactions (TOCTOU)", async () => {
    // A key that was classified as "write" in the plan may already exist with
    // the same value by the time the transaction runs (a concurrent writer
    // wrote the identical value). The in-transaction re-classification must
    // detect this and skip, not blindly overwrite.
    const source = await sourceStorage();
    const document = await exportCoordinatorState(source);
    const target = new ParityStorage();

    // Pre-populate one key with the same value the import would write.
    const existingEntry = document.entries.find((entry) => entry.key === "run:run_1")!;
    await target.put("run:run_1", existingEntry.value);

    const result = await importCoordinatorState(document, target);
    expect(result.applied).toBe(true);
    // run:run_1 should be counted as skipped, not written.
    expect(result.written).toBe(document.entries.length - 1);
  });
});

describe("coordinator migration endpoints", () => {
  const admin = { authorization: "Bearer parity-admin-token" };

  it("requires admin auth", async () => {
    const f = await parityFixture("cloudflare", {
      providers: { hetzner: parityProvider(newCalls()) as never },
    });
    cleanups.push(() => f.stop());
    const anonymous = await f.fetch(
      f.request("POST", "/v1/admin/coordinator/export", { auth: false }),
    );
    expect(anonymous.status).toBe(401);
    const nonAdmin = await f.fetch(f.request("POST", "/v1/admin/coordinator/export"));
    expect(nonAdmin.status).toBe(403);
  });

  it("exports from the Cloudflare leg and imports into the Node leg", async () => {
    const source = await parityFixture("cloudflare", {
      providers: { hetzner: parityProvider(newCalls()) as never },
    });
    cleanups.push(() => source.stop());
    const target = await parityFixture("node", {
      nodeMocks: nodeMocks as CoordinatorParityNodeMocks,
      providers: { hetzner: parityProvider(newCalls()) as never },
    });
    cleanups.push(() => target.stop());

    const lease = parityLease({ id: "cbx_0000000000aa" });
    await source.seed(`lease:${lease.id}`, lease);

    const exported = await source.fetch(
      source.request("POST", "/v1/admin/coordinator/export", {
        auth: false,
        headers: admin,
      }),
    );
    expect(exported.status).toBe(200);
    const document = (await exported.json()) as CoordinatorStateExport;
    expect(document.entries.some((entry) => entry.key === `lease:${lease.id}`)).toBe(true);

    const dryRun = await target.fetch(
      target.request("POST", "/v1/admin/coordinator/import?dryRun=true", {
        auth: false,
        headers: admin,
        body: document,
      }),
    );
    expect(dryRun.status).toBe(200);
    expect(await target.stored(`lease:${lease.id}`)).toBeUndefined();

    const imported = await target.fetch(
      target.request("POST", "/v1/admin/coordinator/import", {
        auth: false,
        headers: admin,
        body: document,
      }),
    );
    expect(imported.status).toBe(200);
    const stored = await target.stored<LeaseRecord>(`lease:${lease.id}`);
    expect(stored?.id).toBe(lease.id);

    const verified = await target.fetch(
      target.request("POST", "/v1/admin/coordinator/verify", {
        auth: false,
        headers: admin,
        body: document,
      }),
    );
    const verification = (await verified.json()) as {
      ok: boolean;
      missing: string[];
      mismatched: unknown[];
    };
    // The target may hold its own bookkeeping keys (e.g., runtime alarm state);
    // every exported key must be present and equal.
    expect(verification.missing).toEqual([]);
    expect(verification.mismatched).toEqual([]);
  });
});

function newCalls(): ParityProviderCalls {
  return { created: [], released: [], deleted: [], deletedSSHKeys: [] };
}
