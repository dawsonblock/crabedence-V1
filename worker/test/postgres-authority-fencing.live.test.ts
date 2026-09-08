import { Pool } from "pg";
import { afterAll, afterEach, describe, expect, it } from "vitest";

import { PostgresCoordinatorStorage } from "../node/postgres-storage";

// Adversarial authority-fencing test: proves that the database-enforced
// transaction-scoped advisory lock prevents split-brain mutations when a
// coordinator's lock session dies while a mutation is in-flight.
//
// Requires a writable PostgreSQL database:
//
//   CRABBOX_TEST_DATABASE_URL=postgres://... npx vitest run test/postgres-authority-fencing.live.test.ts
//
// This test uses pg_terminate_backend to kill the exact lock-owning backend
// during an in-flight mutation, then verifies that a replacement coordinator
// cannot acquire authority until the in-flight transaction commits or rolls
// back. This is the release gate for the PostgreSQL fencing invariant.
const databaseURL = process.env.CRABBOX_TEST_DATABASE_URL;
const runLive = databaseURL ? describe : describe.skip;

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  await Promise.all(cleanups.splice(0).map((cleanup) => cleanup()));
});

// Clean up all test data after the entire test suite so subsequent test
// files (e.g. coordinator-parity.live.test.ts) start with a clean database.
afterAll(async () => {
  if (!databaseURL) return;
  const pool = new Pool({ connectionString: databaseURL });
  pool.on("error", () => {});
  try {
    // Terminate any backends still holding coordinator advisory locks.
    const lockHolders = await pool.query<{ pid: number }>(
      `SELECT pid FROM pg_locks
       WHERE locktype = 'advisory'
         AND classid = 0
         AND objsubid = 1
         AND objid IN (hashtext('crabbox.coordinator'), hashtext('crabbox.coordinator.mutation'))
         AND granted = true`,
    );
    await Promise.all(
      lockHolders.rows.map((row) => pool.query("SELECT pg_terminate_backend($1)", [row.pid])),
    );
    // Clean up test data.
    await pool.query("DELETE FROM crabbox.coordinator_kv WHERE key LIKE 'fencing-test:%'");
  } catch {
    // Table may not exist if all tests were skipped.
  }
  await pool.end();
});

/**
 * Find the PID of the backend holding the crabbox.coordinator advisory lock.
 */
async function findLockHolderPID(pool: Pool): Promise<number | undefined> {
  const result = await pool.query<{ pid: number }>(
    `
    SELECT pid FROM pg_locks
    WHERE locktype = 'advisory'
      AND classid = 0
      AND objsubid = 1
      AND objid = hashtext('crabbox.coordinator')
      AND granted = true
    LIMIT 1
    `,
  );
  return result.rows[0]?.pid;
}

/**
 * Clear any stale coordinator advisory locks from previous test runs.
 * Kills the backend holding the lock if one exists.
 */
async function clearStaleLocks(pool: Pool): Promise<void> {
  const pid = await findLockHolderPID(pool);
  if (pid) {
    await pool.query("SELECT pg_terminate_backend($1)", [pid]);
    // Wait for the lock to be released.
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
}

/**
 * Find the PID of the backend holding the crabbox.coordinator.mutation
 * advisory lock (the transaction-scoped fence lock).
 */
async function findXactLockHolderPID(
  pool: Pool,
  _excludePID: number | undefined,
): Promise<number | undefined> {
  const result = await pool.query<{ pid: number }>(
    `
    SELECT pid FROM pg_locks
    WHERE locktype = 'advisory'
      AND classid = 0
      AND objsubid = 1
      AND objid = hashtext('crabbox.coordinator.mutation')
      AND granted = true
    LIMIT 1
    `,
  );
  return result.rows[0]?.pid;
}

runLive("PostgreSQL authority fencing (live)", () => {
  it("prevents split-brain: in-flight mutation blocks replacement coordinator", async () => {
    const adminPool = new Pool({ connectionString: databaseURL });
    adminPool.on("error", () => {});
    cleanups.push(() => adminPool.end());

    // Ensure the schema exists and clear any stale advisory locks.
    const storageA = new PostgresCoordinatorStorage(databaseURL);
    cleanups.push(() => storageA.close());
    await storageA.initialize();

    // Clear any stale locks from previous test runs.
    await clearStaleLocks(adminPool);

    // Coordinator A acquires the coordinator lock.
    const lockA = await storageA.acquireCoordinatorLock();
    expect(lockA).toBeDefined();
    if (!lockA) return;

    // Track whether A detects authority loss.
    let aLostAuthority = false;
    lockA.onLost(() => {
      aLostAuthority = true;
    });

    // Verify A holds the lock.
    const pidA = await findLockHolderPID(adminPool);
    expect(pidA).toBeDefined();

    // Start an in-flight mutation on A that blocks before commit.
    // Use the pool directly to ensure the xact lock is acquired.
    let resolveBlock: () => void;
    const blockPromise = new Promise<void>((resolve) => {
      resolveBlock = resolve;
    });
    let mutationCommitted = false;
    let mutationError: Error | undefined;

    // Directly check out a client from a separate pool and start a fenced
    // transaction. Using storageA.pool might hang if the pool is exhausted.
    const txPool = new Pool({ connectionString: databaseURL });
    txPool.on("error", () => {});
    cleanups.push(() => txPool.end());
    const txClient = await txPool.connect();
    let mutationDone = false;
    const mutationPromise = (async () => {
      try {
        await txClient.query("begin isolation level serializable");
        await txClient.query("select pg_advisory_xact_lock(hashtext($1))", [
          "crabbox.coordinator.mutation",
        ]);
        // Block here to simulate a slow mutation.
        await blockPromise;
        // Write the test data directly via SQL.
        await txClient.query(
          `insert into crabbox.coordinator_kv (key, value, value_text, value_text_updated_at)
           values ($1, $2::jsonb, $3, now())
           on conflict (key) do update set value = $2::jsonb, value_text = $3, value_text_updated_at = now(), updated_at = now()`,
          ["fencing-test:key", '{"value":"committed-by-A"}', '{"value":"committed-by-A"}'],
        );
        await txClient.query("commit");
        mutationCommitted = true;
      } catch (error) {
        try {
          await txClient.query("rollback");
        } catch {
          // ignore rollback errors
        }
        mutationError = error instanceof Error ? error : new Error(String(error));
      } finally {
        if (!mutationDone) {
          txClient.release();
        }
      }
    })();

    // Give the transaction time to begin and acquire the xact lock.
    // Retry finding the xact lock holder for up to 2 seconds.
    let xactPID: number | undefined;
    for (let i = 0; i < 20 && xactPID === undefined; i++) {
      // eslint-disable-next-line no-await-in-loop
      await new Promise((resolve) => setTimeout(resolve, 100));
      // eslint-disable-next-line no-await-in-loop
      xactPID = await findXactLockHolderPID(adminPool, pidA);
    }

    // If we still can't find the xact lock, debug by listing all advisory locks.
    if (xactPID === undefined) {
      const allLocks = await adminPool.query(
        `SELECT pid, locktype, classid, objid, objsubid, granted
         FROM pg_locks WHERE locktype = 'advisory' AND granted = true`,
      );
      console.log("All advisory locks:", JSON.stringify(allLocks.rows));
      console.log("Session lock PID (pidA):", pidA);
      console.log("mutationError:", mutationError?.message ?? "none");
      console.log("mutationCommitted:", mutationCommitted);
    }

    // Verify the xact lock is held (the in-flight transaction holds it).
    expect(xactPID).toBeDefined();

    // Kill A's lock session — simulate authority loss.
    if (pidA) {
      await adminPool.query("SELECT pg_terminate_backend($1)", [pidA]);
    }

    // Wait for A to detect authority loss (the lock client's error/end
    // event fires asynchronously after pg_terminate_backend).
    let authorityLost = false;
    for (let i = 0; i < 30 && !authorityLost; i++) {
      // eslint-disable-next-line no-await-in-loop
      await new Promise((resolve) => setTimeout(resolve, 100));
      if (aLostAuthority) {
        authorityLost = true;
        break;
      }
      try {
        // eslint-disable-next-line no-await-in-loop
        await storageA.put("fencing-test:rejected", { value: "no" });
      } catch {
        authorityLost = true;
      }
    }
    expect(authorityLost).toBe(true);

    // A's new mutations should be rejected (authority lost).
    await expect(storageA.put("fencing-test:rejected", { value: "no" })).rejects.toThrow(
      "authority",
    );

    // Coordinator B can acquire the session lock (A's session is dead).
    // But B's mutations should block on the xact lock held by A's
    // in-flight transaction. This is the fencing invariant: B cannot
    // mutate authoritative state until A's transaction completes.
    const storageB = new PostgresCoordinatorStorage(databaseURL);
    cleanups.push(() => storageB.close());
    const lockB = await storageB.acquireCoordinatorLock();
    expect(lockB).toBeDefined();

    // B's mutation should block because A's xact lock is still held.
    // Use a timeout to verify it blocks rather than completing immediately.
    let bMutationDone = false;
    const bMutationPromise = storageB.put("fencing-test:b-key", { value: "from-B" }).then(
      () => {
        bMutationDone = true;
        return undefined;
      },
      () => {
        bMutationDone = true;
        return undefined;
      },
    );
    await new Promise((resolve) => setTimeout(resolve, 500));
    expect(bMutationDone).toBe(false); // B is blocked by A's xact lock

    // Release the blocked mutation — A's transaction should commit
    // (it holds the xact lock, so it can still commit).
    resolveBlock!();
    await mutationPromise;

    // The mutation should have committed successfully (the xact lock
    // protected it from being aborted by the lock session death).
    expect(mutationError).toBeUndefined();
    expect(mutationCommitted).toBe(true);

    // Now that A's transaction has committed, the xact lock is released.
    // B's blocked mutation should complete.
    await bMutationPromise;
    expect(bMutationDone).toBe(true);

    // Verify A's mutation was committed to the database.
    const value = await storageB.get<{ value: string }>("fencing-test:key");
    expect(value).toEqual({ value: "committed-by-A" });

    // Clean up test data and release B's lock.
    await storageB.delete("fencing-test:key");
    await storageB.delete("fencing-test:b-key");
    if (lockB) {
      await lockB.release();
    }
  }, 30_000);

  it("rejects new mutations after authority loss", async () => {
    const adminPool = new Pool({ connectionString: databaseURL });
    // Suppress uncaught error events from connections killed by
    // pg_terminate_backend during this test.
    adminPool.on("error", () => {});
    cleanups.push(() => adminPool.end());

    const storage = new PostgresCoordinatorStorage(databaseURL);
    cleanups.push(() => storage.close());
    await storage.initialize();

    // Clear stale locks.
    await clearStaleLocks(adminPool);

    // Acquire the lock.
    const lock = await storage.acquireCoordinatorLock();
    expect(lock).toBeDefined();
    if (!lock) return;

    // Find and kill the lock session.
    const pid = await findLockHolderPID(adminPool);
    expect(pid).toBeDefined();
    if (pid) {
      await adminPool.query("SELECT pg_terminate_backend($1)", [pid]);
    }

    // Wait for authority loss detection.
    await new Promise((resolve) => setTimeout(resolve, 500));

    // All mutations should be rejected.
    await expect(storage.put("fencing-test:post-loss", { value: "no" })).rejects.toThrow(
      "authority",
    );
    await expect(storage.delete("fencing-test:post-loss")).rejects.toThrow("authority");
    await expect(storage.take("fencing-test:post-loss")).rejects.toThrow("authority");

    // A replacement coordinator can acquire the lock.
    const storageB = new PostgresCoordinatorStorage(databaseURL);
    cleanups.push(() => storageB.close());
    const lockB = await storageB.acquireCoordinatorLock();
    expect(lockB).toBeDefined();
    if (lockB) {
      await lockB.release();
    }
  }, 15_000);

  it("second coordinator is rejected while first holds the lock", async () => {
    const storageA = new PostgresCoordinatorStorage(databaseURL);
    cleanups.push(() => storageA.close());
    await storageA.initialize();

    const storageB = new PostgresCoordinatorStorage(databaseURL);
    cleanups.push(() => storageB.close());

    // Clear stale locks.
    const adminPool = new Pool({ connectionString: databaseURL });
    adminPool.on("error", () => {});
    cleanups.push(() => adminPool.end());
    await clearStaleLocks(adminPool);

    // A acquires the lock.
    const lockA = await storageA.acquireCoordinatorLock();
    expect(lockA).toBeDefined();
    if (!lockA) return;

    // B cannot acquire the lock.
    const lockB = await storageB.acquireCoordinatorLock();
    expect(lockB).toBeUndefined();

    // A releases the lock.
    await lockA.release();

    // Now B can acquire the lock.
    const lockB2 = await storageB.acquireCoordinatorLock();
    expect(lockB2).toBeDefined();
    if (lockB2) {
      await lockB2.release();
    }
  }, 10_000);
});
