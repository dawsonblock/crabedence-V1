import { AsyncLocalStorage } from "node:async_hooks";

import { Pool, type PoolClient, type QueryResult, type QueryResultRow } from "pg";

import type {
  CoordinatorLock,
  CoordinatorStorage,
  CoordinatorStorageView,
} from "../src/coordinator-runtime";

const schema = "crabbox";
const table = `${schema}.coordinator_kv`;
const transactionAttempts = 12;
const retryableTransactionErrorCodes = new Set(["40001", "40P01"]);
// Session-scoped advisory lock: exactly one coordinator process may run against
// a database. A crashed holder loses its session, so the lock frees itself.
const coordinatorAdvisoryLockName = "crabbox.coordinator";
// Transaction-scoped advisory lock for fencing mutations. Uses a DIFFERENT
// key from the session lock because PostgreSQL advisory locks are exclusive
// across sessions regardless of lock duration (session vs transaction).
// If both used the same key, the coordinator's own mutations would block
// on the session lock held by the lock client (a different connection).
// The mutation fence key prevents a replacement coordinator from starting
// mutations while an in-flight transaction from the old coordinator is
// still running, even after the old session lock is released.
const coordinatorMutationFenceName = "crabbox.coordinator.mutation";
// Liveness probe interval for the dedicated lock session. PostgreSQL frees the
// advisory lock on session death without notifying the holder, so the holder
// must actively verify its session is still alive.
const lockHeartbeatIntervalMs = 10_000;

/**
 * AsyncLocalStorage tracking the current transaction's PoolClient. When a
 * mutation method (put, delete, take) is called inside an active
 * transaction, it uses this client directly instead of starting a nested
 * fenced transaction. This prevents deadlocks and redundant xact lock
 * acquisition while ensuring all mutations are fenced.
 */
const currentTransactionClient = new AsyncLocalStorage<PoolClient>();

export class PostgresCoordinatorStorage implements CoordinatorStorage {
  readonly pool: Pool;
  private readonly view: PostgresCoordinatorStorageView;
  private lockClient: PoolClient | undefined;
  private lockRelease: (() => Promise<void>) | undefined;
  // Fencing flag: once authority is lost, all mutations must fail closed.
  // This is set by markAuthorityLost() which is called from the lock's
  // onLost callback. A process-level boolean alone is insufficient for
  // split-brain safety, so mutations also acquire a transaction-scoped
  // advisory lock that shares the session lock's namespace.
  private authorityLost = false;

  constructor(connectionString: string, pool?: Pool) {
    this.pool =
      pool ??
      new Pool({
        connectionString,
        application_name: "crabbox-coordinator",
        max: positiveInt(process.env["CRABBOX_DATABASE_POOL_SIZE"], 10),
        connectionTimeoutMillis: positiveInt(
          process.env["CRABBOX_DATABASE_CONNECT_TIMEOUT_MS"],
          10_000,
        ),
      });
    // Suppress uncaught error events from idle connections that die when
    // the lock backend is terminated. The lock-loss callback handles
    // authority loss; pool-level errors are informational only.
    this.pool.on("error", () => {});
    this.view = new PostgresCoordinatorStorageView(storageQuery(this.pool));
  }

  async initialize(): Promise<void> {
    await this.pool.query(`create schema if not exists ${schema}`);
    await this.pool.query(`
      create table if not exists ${table} (
        key text primary key,
        value jsonb not null,
        updated_at timestamptz not null default now()
      )
    `);
    await this.pool.query(`
      alter table ${table}
      add column if not exists value_text text,
      add column if not exists value_text_updated_at timestamptz
    `);
    await this.pool.query(`
      create index if not exists coordinator_kv_updated_at_idx
      on ${table} (updated_at)
    `);
  }

  async ready(): Promise<void> {
    await this.pool.query("select 1");
  }

  async acquireCoordinatorLock(): Promise<CoordinatorLock | undefined> {
    if (this.lockClient) {
      return { release: async () => {}, onLost: () => {} };
    }
    const client = await this.pool.connect();
    try {
      const result = await client.query<{ acquired: boolean }>(
        "select pg_try_advisory_lock(hashtext($1)) as acquired",
        [coordinatorAdvisoryLockName],
      );
      if (!result.rows[0]?.acquired) {
        client.release();
        return undefined;
      }
    } catch (error) {
      client.release();
      throw error;
    }
    this.lockClient = client;
    let released = false;
    const lostCallbacks: Array<() => void> = [];
    let heartbeat: ReturnType<typeof setInterval> | undefined;
    const teardownListeners = () => {
      if (heartbeat) {
        clearInterval(heartbeat);
        heartbeat = undefined;
      }
      client.removeAllListeners("error");
      client.removeAllListeners("end");
    };
    // Session loss means authority loss: PostgreSQL has already freed the
    // advisory lock, so a replacement coordinator may start at any moment.
    // Report it immediately and stop trusting this connection.
    const lost = (reason: string) => {
      if (released || this.lockClient !== client) return;
      this.lockClient = undefined;
      released = true;
      this.authorityLost = true;
      teardownListeners();
      // Re-attach a noop error handler so the client doesn't emit an
      // uncaught 'error' event during pool eviction. The session is dead;
      // further errors are expected and informational only.
      client.on("error", () => {});
      client.on("end", () => {});
      // The session is dead; evict the client from the pool rather than
      // returning a broken connection for reuse.
      client.release(new Error(`coordinator advisory-lock session lost: ${reason}`));
      for (const callback of lostCallbacks) {
        try {
          callback();
        } catch {
          // A misbehaving subscriber must not suppress the others.
        }
      }
    };
    client.on("error", (error) =>
      lost(error instanceof Error ? error.message : "connection error"),
    );
    client.on("end", () => lost("connection ended"));
    // Belt-and-braces liveness probe on the exact session holding the lock:
    // some failure modes (killed backend, NAT timeout) never emit a client
    // event, but a query on the dead session always fails.
    heartbeat = setInterval(() => {
      void client
        .query("select 1")
        .catch((error) => lost(error instanceof Error ? error.message : "heartbeat failed"));
    }, lockHeartbeatIntervalMs);
    heartbeat.unref();
    const release = async () => {
      if (released || this.lockClient !== client) return;
      this.lockClient = undefined;
      released = true;
      teardownListeners();
      // Re-attach noop handlers to prevent uncaught errors during release.
      client.on("error", () => {});
      client.on("end", () => {});
      let unlockError: Error | undefined;
      try {
        await client.query("select pg_advisory_unlock(hashtext($1))", [
          coordinatorAdvisoryLockName,
        ]);
      } catch (error) {
        // The unlock query failed — the connection is likely dead. Capture
        // the error so the client is evicted from the pool below rather than
        // recycled for reuse by other queries.
        unlockError = error instanceof Error ? error : new Error(String(error));
      } finally {
        // Pass any unlock error to release() so pg evicts the broken client
        // instead of returning it to the pool. A dead connection reused for
        // the next query would surface as an opaque later failure.
        client.release(unlockError);
      }
    };
    this.lockRelease = release;
    return {
      release,
      onLost: (callback: () => void) => {
        lostCallbacks.push(callback);
      },
    };
  }

  async close(): Promise<void> {
    const release = this.lockRelease;
    this.lockRelease = undefined;
    if (release) {
      try {
        await release();
      } catch {
        // A dead lock session cannot be unlocked; PostgreSQL already freed it.
      }
    }
    await this.pool.end();
  }

  /**
   * Mark this storage as having lost coordinator authority. All subsequent
   * mutations (put, delete, take, transaction) will fail closed by throwing
   * an AuthorityLostError. This is called from the lock's onLost callback
   * and from the runtime's handleCoordinatorAuthorityLost.
   */
  markAuthorityLost(): void {
    this.authorityLost = true;
  }

  /** Check authority before any mutation. Throws if authority was lost. */
  private assertAuthority(): void {
    if (this.authorityLost) {
      throw new AuthorityLostError(
        "coordinator authority lost; refusing mutation after advisory-lock session death",
      );
    }
  }

  async get<T>(key: string, _options?: { noCache?: boolean }): Promise<T | undefined> {
    return this.view.get<T>(key);
  }

  async put<T>(key: string, value: T, _options?: { noCache?: boolean }): Promise<void> {
    this.assertAuthority();
    const client = currentTransactionClient.getStore();
    if (client) {
      // Inside an active transaction: use the transaction's client directly.
      // The xact lock is already held by the enclosing transaction.
      await new PostgresCoordinatorStorageView(storageQuery(client)).put(key, value);
      return;
    }
    // Outside a transaction: start a new fenced transaction.
    await this.fencedMutation((c) =>
      new PostgresCoordinatorStorageView(storageQuery(c)).put(key, value),
    );
  }

  async delete(key: string): Promise<void> {
    this.assertAuthority();
    const client = currentTransactionClient.getStore();
    if (client) {
      await new PostgresCoordinatorStorageView(storageQuery(client)).delete(key);
      return;
    }
    await this.fencedMutation((c) =>
      new PostgresCoordinatorStorageView(storageQuery(c)).delete(key),
    );
  }

  async take<T>(key: string): Promise<T | undefined> {
    this.assertAuthority();
    const client = currentTransactionClient.getStore();
    if (client) {
      return this.takeWithClient<T>(client, key);
    }
    return this.fencedMutation((c) => this.takeWithClient<T>(c, key));
  }

  private async takeWithClient<T>(client: PoolClient, key: string): Promise<T | undefined> {
    const result = await client.query<{ encoded_value: unknown }>(
      `
        delete from ${table}
        where key = $1
        returning case
          when value_text_updated_at = updated_at then value_text
          else value::text
        end as encoded_value
      `,
      [key],
    );
    const row = result.rows[0];
    return row ? decodeStoredValue<T>(row.encoded_value) : undefined;
  }

  async list<T>({
    prefix = "",
    limit,
    startAfter,
  }: {
    prefix?: string;
    limit?: number;
    startAfter?: string;
    noCache?: boolean;
  } = {}): Promise<Map<string, T>> {
    return this.view.list<T>({
      prefix,
      ...(limit === undefined ? {} : { limit }),
      ...(startAfter === undefined ? {} : { startAfter }),
    });
  }

  async transaction<T>(callback: (transaction: CoordinatorStorageView) => Promise<T>): Promise<T> {
    const attempt = async (remaining: number): Promise<T> => {
      try {
        return await this.transactionAttempt(callback);
      } catch (error) {
        if (remaining > 1 && retryablePostgresTransactionError(error)) {
          const retries = transactionAttempts - remaining;
          const delay = Math.min(50, 2 ** Math.min(retries, 5)) + Math.floor(Math.random() * 8);
          await new Promise<void>((resolve) => setTimeout(resolve, delay));
          return attempt(remaining - 1);
        }
        throw error;
      }
    };
    return attempt(transactionAttempts);
  }

  private async transactionAttempt<T>(
    callback: (transaction: CoordinatorStorageView) => Promise<T>,
  ): Promise<T> {
    this.assertAuthority();
    const client = await this.pool.connect();
    let releaseError: Error | undefined;
    try {
      await client.query("begin isolation level serializable");
      // Acquire a transaction-scoped advisory lock that shares the same
      // namespace as the session-scoped coordinator lock. This ensures
      // that while this mutation transaction is in-flight, no replacement
      // coordinator can acquire the session lock and begin its own
      // mutations. The lock auto-releases on commit/rollback.
      await client.query("select pg_advisory_xact_lock(hashtext($1))", [
        coordinatorMutationFenceName,
      ]);
      // Re-check authority after acquiring the xact lock: the lock session
      // may have died while we were waiting for the xact lock (e.g., behind
      // another in-flight mutation on this same coordinator). If so, abort
      // before executing the callback.
      if (this.authorityLost) {
        await client.query("rollback");
        throw new AuthorityLostError(
          "coordinator authority lost while acquiring transaction fence",
        );
      }
      const result = await currentTransactionClient.run(client, () =>
        callback(new PostgresCoordinatorStorageView(storageQuery(client))),
      );
      await client.query("commit");
      return result;
    } catch (error) {
      try {
        await client.query("rollback");
      } catch (rollbackError) {
        releaseError =
          rollbackError instanceof Error
            ? rollbackError
            : new Error("PostgreSQL rollback failed", { cause: rollbackError });
        const aggregate = new AggregateError(
          [error, rollbackError],
          "PostgreSQL transaction failed and rollback also failed",
          { cause: error },
        );
        throw aggregate;
      }
      throw error;
    } finally {
      if (releaseError) {
        client.release(releaseError);
      } else {
        client.release();
      }
    }
  }

  /**
   * fencedMutation executes a single-key mutation inside a fenced
   * transaction. Unlike transaction(), it does not retry on serialization
   * failures — single-key operations either commit or fail, and the
   * fence is effective either way. This is used by put, delete, and take
   * when called outside an existing transaction.
   */
  private async fencedMutation<T>(fn: (client: PoolClient) => Promise<T>): Promise<T> {
    this.assertAuthority();
    const client = await this.pool.connect();
    let releaseError: Error | undefined;
    try {
      await client.query("begin isolation level serializable");
      await client.query("select pg_advisory_xact_lock(hashtext($1))", [
        coordinatorMutationFenceName,
      ]);
      if (this.authorityLost) {
        await client.query("rollback");
        throw new AuthorityLostError(
          "coordinator authority lost while acquiring transaction fence",
        );
      }
      const result = await currentTransactionClient.run(client, () => fn(client));
      await client.query("commit");
      return result;
    } catch (error) {
      try {
        await client.query("rollback");
      } catch (rollbackError) {
        releaseError =
          rollbackError instanceof Error
            ? rollbackError
            : new Error("PostgreSQL rollback failed", { cause: rollbackError });
        throw new AggregateError(
          [error, rollbackError],
          "PostgreSQL transaction failed and rollback also failed",
          { cause: error },
        );
      }
      throw error;
    } finally {
      if (releaseError) {
        client.release(releaseError);
      } else {
        client.release();
      }
    }
  }
}

function retryablePostgresTransactionError(error: unknown): boolean {
  if (error instanceof AggregateError || !error || typeof error !== "object") return false;
  const code = "code" in error ? error.code : undefined;
  return typeof code === "string" && retryableTransactionErrorCodes.has(code);
}

type StorageQuery = <T extends QueryResultRow>(
  text: string,
  values?: unknown[],
) => Promise<QueryResult<T>>;

function storageQuery(queryable: Pick<Pool | PoolClient, "query">): StorageQuery {
  return async <T extends QueryResultRow>(text: string, values?: unknown[]) =>
    await queryable.query<T>(text, values);
}

class PostgresCoordinatorStorageView implements CoordinatorStorageView {
  constructor(private readonly query: StorageQuery) {}

  async get<T>(key: string, _options?: { noCache?: boolean }): Promise<T | undefined> {
    const result = await this.query<{ encoded_value: unknown }>(
      `
        select case
          when value_text_updated_at = updated_at then value_text
          else value::text
        end as encoded_value
        from ${table}
        where key = $1
      `,
      [key],
    );
    const row = result.rows[0];
    return row ? decodeStoredValue<T>(row.encoded_value) : undefined;
  }

  async put<T>(key: string, value: T, _options?: { noCache?: boolean }): Promise<void> {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) {
      throw new TypeError("coordinator storage cannot persist undefined");
    }
    const jsonbEncoded = jsonbCompatibleEncoding(encoded);
    await this.query(
      `
        insert into ${table} (key, value, value_text, value_text_updated_at)
        values ($1, $2::jsonb, $3, now())
        on conflict (key) do update
        set value = excluded.value,
            value_text = excluded.value_text,
            value_text_updated_at = now(),
            updated_at = now()
      `,
      [key, jsonbEncoded, encoded],
    );
  }

  async delete(key: string): Promise<void> {
    await this.query(`delete from ${table} where key = $1`, [key]);
  }

  async list<T>({
    prefix = "",
    limit,
    startAfter,
  }: {
    prefix?: string;
    limit?: number;
    startAfter?: string;
    noCache?: boolean;
  } = {}): Promise<Map<string, T>> {
    const values: unknown[] = [`${escapeLike(prefix)}%`];
    const afterClause = startAfter ? `and key > $${values.push(startAfter)}` : "";
    const limitClause = limit === undefined ? "" : `limit $${values.push(limit)}`;
    const result = await this.query<{ key: string; encoded_value: unknown }>(
      `
        select key,
               case
                 when value_text_updated_at = updated_at then value_text
                 else value::text
               end as encoded_value
        from ${table}
        where key like $1 escape '\\'
        ${afterClause}
        order by key
        ${limitClause}
      `,
      values,
    );
    return new Map(result.rows.map((row) => [row.key, decodeStoredValue<T>(row.encoded_value)]));
  }
}

function decodeStoredValue<T>(value: unknown): T {
  return (typeof value === "string" ? JSON.parse(value) : value) as T;
}

function jsonbCompatibleEncoding(encoded: string): string {
  if (!encoded.includes("\\u0000")) return encoded;
  return JSON.stringify(replaceNulCharacters(JSON.parse(encoded)));
}

function replaceNulCharacters(value: unknown): unknown {
  if (typeof value === "string") return value.replaceAll("\0", "\uFFFD");
  if (Array.isArray(value)) return value.map(replaceNulCharacters);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key.replaceAll("\0", "\uFFFD"),
      replaceNulCharacters(item),
    ]),
  );
}

function escapeLike(value: string): string {
  return value.replace(/[\\%_]/g, "\\$&");
}

function positiveInt(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

/**
 * Thrown when a mutation is attempted after the coordinator has lost
 * authority (the advisory-lock session died). This is a fencing error:
 * the mutation was refused because the coordinator can no longer prove
 * it is the single writer.
 */
export class AuthorityLostError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuthorityLostError";
  }
}
