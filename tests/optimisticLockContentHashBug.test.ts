/**
 * End-to-end regression for the `get()`-drops-`content_hash` bug (see
 * `pgStorageAdapter.test.ts`'s and `supabaseStorageAdapter.test.ts`'s dedicated
 * SQL-level tests for the fix itself). Every other optimisticLock test in this
 * directory (`optimisticLock.test.ts`, `optimisticLockLegacyRow.test.ts`, etc.) uses
 * a plain `Map`-backed in-memory `StorageAdapter` whose `get()` naturally returns the
 * whole stored record — it can't reproduce a bug that only exists in a real adapter's
 * SQL column projection. This test wires `defineStore` to the REAL `pgStorageAdapter`
 * against a small stateful fake `PgClient` (a single-row table that actually applies
 * the `WHERE content_hash IS NULL` / `WHERE content_hash = $N` guards from the query
 * text), so the read-path gap is genuinely exercised.
 *
 * Symptom reproduced: `store.mutate()` succeeds on the first call (no row yet — the
 * `content_hash IS NULL` guard trivially matches), but a buggy `get()` that never maps
 * `content_hash` makes EVERY subsequent `mutate()` believe `hash: null` — so the second
 * call retries the same "no row yet" guard against a row that now has a REAL hash,
 * the guard excludes it, `putIfMatch` returns `false`, and `mutate()` throws
 * `OptimisticLockConflictError` — deterministically, with zero concurrency involved.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import { z } from "zod";
import { createDekHandle } from "./testKeyHandle.ts";
import {
  configureSecureStore,
  __resetSecureStoreConfig,
  defineStore,
  fingerprintSchema,
  OptimisticLockConflictError,
  type CryptoHandle,
  type KeyProvider,
} from "../index.ts";
import {
  pgStorageAdapter,
  type PgClient,
} from "../adapters/pgStorageAdapter.ts";

/**
 * A one-row-per-key fake Postgres: `query()` pattern-matches the query text shape
 * `pgStorageAdapter` actually issues (SELECT for `get()`, the `ON CONFLICT ... WHERE
 * content_hash IS NULL` upsert for `putIfMatch(..., null)`, the plain conditional
 * `UPDATE ... WHERE content_hash = $N` for `putIfMatch(..., hash)`) and applies the
 * same guard a real Postgres would. Scoped to exactly what a perUser optimisticLock
 * store exercises — not a general SQL engine.
 */
function statefulFakePgClient(): PgClient & {
  rows: Map<string, Record<string, unknown>>;
} {
  const rows = new Map<string, Record<string, unknown>>();
  const client: PgClient = {
    async query<T extends Record<string, unknown>>(
      text: string,
      params: unknown[] = [],
    ) {
      const trimmed = text.trim();
      const collectionMatch = /(?:FROM|INTO|UPDATE) "([^"]+)"/.exec(trimmed);
      if (!collectionMatch) {
        throw new Error(`statefulFakePgClient: unrecognized query: ${text}`);
      }
      const collection = collectionMatch[1];

      if (trimmed.startsWith("SELECT")) {
        const userId = params[0] as string;
        const row = rows.get(`${collection}:${userId}`);
        return { rows: (row ? [row] : []) as T[] };
      }

      if (trimmed.startsWith("INSERT INTO")) {
        // putIfMatch(..., expectedHash: null): conditional upsert guarded by
        // "WHERE content_hash IS NULL" — params = [userId, blob, schema_version,
        // updated_at, content_hash?] for a perUser store (extraKeys: []).
        const [userId, blob, schemaVersion, updatedAt, contentHash] = params;
        const key = `${collection}:${userId}`;
        const existing = rows.get(key);
        if (existing && existing.content_hash != null) {
          return { rows: [] as T[] }; // guard excluded the row: a real hash is present
        }
        rows.set(key, {
          user_id: userId,
          blob,
          schema_version: schemaVersion,
          updated_at: updatedAt,
          content_hash: contentHash ?? null,
        });
        return { rows: [{ user_id: userId }] as unknown as T[] };
      }

      if (trimmed.startsWith("UPDATE")) {
        // putIfMatch(..., expectedHash: <hash>): setValues = [blob, schema_version,
        // updated_at, content_hash], then [userId, expectedHash] for a perUser store.
        const [
          blob,
          schemaVersion,
          updatedAt,
          contentHash,
          userId,
          expectedHash,
        ] = params;
        const key = `${collection}:${userId as string}`;
        const existing = rows.get(key);
        if (!existing || existing.content_hash !== expectedHash) {
          return { rows: [] as T[] };
        }
        rows.set(key, {
          user_id: userId,
          blob,
          schema_version: schemaVersion,
          updated_at: updatedAt,
          content_hash: contentHash,
        });
        return { rows: [{ user_id: userId }] as unknown as T[] };
      }

      throw new Error(`statefulFakePgClient: unrecognized query: ${text}`);
    },
  };
  return Object.assign(client, { rows });
}

function fixedKeyProvider(cryptoHandle: CryptoHandle | null): KeyProvider {
  return {
    getCryptoHandle: () => cryptoHandle,
    getUserId: () => "u1",
    subscribe: () => () => {},
  };
}

const Counter = z.object({ count: z.number().default(0) });

test.beforeEach(() => __resetSecureStoreConfig());

test("optimisticLock content_hash regression: mutate() twice in a row against the real pgStorageAdapter — second call must succeed, not throw OptimisticLockConflictError", async () => {
  const client = statefulFakePgClient();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: pgStorageAdapter(() => client),
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "x_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Counter,
    version: 1,
    contentHash: true,
    optimisticLock: true,
    schemaFingerprint: fingerprintSchema(Counter, "all"),
  });

  const first = await store.mutate((current) => ({
    count: current.count + 1,
  }));
  assert.deepEqual(first, { count: 1 });

  // No real concurrency: this is the exact same key, same process, back-to-back.
  const second = await store.mutate((current) => ({
    count: current.count + 1,
  }));
  assert.deepEqual(
    second,
    { count: 2 },
    "a second, uncontended mutate() must succeed — get() must have returned the real content_hash",
  );

  assert.deepEqual(await store.load("u1", cryptoHandle), { count: 2 });
});

test("optimisticLock content_hash regression: a THIRD mutate() also succeeds (not just a one-off after the first save)", async () => {
  const client = statefulFakePgClient();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: pgStorageAdapter(() => client),
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "x_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Counter,
    version: 1,
    contentHash: true,
    optimisticLock: true,
    schemaFingerprint: fingerprintSchema(Counter, "all"),
  });

  await store.mutate((current) => ({ count: current.count + 1 }));
  await store.mutate((current) => ({ count: current.count + 1 }));
  const third = await store.mutate((current) => ({ count: current.count + 1 }));

  assert.deepEqual(third, { count: 3 });
});

test("optimisticLock content_hash regression: a genuine concurrent write (stale hash) still correctly throws OptimisticLockConflictError", async () => {
  const client = statefulFakePgClient();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: pgStorageAdapter(() => client),
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "x_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Counter,
    version: 1,
    contentHash: true,
    optimisticLock: true,
    schemaFingerprint: fingerprintSchema(Counter, "all"),
  });

  await store.mutate((current) => ({ count: current.count + 1 }));

  // Simulate a genuinely concurrent writer winning the race between our read and write.
  await assert.rejects(
    () =>
      store.mutate((current) => {
        client.rows.set("x_blobs:u1", {
          ...client.rows.get("x_blobs:u1"),
          content_hash: "some-other-writer-hash",
        });
        return { count: current.count + 1 };
      }),
    (error: unknown) => error instanceof OptimisticLockConflictError,
  );
});
