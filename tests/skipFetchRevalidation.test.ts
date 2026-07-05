/**
 * In-session skip-fetch revalidation: a cached `{data, hash}` slot is served without a
 * full load ONLY after the server's current `content_hash` is confirmed to still match
 * it. Exercised through the public `defineStore` API (perKey and perUser) — this is the
 * core wiring in `buildKeyedStore`/`buildPerUserStore`, not the internal helper directly.
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
  type StorageAdapter,
  type CacheAdapter,
  type BlobRecord,
  type CryptoHandle,
  type KeyProvider,
} from "../index.ts";

function fixedKeyProvider(cryptoHandle: CryptoHandle | null): KeyProvider {
  return {
    getCryptoHandle: () => cryptoHandle,
    getUserId: () => "u1",
    subscribe: () => () => {},
  };
}

// In-memory adapter shared by perUser (extraKeys: []) and perKey (extraKeys: [{column,value}])
// stores, counting `get`/`getHash` calls so tests can assert which path a load took.
function countingMemoryAdapter(
  opts: { withHash?: boolean; withPutIfMatch?: boolean } = {},
): StorageAdapter & {
  rows: Map<string, BlobRecord>;
  getCalls: number;
  getHashCalls: number;
} {
  const rows = new Map<string, BlobRecord>();
  const rowKey = (
    collection: string,
    userId: string,
    extraKeys: { column: string; value: string }[],
  ) => `${collection}:${userId}:${extraKeys[0]?.value ?? ""}`;

  const adapter: StorageAdapter & {
    rows: typeof rows;
    getCalls: number;
    getHashCalls: number;
  } = {
    rows,
    getCalls: 0,
    getHashCalls: 0,
    async get(collection, userId, extraKeys) {
      adapter.getCalls++;
      return rows.get(rowKey(collection, userId, extraKeys)) ?? null;
    },
    async put(collection, userId, extraKeys, record) {
      rows.set(rowKey(collection, userId, extraKeys), record);
    },
  };
  if (opts.withHash) {
    adapter.getHash = async (collection, userId, extraKeys) => {
      adapter.getHashCalls++;
      const row = rows.get(rowKey(collection, userId, extraKeys));
      return row?.contentHash ?? null;
    };
  }
  if (opts.withPutIfMatch) {
    adapter.putIfMatch = async (
      collection,
      userId,
      extraKeys,
      record,
      expectedHash,
    ) => {
      const key = rowKey(collection, userId, extraKeys);
      const current = rows.get(key) ?? null;
      if (expectedHash === null) {
        if (current) return false;
        rows.set(key, record);
        return true;
      }
      if (!current || current.contentHash !== expectedHash) return false;
      rows.set(key, record);
      return true;
    };
  }
  return adapter;
}

function memoryCache(): { cache: CacheAdapter; state: { setCalls: number } } {
  const map = new Map<string, unknown>();
  const state = { setCalls: 0 };
  const cache: CacheAdapter = {
    get: <T>(key: string) => map.get(key) as T | undefined,
    set: <T>(key: string, data: T) => {
      state.setCalls++;
      map.set(key, data);
    },
    subscribe: () => () => {},
    clear: () => map.clear(),
  };
  return { cache, state };
}

const Batch = z.object({ count: z.number().default(0) });

test.beforeEach(() => __resetSecureStoreConfig());

test("skip-fetch: perKey serves the cached entry without a full load once the server hash matches it", async () => {
  const adapter = countingMemoryAdapter({ withHash: true });
  const { cache } = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "skipfetch_perkey",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    contentHash: true,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.save("u1", cryptoHandle, "2026-01", { count: 1 });

  const first = await store.load("u1", cryptoHandle, "2026-01");
  assert.equal(adapter.getCalls, 1);
  assert.deepEqual(first, { count: 1 });

  const second = await store.load("u1", cryptoHandle, "2026-01");
  assert.equal(
    adapter.getCalls,
    1,
    "second load must not re-download the blob",
  );
  assert.equal(adapter.getHashCalls, 1);
  assert.deepEqual(second, { count: 1 });
});

test("skip-fetch: perKey does a full load again once the server hash changed", async () => {
  const adapter = countingMemoryAdapter({ withHash: true });
  const { cache } = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "skipfetch_perkey_changed",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    contentHash: true,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.save("u1", cryptoHandle, "2026-01", { count: 1 });
  await store.load("u1", cryptoHandle, "2026-01"); // populates the cache slot
  assert.equal(adapter.getCalls, 1);

  await store.save("u1", cryptoHandle, "2026-01", { count: 2 }); // slot is now stale

  const second = await store.load("u1", cryptoHandle, "2026-01");
  assert.equal(adapter.getCalls, 2, "hash mismatch must trigger a full load");
  assert.deepEqual(second, { count: 2 });

  const third = await store.load("u1", cryptoHandle, "2026-01");
  assert.equal(
    adapter.getCalls,
    2,
    "the slot was refreshed, so this load can skip again",
  );
  assert.deepEqual(third, { count: 2 });
});

test("skip-fetch: perKey falls back to a full load (no throw) when the row's hash is gone", async () => {
  const adapter = countingMemoryAdapter({ withHash: true });
  const { cache } = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "skipfetch_perkey_deleted",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    contentHash: true,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.save("u1", cryptoHandle, "2026-01", { count: 1 });
  await store.load("u1", cryptoHandle, "2026-01"); // populates the cache slot
  adapter.rows.clear(); // row disappears server-side

  const result = await store.load("u1", cryptoHandle, "2026-01");
  assert.deepEqual(result, { count: 0 }); // store's empty default, no throw
});

test("skip-fetch: no cache configured means every load is a full load", async () => {
  const adapter = countingMemoryAdapter({ withHash: true });
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "skipfetch_no_cache",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    contentHash: true,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.save("u1", cryptoHandle, "2026-01", { count: 1 });
  await store.load("u1", cryptoHandle, "2026-01");
  await store.load("u1", cryptoHandle, "2026-01");

  assert.equal(adapter.getCalls, 2);
  assert.equal(adapter.getHashCalls, 0);
});

test("skip-fetch: adapter without getHash means every load is a full load", async () => {
  const adapter = countingMemoryAdapter({ withHash: false });
  const { cache } = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "skipfetch_no_gethash",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    contentHash: true,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.save("u1", cryptoHandle, "2026-01", { count: 1 });
  await store.load("u1", cryptoHandle, "2026-01");
  await store.load("u1", cryptoHandle, "2026-01");

  assert.equal(adapter.getCalls, 2);
});

test("skip-fetch: store without contentHash never revalidates and never populates the cache", async () => {
  const adapter = countingMemoryAdapter({ withHash: true });
  const { cache, state } = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "skipfetch_no_contenthash",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.save("u1", cryptoHandle, "2026-01", { count: 1 });
  await store.load("u1", cryptoHandle, "2026-01");
  await store.load("u1", cryptoHandle, "2026-01");

  assert.equal(adapter.getCalls, 2);
  assert.equal(
    state.setCalls,
    0,
    "cache.set must never be called for a non-contentHash store",
  );
});

test("skip-fetch: perUser serves the cached entry without a full load once the server hash matches it", async () => {
  const adapter = countingMemoryAdapter({ withHash: true });
  const { cache } = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "skipfetch_peruser",
    encrypt: "all",
    schema: Batch,
    version: 1,
    contentHash: true,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.save("u1", cryptoHandle, { count: 1 });

  const first = await store.load("u1", cryptoHandle);
  assert.equal(adapter.getCalls, 1);
  assert.deepEqual(first, { count: 1 });

  const second = await store.load("u1", cryptoHandle);
  assert.equal(
    adapter.getCalls,
    1,
    "second load must not re-download the blob",
  );
  assert.equal(adapter.getHashCalls, 1);
  assert.deepEqual(second, { count: 1 });
});

test("skip-fetch: mutate() after a skipped load still threads the revalidated hash into saveIfMatch", async () => {
  const adapter = countingMemoryAdapter({
    withHash: true,
    withPutIfMatch: true,
  });
  const { cache } = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "skipfetch_perkey_mutate",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    contentHash: true,
    optimisticLock: true,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.save("u1", cryptoHandle, "2026-01", { count: 1 });
  await store.get("2026-01"); // populates the cache slot with the current hash

  const result = await store.mutate("2026-01", (current) => ({
    count: current.count + 1,
  }));

  assert.deepEqual(result, { count: 2 });
});
