/**
 * Cache-aware ambient writes: `set()`/`mutate()` (perUser and perKey) must push the
 * new value into the configured `CacheAdapter` right after a successful persist — not
 * just the React binding's `save()`. Before this fix, only `useStore`/`useKeyedStore`
 * wrote to cache, so a service calling `.mutate()` ambient (e.g.
 * `patchPortfolioTransaction`) left every mounted `useStore` consumer stale until its
 * own next full reload.
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

function memoryAdapter(
  opts: { withHash?: boolean; withPutIfMatch?: boolean } = {},
): StorageAdapter & { rows: Map<string, BlobRecord> } {
  const rows = new Map<string, BlobRecord>();
  const rowKey = (
    collection: string,
    userId: string,
    extraKeys: { column: string; value: string }[],
  ) => `${collection}:${userId}:${extraKeys[0]?.value ?? ""}`;

  const adapter: StorageAdapter & { rows: typeof rows } = {
    rows,
    async get(collection, userId, extraKeys) {
      return rows.get(rowKey(collection, userId, extraKeys)) ?? null;
    },
    async put(collection, userId, extraKeys, record) {
      rows.set(rowKey(collection, userId, extraKeys), record);
    },
  };
  if (opts.withHash) {
    adapter.getHash = async (collection, userId, extraKeys) => {
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

const Portfolio = z.object({
  positions: z.array(z.string()).default([]),
  count: z.number().default(0),
});
const Batch = z.object({ count: z.number().default(0) });

test.beforeEach(() => __resetSecureStoreConfig());

test("cache-aware write: perUser mutate() ambient reflects in cache immediately, without a fresh load", async () => {
  const adapter = memoryAdapter({ withHash: true });
  const { cache } = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "cacheaware_perUser",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  await store.mutate((current) => ({
    ...current,
    positions: [...current.positions, "AAPL"],
    count: current.count + 1,
  }));

  const cached = cache.get<{ data: unknown; hash: string | null }>(
    "cacheaware_perUser:u1",
  );
  assert.ok(
    cached,
    "cache must hold an entry for this store right after mutate()",
  );
  assert.deepEqual(cached!.data, { positions: ["AAPL"], count: 1 });
});

test("cache-aware write: perUser set() ambient reflects in cache immediately", async () => {
  const adapter = memoryAdapter();
  const { cache } = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "cacheaware_perUser_set",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  await store.set({ positions: ["MSFT"], count: 3 });

  const cached = cache.get<{ data: unknown; hash: string | null }>(
    "cacheaware_perUser_set:u1",
  );
  assert.ok(cached, "cache must hold an entry right after set()");
  assert.deepEqual(cached!.data, { positions: ["MSFT"], count: 3 });
});

test("cache-aware write: perKey mutate() ambient reflects in cache immediately", async () => {
  const adapter = memoryAdapter({ withHash: true });
  const { cache } = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "cacheaware_perkey",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.mutate("2026-07", (current) => ({ count: current.count + 1 }));

  const cached = cache.get<{ data: unknown; hash: string | null }>(
    "cacheaware_perkey:u1:2026-07",
  );
  assert.ok(
    cached,
    "cache must hold an entry for this key right after mutate()",
  );
  assert.deepEqual(cached!.data, { count: 1 });
});

test("cache-aware write: perKey set() ambient reflects in cache immediately", async () => {
  const adapter = memoryAdapter();
  const { cache } = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "cacheaware_perkey_set",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.set("2026-07", { count: 9 });

  const cached = cache.get<{ data: unknown; hash: string | null }>(
    "cacheaware_perkey_set:u1:2026-07",
  );
  assert.ok(cached, "cache must hold an entry right after set()");
  assert.deepEqual(cached!.data, { count: 9 });
});

test("cache-aware write: perUser mutate() on an optimisticLock store caches the post-write hash — next load skips the full fetch", async () => {
  const adapter = memoryAdapter({ withHash: true, withPutIfMatch: true });
  const { cache } = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "cacheaware_lock",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    contentHash: true,
    optimisticLock: true,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  await store.mutate((current) => ({ ...current, count: current.count + 1 }));

  const cached = cache.get<{ data: unknown; hash: string | null }>(
    "cacheaware_lock:u1",
  );
  assert.ok(cached, "cache must hold an entry right after mutate()");
  assert.ok(cached!.hash, "cache entry must carry the real post-write hash");

  // A second read, via a fresh store instance sharing the same cache/adapter,
  // must be served from cache without hitting storage.get again — proof the
  // cached hash matches what got persisted.
  let getCalls = 0;
  const wrappedAdapter: StorageAdapter = {
    ...adapter,
    get: async (...args) => {
      getCalls++;
      return adapter.get(...args);
    },
  };
  configureSecureStore({
    storage: wrappedAdapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });
  const second = await store.load("u1", cryptoHandle);
  assert.equal(
    getCalls,
    0,
    "load after an ambient mutate() must be served from cache",
  );
  assert.equal(second.count, 1);
});

test("cache-aware write: perUser mutate() skip-write path does not touch the cache set() count unnecessarily", async () => {
  const adapter = memoryAdapter({ withHash: true });
  const { cache, state } = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "cacheaware_skipwrite",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    contentHash: true,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  await store.mutate((current) => ({ ...current, count: current.count + 1 }));
  const callsAfterFirst = state.setCalls;

  // No-op transform: identical content → skip-write, no redundant persist/cache churn.
  await store.mutate((current) => current);
  assert.equal(
    state.setCalls,
    callsAfterFirst,
    "a no-op mutate() must not issue a redundant cache.set()",
  );
});
