/**
 * `defineAggregation` — `KeyedStore` (`perKey`) source read at a fixed key (Task 5-pre-2 of
 * the "aggregazioni dichiarative persistite" plan).
 *
 * Two real `sources` the dashboard wiring (Task 5) needs — `snapshotStore`,
 * `accountMetaStore` — are both `perKey` stores always read through ONE sentinel key, never
 * a `perUser` `Store`. This file covers the `keyedSource()` factory + the engine's third
 * `Source` discriminator branch:
 *
 *  1. An aggregation sourcing `keyedSource(store, key)` reads/computes from THAT key only —
 *     other keys in the same `KeyedStore` are invisible to it.
 *  2. Fingerprint-gating is isolated PER KEY, not per store: a real write (via the
 *     `KeyedStore`'s own public `set()`) to the key the aggregation actually reads marks it
 *     stale and triggers a recompute; a real write to a DIFFERENT key of the same store must
 *     not — proves the subscription cache key matches `store.ts`'s `cacheKeyFor` format
 *     exactly (`${storeName}:${userId}:${key}`), not just that data injected straight into
 *     the test cache happens to line up.
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
  defineAggregation,
  keyedSource,
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
    getUserId: () => (cryptoHandle ? "u1" : null),
    subscribe: () => () => {},
  };
}

/** Same fixture as `aggregation.test.ts`'s `memoryAdapter` (deliberate duplication — this
 * repo's established per-test-file convention, see e.g. `defineStorePerKey.test.ts`'s own
 * `keyedMemoryAdapter`) — generic over `extraKeys`, so it backs BOTH the `perKey` source
 * store AND the aggregation's own internal `perKey` persistence table. */
function memoryAdapter(): StorageAdapter & {
  rows: Map<string, BlobRecord>;
  putCallsFor: (collection: string) => number;
} {
  const rows = new Map<string, BlobRecord>();
  const putCallsByCollection = new Map<string, number>();
  const rowKey = (
    collection: string,
    userId: string,
    extraKeys: { column: string; value: string }[],
  ) => `${collection}:${userId}:${extraKeys[0]?.value ?? ""}`;

  return {
    rows,
    putCallsFor: (collection) => putCallsByCollection.get(collection) ?? 0,
    async get(collection, userId, extraKeys) {
      return rows.get(rowKey(collection, userId, extraKeys)) ?? null;
    },
    async put(collection, userId, extraKeys, record) {
      putCallsByCollection.set(
        collection,
        (putCallsByCollection.get(collection) ?? 0) + 1,
      );
      rows.set(rowKey(collection, userId, extraKeys), record);
    },
    async getHash(collection, userId, extraKeys) {
      return (
        rows.get(rowKey(collection, userId, extraKeys))?.contentHash ?? null
      );
    },
  };
}

/** Same fixture as `aggregation.test.ts`'s `memoryCache` — a real subscribable in-memory
 * `CacheAdapter`; `set()` invokes callbacks registered via `subscribe(key, cb)`, which is
 * what lets an aggregation detect an ambient write on one of its sources. */
function memoryCache(): CacheAdapter {
  const data = new Map<string, unknown>();
  const subs = new Map<string, Set<() => void>>();
  return {
    get: (key) => data.get(key) as never,
    set: (key, value) => {
      data.set(key, value);
      for (const cb of subs.get(key) ?? []) cb();
    },
    subscribe: (key, cb) => {
      if (!subs.has(key)) subs.set(key, new Set());
      subs.get(key)!.add(cb);
      return () => subs.get(key)?.delete(cb);
    },
    clear: () => {
      data.clear();
      for (const set of subs.values()) for (const cb of set) cb();
    },
  };
}

async function waitFor(
  predicate: () => boolean,
  timeoutMs = 2000,
): Promise<void> {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) {
      throw new Error(
        "waitFor: timed out waiting for the background recompute",
      );
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

function settle(ms = 100): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const KeyedSchema = z.object({ value: z.number().default(0) });
const OutputSchema = z.object({ total: z.number() });

function makeKeyedSource(name: string) {
  return defineStore({
    name,
    identity: { perKey: "domain_key" },
    encrypt: "all",
    schema: KeyedSchema,
    version: 1,
    contentHash: true,
    schemaFingerprint: fingerprintSchema(KeyedSchema, "all"),
  });
}

test.beforeEach(() => __resetSecureStoreConfig());

test("keyedSource: an aggregation reads ONLY the fixed key it's given, other keys in the same KeyedStore are invisible", async () => {
  const adapter = memoryAdapter();
  const cache = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = makeKeyedSource("ks1_source");
  await store.set("keyA", { value: 10 });
  await store.set("keyB", { value: 999 }); // must never leak into the aggregate below

  let computeCalls = 0;
  const agg = defineAggregation({
    version: 1,
    schema: OutputSchema,
    schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
    storage: { table: "ks1_agg", key: "__agg__" },
    sources: { src: keyedSource(store, "keyA") },
    compute: ({ sources }) => {
      computeCalls++;
      return { total: sources.src.value * 2 };
    },
  });

  const first = await agg.get();
  assert.deepEqual(first, {
    data: null,
    computing: true,
    stale: true,
    error: null,
  });

  // Wait for the PERSIST too (not just `computeCalls`) — same discipline as
  // `aggregation.test.ts`'s scenario 1: `computeCalls` increments the instant `compute()`
  // is invoked, before its result is written to `ks1_agg`; reading via `agg.get()` before
  // that write lands would still see `data: null`.
  await waitFor(
    () => computeCalls === 1 && adapter.putCallsFor("ks1_agg") === 1,
  );

  const second = await agg.get();
  assert.deepEqual(
    second.data,
    { total: 20 },
    "must read only 'keyA' (value:10) -> 20, never 'keyB' (value:999)",
  );
  assert.equal(second.stale, false);
  assert.equal(computeCalls, 1);
});

test("keyedSource: a real write to the SAME key marks the aggregate stale and triggers a recompute", async () => {
  const adapter = memoryAdapter();
  const cache = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = makeKeyedSource("ks2_source");
  await store.set("keyA", { value: 1 });

  let computeCalls = 0;
  const agg = defineAggregation({
    version: 1,
    schema: OutputSchema,
    schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
    storage: { table: "ks2_agg", key: "__agg__" },
    sources: { src: keyedSource(store, "keyA") },
    debounceMs: 20,
    compute: ({ sources }) => {
      computeCalls++;
      return { total: sources.src.value };
    },
  });

  await agg.get();
  await waitFor(() => computeCalls === 1);

  // Real write via the KeyedStore's own public API — must land in the same cache slot
  // (`${store.name}:${userId}:${key}`) `ensureSubscribed` subscribed to, not just data
  // injected directly into the test's cache fixture.
  await store.set("keyA", { value: 42 });

  // Wait for the PERSIST too (not just `computeCalls`) — same discipline as
  // `aggregation.test.ts`'s scenario 1: `computeCalls` increments the instant `compute()`
  // is invoked, before its result is written to `ks2_agg`; reading via `agg.get()` before
  // that write lands would still see the previous (stale) envelope.
  await waitFor(
    () => computeCalls === 2 && adapter.putCallsFor("ks2_agg") === 2,
    3000,
  );
  const state = await agg.get();
  assert.deepEqual(state.data, { total: 42 });
});

test("keyedSource: a real write to a DIFFERENT key of the same KeyedStore does NOT mark the aggregate stale", async () => {
  const adapter = memoryAdapter();
  const cache = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = makeKeyedSource("ks3_source");
  await store.set("keyA", { value: 1 });
  await store.set("keyB", { value: 5 });

  let computeCalls = 0;
  const agg = defineAggregation({
    version: 1,
    schema: OutputSchema,
    schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
    storage: { table: "ks3_agg", key: "__agg__" },
    sources: { src: keyedSource(store, "keyA") },
    debounceMs: 20,
    compute: ({ sources }) => {
      computeCalls++;
      return { total: sources.src.value };
    },
  });

  await agg.get();
  await waitFor(
    () => computeCalls === 1 && adapter.putCallsFor("ks3_agg") === 1,
  );

  // A write to a DIFFERENT key of the SAME underlying KeyedStore — must be invisible to
  // this aggregation (isolated per-key cache subscription, not per-store).
  await store.set("keyB", { value: 999 });
  await settle(100); // well past the 20ms debounce — nothing should fire

  assert.equal(
    computeCalls,
    1,
    "a write to a key this aggregation does NOT read must never trigger a recompute",
  );

  const state = await agg.get();
  assert.equal(
    state.stale,
    false,
    "still fresh — no observed change on 'keyA'",
  );
  assert.deepEqual(state.data, { total: 1 });
});
