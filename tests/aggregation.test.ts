/**
 * `defineAggregation` core (Task 1 of the "aggregazioni dichiarative persistite" plan) —
 * scenarios 1, 2, 7, 8 from the plan/brief:
 *
 *  1. Never persisted -> first `get()` is `{data:null, computing:true}`, the background
 *     compute settles and swaps in atomically.
 *  2. An ambient write on a source marks the aggregate stale and schedules a debounced
 *     recompute — N rapid writes coalesce into exactly ONE `compute()` call.
 *  7. A recompute that yields byte-identical content is never re-persisted (skip-write,
 *     counted at the storage layer, never assumed).
 *  8. A throwing `compute()` surfaces the error to the caller, leaves the previously
 *     persisted aggregate completely intact, and a later `refresh()` can still succeed.
 *
 * Plus one extra test for single-flight (also called out as mandatory core behavior in
 * the brief, alongside debounce, even though its own exhaustive CT2-style coverage is a
 * later task for the write-reaction primitive).
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

/**
 * One adapter instance backs BOTH the test's source store(s) AND the aggregation's own
 * internal table (real usage shares one physical Postgres/Supabase connection the same
 * way) — so `put()` calls must be counted PER COLLECTION, not globally, or a source's own
 * seed write (`source.set(...)`) would be indistinguishable from the aggregation's
 * persisted write when asserting "exactly one write happened".
 */
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

  const adapter: StorageAdapter & {
    rows: typeof rows;
    putCallsFor: (collection: string) => number;
  } = {
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
  return adapter;
}

/** Real subscribable in-memory CacheAdapter (mirrors `useStore.test.tsx`'s fixture) —
 * `set()` actually invokes callbacks registered via `subscribe(key, cb)`, which is what
 * lets an aggregation detect an ambient write on one of its sources. */
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

/** Same polling pattern as `aadLazyUpgrade.test.ts`'s `waitFor` — this module's
 * recomputes are fire-and-forget background work, not awaited by the triggering call. */
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

const SourceSchema = z.object({ value: z.number().default(0) });
const OutputSchema = z.object({ total: z.number() });

function makeSource(name: string) {
  return defineStore({
    name,
    encrypt: "all",
    schema: SourceSchema,
    version: 1,
    contentHash: true,
    schemaFingerprint: fingerprintSchema(SourceSchema, "all"),
  });
}

test.beforeEach(() => __resetSecureStoreConfig());

test("scenario 1: never persisted -> first get() is {data:null, computing:true}, background compute settles and swaps in atomically", async () => {
  const adapter = memoryAdapter();
  const cache = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const source = makeSource("s1_source");
  await source.set({ value: 10 });

  let computeCalls = 0;
  const agg = defineAggregation({
    version: 1,
    schema: OutputSchema,
    schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
    storage: { table: "s1_agg", key: "__agg__" },
    sources: { src: source },
    compute: ({ sources }) => {
      computeCalls++;
      return { total: sources.src.value * 2 };
    },
  });

  const first = await agg.get();
  assert.deepEqual(
    first,
    { data: null, computing: true, stale: true, error: null },
    "nothing persisted yet -> null data + in-flight compute, no partial/intermediate state",
  );

  await waitFor(
    () => computeCalls === 1 && adapter.putCallsFor("s1_agg") === 1,
  );

  const second = await agg.get();
  assert.deepEqual(
    second.data,
    { total: 20 },
    "the atomic swap must reflect the full computed result",
  );
  assert.equal(second.computing, false);
  assert.equal(second.stale, false);
  assert.equal(second.error, null);
  assert.equal(
    computeCalls,
    1,
    "must compute exactly once for the first-ever read",
  );
});

test("scenario 2: N rapid ambient writes on a source coalesce into exactly ONE debounced recompute", async () => {
  const adapter = memoryAdapter();
  const cache = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const source = makeSource("s2_source");
  await source.set({ value: 1 });

  let computeCalls = 0;
  const agg = defineAggregation({
    version: 1,
    schema: OutputSchema,
    schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
    storage: { table: "s2_agg", key: "__agg__" },
    sources: { src: source },
    debounceMs: 50,
    compute: ({ sources }) => {
      computeCalls++;
      return { total: sources.src.value };
    },
  });

  // Establish the subscription + settle the initial (first-ever) compute first, so the
  // burst below is unambiguously the ONE we're measuring.
  await agg.get();
  await waitFor(() => computeCalls === 1);

  await source.set({ value: 2 });
  await source.set({ value: 3 });
  await source.set({ value: 4 });

  await waitFor(() => computeCalls === 2, 3000);
  await settle(); // confirm nothing extra sneaks in after the coalesced recompute
  assert.equal(
    computeCalls,
    2,
    "N rapid writes within the debounce window must coalesce into exactly one recompute",
  );

  const state = await agg.get();
  assert.deepEqual(
    state.data,
    { total: 4 },
    "the recompute must reflect the LAST write, not an intermediate one",
  );
});

test("single-flight: a debounce firing while a recompute is already running does not start a second one in parallel — it re-runs once, right after", async () => {
  const adapter = memoryAdapter();
  const cache = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const source = makeSource("sf_source");
  await source.set({ value: 1 });

  let computeCalls = 0;
  let concurrent = 0;
  let maxConcurrent = 0;
  const agg = defineAggregation({
    version: 1,
    schema: OutputSchema,
    schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
    storage: { table: "sf_agg", key: "__agg__" },
    sources: { src: source },
    debounceMs: 5,
    compute: async ({ sources }) => {
      computeCalls++;
      concurrent++;
      maxConcurrent = Math.max(maxConcurrent, concurrent);
      await settle(80); // slow compute — long enough for a debounce to fire mid-flight
      concurrent--;
      return { total: sources.src.value };
    },
  });

  // Kicks off compute #1 (first-ever, ~80ms) — do NOT await its completion.
  void agg.get();
  await waitFor(() => computeCalls === 1);

  // Fires while compute #1 is still running: single-flight must queue it, not start #2.
  await source.set({ value: 2 });
  await settle(20); // well past the 5ms debounce, still well within compute #1's 80ms
  assert.equal(
    computeCalls,
    1,
    "a write during an in-flight compute must not start a second one yet",
  );

  // `computeCalls === 2` only proves the queued re-run STARTED — it still has its own
  // 80ms compute delay ahead of it before the result is actually persisted.
  await waitFor(() => adapter.putCallsFor("sf_agg") === 2, 3000);
  assert.equal(computeCalls, 2, "exactly one queued re-run, never a third");
  assert.equal(
    maxConcurrent,
    1,
    "at no point must two computes run concurrently",
  );

  const state = await agg.get();
  assert.deepEqual(
    state.data,
    { total: 2 },
    "the queued re-run must reflect the latest source value",
  );
});

test("scenario 7: a recompute that yields byte-identical content is never re-persisted (skip-write, counted at the storage layer)", async () => {
  const adapter = memoryAdapter();
  const cache = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const source = makeSource("s7_source");
  await source.set({ value: 5 });

  let computeCalls = 0;
  const agg = defineAggregation({
    version: 1,
    schema: OutputSchema,
    schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
    storage: { table: "s7_agg", key: "__agg__" },
    sources: { src: source },
    // Always the same output, regardless of the source's exact value — a forced
    // recompute still yields byte-identical content.
    compute: () => {
      computeCalls++;
      return { total: 100 };
    },
  });

  await agg.get();
  await waitFor(
    () => computeCalls === 1 && adapter.putCallsFor("s7_agg") === 1,
  );

  await agg.refresh();
  assert.equal(
    computeCalls,
    2,
    "compute() itself must still run on an explicit refresh",
  );
  assert.equal(
    adapter.putCallsFor("s7_agg"),
    1,
    "identical content must not trigger a second write at the storage layer",
  );
});

test("regression: a skip-write (data unchanged) must still refresh the persisted fingerprints, or isFresh() is permanently stuck stale and recomputes forever", async () => {
  const adapter = memoryAdapter();
  const cache = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const source = makeSource("s7b_source");
  await source.set({ value: 5 });

  let computeCalls = 0;
  const agg = defineAggregation({
    version: 1,
    schema: OutputSchema,
    schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
    storage: { table: "s7b_agg", key: "__agg__" },
    debounceMs: 20,
    sources: { src: source },
    // Deliberately ignores the source's exact value — a source write changes its
    // fingerprint (contentHash) even though the COMPUTED output stays byte-identical,
    // which is exactly the case the skip-write path must still keep the persisted
    // sourceFingerprints in sync for.
    compute: () => {
      computeCalls++;
      return { total: 100 };
    },
  });

  await agg.get();
  await waitFor(
    () => computeCalls === 1 && adapter.putCallsFor("s7b_agg") === 1,
  );

  // Ambient write on the source: changes its fingerprint, but the recompute it triggers
  // still yields {total: 100} — the skip-write scenario, now reached via a REAL
  // fingerprint change rather than an unchanged source (scenario 7 never changes the
  // source at all, so it can't exercise this).
  await source.set({ value: 999 });
  await waitFor(() => computeCalls === 2, 3000);
  await settle();

  // The critical assertion: after the skip-write recompute settles, a fresh get() must
  // see the aggregate as fresh (its persisted sourceFingerprints must have been brought
  // up to date even though `data` itself didn't change) and must NOT kick off yet
  // another background recompute.
  const state = await agg.get();
  assert.equal(
    state.stale,
    false,
    "sources haven't changed since the last (skip-write) recompute — must be fresh",
  );

  await settle(200);
  assert.equal(
    computeCalls,
    2,
    "a skip-write recompute must not leave the aggregate permanently stale and " +
      "re-triggering compute() forever on every subsequent get()",
  );

  // A second, independent get() must also stay stable (not just the first one right
  // after the fix landed).
  const state2 = await agg.get();
  assert.equal(state2.stale, false);
  await settle(200);
  assert.equal(computeCalls, 2);
});

test("scenario 8: a throwing compute() surfaces the error, leaves the previously persisted aggregate intact, and a later refresh() can still succeed", async () => {
  const adapter = memoryAdapter();
  const cache = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const source = makeSource("s8_source");
  await source.set({ value: 7 });

  let shouldThrow = false;
  const agg = defineAggregation({
    version: 1,
    schema: OutputSchema,
    schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
    storage: { table: "s8_agg", key: "__agg__" },
    sources: { src: source },
    compute: ({ sources }) => {
      if (shouldThrow) throw new Error("boom: compute exploded");
      return { total: sources.src.value };
    },
  });

  await agg.get();
  await waitFor(() => adapter.putCallsFor("s8_agg") === 1);
  const before = adapter.rows.get("s8_agg:u1:__agg__");
  assert.ok(before, "sanity: the first compute must have persisted something");

  shouldThrow = true;
  await assert.rejects(() => agg.refresh(), /boom: compute exploded/);

  const afterFailure = adapter.rows.get("s8_agg:u1:__agg__");
  assert.deepEqual(
    afterFailure,
    before,
    "the previously persisted aggregate must remain byte-for-byte intact after a failed recompute",
  );

  const stateAfterFailure = await agg.get();
  assert.equal(stateAfterFailure.error?.message, "boom: compute exploded");
  assert.deepEqual(
    stateAfterFailure.data,
    { total: 7 },
    "the stale-but-valid previous data is still served, never emptied/corrupted",
  );

  shouldThrow = false;
  const retried = await agg.refresh();
  assert.deepEqual(retried, { total: 7 });

  const stateAfterRetry = await agg.get();
  assert.equal(
    stateAfterRetry.error,
    null,
    "a successful retry must clear the previous error",
  );
});
