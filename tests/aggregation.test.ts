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
  invalidateChannel,
  keyedSource,
  fingerprintSchema,
  isAnyAggregationComputing,
  subscribeGlobalAggregationActivity,
  __resetGlobalAggregationActivity,
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

/** Same shape as `fixedKeyProvider`, but `lock()` can flip the ambient identity to
 * "locked" mid-test — needed to reproduce a lock firing DURING an in-flight async
 * operation (see the "review finding" test below), which `fixedKeyProvider` can't do. */
function mutableKeyProvider(initial: CryptoHandle | null): {
  provider: KeyProvider;
  lock: () => void;
} {
  let cryptoHandle = initial;
  return {
    provider: {
      getCryptoHandle: () => cryptoHandle,
      getUserId: () => (cryptoHandle ? "u1" : null),
      subscribe: () => () => {},
    },
    lock: () => {
      cryptoHandle = null;
    },
  };
}

/** Same shape as `mutableKeyProvider`, but `switchTo()` can move the ambient identity
 * between TWO DIFFERENT users (not just unlock/lock the same one) — needed to
 * reproduce a live-instance user switch (A logs out, B logs in in the same tab) while
 * an async read started under A's identity is still in flight (see the
 * "loadEnvelopeDeduped must not ignore identity" regression test below). */
function switchableKeyProvider(): {
  provider: KeyProvider;
  switchTo: (userId: string, cryptoHandle: CryptoHandle | null) => void;
} {
  let userId: string | null = null;
  let cryptoHandle: CryptoHandle | null = null;
  return {
    provider: {
      getCryptoHandle: () => cryptoHandle,
      getUserId: () => userId,
      subscribe: () => () => {},
    },
    switchTo: (nextUserId, nextCryptoHandle) => {
      userId = nextUserId;
      cryptoHandle = nextCryptoHandle;
    },
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
  /** Every distinct `extraKeys[].column` name this adapter has ever seen for a given
   * collection — lets a test assert WHICH sentinel column name the store actually used
   * (e.g. `"key"` vs a configured `keyColumn` like `"year_month"`), not just that
   * read/write round-tripped correctly. */
  columnsUsedFor: (collection: string) => Set<string>;
  /** Number of `getHashesByKeys` calls for a given collection — lets a test assert
   * that N sources sharing one physical table cost ONE batched call, not N. */
  getHashesByKeysCallsFor: (collection: string) => number;
  /** Number of single-key `getHash` calls for a given collection. */
  getHashCallsFor: (collection: string) => number;
} {
  const rows = new Map<string, BlobRecord>();
  const putCallsByCollection = new Map<string, number>();
  const columnsByCollection = new Map<string, Set<string>>();
  const getHashesByKeysCallsByCollection = new Map<string, number>();
  const getHashCallsByCollection = new Map<string, number>();
  const rowKey = (
    collection: string,
    userId: string,
    extraKeys: { column: string; value: string }[],
  ) => `${collection}:${userId}:${extraKeys[0]?.value ?? ""}`;
  const recordColumns = (
    collection: string,
    extraKeys: { column: string; value: string }[],
  ) => {
    const seen = columnsByCollection.get(collection) ?? new Set<string>();
    for (const k of extraKeys) seen.add(k.column);
    columnsByCollection.set(collection, seen);
  };

  const adapter: StorageAdapter & {
    rows: typeof rows;
    putCallsFor: (collection: string) => number;
    columnsUsedFor: (collection: string) => Set<string>;
    getHashesByKeysCallsFor: (collection: string) => number;
    getHashCallsFor: (collection: string) => number;
  } = {
    rows,
    putCallsFor: (collection) => putCallsByCollection.get(collection) ?? 0,
    columnsUsedFor: (collection) =>
      columnsByCollection.get(collection) ?? new Set(),
    getHashesByKeysCallsFor: (collection) =>
      getHashesByKeysCallsByCollection.get(collection) ?? 0,
    getHashCallsFor: (collection) =>
      getHashCallsByCollection.get(collection) ?? 0,
    async get(collection, userId, extraKeys) {
      recordColumns(collection, extraKeys);
      return rows.get(rowKey(collection, userId, extraKeys)) ?? null;
    },
    async put(collection, userId, extraKeys, record) {
      recordColumns(collection, extraKeys);
      putCallsByCollection.set(
        collection,
        (putCallsByCollection.get(collection) ?? 0) + 1,
      );
      rows.set(rowKey(collection, userId, extraKeys), record);
    },
    async getHash(collection, userId, extraKeys) {
      recordColumns(collection, extraKeys);
      getHashCallsByCollection.set(
        collection,
        (getHashCallsByCollection.get(collection) ?? 0) + 1,
      );
      return (
        rows.get(rowKey(collection, userId, extraKeys))?.contentHash ?? null
      );
    },
    async getHashesByKeys(collection, userId, keyColumn, keys) {
      getHashesByKeysCallsByCollection.set(
        collection,
        (getHashesByKeysCallsByCollection.get(collection) ?? 0) + 1,
      );
      const result: Record<string, string | null> = {};
      for (const key of keys) {
        result[key] =
          rows.get(
            rowKey(collection, userId, [{ column: keyColumn, value: key }]),
          )?.contentHash ?? null;
      }
      return result;
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
  predicate: () => boolean | Promise<boolean>,
  timeoutMs = 2000,
): Promise<void> {
  const start = Date.now();
  while (!(await predicate())) {
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

test.beforeEach(() => {
  __resetSecureStoreConfig();
  __resetGlobalAggregationActivity();
});

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

test("isAnyAggregationComputing: true while ANY aggregation has a compute in flight, across independent aggregations, false only once ALL have settled", async () => {
  const adapter = memoryAdapter();
  const cache = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  assert.equal(
    isAnyAggregationComputing(),
    false,
    "nothing computing before any aggregation is even read",
  );

  const source1 = makeSource("gac_source1");
  const source2 = makeSource("gac_source2");
  await source1.set({ value: 1 });
  await source2.set({ value: 2 });

  let releaseA: () => void = () => {};
  const gateA = new Promise<void>((resolve) => {
    releaseA = resolve;
  });
  const aggA = defineAggregation({
    version: 1,
    schema: OutputSchema,
    schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
    storage: { table: "gac_agg_a", key: "__agg__" },
    sources: { src: source1 },
    compute: async ({ sources }) => {
      await gateA;
      return { total: sources.src.value };
    },
  });

  let releaseB: () => void = () => {};
  const gateB = new Promise<void>((resolve) => {
    releaseB = resolve;
  });
  const aggB = defineAggregation({
    version: 1,
    schema: OutputSchema,
    schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
    storage: { table: "gac_agg_b", key: "__agg__" },
    sources: { src: source2 },
    compute: async ({ sources }) => {
      await gateB;
      return { total: sources.src.value };
    },
  });

  void aggA.get();
  await waitFor(() => isAnyAggregationComputing());
  assert.equal(isAnyAggregationComputing(), true, "A's compute is in flight");

  void aggB.get();
  await settle(10);
  assert.equal(
    isAnyAggregationComputing(),
    true,
    "still true while B starts — A hasn't finished yet",
  );

  releaseA();
  await waitFor(async () => (await aggA.get()).computing === false);
  assert.equal(
    isAnyAggregationComputing(),
    true,
    "A finished but B is still in flight — must stay true",
  );

  releaseB();
  await waitFor(async () => (await aggB.get()).computing === false);
  assert.equal(
    isAnyAggregationComputing(),
    false,
    "both settled — must go back to false",
  );
});

test(
  "isAnyAggregationComputing: COLD start of a 2-level aggregation-as-source chain " +
    "(D sources C, C never computed) must stay true across C's real compute AND D's " +
    "subsequent DEBOUNCED recompute — not just during each's own triggerRecompute() " +
    "window. Regression: D's first read of C throws immediately (C has no persisted " +
    "value yet, by design — see computeAndPersist's isAggregationSource branch), C's own " +
    "cold triggerRecompute settles D's OWN attempt back to 'idle' the instant it fails, " +
    "and D's real retry (once C publishes) only fires via ensureSubscribed's " +
    "scheduleDebouncedRecompute — which previously did not count as 'busy' while its " +
    "timer was armed, leaving a real, observable gap where isAnyAggregationComputing() " +
    "reported false even though the graph had NOT converged yet (reproduced live via " +
    "the video-tutorial recording: a fresh page's first dashboard render showed the " +
    "zero placeholder well after an E2E wait on this exact signal had already resolved)",
  async () => {
    const adapter = memoryAdapter();
    const cache = memoryCache();
    const cryptoHandle = createDekHandle(randomBytes(32));
    configureSecureStore({
      storage: adapter,
      cache,
      keys: fixedKeyProvider(cryptoHandle),
    });

    const source = makeSource("gac_chain_source");
    await source.set({ value: 7 });

    // C: real, gated compute — controls exactly when the FIRST hop of the chain
    // actually finishes, same technique as the other isAnyAggregationComputing tests.
    let releaseC: () => void = () => {};
    const gateC = new Promise<void>((resolve) => {
      releaseC = resolve;
    });
    const aggC = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "gac_chain_agg_c", key: "__agg__" },
      debounceMs: 50,
      sources: { src: source },
      compute: async ({ sources }) => {
        await gateC;
        return { total: sources.src.value * 10 };
      },
    });

    // D: sources C as an aggregation-source — the `dashboardAgg` role. Short
    // `debounceMs` keeps the test fast while still exercising the real debounced
    // reactive-recompute path (production default is 500ms for both).
    const aggD = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "gac_chain_agg_d", key: "__agg__" },
      debounceMs: 50,
      sources: { c: aggC },
      compute: ({ sources }) => ({ total: sources.c.total + 1 }),
    });

    let sawBusy = false;
    let falseAfterBusyBeforeConverged = false;
    const unsubscribe = subscribeGlobalAggregationActivity(() => {
      const busy = isAnyAggregationComputing();
      if (busy) sawBusy = true;
      if (!busy && sawBusy && !falseAfterBusyBeforeConverged) {
        // `converged` is read synchronously here, not awaited — a plain boolean
        // flag set once `aggD`'s final value has actually landed (below).
        if (!converged) falseAfterBusyBeforeConverged = true;
      }
    });

    let converged = false;
    void aggD.get(); // cold start — D's first read of C (also cold) throws immediately

    // Let D's own failed attempt settle before releasing C, so the test actually
    // exercises the gap BETWEEN "D's first attempt failed" and "C's real compute
    // finishes" — releasing C too early would let everything resolve in one tick.
    await waitFor(() => isAnyAggregationComputing());
    await settle(20);
    releaseC();

    await waitFor(async () => {
      const state = await aggD.get();
      if (state.data !== null && state.data.total === 71) {
        converged = true;
        return true;
      }
      return false;
    }, 3000);

    unsubscribe();

    assert.equal(
      falseAfterBusyBeforeConverged,
      false,
      "isAnyAggregationComputing() went idle before D's real, converged value was " +
        "available — an E2E/tutorial wait on this signal can resolve too early",
    );
  },
);

test("subscribeGlobalAggregationActivity: notifies on every transition, unsubscribes cleanly", async () => {
  const adapter = memoryAdapter();
  const cache = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const source = makeSource("gac_sub_source");
  await source.set({ value: 5 });

  let releaseCompute: () => void = () => {};
  const gate = new Promise<void>((resolve) => {
    releaseCompute = resolve;
  });
  const agg = defineAggregation({
    version: 1,
    schema: OutputSchema,
    schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
    storage: { table: "gac_sub_agg", key: "__agg__" },
    sources: { src: source },
    compute: async ({ sources }) => {
      await gate;
      return { total: sources.src.value };
    },
  });

  let notifications = 0;
  const unsubscribe = subscribeGlobalAggregationActivity(() => {
    notifications++;
  });

  void agg.get();
  await waitFor(() => notifications >= 1);
  assert.equal(isAnyAggregationComputing(), true);

  releaseCompute();
  await waitFor(() => notifications >= 2);
  assert.equal(isAnyAggregationComputing(), false);

  const countAfterUnsub = notifications;
  unsubscribe();
  await agg.refresh({ bypassExternalsTtl: true }).catch(() => {});
  assert.equal(
    notifications,
    countAfterUnsub,
    "no further notifications after unsubscribe — listener must be gone",
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

test("scenario 9: an Aggregation as a source — a downstream aggregate reads the source's persisted value and propagates its fingerprint, without ever causing a duplicate fetch of the source's own externals", async () => {
  const adapter = memoryAdapter();
  const cache = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const source = makeSource("s9_source");
  await source.set({ value: 1 });

  // A: a store-sourced aggregation with a mocked, counted external (the "expensive price
  // fetch" from the plan's motivation) — a long TTL so, within this test, it is only ever
  // fetched on A's OWN first compute, never again just because a store change happened.
  let priceFetchCalls = 0;
  let computeCallsA = 0;
  const aggA = defineAggregation({
    version: 1,
    schema: OutputSchema,
    schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
    storage: { table: "s9_agg_a", key: "__agg__" },
    debounceMs: 20,
    sources: { src: source },
    externals: {
      prices: {
        load: async () => {
          priceFetchCalls++;
          return 100;
        },
        ttlMs: 10 * 60 * 1000,
      },
    },
    compute: ({ sources, externals }) => {
      computeCallsA++;
      return { total: sources.src.value + externals.prices };
    },
  });

  // C: an aggregation whose ONLY source is A itself (Aggregation-as-source, not a store).
  let computeCallsC = 0;
  const aggC = defineAggregation({
    version: 1,
    schema: OutputSchema,
    schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
    storage: { table: "s9_agg_c", key: "__agg__" },
    debounceMs: 20,
    sources: { a: aggA },
    compute: ({ sources }) => {
      computeCallsC++;
      return { total: sources.a.total * 10 };
    },
  });

  // D: a third level, sourcing C — proves the fingerprint propagates along the whole DAG,
  // not just one hop.
  let computeCallsD = 0;
  const aggD = defineAggregation({
    version: 1,
    schema: OutputSchema,
    schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
    storage: { table: "s9_agg_d", key: "__agg__" },
    debounceMs: 20,
    sources: { c: aggC },
    compute: ({ sources }) => {
      computeCallsD++;
      return { total: sources.c.total + 1 };
    },
  });

  // Establish each level in dependency order — same discipline scenario 2 uses to
  // establish the subscription before the burst being measured. Waiting on the
  // storage-layer put count too (not just the compute counter) matters here: the
  // counter increments the instant `compute()` runs, BEFORE the result is actually
  // persisted — reading a downstream level's `.get()` right after only the counter
  // condition can race ahead of that persist and observe a stale/null value (see
  // scenario 1's identical `adapter.putCallsFor(...)` discipline).
  await aggA.get();
  await waitFor(
    () =>
      computeCallsA === 1 &&
      priceFetchCalls === 1 &&
      adapter.putCallsFor("s9_agg_a") === 1,
  );

  await aggC.get();
  await waitFor(
    () => computeCallsC === 1 && adapter.putCallsFor("s9_agg_c") === 1,
  );
  assert.deepEqual((await aggC.get()).data, { total: 1010 }); // (1 + 100) * 10

  await aggD.get();
  await waitFor(
    () => computeCallsD === 1 && adapter.putCallsFor("s9_agg_d") === 1,
  );
  assert.deepEqual((await aggD.get()).data, { total: 1011 }); // 1010 + 1

  assert.equal(
    priceFetchCalls,
    1,
    "sanity: nothing but A's own compute ever touches the external",
  );

  // 1. A really changes (its store source changes) -> A recomputes -> C (source = A)
  //    detects a different fingerprint -> C recomputes -> D (source = C) cascades too.
  await source.set({ value: 2 });
  await waitFor(
    () => computeCallsA === 2 && adapter.putCallsFor("s9_agg_a") === 2,
    3000,
  );
  await waitFor(
    () => computeCallsC === 2 && adapter.putCallsFor("s9_agg_c") === 2,
    3000,
  );
  await waitFor(
    () => computeCallsD === 2 && adapter.putCallsFor("s9_agg_d") === 2,
    3000,
  );
  await settle();

  assert.equal(
    priceFetchCalls,
    1,
    "the external's TTL hasn't expired — A's recompute must reuse its cached price, " +
      "never refetch it just because the store source changed",
  );
  assert.deepEqual((await aggC.get()).data, { total: 1020 }); // (2 + 100) * 10
  assert.deepEqual((await aggD.get()).data, { total: 1021 }); // 1020 + 1

  // 2. A does NOT change from here on. Forcing D to recompute must read C's persisted
  //    value (which itself reads A's persisted value) with ZERO additional invocations of
  //    A's compute and ZERO additional fetches of A's external — proves there is no
  //    double fetch of the source aggregate's externals anywhere in the DAG.
  const computeCallsABefore = computeCallsA;
  const priceFetchCallsBefore = priceFetchCalls;
  await aggD.refresh();
  assert.equal(
    computeCallsA,
    computeCallsABefore,
    "forcing a recompute at the bottom of the DAG (D) must never cascade into a " +
      "recompute of A when A's own sources haven't changed",
  );
  assert.equal(
    priceFetchCalls,
    priceFetchCallsBefore,
    "forcing D to recompute must never cause A's external to be fetched again",
  );
});

test(
  "cold start: a brand-new user's very first read is the BOTTOM of a 3-level DAG " +
    "(D sources C, C sources A, none of the three has EVER computed anything for this " +
    "user — the exact 'first-ever /dashboard visit, never been to /investimenti' shape) " +
    "— must self-heal to the correct value in a small, bounded number of rounds, never " +
    "loop or stall",
  async () => {
    const adapter = memoryAdapter();
    const cache = memoryCache();
    const cryptoHandle = createDekHandle(randomBytes(32));
    configureSecureStore({
      storage: adapter,
      cache,
      keys: fixedKeyProvider(cryptoHandle),
    });

    const source = makeSource("cold_source");
    await source.set({ value: 3 });

    // A: bottom of the DAG, sourced only from a plain Store — never fails, since a Store
    // source always has schema-default data even when never written (unlike an
    // Aggregation source, which is null until its OWN first compute lands).
    let computeCallsA = 0;
    const aggA = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "cold_agg_a", key: "__agg__" },
      debounceMs: 20,
      sources: { src: source },
      compute: ({ sources }) => {
        computeCallsA++;
        return { total: sources.src.value * 2 };
      },
    });

    // C: middle of the DAG, sources A (an Aggregation, not a Store) — this is the shape
    // that CAN throw "has no persisted value yet" on a cold read.
    let computeCallsC = 0;
    const aggC = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "cold_agg_c", key: "__agg__" },
      debounceMs: 20,
      sources: { a: aggA },
      compute: ({ sources }) => {
        computeCallsC++;
        return { total: sources.a.total + 100 };
      },
    });

    // D: top of the DAG (the thing `Dashboard.tsx` actually mounts) — sources C.
    let computeCallsD = 0;
    const aggD = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "cold_agg_d", key: "__agg__" },
      debounceMs: 20,
      sources: { c: aggC },
      compute: ({ sources }) => {
        computeCallsD++;
        return { total: sources.c.total + 1000 };
      },
    });

    // Intercept console.error (the channel `logBackgroundFailure` uses for every
    // fire-and-forget background failure) so this test can prove the cold cascade fails
    // AT MOST ONCE per intermediate level — never a retry storm — instead of merely
    // trusting that it eventually converges.
    const loggedErrors: unknown[] = [];
    const originalConsoleError = console.error;
    console.error = (...args: unknown[]) => {
      loggedErrors.push(args);
    };

    try {
      // Simulate `Dashboard.tsx` mounting for a user who has NEVER visited
      // `/investimenti` (aggA) or any intermediate page (aggC) — `aggD.get()` is the
      // very first call to `.get()`/`.refresh()` on ANY of the three aggregations.
      const first = await aggD.get();
      assert.deepEqual(
        first,
        { data: null, computing: true, stale: true, error: null },
        "first-ever read of the bottom of a totally cold DAG must be null+computing, " +
          "never throw synchronously to the caller",
      );

      // Bounded poll: the engine mechanics (read `datacloak/core/aggregation.ts`)
      // predict convergence in exactly 3 rounds — A's own first compute (no aggregation
      // sources of its own, so it can never throw on this path) succeeds immediately;
      // A's persist-and-publish (`computeAndPersist`'s `cache?.set` at the end) wakes
      // C's subscription (`ensureSubscribed`'s `cache.subscribe` callback) and schedules
      // C's debounced recompute, which now succeeds; C's own persist-and-publish then
      // wakes D's subscription the same way. Cap the wait well above what two
      // sequential 20ms debounces need, far below "would indicate a stall". Waiting on
      // `adapter.putCallsFor(...)` too (not just the compute counters) matters here,
      // same discipline as scenario 9 above: the counter increments the instant
      // `compute()` runs, BEFORE the result is actually persisted — reading `aggD.get()`
      // right after only the counter condition can race ahead of D's own persist and
      // observe a still-null value.
      await waitFor(
        () =>
          computeCallsA === 1 &&
          computeCallsC === 1 &&
          computeCallsD === 1 &&
          adapter.putCallsFor("cold_agg_a") === 1 &&
          adapter.putCallsFor("cold_agg_c") === 1 &&
          adapter.putCallsFor("cold_agg_d") === 1,
        3000,
      );

      const final = await aggD.get();
      assert.deepEqual(
        final.data,
        { total: 3 * 2 + 100 + 1000 },
        "the converged value must come from the REAL fixture data at the bottom of the " +
          "DAG, not a placeholder/default",
      );
      assert.equal(final.computing, false);
      assert.equal(final.stale, false);
      assert.equal(final.error, null);

      // No loop / no stall: hold steady well past convergence and confirm nothing
      // recomputes again — the cascade settles, it never oscillates.
      await settle(200);
      assert.equal(
        computeCallsA,
        1,
        "A must never recompute again once the DAG has converged",
      );
      assert.equal(
        computeCallsC,
        1,
        "C must never recompute again once the DAG has converged",
      );
      assert.equal(
        computeCallsD,
        1,
        "D must never recompute again once the DAG has converged",
      );

      // Exactly one failed FIRST attempt each for C (reading a still-empty A) and D
      // (reading a still-empty C) is the expected, self-healing shape — more than one
      // each would mean an uncontrolled retry storm rather than a clean one-shot cascade.
      const noPersistedValueErrors = loggedErrors.filter((args) =>
        String((args as unknown[])[1] ?? "").includes(
          "has no persisted value yet",
        ),
      );
      assert.equal(
        noPersistedValueErrors.length,
        2,
        "exactly one logged 'has no persisted value yet' failure each for C and D — " +
          "never more (a retry storm) and never fewer (the cold-read guard silently " +
          "swallowed instead of surfacing)",
      );
    } finally {
      console.error = originalConsoleError;
    }
  },
);

test(
  "diamond DAG (D sources BOTH A directly AND C, which itself sources A — the exact " +
    "shape of dashboardAgg's real 'portfolioSeries' + 'netWorthSeries' sources): a " +
    "single upstream change must still recompute C exactly ONCE, never twice, even " +
    "though D's OWN sourceEntries read C eagerly (via aggC.get()) on every attempt, " +
    "racing C's own debounce-scheduled recompute for the SAME staleness event",
  async () => {
    const adapter = memoryAdapter();
    const cache = memoryCache();
    const cryptoHandle = createDekHandle(randomBytes(32));
    configureSecureStore({
      storage: adapter,
      cache,
      keys: fixedKeyProvider(cryptoHandle),
    });

    const source = makeSource("diamond_source");
    await source.set({ value: 3 });

    let computeCallsA = 0;
    const aggA = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "diamond_agg_a", key: "__agg__" },
      debounceMs: 20,
      sources: { src: source },
      compute: ({ sources }) => {
        computeCallsA++;
        return { total: sources.src.value * 2 };
      },
    });

    let computeCallsC = 0;
    const aggC = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "diamond_agg_c", key: "__agg__" },
      debounceMs: 20,
      sources: { a: aggA },
      compute: ({ sources }) => {
        computeCallsC++;
        return { total: sources.a.total + 100 };
      },
    });

    // D sources BOTH `a` (aggA) AND `c` (aggC) directly — the diamond shape that
    // `dashboardAggregation.ts` actually has (`portfolioSeries: portfolioSeriesAgg`
    // + `netWorthSeries: netWorthSeriesAgg`, where netWorthSeriesAgg itself sources
    // portfolioSeriesAgg). Every time D's OWN `computeAndPersist()` assembles its
    // sources it calls `aggC.get()` (the `c` entry) EAGERLY — a second path into C
    // besides C's own `ensureSubscribed` debounce timer reacting to the same A
    // publish.
    let computeCallsD = 0;
    const aggD = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "diamond_agg_d", key: "__agg__" },
      debounceMs: 20,
      sources: { a: aggA, c: aggC },
      compute: ({ sources }) => {
        computeCallsD++;
        return { total: sources.a.total + sources.c.total + 1000 };
      },
    });

    const loggedErrors: unknown[] = [];
    const originalConsoleError = console.error;
    console.error = (...args: unknown[]) => {
      loggedErrors.push(args);
    };

    try {
      // Cold start, exactly like the "cold start" test above — the very first read
      // of the whole DAG is at the top (D), nobody has visited A or C directly yet.
      await aggD.get();

      await waitFor(
        () => computeCallsD === 1 && adapter.putCallsFor("diamond_agg_d") === 1,
        3000,
      );
      // Hold well past convergence — this is where a redundant rerun (queued while
      // C's in-flight compute settles, then fired unconditionally regardless of
      // whether anything is ACTUALLY still stale) would show up as computeCallsC
      // ticking past 1.
      await settle(500);

      assert.equal(
        computeCallsA,
        1,
        "A must compute exactly once for a single upstream change",
      );
      assert.equal(
        computeCallsC,
        1,
        "C must compute exactly once for a single upstream change — a redundant " +
          "rerun (D's eager aggC.get() racing C's own pending debounce timer for " +
          "the SAME staleness event) must never cause a second real compute()",
      );
      assert.equal(
        computeCallsD,
        1,
        "D must compute exactly once for a single upstream change",
      );
    } finally {
      console.error = originalConsoleError;
    }
  },
);

test(
  "diamond DAG, WARM (not cold-start): D shares a DIRECT store source with C (the " +
    "exact shape of dashboardAgg's real `snapshots` keyedSource, subscribed by BOTH " +
    "dashboardAgg AND netWorthSeriesAgg directly) — a single write to that shared " +
    "source, AFTER both C and D already have a valid persisted value, must still " +
    "recompute D exactly ONCE, never twice (CT6 diamond-DAG gap, see the plan's CT6 " +
    "report: before this fix, D's own eager `aggC.get()` returned the pre-write value " +
    "— C hadn't republished yet — D persisted with it, then recomputed a second time " +
    "the instant C's fresh fingerprint arrived)",
  async () => {
    const adapter = memoryAdapter();
    const cache = memoryCache();
    const cryptoHandle = createDekHandle(randomBytes(32));
    configureSecureStore({
      storage: adapter,
      cache,
      keys: fixedKeyProvider(cryptoHandle),
    });

    const source = makeSource("warm_diamond_source");
    await source.set({ value: 1 });

    // C: sources the shared store DIRECTLY — the `netWorthSeriesAgg` role.
    let computeCallsC = 0;
    const aggC = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "warm_diamond_agg_c", key: "__agg__" },
      debounceMs: 30,
      sources: { src: source },
      compute: ({ sources }) => {
        computeCallsC++;
        return { total: sources.src.value * 10 };
      },
    });

    // D: sources the SAME store directly AND `aggC` as an aggregation-source — the
    // `dashboardAgg` role. SAME `debounceMs` as C (production default is 500ms for
    // both) — no structural head start for either side, the fix must not depend on one.
    let computeCallsD = 0;
    const aggD = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "warm_diamond_agg_d", key: "__agg__" },
      debounceMs: 30,
      sources: { src: source, c: aggC },
      compute: ({ sources }) => {
        computeCallsD++;
        return { total: sources.src.value + sources.c.total };
      },
    });

    // Prime WARM (not cold): converge the whole DAG once, exactly like the real CT6
    // test's `primeColdStart` does. Calling `aggD.get()` first (not `aggC.get()`) also
    // reproduces the real subscription ORDER: D's own `ensureSubscribed` subscribes to
    // `source` (its `src` entry) BEFORE C ever subscribes to anything — C's
    // `ensureSubscribed` only runs later, nested inside D's first `computeAndPersist`
    // when it reads `aggC.get()` for its `c` entry. This is the exact order
    // `dashboardAgg`/`netWorthSeriesAgg` have in production (see the CT6 report).
    await aggD.get();
    await waitFor(
      () =>
        computeCallsC === 1 &&
        computeCallsD === 1 &&
        adapter.putCallsFor("warm_diamond_agg_c") === 1 &&
        adapter.putCallsFor("warm_diamond_agg_d") === 1,
      3000,
    );
    await settle(200);

    // The real scenario: a SINGLE write to the shared leaf once both C and D already
    // hold valid persisted data (warm) — this is what a live transaction burst does to
    // `snapshotStore` in production (see `ct6-single-pass.test.tsx`).
    computeCallsC = 0;
    computeCallsD = 0;
    await source.set({ value: 2 });

    await waitFor(() => computeCallsC >= 1 && computeCallsD >= 1, 3000);
    // Hold well past a possible SECOND debounce/recompute round — this is exactly where
    // the pre-fix gap showed up (D recomputing again once C republished).
    await settle(500);

    assert.equal(
      computeCallsC,
      1,
      "C must recompute exactly once for a single upstream change",
    );
    assert.equal(
      computeCallsD,
      1,
      "D must recompute exactly once for a single upstream change — before the CT6 " +
        "fix this was deterministically 2 (D's eager read of C returned the stale " +
        "pre-write value, then D recomputed again once C republished its fresh " +
        "fingerprint)",
    );

    const final = await aggD.get();
    assert.deepEqual(
      final.data,
      { total: 2 + 20 },
      "the converged value must reflect the NEW source value on BOTH the direct path " +
        "and via C, never a mix of stale-C + fresh-src",
    );
  },
);

test(
  "refresh({ bypassExternalsTtl: true }): forces a fresh external fetch even inside its " +
    "TTL window; a plain refresh() keeps reusing the cached value (Task 5 review, Finding " +
    "3 — a worker that just wrote new market data needs the NEXT recompute to see it now, " +
    "not after the external's TTL expires)",
  async () => {
    const adapter = memoryAdapter();
    const cache = memoryCache();
    const cryptoHandle = createDekHandle(randomBytes(32));
    configureSecureStore({
      storage: adapter,
      cache,
      keys: fixedKeyProvider(cryptoHandle),
    });

    const source = makeSource("bypass_ttl_source");
    await source.set({ value: 1 });

    let priceFetchCalls = 0;
    // The external's return value changes on every REAL fetch (a fresh market snapshot),
    // so the test can tell a bypassed refetch apart from a reused cache entry by the
    // persisted `data`, not just a call counter.
    const agg = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "bypass_ttl_agg", key: "__agg__" },
      sources: { src: source },
      externals: {
        prices: {
          load: async () => {
            priceFetchCalls++;
            return priceFetchCalls * 100;
          },
          // Long TTL — deliberately far outside this test's runtime, so any refetch
          // observed below can only be explained by an explicit bypass, never expiry.
          ttlMs: 10 * 60 * 1000,
        },
      },
      compute: ({ sources, externals }) => ({
        total: sources.src.value + externals.prices,
      }),
    });

    await agg.get();
    await waitFor(
      () =>
        priceFetchCalls === 1 && adapter.putCallsFor("bypass_ttl_agg") === 1,
    );
    assert.deepEqual((await agg.get()).data, { total: 101 }); // 1 + 100

    // Plain refresh(): existing guarantee (scenario 9) must still hold — reuses the
    // cached external within its TTL.
    await agg.refresh();
    assert.equal(
      priceFetchCalls,
      1,
      "a plain refresh() must not refetch an external that's still within its TTL",
    );
    assert.deepEqual((await agg.get()).data, { total: 101 });

    // Explicit bypass: must refetch NOW, well within the TTL window, and persist the
    // new value.
    await agg.refresh({ bypassExternalsTtl: true });
    assert.equal(
      priceFetchCalls,
      2,
      "refresh({ bypassExternalsTtl: true }) must force a fresh external fetch even " +
        "though the TTL hasn't expired",
    );
    assert.deepEqual((await agg.get()).data, { total: 201 }); // 1 + 200

    // A subsequent PLAIN refresh() must go back to reusing the cache the bypass just
    // refreshed — bypass is a one-shot escape hatch, not a standing TTL override.
    await agg.refresh();
    assert.equal(
      priceFetchCalls,
      2,
      "a plain refresh() right after a bypass must reuse the just-refreshed cache, not " +
        "fetch again",
    );
  },
);

test(
  "review finding: a lock firing DURING internalStore.save()'s own internal await " +
    "(not just before it starts) must not update lastEnvelope or publish the downstream " +
    "fingerprint — a narrower race window than the guard's stated precedent, reload()",
  async () => {
    const adapter = memoryAdapter();
    const cache = memoryCache();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider, lock } = mutableKeyProvider(cryptoHandle);

    // Gate `put()` for the aggregation's OWN table only — pauses AFTER the ambient
    // identity check inside `computeAndPersist` has already passed (that check runs
    // strictly before this call), reproducing a lock that fires while `save()`'s own
    // internal awaits (encrypt + storage put) are in flight, not before them.
    let putGateActive = false;
    let onPutEntered: (() => void) | null = null;
    let releasePut!: () => void;
    const gatedAdapter: StorageAdapter & {
      putCallsFor: (c: string) => number;
    } = {
      ...adapter,
      async put(collection, userId, extraKeys, record) {
        if (collection === "rf1_agg" && putGateActive) {
          onPutEntered?.();
          await new Promise<void>((resolve) => {
            releasePut = resolve;
          });
        }
        return adapter.put(collection, userId, extraKeys, record);
      },
    };
    configureSecureStore({ storage: gatedAdapter, cache, keys: provider });

    const source = makeSource("rf1_source");
    await source.set({ value: 1 });

    const agg = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "rf1_agg", key: "__agg__" },
      sources: { src: source },
      compute: ({ sources }) => ({ total: sources.src.value * 10 }),
    });

    await agg.refresh(); // seed — unlocked throughout, completes normally
    assert.equal(adapter.putCallsFor("rf1_agg"), 1);
    const fingerprintKey = `rf1_agg:__agg__:u1`;
    const seededFingerprint = cache.get(fingerprintKey);
    assert.notEqual(
      seededFingerprint,
      undefined,
      "the seed's own persist must have published its fingerprint",
    );

    // Second recompute must actually produce a DIFFERENT envelope (data + fingerprints),
    // or `computeAndPersist` takes the skip-write branch and never calls
    // `internalStore.save()` at all — nothing to gate. Gate the aggregation's OWN put()
    // so we can lock exactly while internalStore.save()'s underlying storage write is in
    // flight.
    await source.set({ value: 2 });
    putGateActive = true;
    const entered = new Promise<void>((resolve) => {
      onPutEntered = resolve;
    });
    const refreshPromise = agg.refresh();
    await entered; // storage.put() has been called and is now paused mid-flight

    lock(); // lock NOW — strictly after computeAndPersist's first identity check passed

    releasePut();
    await refreshPromise; // never throws — the guard fails open, it doesn't reject

    // The storage write itself did complete (can't be undone once started) ...
    assert.equal(
      adapter.putCallsFor("rf1_agg"),
      2,
      "the underlying storage write completes even though the session locked mid-flight",
    );
    // ... but nothing computed under the now-superseded session may be treated as valid:
    // the downstream fingerprint slot a future aggregation source would read from must
    // still hold the SEEDED value, never resurrected/overwritten with the post-lock write.
    assert.deepEqual(
      cache.get(fingerprintKey),
      seededFingerprint,
      "a lock firing during save()'s own internal await must not publish the downstream " +
        "fingerprint for a compute that finished after the session was superseded",
    );
  },
);

test(
  "review finding: loadEnvelopeDeduped must not ignore identity — a user B get() call " +
    "started while user A's read is still in flight must never be served A's decrypted " +
    "envelope (the in-flight promise has to be keyed by userId/cryptoHandle, not a " +
    "single un-keyed slot, mirroring react/useStore.ts's ${store.name}:${userId} registry)",
  async () => {
    const adapter = memoryAdapter();
    const cache = memoryCache();
    const handleA = createDekHandle(randomBytes(32));
    const handleB = createDekHandle(randomBytes(32));
    const { provider, switchTo } = switchableKeyProvider();

    // Gate `get()` for the aggregation's OWN table only, and only its FIRST invocation
    // once armed — reproducing user A's `get()` starting a real read that's still in
    // flight when user B logs in on this SAME live instance and calls `get()` too.
    let armed = false;
    const raceGetCalls: string[] = []; // userId of every storage.get() on the race table while armed
    let releaseGate!: () => void;
    const gate = new Promise<void>((resolve) => {
      releaseGate = resolve;
    });
    const gatedAdapter: StorageAdapter = {
      ...adapter,
      async get(collection, userId, extraKeys) {
        if (armed && collection === "race_agg") {
          raceGetCalls.push(userId);
          if (raceGetCalls.length === 1) {
            await gate; // hold ONLY the first (user A's) real read in flight
          }
        }
        return adapter.get(collection, userId, extraKeys);
      },
    };
    configureSecureStore({ storage: gatedAdapter, cache, keys: provider });

    const source = makeSource("race_source");
    const agg = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "race_agg", key: "__agg__" },
      sources: { src: source },
      compute: ({ sources }) => ({ total: sources.src.value }),
    });

    // Seed BOTH users' persisted envelopes up front — before arming the gate, so the
    // seeds' own internal reads/writes are never intercepted by it.
    switchTo("userA", handleA);
    await source.set({ value: 1 });
    await agg.refresh(); // persists { total: 1 } under userA

    switchTo("userB", handleB);
    await source.set({ value: 99 });
    await agg.refresh(); // persists { total: 99 } under userB

    // Drop every cache entry the seeds left behind (source fingerprint slots AND the
    // internal envelope table's own revalidation cache) so the race below performs a
    // REAL storage read for each identity, not a warm-cache hit — `loadRevalidated`
    // (store.ts) skips `storage.get` entirely when its cache slot already holds a
    // matching hash.
    cache.clear();

    armed = true;
    switchTo("userA", handleA);
    const getA = agg.get(); // starts a real read for A; storage.get() gated, hangs

    switchTo("userB", handleB); // user B logs in on this SAME live instance, mid-read
    const getB = agg.get(); // must start its OWN read for B, never reuse A's in-flight promise

    releaseGate(); // let A's held-open read proceed
    const [resultA, resultB] = await Promise.all([getA, getB]);

    assert.deepEqual(
      resultA.data,
      { total: 1 },
      "A's own get() must still resolve with A's own persisted value",
    );
    assert.deepEqual(
      resultB.data,
      { total: 99 },
      "B's get() must resolve with B's OWN persisted value, never A's — a single " +
        "un-keyed in-flight promise would serve A's decrypted envelope to B here",
    );
    assert.deepEqual(
      raceGetCalls,
      ["userA", "userB"],
      "both identities must trigger their OWN real storage read — reusing A's in-flight " +
        "promise for B would mean only ONE storage.get() call happened here",
    );
  },
);

// ── Task 5-pre: `storage.keyColumn` — configurable sentinel column name ────────────────
//
// The internal store `defineAggregation` builds for itself must be wireable onto a
// PRE-EXISTING table whose sentinel column isn't literally named `"key"` (e.g.
// `account_snapshot_blobs.year_month`, the table Task 5 reuses for the dashboard
// aggregate with zero migration). These two tests assert on the ACTUAL column name the
// adapter observed (`columnsUsedFor`), not just that the read/write round-tripped —
// asserting only the round-trip would pass even if the column name were silently wrong,
// since the in-memory adapter's `rowKey` doesn't itself depend on the column name.

test('keyColumn: a custom sentinel column name is used for persistence instead of the literal "key"', async () => {
  const adapter = memoryAdapter();
  const cache = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const source = makeSource("keycol_custom_source");
  await source.set({ value: 5 });

  const agg = defineAggregation({
    version: 1,
    schema: OutputSchema,
    schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
    storage: {
      table: "keycol_custom_agg",
      key: "__dashboard__",
      keyColumn: "year_month",
    },
    sources: { src: source },
    compute: ({ sources }) => ({ total: sources.src.value }),
  });

  await agg.get();
  await waitFor(() => adapter.putCallsFor("keycol_custom_agg") === 1);

  assert.deepEqual(
    [...adapter.columnsUsedFor("keycol_custom_agg")],
    ["year_month"],
    "the internal store must persist using the configured keyColumn, never the " +
      'hardcoded literal "key"',
  );
});

test('keyColumn: omitted -> defaults to the literal column "key" (Task 1-4 backward compatibility, unchanged)', async () => {
  const adapter = memoryAdapter();
  const cache = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const source = makeSource("keycol_default_source");
  await source.set({ value: 7 });

  const agg = defineAggregation({
    version: 1,
    schema: OutputSchema,
    schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
    storage: { table: "keycol_default_agg", key: "__agg__" },
    sources: { src: source },
    compute: ({ sources }) => ({ total: sources.src.value }),
  });

  await agg.get();
  await waitFor(() => adapter.putCallsFor("keycol_default_agg") === 1);

  assert.deepEqual(
    [...adapter.columnsUsedFor("keycol_default_agg")],
    ["key"],
    "an aggregation that doesn't specify keyColumn must keep persisting under the " +
      'literal column "key" — exactly Task 1-4\'s existing, already-tested behavior',
  );
});

// ─── invalidateOn / invalidateChannel — externals sourced from non-Store data ──
//
// An `external` can depend on data DataCloak has no write-interception hook for
// at all (a plaintext table read via a plain REST call, e.g. "which account ids
// currently exist") — no source ever changes when that data changes, so nothing
// naturally marks the aggregation stale before its TTL expires. `invalidateOn`
// lets an external declare the named channel(s) it depends on; the app calls
// `invalidateChannel(name)` once, at the single place the underlying mutation
// happens, without needing to know which aggregation(s) (if any) care.

test("invalidateChannel: forces an immediate recompute with a freshly refetched external, with no source change at all", async () => {
  const adapter = memoryAdapter();
  const cache = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const source = makeSource("invchan_source");
  await source.set({ value: 1 });

  let externalValue = 100;
  let externalFetchCalls = 0;
  const agg = defineAggregation({
    version: 1,
    schema: OutputSchema,
    schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
    storage: { table: "invchan_agg", key: "__agg__" },
    sources: { src: source },
    externals: {
      thing: {
        load: async () => {
          externalFetchCalls++;
          return externalValue;
        },
        ttlMs: 10 * 60 * 1000,
        invalidateOn: ["invchan-test-1"],
      },
    },
    compute: ({ sources, externals }) => ({
      total: sources.src.value + externals.thing,
    }),
  });

  await agg.get();
  await waitFor(() => adapter.putCallsFor("invchan_agg") === 1);
  assert.deepEqual((await agg.get()).data, { total: 101 });
  assert.equal(externalFetchCalls, 1);

  // The underlying non-Store data changes — nothing here is a `source`, so
  // nothing naturally marks the aggregate stale.
  externalValue = 200;
  await settle(50);
  assert.deepEqual(
    (await agg.get()).data,
    { total: 101 },
    "sanity: the external's long TTL means an ordinary get() must NOT see the change yet",
  );

  invalidateChannel("invchan-test-1");
  await waitFor(() => externalFetchCalls === 2, 2000);
  await waitFor(() => adapter.putCallsFor("invchan_agg") === 2, 2000);

  assert.deepEqual(
    (await agg.get()).data,
    { total: 201 },
    "invalidateChannel must force the external to refetch and the aggregate to " +
      "recompute immediately, without waiting out its TTL and without any source change",
  );
});

test("invalidateChannel: only the external(s) declaring that channel are refetched, not unrelated ones on the same aggregation", async () => {
  const adapter = memoryAdapter();
  const cache = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const source = makeSource("invchan_scope_source");
  await source.set({ value: 1 });

  let watchedFetchCalls = 0;
  let unrelatedFetchCalls = 0;
  const agg = defineAggregation({
    version: 1,
    schema: OutputSchema,
    schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
    storage: { table: "invchan_scope_agg", key: "__agg__" },
    sources: { src: source },
    externals: {
      watched: {
        load: async () => {
          watchedFetchCalls++;
          return 10;
        },
        ttlMs: 10 * 60 * 1000,
        invalidateOn: ["invchan-test-2"],
      },
      unrelated: {
        load: async () => {
          unrelatedFetchCalls++;
          return 1000;
        },
        ttlMs: 10 * 60 * 1000,
        // No invalidateOn at all — must never be refetched by a channel invalidation.
      },
    },
    compute: ({ sources, externals }) => ({
      total: sources.src.value + externals.watched + externals.unrelated,
    }),
  });

  await agg.get();
  await waitFor(() => adapter.putCallsFor("invchan_scope_agg") === 1);
  assert.equal(watchedFetchCalls, 1);
  assert.equal(unrelatedFetchCalls, 1);

  invalidateChannel("invchan-test-2");
  await waitFor(() => watchedFetchCalls === 2, 2000);
  await waitFor(() => adapter.putCallsFor("invchan_scope_agg") === 2, 2000);

  assert.equal(
    unrelatedFetchCalls,
    1,
    "an external with no invalidateOn for this channel must never be refetched by it",
  );
});

test("invalidateChannel: a single call reaches EVERY aggregation subscribed to that channel, not just one", async () => {
  const adapter = memoryAdapter();
  const cache = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const source = makeSource("invchan_multi_source");
  await source.set({ value: 1 });

  let fetchCallsA = 0;
  const aggA = defineAggregation({
    version: 1,
    schema: OutputSchema,
    schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
    storage: { table: "invchan_multi_agg_a", key: "__agg__" },
    sources: { src: source },
    externals: {
      thing: {
        load: async () => {
          fetchCallsA++;
          return 1;
        },
        ttlMs: 10 * 60 * 1000,
        invalidateOn: ["invchan-test-3"],
      },
    },
    compute: ({ sources, externals }) => ({
      total: sources.src.value + externals.thing,
    }),
  });

  let fetchCallsB = 0;
  const aggB = defineAggregation({
    version: 1,
    schema: OutputSchema,
    schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
    storage: { table: "invchan_multi_agg_b", key: "__agg__" },
    sources: { src: source },
    externals: {
      thing: {
        load: async () => {
          fetchCallsB++;
          return 2;
        },
        ttlMs: 10 * 60 * 1000,
        invalidateOn: ["invchan-test-3"],
      },
    },
    compute: ({ sources, externals }) => ({
      total: sources.src.value + externals.thing,
    }),
  });

  await aggA.get();
  await aggB.get();
  await waitFor(
    () =>
      adapter.putCallsFor("invchan_multi_agg_a") === 1 &&
      adapter.putCallsFor("invchan_multi_agg_b") === 1,
  );
  assert.equal(fetchCallsA, 1);
  assert.equal(fetchCallsB, 1);

  invalidateChannel("invchan-test-3");
  await waitFor(() => fetchCallsA === 2 && fetchCallsB === 2, 2000);

  assert.equal(
    fetchCallsA,
    2,
    "one invalidateChannel call must reach aggregation A",
  );
  assert.equal(
    fetchCallsB,
    2,
    "the SAME invalidateChannel call must ALSO reach aggregation B — the app names " +
      "the channel once, it never needs to know which aggregations depend on it",
  );
});

test("invalidateChannel: an unused channel name is a safe no-op", async () => {
  const adapter = memoryAdapter();
  const cache = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  assert.doesNotThrow(() =>
    invalidateChannel("nobody-subscribes-to-this-channel"),
  );
});

// ─── Cold-session freshness verification — hash check against the real server ──
//
// `isFresh()` normally trusts the persisted envelope blindly for any source never
// OBSERVED live in this session (`currentSourceFingerprints.get(name) === undefined`
// -> "no signal, assume unchanged"). That's correct for a source that genuinely
// hasn't changed, but wrong if it changed via a path this session's live
// subscriptions never saw — e.g. a previous session's write succeeded but its
// OWN recompute was interrupted (tab closed) before persisting, or another
// device/tab wrote it. A brand-new `.get()` (first call for a fresh instance/
// identity) now verifies any never-observed source against the REAL current hash
// before trusting the envelope, instead of trusting it unconditionally.

test("cold get(): a perUser Store source changed via a path never observed live is detected via a real hash check and forces a recompute", async () => {
  const adapter = memoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));

  // "Session A": establishes the aggregate, persisted with value 1.
  {
    const cacheA = memoryCache();
    configureSecureStore({
      storage: adapter,
      cache: cacheA,
      keys: fixedKeyProvider(cryptoHandle),
    });
    const source = makeSource("cold_perUser_source");
    await source.set({ value: 1 });
    const aggA = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "cold_perUser_agg", key: "__agg__" },
      debounceMs: 20,
      sources: { src: source },
      compute: ({ sources }) => ({ total: sources.src.value }),
    });
    await aggA.get();
    await waitFor(() => adapter.putCallsFor("cold_perUser_agg") === 1);
    assert.deepEqual((await aggA.get()).data, { total: 1 });
  }

  // The source changes via a DIFFERENT session (own cache) — session A's cache
  // (and any future fresh instance's empty cache) never observes this write live.
  {
    const cacheB = memoryCache();
    configureSecureStore({
      storage: adapter,
      cache: cacheB,
      keys: fixedKeyProvider(cryptoHandle),
    });
    const source = makeSource("cold_perUser_source");
    await source.set({ value: 2 });
  }

  // "Session C": brand-new cache + brand-new aggregation instance — must
  // self-heal via the cold hash check, not serve session A's stale total:1.
  {
    const cacheC = memoryCache();
    configureSecureStore({
      storage: adapter,
      cache: cacheC,
      keys: fixedKeyProvider(cryptoHandle),
    });
    const source = makeSource("cold_perUser_source");
    const aggC = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "cold_perUser_agg", key: "__agg__" },
      debounceMs: 20,
      sources: { src: source },
      compute: ({ sources }) => ({ total: sources.src.value }),
    });
    await waitFor(async () => (await aggC.get()).data?.total === 2, 3000);
  }
});

test("cold get(): nothing changed since the persisted envelope -> no unnecessary recompute, just the verification read", async () => {
  const adapter = memoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));

  {
    const cacheA = memoryCache();
    configureSecureStore({
      storage: adapter,
      cache: cacheA,
      keys: fixedKeyProvider(cryptoHandle),
    });
    const source = makeSource("cold_nochange_source");
    await source.set({ value: 5 });
    const aggA = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "cold_nochange_agg", key: "__agg__" },
      debounceMs: 20,
      sources: { src: source },
      compute: ({ sources }) => ({ total: sources.src.value }),
    });
    await aggA.get();
    await waitFor(() => adapter.putCallsFor("cold_nochange_agg") === 1);
  }

  // "Session B": fresh instance, but NOTHING changed since session A persisted.
  {
    const cacheB = memoryCache();
    configureSecureStore({
      storage: adapter,
      cache: cacheB,
      keys: fixedKeyProvider(cryptoHandle),
    });
    const source = makeSource("cold_nochange_source");
    const aggB = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "cold_nochange_agg", key: "__agg__" },
      debounceMs: 20,
      sources: { src: source },
      compute: ({ sources }) => ({ total: sources.src.value }),
    });
    const state = await aggB.get();
    assert.deepEqual(state.data, { total: 5 });
    await settle(50);
    assert.equal(
      adapter.putCallsFor("cold_nochange_agg"),
      1,
      "the cold verification confirmed the source is unchanged — no second, " +
        "unnecessary recompute/persist should happen",
    );
  }
});

test("cold get(): several KeyedSourceRef sources sharing ONE physical table are verified with ONE batched getHashesByKeys call, not one per source", async () => {
  const adapter = memoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));

  function makeKeyedSource(name: string) {
    return defineStore({
      name,
      identity: { perKey: "k" as const },
      encrypt: "all",
      schema: SourceSchema,
      version: 1,
      contentHash: true,
      schemaFingerprint: fingerprintSchema(SourceSchema, "all"),
    });
  }

  {
    const cacheA = memoryCache();
    configureSecureStore({
      storage: adapter,
      cache: cacheA,
      keys: fixedKeyProvider(cryptoHandle),
    });
    const keyedStore = makeKeyedSource("cold_keyed_shared_table");
    await keyedStore.set("k1", { value: 1 });
    await keyedStore.set("k2", { value: 10 });
    const aggA = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "cold_keyed_agg", key: "__agg__" },
      debounceMs: 20,
      sources: {
        a: keyedSource(keyedStore, "k1"),
        b: keyedSource(keyedStore, "k2"),
      },
      compute: ({ sources }) => ({ total: sources.a.value + sources.b.value }),
    });
    await aggA.get();
    await waitFor(() => adapter.putCallsFor("cold_keyed_agg") === 1);
    assert.deepEqual((await aggA.get()).data, { total: 11 });
  }

  // Session B changes k2 via a path session C will never observe live.
  {
    const cacheB = memoryCache();
    configureSecureStore({
      storage: adapter,
      cache: cacheB,
      keys: fixedKeyProvider(cryptoHandle),
    });
    const keyedStore = makeKeyedSource("cold_keyed_shared_table");
    await keyedStore.set("k2", { value: 20 });
  }

  // Session C: fresh instance, both `a` and `b` share ONE physical table
  // (cold_keyed_shared_table) -> ONE getHashesByKeys call verifies both.
  {
    const cacheC = memoryCache();
    configureSecureStore({
      storage: adapter,
      cache: cacheC,
      keys: fixedKeyProvider(cryptoHandle),
    });
    const keyedStore = makeKeyedSource("cold_keyed_shared_table");
    const aggC = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "cold_keyed_agg", key: "__agg__" },
      debounceMs: 20,
      sources: {
        a: keyedSource(keyedStore, "k1"),
        b: keyedSource(keyedStore, "k2"),
      },
      compute: ({ sources }) => ({ total: sources.a.value + sources.b.value }),
    });
    await waitFor(async () => (await aggC.get()).data?.total === 21, 3000);
    assert.equal(
      adapter.getHashesByKeysCallsFor("cold_keyed_shared_table"),
      1,
      "two KeyedSourceRef sources sharing one physical table must cost ONE " +
        "batched getHashesByKeys call, not one getHash call per source",
    );
  }
});

test("cold get(): an Aggregation-as-source that changed upstream (never observed live) is detected via its own fingerprint", async () => {
  const adapter = memoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));

  function buildUpstreamAndDownstream() {
    const upSource = makeSource("cold_agg_source_upstream_src");
    const upstream = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "cold_agg_source_upstream", key: "__agg__" },
      debounceMs: 20,
      sources: { src: upSource },
      compute: ({ sources }) => ({ total: sources.src.value }),
    });
    const downstream = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "cold_agg_source_downstream", key: "__agg__" },
      debounceMs: 20,
      sources: { up: upstream },
      compute: ({ sources }) => ({ total: sources.up.total * 10 }),
    });
    return { upSource, upstream, downstream };
  }

  {
    const cacheA = memoryCache();
    configureSecureStore({
      storage: adapter,
      cache: cacheA,
      keys: fixedKeyProvider(cryptoHandle),
    });
    const { upSource, upstream, downstream } = buildUpstreamAndDownstream();
    await upSource.set({ value: 1 });
    await upstream.get();
    await waitFor(() => adapter.putCallsFor("cold_agg_source_upstream") === 1);
    await downstream.get();
    await waitFor(
      () => adapter.putCallsFor("cold_agg_source_downstream") === 1,
    );
    assert.deepEqual((await downstream.get()).data, { total: 10 });
  }

  // Session B changes the upstream's OWN source and recomputes upstream, via a
  // path session C's downstream instance never observes live.
  {
    const cacheB = memoryCache();
    configureSecureStore({
      storage: adapter,
      cache: cacheB,
      keys: fixedKeyProvider(cryptoHandle),
    });
    const { upSource, upstream } = buildUpstreamAndDownstream();
    await upSource.set({ value: 2 });
    await upstream.get();
    await waitFor(() => adapter.putCallsFor("cold_agg_source_upstream") === 2);
  }

  // Session C: fresh downstream instance must detect the upstream's persisted
  // fingerprint changed and recompute, even though downstream's OWN cache never
  // saw any write on the upstream's table.
  {
    const cacheC = memoryCache();
    configureSecureStore({
      storage: adapter,
      cache: cacheC,
      keys: fixedKeyProvider(cryptoHandle),
    });
    const { downstream } = buildUpstreamAndDownstream();
    await waitFor(
      async () => (await downstream.get()).data?.total === 20,
      3000,
    );
  }
});
