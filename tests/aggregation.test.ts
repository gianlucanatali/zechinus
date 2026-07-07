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
