/**
 * Tests the React binding (`useAggregation`) — Task 4 of the "aggregazioni dichiarative
 * persistite" plan, scenarios 3, 4, 5, 6 from the plan/brief:
 *
 *  3. Fingerprint match on mount: no recompute, no fetch of the SOURCE's own blob (only
 *     this aggregation's own persisted envelope is read).
 *  4. Fingerprint mismatch on mount: serves the stale persisted value immediately
 *     (`stale: true`) while a recompute runs in the background, then swaps to the new
 *     value atomically — no intermediate/partial state ever observed.
 *  5. A lock (unlock -> lock) while a compute is in flight must not persist, nor
 *     re-publish that compute's result once it settles (fail-open, same discipline as
 *     `react/useStore.ts`'s `reload()`).
 *  6. An expired `external` TTL triggers a recompute even when the source fingerprints
 *     are unchanged.
 *
 * Needs jsdom + React rendering — runs under Vitest (`npm run test:components`), same as
 * `useStore.test.tsx` and friends (see that file's own header comment for why).
 */
import { describe, it, expect, afterEach } from "vitest";
import { cleanup, renderHook, act, waitFor } from "@testing-library/react";
import { randomBytes } from "@noble/ciphers/utils.js";
import { z } from "zod";

import { createDekHandle } from "./testKeyHandle.ts";
import {
  configureSecureStore,
  __resetSecureStoreConfig,
  defineStore,
  defineAggregation,
  invalidateChannel,
  fingerprintSchema,
  type StorageAdapter,
  type CacheAdapter,
  type BlobRecord,
  type CryptoHandle,
  type KeyProvider,
} from "../index.ts";
import { useAggregation } from "../react/useAggregation.ts";

/**
 * Same shape as `aggregation.test.ts`'s `memoryAdapter` (one adapter instance backs both
 * source stores AND the aggregation's own internal table), plus a per-collection `get()`
 * counter — Task 4's scenario 3 needs to assert ZERO reads of the SOURCE's own collection,
 * not just "the returned value is correct".
 */
function memoryAdapter(): StorageAdapter & {
  rows: Map<string, BlobRecord>;
  putCallsFor: (collection: string) => number;
  getCallsFor: (collection: string) => number;
  resetCounts: () => void;
} {
  const rows = new Map<string, BlobRecord>();
  const putCallsByCollection = new Map<string, number>();
  const getCallsByCollection = new Map<string, number>();
  const rowKey = (
    collection: string,
    userId: string,
    extraKeys: { column: string; value: string }[],
  ) => `${collection}:${userId}:${extraKeys[0]?.value ?? ""}`;

  return {
    rows,
    putCallsFor: (collection) => putCallsByCollection.get(collection) ?? 0,
    getCallsFor: (collection) => getCallsByCollection.get(collection) ?? 0,
    resetCounts: () => {
      putCallsByCollection.clear();
      getCallsByCollection.clear();
    },
    async get(collection, userId, extraKeys) {
      getCallsByCollection.set(
        collection,
        (getCallsByCollection.get(collection) ?? 0) + 1,
      );
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

/** Real subscribable in-memory CacheAdapter — same fixture as `useStore.test.tsx` and
 * `aggregation.test.ts`'s own `memoryCache`. */
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

function fakeKeys(initial: CryptoHandle | null) {
  let cryptoHandle = initial;
  const subs = new Set<() => void>();
  const provider: KeyProvider = {
    getCryptoHandle: () => cryptoHandle,
    getUserId: () => (cryptoHandle ? "u1" : null),
    subscribe(cb) {
      subs.add(cb);
      return () => subs.delete(cb);
    },
  };
  return {
    provider,
    setDek(next: CryptoHandle | null) {
      cryptoHandle = next;
      for (const cb of subs) cb();
    },
  };
}

function settle(ms = 50): Promise<void> {
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

describe("useAggregation", () => {
  afterEach(() => {
    cleanup();
    __resetSecureStoreConfig();
  });

  it("scenario 3: fingerprint match on mount — no recompute, no fetch of the source's own blob", async () => {
    const storage = memoryAdapter();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    const cache = memoryCache();
    configureSecureStore({ storage, keys: provider, cache });

    const source = makeSource("s3_source");
    await source.set({ value: 10 }); // ambient write -> populates the source's cache slot

    let computeCalls = 0;
    const agg = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "s3_agg", key: "__agg__" },
      sources: { src: source },
      compute: ({ sources }) => {
        computeCalls++;
        return { total: sources.src.value * 2 };
      },
    });

    // Seed the persisted value via refresh() (never subscribes) — mirrors "the app was
    // already using this aggregate in a previous session", not this hook's own doing.
    await agg.refresh();
    expect(computeCalls).toBe(1);

    // Reset counters AFTER the seed: from here on, mounting the hook must not read the
    // source's own collection again — that's the whole point of this scenario.
    storage.resetCounts();

    const { result } = renderHook(() => useAggregation(agg));
    await waitFor(() => expect(result.current.computing).toBe(false));

    expect(result.current.data).toEqual({ total: 20 });
    expect(result.current.stale).toBe(false);
    expect(result.current.error).toBeNull();
    expect(computeCalls).toBe(1); // no recompute triggered by mounting
    expect(storage.getCallsFor("s3_source")).toBe(0); // the explicit assertion this scenario is about: the source blob is never fetched
  });

  it("scenario 4: fingerprint mismatch on mount — serves the stale persisted value immediately while recomputing, then swaps atomically", async () => {
    const storage = memoryAdapter();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    const cache = memoryCache();
    configureSecureStore({ storage, keys: provider, cache });

    const source = makeSource("s4_source");
    await source.set({ value: 1 });

    let releaseCompute!: () => void;
    const gate = new Promise<void>((resolve) => {
      releaseCompute = resolve;
    });
    let computeCalls = 0;
    const agg = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "s4_agg", key: "__agg__" },
      sources: { src: source },
      compute: async ({ sources }) => {
        computeCalls++;
        if (computeCalls === 2) await gate; // only the recompute (2nd call) is gated
        return { total: sources.src.value * 10 };
      },
    });

    await agg.refresh(); // seed: { total: 10 }
    expect(computeCalls).toBe(1);

    await source.set({ value: 2 }); // fingerprint mismatch relative to the persisted envelope

    const seen: unknown[] = [];
    const { result } = renderHook(() => {
      const r = useAggregation(agg);
      seen.push(r.data);
      return r;
    });

    // Synchronize on the mount's OWN recompute actually starting — `computeCalls` only
    // increments when the mocked `compute()` itself runs, which (per `computeAndPersist`)
    // can only happen strictly AFTER `triggerRecompute()` has already synchronously
    // published `computing: true`/`stale: true` (for this SAME `lastEnvelope` snapshot) to
    // the react-state cache slot. Waiting on `result.current.data` here instead would be
    // racy: the seed's OWN `refresh()` call above (before mount) already published
    // `{ data: { total: 10 }, computing: false, stale: false }` to the exact same cache
    // slot the hook reads on its very first render, so a `waitFor` on `data` alone can be
    // satisfied by that PRE-EXISTING snapshot before the mount's effect has done any work
    // at all — a real, reproduced flake, see task-4-report.md's addendum.
    await waitFor(() => expect(computeCalls).toBe(2));
    expect(result.current.data).toEqual({ total: 10 });
    expect(result.current.stale).toBe(true);
    expect(result.current.computing).toBe(true); // recompute already kicked off in the background

    releaseCompute();

    await waitFor(() => expect(result.current.data).toEqual({ total: 20 }));
    expect(result.current.stale).toBe(false);
    expect(result.current.computing).toBe(false);
    expect(result.current.error).toBeNull();

    // No intermediate/partial state ever observed — every render's `data` is either the
    // OLD full value, the NEW full value, or `null` (before hydration) — never a mix.
    const allowed = [null, { total: 10 }, { total: 20 }].map((v) =>
      JSON.stringify(v),
    );
    for (const value of seen) {
      expect(allowed).toContain(JSON.stringify(value));
    }
  });

  it("scenario 5: a lock while a compute is in flight must not persist or re-publish that compute's result", async () => {
    const storage = memoryAdapter();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider, setDek } = fakeKeys(cryptoHandle);
    const cache = memoryCache();
    configureSecureStore({ storage, keys: provider, cache });

    const source = makeSource("s5_source");
    await source.set({ value: 1 });

    let releaseCompute!: () => void;
    const gate = new Promise<void>((resolve) => {
      releaseCompute = resolve;
    });
    let computeCalls = 0;
    const agg = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "s5_agg", key: "__agg__" },
      sources: { src: source },
      compute: async ({ sources }) => {
        computeCalls++;
        if (computeCalls === 2) await gate;
        return { total: sources.src.value * 10 };
      },
    });

    await agg.refresh(); // seed
    expect(storage.putCallsFor("s5_agg")).toBe(1);

    await source.set({ value: 2 }); // will trigger a (gated) recompute once mounted

    const { result } = renderHook(() => useAggregation(agg));
    await waitFor(() => expect(result.current.computing).toBe(true));
    expect(computeCalls).toBe(2); // the gated recompute has started

    act(() => setDek(null)); // lock WHILE the gated compute is in flight
    expect(result.current.data).toBeNull(); // hook now shows the locked defaults

    releaseCompute();
    await settle(); // let the gated compute actually finish in the background

    expect(storage.putCallsFor("s5_agg")).toBe(1); // still just the seed — never persisted
    expect(cache.get(`s5_agg:__agg__:u1`)).toBeUndefined(); // downstream fingerprint slot never resurrected
    expect(cache.get(`s5_agg:__agg__:react:u1`)).toBeUndefined(); // react-state slot never resurrected either
    expect(result.current.data).toBeNull(); // still locked, still nothing shown
  });

  it("scenario 6: an expired external TTL triggers a recompute even when source fingerprints are unchanged", async () => {
    const storage = memoryAdapter();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    const cache = memoryCache();
    configureSecureStore({ storage, keys: provider, cache });

    const source = makeSource("s6_source");
    await source.set({ value: 5 });

    let releaseCompute!: () => void;
    const gate = new Promise<void>((resolve) => {
      releaseCompute = resolve;
    });
    let computeCalls = 0;
    let externalLoads = 0;
    const agg = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "s6_agg", key: "__agg__" },
      sources: { src: source },
      externals: {
        rate: {
          load: async () => {
            externalLoads++;
            return 2;
          },
          ttlMs: 10,
        },
      },
      compute: async ({ sources, externals }) => {
        computeCalls++;
        if (computeCalls === 2) await gate; // only the recompute (2nd call) is gated
        return { total: sources.src.value * externals.rate };
      },
    });

    await agg.refresh(); // seed: total=10, computeCalls=1, externalLoads=1
    expect(computeCalls).toBe(1);
    expect(externalLoads).toBe(1);

    await settle(30); // TTL (10ms) is definitely expired by now — source unchanged

    const { result } = renderHook(() => useAggregation(agg));

    // Synchronize on the mount's OWN recompute actually starting, same reasoning as
    // scenario 4 above: the seed's `refresh()` (before mount) already published
    // `{ computing: false, data: { total: 10 } }` to the SAME react-state cache slot the
    // hook reads on its very first render, so a `waitFor` on `result.current.computing`
    // being `false` can be satisfied by that PRE-EXISTING snapshot before the mount's
    // effect has done any work — a real, reproduced flake (`expected 1 to be 2` on
    // `computeCalls`), see task-4-report.md's addendum. Gating the 2nd compute call lets
    // us assert the intermediate "recompute genuinely in flight" state deterministically
    // (compute() cannot resolve until we release it), instead of racing two independent
    // promise chains against each other.
    await waitFor(() => expect(computeCalls).toBe(2));
    expect(result.current.computing).toBe(true); // the mount's recompute is definitely in flight (gated, hasn't resolved yet)
    expect(externalLoads).toBe(2); // externals are re-fetched BEFORE compute() runs (see computeAndPersist) — already true here

    releaseCompute();

    await waitFor(() => expect(result.current.computing).toBe(false));
    expect(result.current.data).toEqual({ total: 10 }); // same source value -> same total
    expect(result.current.error).toBeNull();
  });

  it("review finding: dedupes concurrent reads of the same aggregation's envelope across independent hook instances (regression: two mounted useAggregation(sameAgg) components must share ONE storage read, not one each)", async () => {
    const storage = memoryAdapter();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    const cache = memoryCache();
    configureSecureStore({ storage, keys: provider, cache });

    const source = makeSource("dedup_source");
    await source.set({ value: 5 });

    const agg = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "dedup_agg", key: "__agg__" },
      sources: { src: source },
      compute: ({ sources }) => ({ total: sources.src.value }),
    });

    await agg.refresh(); // seed — fresh relative to the (unchanged) source afterwards
    storage.resetCounts();

    // Two independent components mounting the SAME aggregation at once — each runs its
    // own effect -> own agg.get() call.
    const first = renderHook(() => useAggregation(agg));
    const second = renderHook(() => useAggregation(agg));

    await waitFor(() => expect(first.result.current.computing).toBe(false));
    await waitFor(() => expect(second.result.current.computing).toBe(false));

    expect(first.result.current.data).toEqual({ total: 5 });
    expect(second.result.current.data).toEqual({ total: 5 });
    // The explicit assertion this finding is about: only ONE real read of the
    // aggregation's own persisted envelope, not one per mounted hook instance.
    expect(storage.getCallsFor("dedup_agg")).toBe(1);
  });

  it("respects the lock from mount: never calls get(), shows the locked defaults, refresh() throws", async () => {
    const storage = memoryAdapter();
    const { provider } = fakeKeys(null);
    const cache = memoryCache();
    configureSecureStore({ storage, keys: provider, cache });

    const source = makeSource("locked_source");
    const agg = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "locked_agg", key: "__agg__" },
      sources: { src: source },
      compute: ({ sources }) => ({ total: sources.src.value }),
    });

    const { result } = renderHook(() => useAggregation(agg));

    expect(result.current.data).toBeNull();
    expect(result.current.computing).toBe(false);
    expect(result.current.stale).toBe(true);
    expect(result.current.error).toBeNull();
    expect(() => result.current.refresh()).toThrow(/locked/);

    await settle(20); // give any errant background effect a chance to run
    expect(storage.getCallsFor("locked_agg")).toBe(0);
    expect(storage.getCallsFor("locked_source")).toBe(0);
  });

  it("bugfix regression: a source write landing WHILE an invalidateChannel-triggered recompute is still awaiting its external must still reach the RENDERED hook value, not just the persisted envelope", async () => {
    // Same production bug as `aggregation.test.ts`'s core-level regression test, but
    // exercised through the actual React binding: `zechinus/core/aggregation.ts`'s
    // `computeAndPersist()` was already proven correct at the pure-framework level —
    // this isolates whether the gap is instead in how `useAggregation` republishes
    // (or fails to republish) the converged value to a mounted component.
    const storage = memoryAdapter();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    const cache = memoryCache();
    configureSecureStore({ storage, keys: provider, cache });

    const BalancesSchema = z.object({
      balances: z.record(z.string(), z.number()).default({}),
    });
    const source = defineStore({
      name: "hook_race_source",
      encrypt: "all",
      schema: BalancesSchema,
      version: 1,
      contentHash: true,
      schemaFingerprint: fingerprintSchema(BalancesSchema, "all"),
    });
    await source.set({ balances: { acc1: 100 } });

    let existingIds = ["acc1"];
    let externalFetchCalls = 0;
    let releaseSecondFetch!: () => void;
    const secondFetchGate = new Promise<void>((resolve) => {
      releaseSecondFetch = resolve;
    });

    const agg = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "hook_race_agg", key: "__agg__" },
      debounceMs: 20,
      sources: { bal: source },
      externals: {
        ids: {
          load: async () => {
            externalFetchCalls++;
            if (externalFetchCalls === 2) await secondFetchGate;
            return existingIds;
          },
          ttlMs: 10 * 60 * 1000,
          invalidateOn: ["hook-race-test"],
        },
      },
      compute: ({ sources, externals }) => {
        const idSet = new Set(externals.ids);
        let total = 0;
        for (const [id, balance] of Object.entries(sources.bal.balances)) {
          if (idSet.has(id)) total += balance;
        }
        return { total };
      },
    });

    await agg.refresh(); // seed: { total: 100 }
    expect(externalFetchCalls).toBe(1);

    const { result } = renderHook(() => useAggregation(agg));
    await waitFor(() => expect(result.current.data).toEqual({ total: 100 }));

    // "Account created": the new account already exists server-side by the time
    // invalidateChannel fires.
    existingIds = ["acc1", "acc2"];
    invalidateChannel("hook-race-test");
    await waitFor(() => expect(externalFetchCalls).toBe(2));

    // "Import lands while account creation's own recompute is still in flight": an
    // ordinary source write.
    await source.mutate((current) => ({
      balances: { ...current.balances, acc2: 50 },
    }));

    // Let the channel-triggered recompute (and its queued rerun) finish.
    releaseSecondFetch();

    await waitFor(() => expect(result.current.data).toEqual({ total: 150 }), {
      timeout: 3000,
    });
    expect(result.current.stale).toBe(false);
    expect(result.current.computing).toBe(false);
    expect(result.current.error).toBeNull();
  });
});
