/**
 * Same infra as useKeyedStore.test.tsx — needs jsdom, runs under Vitest.
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
  fingerprintSchema,
  type CryptoHandle,
  type StorageAdapter,
  type BlobRecord,
  type KeyProvider,
  type CacheAdapter,
} from "../index.ts";
import { useKeyedStoreRange } from "../react/useKeyedStoreRange.ts";
import { __resetGlobalKeyedStoreActivity } from "../react/keyedStoreActivity.ts";

function rangeMemoryStorage(): StorageAdapter & {
  rows: Map<string, BlobRecord>;
} {
  const rows = new Map<string, BlobRecord>();
  const rowKey = (collection: string, userId: string, key: string) =>
    `${collection}:${userId}:${key}`;
  return {
    rows,
    async get(collection, userId, extraKeys) {
      return (
        rows.get(rowKey(collection, userId, extraKeys[0]?.value ?? "")) ?? null
      );
    },
    async put(collection, userId, extraKeys, record) {
      rows.set(rowKey(collection, userId, extraKeys[0]?.value ?? ""), record);
    },
    async listByKeyRange(collection, userId, _keyColumn, from, to) {
      const prefix = `${collection}:${userId}:`;
      const results: Array<{ key: string; record: BlobRecord }> = [];
      for (const [k, record] of rows.entries()) {
        if (!k.startsWith(prefix)) continue;
        const key = k.slice(prefix.length);
        if (key >= from && key <= to) results.push({ key, record });
      }
      return results.sort((a, b) => a.key.localeCompare(b.key));
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

const Batch = z.object({ count: z.number().default(0) });

describe("useKeyedStoreRange", () => {
  afterEach(() => {
    cleanup();
    __resetSecureStoreConfig();
    __resetGlobalKeyedStoreActivity();
  });

  it("locked: no data, locked:true", () => {
    const { provider } = fakeKeys(null);
    configureSecureStore({
      storage: rangeMemoryStorage(),
      keys: provider,
      cache: memoryCache(),
    });
    const store = defineStore({
      name: "range_locked",
      identity: { perKey: "year_month" },
      encrypt: "all",
      schema: Batch,
      version: 1,
      schemaFingerprint: fingerprintSchema(Batch, "all"),
    });

    const { result } = renderHook(() =>
      useKeyedStoreRange(store, { from: "2026-01", to: "2026-12" }),
    );

    expect(result.current.data).toBeUndefined();
    expect(result.current.locked).toBe(true);
  });

  it("loads a range of keys, aggregated correctly", async () => {
    const storage = rangeMemoryStorage();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    configureSecureStore({ storage, keys: provider, cache: memoryCache() });
    const store = defineStore({
      name: "range_basic",
      identity: { perKey: "year_month" },
      encrypt: "all",
      schema: Batch,
      version: 1,
      schemaFingerprint: fingerprintSchema(Batch, "all"),
    });

    await store.save("u1", cryptoHandle, "2026-01", { count: 1 });
    await store.save("u1", cryptoHandle, "2026-02", { count: 2 });
    await store.save("u1", cryptoHandle, "2026-06", { count: 6 });
    // outside the queried range — must NOT appear in the result
    await store.save("u1", cryptoHandle, "2027-01", { count: 99 });

    const { result } = renderHook(() =>
      useKeyedStoreRange(store, { from: "2026-01", to: "2026-12" }),
    );

    await waitFor(() => expect(result.current.loading).toBe(false));

    expect(result.current.data).toEqual([
      { key: "2026-01", data: { count: 1 } },
      { key: "2026-02", data: { count: 2 } },
      { key: "2026-06", data: { count: 6 } },
    ]);
  });

  it("cache reflects an ambient mutate() on one key of the range, without remounting", async () => {
    const storage = rangeMemoryStorage();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    configureSecureStore({ storage, keys: provider, cache: memoryCache() });
    const store = defineStore({
      name: "range_ambient_write",
      identity: { perKey: "year_month" },
      encrypt: "all",
      schema: Batch,
      version: 1,
      schemaFingerprint: fingerprintSchema(Batch, "all"),
    });

    await store.save("u1", cryptoHandle, "2026-03", { count: 3 });

    const { result } = renderHook(() =>
      useKeyedStoreRange(store, { from: "2026-01", to: "2026-12" }),
    );
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.data).toEqual([
      { key: "2026-03", data: { count: 3 } },
    ]);

    // ambient write on a NEW key inside the same range — simulates a service
    // (e.g. upsertTransaction) calling store.mutate() directly, outside any hook.
    await act(async () => {
      await store.mutate("2026-04", (current) => ({
        count: current.count + 4,
      }));
    });

    await waitFor(() =>
      expect(result.current.data).toEqual([
        { key: "2026-03", data: { count: 3 } },
        { key: "2026-04", data: { count: 4 } },
      ]),
    );
  });

  it("an ambient write OUTSIDE the range still triggers a refetch (epoch is per-store, not per-range) but the result is unchanged", async () => {
    const storage = rangeMemoryStorage();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    configureSecureStore({ storage, keys: provider, cache: memoryCache() });
    const store = defineStore({
      name: "range_outside_write",
      identity: { perKey: "year_month" },
      encrypt: "all",
      schema: Batch,
      version: 1,
      schemaFingerprint: fingerprintSchema(Batch, "all"),
    });

    await store.save("u1", cryptoHandle, "2026-05", { count: 5 });

    const { result } = renderHook(() =>
      useKeyedStoreRange(store, { from: "2026-01", to: "2026-06" }),
    );
    await waitFor(() => expect(result.current.loading).toBe(false));

    await act(async () => {
      await store.mutate("2099-01", (current) => ({
        count: current.count + 1,
      }));
    });

    await waitFor(() =>
      expect(result.current.data).toEqual([
        { key: "2026-05", data: { count: 5 } },
      ]),
    );
  });

  it("dedupes concurrent fetches for the SAME range across independent hook instances (regression: two components mounting together must share ONE fetch, not one each)", async () => {
    const storage = rangeMemoryStorage();
    let listCalls = 0;
    const countingStorage: StorageAdapter = {
      ...storage,
      listByKeyRange: (...args) => {
        listCalls++;
        return storage.listByKeyRange!(...args);
      },
    };
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    configureSecureStore({
      storage: countingStorage,
      keys: provider,
      cache: memoryCache(),
    });
    const store = defineStore({
      name: "range_concurrent_mount",
      identity: { perKey: "year_month" },
      encrypt: "all",
      schema: Batch,
      version: 1,
      schemaFingerprint: fingerprintSchema(Batch, "all"),
    });

    await store.save("u1", cryptoHandle, "2026-01", { count: 1 });

    // Two independent components mounting the SAME range at the same time —
    // e.g. AccountsRegister + a summary panel both querying the same months.
    const first = renderHook(() =>
      useKeyedStoreRange(store, { from: "2026-01", to: "2026-01" }),
    );
    const second = renderHook(() =>
      useKeyedStoreRange(store, { from: "2026-01", to: "2026-01" }),
    );

    await waitFor(() => expect(first.result.current.loading).toBe(false));
    await waitFor(() => expect(second.result.current.loading).toBe(false));

    expect(listCalls).toBe(1);
    expect(first.result.current.data).toEqual([
      { key: "2026-01", data: { count: 1 } },
    ]);
    expect(second.result.current.data).toEqual(first.result.current.data);
  });

  it("reload() forces a fresh fetch even when the cached epoch already matches (no natural refetch would fire)", async () => {
    const storage = rangeMemoryStorage();
    let listCalls = 0;
    const countingStorage: StorageAdapter = {
      ...storage,
      listByKeyRange: (...args) => {
        listCalls++;
        return storage.listByKeyRange!(...args);
      },
    };
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    configureSecureStore({
      storage: countingStorage,
      keys: provider,
      cache: memoryCache(),
    });
    const store = defineStore({
      name: "range_reload",
      identity: { perKey: "year_month" },
      encrypt: "all",
      schema: Batch,
      version: 1,
      schemaFingerprint: fingerprintSchema(Batch, "all"),
    });

    await store.save("u1", cryptoHandle, "2026-01", { count: 1 });

    const { result } = renderHook(() =>
      useKeyedStoreRange(store, { from: "2026-01", to: "2026-01" }),
    );
    await waitFor(() => expect(result.current.loading).toBe(false));
    const callsAfterInitialLoad = listCalls;
    expect(result.current.data).toEqual([
      { key: "2026-01", data: { count: 1 } },
    ]);

    // No write happened — the cached epoch still matches. A natural re-render
    // would NOT trigger a refetch (the whole point of the epoch-match skip).
    // reload() must fetch anyway.
    await act(async () => {
      await result.current.reload();
    });

    expect(listCalls).toBe(callsAfterInitialLoad + 1);
  });

  it("isPlaceholderData: switching to a new range keeps the old data visible while the new one loads", async () => {
    const storage = rangeMemoryStorage();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    configureSecureStore({ storage, keys: provider, cache: memoryCache() });
    const store = defineStore({
      name: "range_placeholder",
      identity: { perKey: "year_month" },
      encrypt: "all",
      schema: Batch,
      version: 1,
      schemaFingerprint: fingerprintSchema(Batch, "all"),
    });

    await store.save("u1", cryptoHandle, "2026-06", { count: 6 });
    await store.save("u1", cryptoHandle, "2026-01", { count: 1 });

    const { result, rerender } = renderHook(
      ({ range }) => useKeyedStoreRange(store, range),
      { initialProps: { range: { from: "2026-06", to: "2026-06" } } },
    );
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.data).toEqual([
      { key: "2026-06", data: { count: 6 } },
    ]);
    expect(result.current.isPlaceholderData).toBe(false);

    // Widen the range backward — a DIFFERENT cache slot, not yet fetched.
    rerender({ range: { from: "2026-01", to: "2026-06" } });

    // The old range's data is shown immediately as a placeholder — never a
    // loading flash — while the new range resolves in the background.
    expect(result.current.data).toEqual([
      { key: "2026-06", data: { count: 6 } },
    ]);
    expect(result.current.isPlaceholderData).toBe(true);
    expect(result.current.loading).toBe(false);

    await waitFor(() =>
      expect(result.current.data).toEqual([
        { key: "2026-01", data: { count: 1 } },
        { key: "2026-06", data: { count: 6 } },
      ]),
    );
    expect(result.current.isPlaceholderData).toBe(false);
  });

  it("isPlaceholderData/data never survive a lock — no stale decrypted content after DEK clears", async () => {
    const storage = rangeMemoryStorage();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider, setDek } = fakeKeys(cryptoHandle);
    configureSecureStore({ storage, keys: provider, cache: memoryCache() });
    const store = defineStore({
      name: "range_lock_wipe",
      identity: { perKey: "year_month" },
      encrypt: "all",
      schema: Batch,
      version: 1,
      schemaFingerprint: fingerprintSchema(Batch, "all"),
    });

    await store.save("u1", cryptoHandle, "2026-02", { count: 2 });

    const { result } = renderHook(() =>
      useKeyedStoreRange(store, { from: "2026-01", to: "2026-12" }),
    );
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.data).toEqual([
      { key: "2026-02", data: { count: 2 } },
    ]);

    act(() => setDek(null));

    expect(result.current.locked).toBe(true);
    expect(result.current.data).toBeUndefined();
    expect(result.current.isPlaceholderData).toBe(false);
  });

  it("reload(): a lock that happens WHILE the fetch is in flight must not repopulate the cache with stale decrypted data", async () => {
    const base = rangeMemoryStorage();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider, setDek } = fakeKeys(cryptoHandle);
    const cache = memoryCache();

    let listCalls = 0;
    let releaseSecondList!: () => void;
    const secondGate = new Promise<void>((resolve) => {
      releaseSecondList = resolve;
    });
    const gatedStorage: StorageAdapter = {
      ...base,
      async listByKeyRange(...args) {
        listCalls++;
        if (listCalls === 2) await secondGate;
        return base.listByKeyRange!(...args);
      },
    };
    configureSecureStore({ storage: gatedStorage, keys: provider, cache });

    const store = defineStore({
      name: "range_reload_lock",
      identity: { perKey: "year_month" },
      encrypt: "all",
      schema: Batch,
      version: 1,
      schemaFingerprint: fingerprintSchema(Batch, "all"),
    });

    await store.save("u1", cryptoHandle, "2026-01", { count: 1 });

    const { result } = renderHook(() =>
      useKeyedStoreRange(store, { from: "2026-01", to: "2026-01" }),
    );
    await waitFor(() => expect(result.current.loading).toBe(false));

    const reloadPromise = result.current.reload(); // fetch #2 now in flight, gated

    act(() => setDek(null)); // lock happens WHILE the fetch is pending
    expect(result.current.locked).toBe(true);

    releaseSecondList();
    await act(async () => {
      await reloadPromise;
    });

    expect(
      cache.get(`range_reload_lock:u1:range:2026-01:2026-01`),
    ).toBeUndefined();
    expect(result.current.data).toBeUndefined();
  });

  it("a range fetch registers with the shared isAnyKeyedStoreLoading() signal (same registry useKeyedStore uses)", async () => {
    const { isAnyKeyedStoreLoading } =
      await import("../react/keyedStoreActivity.ts");
    expect(isAnyKeyedStoreLoading()).toBe(false);

    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    let releaseList!: () => void;
    const gate = new Promise<void>((resolve) => {
      releaseList = resolve;
    });
    const storage: StorageAdapter = {
      async get() {
        return null;
      },
      async put() {},
      async listByKeyRange() {
        await gate;
        return [];
      },
    };
    configureSecureStore({ storage, keys: provider, cache: memoryCache() });
    const store = defineStore({
      name: "range_activity_signal",
      identity: { perKey: "year_month" },
      encrypt: "all",
      schema: Batch,
      version: 1,
      schemaFingerprint: fingerprintSchema(Batch, "all"),
    });

    const { result } = renderHook(() =>
      useKeyedStoreRange(store, { from: "2026-01", to: "2026-01" }),
    );
    expect(result.current.loading).toBe(true);
    await waitFor(() => expect(isAnyKeyedStoreLoading()).toBe(true));

    releaseList();
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(isAnyKeyedStoreLoading()).toBe(false);
  });
});
