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
});
