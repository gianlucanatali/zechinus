/**
 * Tests the React binding (`useStore`). Needs jsdom + React rendering — runs under
 * Vitest (`npm run test:components`), unlike the rest of datacloak/'s tests which
 * run under plain `node --test` (see config/vitest.config.ts).
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
import { useStore } from "../react/useStore.ts";
import { OptimisticLockConflictError } from "../react/errors.ts";

function memoryStorage(): StorageAdapter & { rows: Map<string, BlobRecord> } {
  const rows = new Map<string, BlobRecord>();
  return {
    rows,
    async get(collection, userId) {
      return rows.get(`${collection}:${userId}`) ?? null;
    },
    async put(collection, userId, _extraKeys, record) {
      rows.set(`${collection}:${userId}`, record);
    },
  };
}

function conditionalMemoryStorage(): StorageAdapter & {
  rows: Map<string, BlobRecord>;
} {
  const rows = new Map<string, BlobRecord>();
  return {
    rows,
    async get(collection, userId) {
      return rows.get(`${collection}:${userId}`) ?? null;
    },
    async put(collection, userId, _extraKeys, record) {
      rows.set(`${collection}:${userId}`, record);
    },
    async putIfMatch(collection, userId, _extraKeys, record, expectedHash) {
      const key = `${collection}:${userId}`;
      const current = rows.get(key) ?? null;
      if (expectedHash === null) {
        if (current) return false;
        rows.set(key, record);
        return true;
      }
      if (!current || current.contentHash !== expectedHash) return false;
      rows.set(key, record);
      return true;
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

const Portfolio = z.object({ positions: z.array(z.string()).default([]) });

describe("useStore", () => {
  afterEach(() => {
    cleanup();
    __resetSecureStoreConfig();
  });

  it("locked (no cryptoHandle): returns no data, not loading, locked:true; save() throws", async () => {
    const storage = memoryStorage();
    const { provider } = fakeKeys(null);
    const cache = memoryCache();
    configureSecureStore({ storage, keys: provider, cache });

    const store = defineStore({
      name: "portfolio_blobs",
      encrypt: "all",
      schema: Portfolio,
      version: 1,
      schemaFingerprint: fingerprintSchema(Portfolio, "all"),
    });

    const { result } = renderHook(() => useStore(store));

    expect(result.current.data).toBeUndefined();
    expect(result.current.loading).toBe(false);
    expect(result.current.locked).toBe(true);
    await expect(result.current.save({ positions: ["x"] })).rejects.toThrow(
      /locked/,
    );
  });

  it("unlocked, nothing saved yet: loads via store.load(), populates data, loading flips to false", async () => {
    const storage = memoryStorage();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    const cache = memoryCache();
    configureSecureStore({ storage, keys: provider, cache });

    const store = defineStore({
      name: "portfolio_blobs",
      encrypt: "all",
      schema: Portfolio,
      version: 1,
      schemaFingerprint: fingerprintSchema(Portfolio, "all"),
    });

    const { result } = renderHook(() => useStore(store));

    expect(result.current.locked).toBe(false);
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.data).toEqual({ positions: [] });
  });

  it("save(): optimistic update immediately, then persists to storage", async () => {
    const storage = memoryStorage();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    const cache = memoryCache();
    configureSecureStore({ storage, keys: provider, cache });

    const store = defineStore({
      name: "portfolio_blobs",
      encrypt: "all",
      schema: Portfolio,
      version: 1,
      schemaFingerprint: fingerprintSchema(Portfolio, "all"),
    });

    const { result } = renderHook(() => useStore(store));
    await waitFor(() => expect(result.current.loading).toBe(false));

    await act(async () => {
      await result.current.save({ positions: ["AAPL"] });
    });

    expect(result.current.data).toEqual({ positions: ["AAPL"] });
    const raw = storage.rows.get("portfolio_blobs:u1");
    expect(raw?.blob.startsWith("enc:")).toBe(true);
  });

  it("save(): rolls back the optimistic value if the underlying store.save() rejects", async () => {
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    const cache = memoryCache();
    const failingStorage: StorageAdapter = {
      async get() {
        return null;
      },
      async put() {
        throw new Error("simulated write failure");
      },
    };
    configureSecureStore({ storage: failingStorage, keys: provider, cache });

    const store = defineStore({
      name: "portfolio_blobs",
      encrypt: "all",
      schema: Portfolio,
      version: 1,
      schemaFingerprint: fingerprintSchema(Portfolio, "all"),
    });

    const { result } = renderHook(() => useStore(store));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.data).toEqual({ positions: [] });

    await act(async () => {
      await expect(
        result.current.save({ positions: ["will-fail"] }),
      ).rejects.toThrow(/simulated write failure/);
    });

    expect(result.current.data).toEqual({ positions: [] });
  });

  it("lock (cryptoHandle → null) after being unlocked: cache clears, hook reflects locked state", async () => {
    const storage = memoryStorage();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider, setDek } = fakeKeys(cryptoHandle);
    const cache = memoryCache();
    configureSecureStore({ storage, keys: provider, cache });

    const store = defineStore({
      name: "portfolio_blobs",
      encrypt: "all",
      schema: Portfolio,
      version: 1,
      schemaFingerprint: fingerprintSchema(Portfolio, "all"),
    });

    const { result } = renderHook(() => useStore(store));
    await waitFor(() => expect(result.current.loading).toBe(false));

    act(() => {
      setDek(null);
    });

    expect(result.current.locked).toBe(true);
    expect(result.current.data).toBeUndefined();
  });

  it("optimisticLock: save() threads the hash automatically — caller never passes one", async () => {
    const storage = conditionalMemoryStorage();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    const cache = memoryCache();
    configureSecureStore({ storage, keys: provider, cache });

    const store = defineStore({
      name: "portfolio_blobs",
      encrypt: "all",
      schema: Portfolio,
      version: 1,
      schemaFingerprint: fingerprintSchema(Portfolio, "all"),
      contentHash: true,
      optimisticLock: true,
    });

    const { result } = renderHook(() => useStore(store));
    await waitFor(() => expect(result.current.loading).toBe(false));

    await act(async () => {
      await result.current.save({ positions: ["AAPL"] });
    });
    expect(result.current.data).toEqual({ positions: ["AAPL"] });

    // A second save with no manual hash handling must still succeed — the hook
    // already knows the hash from the first save's result.
    await act(async () => {
      await result.current.save({ positions: ["AAPL", "MSFT"] });
    });
    expect(result.current.data).toEqual({ positions: ["AAPL", "MSFT"] });
  });

  it("optimisticLock: a conflicting concurrent write makes the next save() throw OptimisticLockConflictError and roll back", async () => {
    const storage = conditionalMemoryStorage();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    const cache = memoryCache();
    configureSecureStore({ storage, keys: provider, cache });

    const store = defineStore({
      name: "portfolio_blobs",
      encrypt: "all",
      schema: Portfolio,
      version: 1,
      schemaFingerprint: fingerprintSchema(Portfolio, "all"),
      contentHash: true,
      optimisticLock: true,
    });

    const { result } = renderHook(() => useStore(store));
    await waitFor(() => expect(result.current.loading).toBe(false));

    await act(async () => {
      await result.current.save({ positions: ["AAPL"] });
    });

    // A "concurrent tab" writes directly through the store, bypassing this hook's cache.
    const { hash } = await store.loadWithHash!("u1", cryptoHandle);
    await store.saveIfMatch!(
      "u1",
      cryptoHandle,
      { positions: ["concurrent-write"] },
      hash,
    );

    await act(async () => {
      await expect(
        result.current.save({ positions: ["mine"] }),
      ).rejects.toThrow(OptimisticLockConflictError);
    });

    // Rolled back to what the hook believed was current, not silently overwritten.
    expect(result.current.data).toEqual({ positions: ["AAPL"] });
  });

  it("reload(): picks up a write that happened OUTSIDE this hook's save() (e.g. a backend endpoint writing directly, no ambient mutate() in this tab)", async () => {
    const storage = memoryStorage();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    configureSecureStore({ storage, keys: provider, cache: memoryCache() });
    const store = defineStore({
      name: "portfolio_blobs",
      identity: "perUser",
      encrypt: "all",
      schema: Portfolio,
      version: 1,
      schemaFingerprint: fingerprintSchema(Portfolio, "all"),
    });

    const { result } = renderHook(() => useStore(store));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.data).toEqual({ positions: [] });

    // Out-of-band write: goes straight through store.save(), never through this
    // hook's cache-aware save() — simulates a backend endpoint persisting directly.
    await store.save("u1", cryptoHandle, { positions: ["out-of-band"] });
    expect(result.current.data).toEqual({ positions: [] }); // still stale

    await act(async () => {
      await result.current.reload();
    });

    expect(result.current.data).toEqual({ positions: ["out-of-band"] });
  });
});
