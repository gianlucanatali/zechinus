/**
 * Same infra as useStore.test.tsx — needs jsdom, runs under Vitest.
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
import { useKeyedStore } from "../react/useKeyedStore.ts";
import { OptimisticLockConflictError } from "../react/errors.ts";

function keyedMemoryStorage(): StorageAdapter & {
  rows: Map<string, BlobRecord>;
} {
  const rows = new Map<string, BlobRecord>();
  return {
    rows,
    async get(collection, userId, extraKeys) {
      return rows.get(`${collection}:${userId}:${extraKeys[0]?.value}`) ?? null;
    },
    async put(collection, userId, extraKeys, record) {
      rows.set(`${collection}:${userId}:${extraKeys[0]?.value}`, record);
    },
  };
}

function conditionalKeyedStorage(): StorageAdapter & {
  rows: Map<string, BlobRecord>;
} {
  const rows = new Map<string, BlobRecord>();
  return {
    rows,
    async get(collection, userId, extraKeys) {
      return rows.get(`${collection}:${userId}:${extraKeys[0]?.value}`) ?? null;
    },
    async put(collection, userId, extraKeys, record) {
      rows.set(`${collection}:${userId}:${extraKeys[0]?.value}`, record);
    },
    async putIfMatch(collection, userId, extraKeys, record, expectedHash) {
      const key = `${collection}:${userId}:${extraKeys[0]?.value}`;
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

const Batch = z.object({ transactions: z.array(z.string()).default([]) });

describe("useKeyedStore", () => {
  afterEach(() => {
    cleanup();
    __resetSecureStoreConfig();
  });

  it("locked: no data, locked:true, save() throws", async () => {
    const { provider } = fakeKeys(null);
    configureSecureStore({
      storage: keyedMemoryStorage(),
      keys: provider,
      cache: memoryCache(),
    });
    const store = defineStore({
      name: "transaction_blobs",
      identity: { perKey: "year_month" },
      encrypt: "all",
      schema: Batch,
      version: 1,
      schemaFingerprint: fingerprintSchema(Batch, "all"),
    });

    const { result } = renderHook(() => useKeyedStore(store, "2026-06"));

    expect(result.current.data).toBeUndefined();
    expect(result.current.locked).toBe(true);
    await expect(result.current.save({ transactions: ["x"] })).rejects.toThrow(
      /locked/,
    );
  });

  it("unlocked: loads via store.load(userId,cryptoHandle,key), keys are independent per month", async () => {
    const storage = keyedMemoryStorage();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    configureSecureStore({ storage, keys: provider, cache: memoryCache() });
    const store = defineStore({
      name: "transaction_blobs",
      identity: { perKey: "year_month" },
      encrypt: "all",
      schema: Batch,
      version: 1,
      schemaFingerprint: fingerprintSchema(Batch, "all"),
    });
    await store.save("u1", cryptoHandle, "2026-06", { transactions: ["june"] });

    const june = renderHook(() => useKeyedStore(store, "2026-06"));
    const july = renderHook(() => useKeyedStore(store, "2026-07"));

    await waitFor(() => expect(june.result.current.loading).toBe(false));
    await waitFor(() => expect(july.result.current.loading).toBe(false));

    expect(june.result.current.data).toEqual({ transactions: ["june"] });
    expect(july.result.current.data).toEqual({ transactions: [] });
  });

  it("save(): optimistic then persists; rollback on failure", async () => {
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    let shouldFail = false;
    const storage: StorageAdapter = {
      async get() {
        return null;
      },
      async put() {
        if (shouldFail) throw new Error("simulated failure");
      },
    };
    configureSecureStore({ storage, keys: provider, cache: memoryCache() });
    const store = defineStore({
      name: "transaction_blobs",
      identity: { perKey: "year_month" },
      encrypt: "all",
      schema: Batch,
      version: 1,
      schemaFingerprint: fingerprintSchema(Batch, "all"),
    });

    const { result } = renderHook(() => useKeyedStore(store, "2026-06"));
    await waitFor(() => expect(result.current.loading).toBe(false));

    await act(async () => {
      await result.current.save({ transactions: ["ok"] });
    });
    expect(result.current.data).toEqual({ transactions: ["ok"] });

    shouldFail = true;
    await act(async () => {
      await expect(
        result.current.save({ transactions: ["will-fail"] }),
      ).rejects.toThrow(/simulated failure/);
    });
    expect(result.current.data).toEqual({ transactions: ["ok"] });
  });

  it("optimisticLock: save() threads the hash automatically per key, independently across keys", async () => {
    const storage = conditionalKeyedStorage();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    configureSecureStore({ storage, keys: provider, cache: memoryCache() });
    const store = defineStore({
      name: "transaction_blobs",
      identity: { perKey: "year_month" },
      encrypt: "all",
      schema: Batch,
      version: 1,
      schemaFingerprint: fingerprintSchema(Batch, "all"),
      contentHash: true,
      optimisticLock: true,
    });

    const { result } = renderHook(() => useKeyedStore(store, "2026-06"));
    await waitFor(() => expect(result.current.loading).toBe(false));

    await act(async () => {
      await result.current.save({ transactions: ["june-1"] });
    });
    await act(async () => {
      await result.current.save({ transactions: ["june-1", "june-2"] });
    });
    expect(result.current.data).toEqual({ transactions: ["june-1", "june-2"] });
  });

  it("optimisticLock: a conflicting concurrent write on the same key makes save() throw and roll back", async () => {
    const storage = conditionalKeyedStorage();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    configureSecureStore({ storage, keys: provider, cache: memoryCache() });
    const store = defineStore({
      name: "transaction_blobs",
      identity: { perKey: "year_month" },
      encrypt: "all",
      schema: Batch,
      version: 1,
      schemaFingerprint: fingerprintSchema(Batch, "all"),
      contentHash: true,
      optimisticLock: true,
    });

    const { result } = renderHook(() => useKeyedStore(store, "2026-06"));
    await waitFor(() => expect(result.current.loading).toBe(false));

    await act(async () => {
      await result.current.save({ transactions: ["mine"] });
    });

    const { hash } = await store.loadWithHash!("u1", cryptoHandle, "2026-06");
    await store.saveIfMatch!(
      "u1",
      cryptoHandle,
      "2026-06",
      { transactions: ["concurrent"] },
      hash,
    );

    await act(async () => {
      await expect(
        result.current.save({ transactions: ["mine-again"] }),
      ).rejects.toThrow(OptimisticLockConflictError);
    });
    expect(result.current.data).toEqual({ transactions: ["mine"] });
  });
});
