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
import {
  useKeyedStore,
  isAnyKeyedStoreLoading,
  subscribeGlobalKeyedStoreActivity,
} from "../react/useKeyedStore.ts";
import { __resetGlobalKeyedStoreActivity } from "../react/keyedStoreActivity.ts";
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
    __resetGlobalKeyedStoreActivity();
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

  it("reload(): picks up a write that happened OUTSIDE this hook's save() (e.g. a backend endpoint writing directly, no ambient mutate() in this tab)", async () => {
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

    const { result } = renderHook(() => useKeyedStore(store, "2026-06"));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.data).toEqual({ transactions: [] });

    await store.save("u1", cryptoHandle, "2026-06", {
      transactions: ["out-of-band"],
    });
    expect(result.current.data).toEqual({ transactions: [] }); // still stale

    await act(async () => {
      await result.current.reload();
    });

    expect(result.current.data).toEqual({ transactions: ["out-of-band"] });
  });

  it("reload(): a lock that happens WHILE the fetch is in flight must not repopulate the cache with stale decrypted data", async () => {
    const base = keyedMemoryStorage();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider, setDek } = fakeKeys(cryptoHandle);
    const cache = memoryCache();

    let getCalls = 0;
    let releaseSecondGet!: () => void;
    const secondGate = new Promise<void>((resolve) => {
      releaseSecondGet = resolve;
    });
    const gatedStorage: StorageAdapter = {
      ...base,
      async get(...args) {
        getCalls++;
        if (getCalls === 2) await secondGate;
        return base.get(...args);
      },
    };
    configureSecureStore({ storage: gatedStorage, keys: provider, cache });

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

    await store.save("u1", cryptoHandle, "2026-06", {
      transactions: ["out-of-band"],
    });

    const reloadPromise = result.current.reload(); // fetch #2 now in flight, gated

    act(() => setDek(null)); // lock happens WHILE the fetch is pending
    expect(result.current.locked).toBe(true);

    releaseSecondGet();
    await act(async () => {
      await reloadPromise;
    });

    expect(cache.get(`transaction_blobs:u1:2026-06`)).toBeUndefined();
    expect(result.current.data).toBeUndefined();
  });

  it("dedupes concurrent fetches for the SAME key across independent hook instances (regression: two globally-mounted components — e.g. a copilot widget and an import provider both reading the same label dict — must share ONE fetch, not one each)", async () => {
    const storage = keyedMemoryStorage();
    let getCalls = 0;
    const countingStorage: StorageAdapter = {
      ...storage,
      get: (...args) => {
        getCalls++;
        return storage.get(...args);
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
      name: "key_concurrent_mount",
      identity: { perKey: "year_month" },
      encrypt: "all",
      schema: Batch,
      version: 1,
      schemaFingerprint: fingerprintSchema(Batch, "all"),
    });

    await store.save("u1", cryptoHandle, "2026-06", {
      transactions: ["seeded"],
    });

    // Two independent components mounting the SAME key at the same time.
    const first = renderHook(() => useKeyedStore(store, "2026-06"));
    const second = renderHook(() => useKeyedStore(store, "2026-06"));

    await waitFor(() => expect(first.result.current.loading).toBe(false));
    await waitFor(() => expect(second.result.current.loading).toBe(false));

    expect(getCalls).toBe(1);
    expect(first.result.current.data).toEqual({ transactions: ["seeded"] });
    expect(second.result.current.data).toEqual(first.result.current.data);
  });

  describe("isAnyKeyedStoreLoading / subscribeGlobalKeyedStoreActivity", () => {
    it("is false when no fetch is in flight, true while one is pending, false again once it settles", async () => {
      expect(isAnyKeyedStoreLoading()).toBe(false);

      const cryptoHandle = createDekHandle(randomBytes(32));
      const { provider } = fakeKeys(cryptoHandle);
      let releaseGet!: () => void;
      const gate = new Promise<void>((resolve) => {
        releaseGet = resolve;
      });
      const storage: StorageAdapter = {
        async get() {
          await gate;
          return null;
        },
        async put() {},
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
      expect(result.current.loading).toBe(true);
      await waitFor(() => expect(isAnyKeyedStoreLoading()).toBe(true));

      releaseGet();
      await waitFor(() => expect(result.current.loading).toBe(false));
      expect(isAnyKeyedStoreLoading()).toBe(false);
    });

    it("subscribeGlobalKeyedStoreActivity notifies on both the start and the end of a fetch", async () => {
      const cryptoHandle = createDekHandle(randomBytes(32));
      const { provider } = fakeKeys(cryptoHandle);
      let releaseGet!: () => void;
      const gate = new Promise<void>((resolve) => {
        releaseGet = resolve;
      });
      const storage: StorageAdapter = {
        async get() {
          await gate;
          return null;
        },
        async put() {},
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

      const notifications: boolean[] = [];
      const unsubscribe = subscribeGlobalKeyedStoreActivity(() => {
        notifications.push(isAnyKeyedStoreLoading());
      });

      renderHook(() => useKeyedStore(store, "2026-06"));
      await waitFor(() => expect(notifications).toContain(true));

      releaseGet();
      await waitFor(() => expect(notifications).toContain(false));
      unsubscribe();

      expect(notifications[0]).toBe(true);
      expect(notifications[notifications.length - 1]).toBe(false);
    });

    it("stays true while TWO independent keys are both in flight, only goes false once BOTH settle", async () => {
      const cryptoHandle = createDekHandle(randomBytes(32));
      const { provider } = fakeKeys(cryptoHandle);
      let releaseJune!: () => void;
      let releaseJuly!: () => void;
      const juneGate = new Promise<void>((resolve) => {
        releaseJune = resolve;
      });
      const julyGate = new Promise<void>((resolve) => {
        releaseJuly = resolve;
      });
      const storage: StorageAdapter = {
        async get(_collection, _userId, extraKeys) {
          await (extraKeys[0]?.value === "2026-06" ? juneGate : julyGate);
          return null;
        },
        async put() {},
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

      renderHook(() => useKeyedStore(store, "2026-06"));
      renderHook(() => useKeyedStore(store, "2026-07"));
      await waitFor(() => expect(isAnyKeyedStoreLoading()).toBe(true));

      releaseJune();
      // June alone settling must NOT flip the global signal — July is still pending.
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(isAnyKeyedStoreLoading()).toBe(true);

      releaseJuly();
      await waitFor(() => expect(isAnyKeyedStoreLoading()).toBe(false));
    });
  });
});
