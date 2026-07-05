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
import { useCollectionStore } from "../react/useCollectionStore.ts";
import { OptimisticLockConflictError } from "../react/errors.ts";

function collectionMemoryStorage(): StorageAdapter & {
  rows: Map<string, BlobRecord>;
} {
  const rows = new Map<string, BlobRecord>();
  const keyOf = (c: string, u: string, id: string) => `${c}:${u}:${id}`;
  return {
    rows,
    async get() {
      return null;
    },
    async put() {},
    async list(collection, userId) {
      const prefix = `${collection}:${userId}:`;
      const out: Array<{
        id: string;
        record: BlobRecord;
        plain: Record<string, unknown>;
      }> = [];
      for (const [k, record] of rows) {
        if (k.startsWith(prefix))
          out.push({ id: k.slice(prefix.length), record, plain: {} });
      }
      return out;
    },
    async insert(collection, userId, id, record) {
      rows.set(keyOf(collection, userId, id), record);
    },
    async updateById(collection, userId, id, record) {
      rows.set(keyOf(collection, userId, id), record);
    },
    async deleteById(collection, userId, id) {
      rows.delete(keyOf(collection, userId, id));
    },
  };
}

function conditionalCollectionStorage(): StorageAdapter & {
  rows: Map<string, { record: BlobRecord; plain: Record<string, unknown> }>;
} {
  const rows = new Map<
    string,
    { record: BlobRecord; plain: Record<string, unknown> }
  >();
  const keyOf = (c: string, u: string, id: string) => `${c}:${u}:${id}`;
  return {
    rows,
    async get() {
      return null;
    },
    async put() {},
    async list(collection, userId) {
      const prefix = `${collection}:${userId}:`;
      const out: Array<{
        id: string;
        record: BlobRecord;
        plain: Record<string, unknown>;
      }> = [];
      for (const [k, { record, plain }] of rows) {
        if (k.startsWith(prefix))
          out.push({ id: k.slice(prefix.length), record, plain });
      }
      return out;
    },
    async insert(collection, userId, id, record, plain) {
      rows.set(keyOf(collection, userId, id), { record, plain });
    },
    async updateById(collection, userId, id, record, plain) {
      rows.set(keyOf(collection, userId, id), { record, plain });
    },
    async updateByIdIfMatch(
      collection,
      userId,
      id,
      record,
      plain,
      expectedHash,
    ) {
      const key = keyOf(collection, userId, id);
      const current = rows.get(key) ?? null;
      if (expectedHash === null) {
        if (current) return false;
        rows.set(key, { record, plain });
        return true;
      }
      if (!current || current.record.contentHash !== expectedHash) return false;
      rows.set(key, { record, plain });
      return true;
    },
    async deleteById(collection, userId, id) {
      rows.delete(keyOf(collection, userId, id));
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
    setDek: (n: CryptoHandle | null) => {
      cryptoHandle = n;
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

const Sim = z.object({
  name: z.string().default(""),
  addedLiquidity: z.number().default(0),
});

describe("useCollectionStore", () => {
  afterEach(() => {
    cleanup();
    __resetSecureStoreConfig();
  });

  it("locked: items empty, locked:true, create() throws", async () => {
    const { provider } = fakeKeys(null);
    configureSecureStore({
      storage: collectionMemoryStorage(),
      keys: provider,
      cache: memoryCache(),
    });
    const store = defineStore({
      name: "rebalance_simulations",
      identity: "many",
      encrypt: "all",
      schema: Sim,
      version: 1,
      schemaFingerprint: fingerprintSchema(Sim, "all"),
    });

    const { result } = renderHook(() => useCollectionStore(store));

    expect(result.current.items).toEqual([]);
    expect(result.current.locked).toBe(true);
    await expect(
      result.current.create({ name: "x", addedLiquidity: 0 }),
    ).rejects.toThrow(/locked/);
  });

  it("unlocked: loads via store.list() on mount", async () => {
    const storage = collectionMemoryStorage();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    configureSecureStore({ storage, keys: provider, cache: memoryCache() });
    const store = defineStore({
      name: "rebalance_simulations",
      identity: "many",
      encrypt: "all",
      schema: Sim,
      version: 1,
      schemaFingerprint: fingerprintSchema(Sim, "all"),
    });
    const id = await store.create("u1", cryptoHandle, {
      name: "sim-1",
      addedLiquidity: 100,
    });

    const { result } = renderHook(() => useCollectionStore(store));
    await waitFor(() => expect(result.current.loading).toBe(false));

    expect(result.current.items).toEqual([
      { id, data: { name: "sim-1", addedLiquidity: 100 }, hash: null },
    ]);
  });

  it("create(): optimistically appends, then persists with the real generated id", async () => {
    const storage = collectionMemoryStorage();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    configureSecureStore({ storage, keys: provider, cache: memoryCache() });
    const store = defineStore({
      name: "rebalance_simulations",
      identity: "many",
      encrypt: "all",
      schema: Sim,
      version: 1,
      schemaFingerprint: fingerprintSchema(Sim, "all"),
    });

    const { result } = renderHook(() => useCollectionStore(store));
    await waitFor(() => expect(result.current.loading).toBe(false));

    let newId = "";
    await act(async () => {
      newId = await result.current.create({
        name: "sim-1",
        addedLiquidity: 50,
      });
    });

    expect(result.current.items).toEqual([
      { id: newId, data: { name: "sim-1", addedLiquidity: 50 }, hash: null },
    ]);
    assertRowPersisted(storage, newId);
  });

  it("update(): optimistic, rolls back the whole list on failure", async () => {
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    let shouldFail = false;
    const storage: StorageAdapter = {
      async get() {
        return null;
      },
      async put() {},
      async list() {
        return [];
      },
      async insert(_c, _u, id, record) {
        seed.set(id, record);
      },
      async updateById(_c, _u, id, record) {
        if (shouldFail) throw new Error("simulated update failure");
        seed.set(id, record);
      },
      async deleteById(_c, _u, id) {
        seed.delete(id);
      },
    };
    const seed = new Map<string, BlobRecord>();
    (
      storage as StorageAdapter & { list: NonNullable<StorageAdapter["list"]> }
    ).list = async () =>
      [...seed].map(([id, record]) => ({ id, record, plain: {} }));
    configureSecureStore({ storage, keys: provider, cache: memoryCache() });
    const store = defineStore({
      name: "rebalance_simulations",
      identity: "many",
      encrypt: "all",
      schema: Sim,
      version: 1,
      schemaFingerprint: fingerprintSchema(Sim, "all"),
    });
    const id = await store.create("u1", cryptoHandle, {
      name: "v1",
      addedLiquidity: 1,
    });

    const { result } = renderHook(() => useCollectionStore(store));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.items).toEqual([
      { id, data: { name: "v1", addedLiquidity: 1 }, hash: null },
    ]);

    shouldFail = true;
    await act(async () => {
      await expect(
        result.current.update(id, { name: "v2", addedLiquidity: 2 }),
      ).rejects.toThrow(/simulated update failure/);
    });

    expect(result.current.items).toEqual([
      { id, data: { name: "v1", addedLiquidity: 1 }, hash: null },
    ]);
  });

  it("remove(): optimistically filters the item out, then persists the delete", async () => {
    const storage = collectionMemoryStorage();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    configureSecureStore({ storage, keys: provider, cache: memoryCache() });
    const store = defineStore({
      name: "rebalance_simulations",
      identity: "many",
      encrypt: "all",
      schema: Sim,
      version: 1,
      schemaFingerprint: fingerprintSchema(Sim, "all"),
    });
    const id = await store.create("u1", cryptoHandle, {
      name: "v1",
      addedLiquidity: 1,
    });

    const { result } = renderHook(() => useCollectionStore(store));
    await waitFor(() => expect(result.current.loading).toBe(false));

    await act(async () => {
      await result.current.remove(id);
    });

    expect(result.current.items).toEqual([]);
    expect(storage.rows.has(`rebalance_simulations:u1:${id}`)).toBe(false);
  });

  it("optimisticLock: update() threads each row's hash automatically", async () => {
    const storage = conditionalCollectionStorage();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    configureSecureStore({ storage, keys: provider, cache: memoryCache() });
    const store = defineStore({
      name: "rebalance_simulations",
      identity: "many",
      encrypt: "all",
      schema: Sim,
      version: 1,
      schemaFingerprint: fingerprintSchema(Sim, "all"),
      contentHash: true,
      optimisticLock: true,
    });
    const id = await store.create("u1", cryptoHandle, {
      name: "v1",
      addedLiquidity: 1,
    });

    const { result } = renderHook(() => useCollectionStore(store));
    await waitFor(() => expect(result.current.loading).toBe(false));

    await act(async () => {
      await result.current.update(id, { name: "v2", addedLiquidity: 2 });
    });
    await act(async () => {
      await result.current.update(id, { name: "v3", addedLiquidity: 3 });
    });

    expect(result.current.items).toEqual([
      { id, data: { name: "v3", addedLiquidity: 3 }, hash: expect.any(String) },
    ]);
  });

  it("optimisticLock: a conflicting concurrent update makes update() throw and roll back only that row", async () => {
    const storage = conditionalCollectionStorage();
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    configureSecureStore({ storage, keys: provider, cache: memoryCache() });
    const store = defineStore({
      name: "rebalance_simulations",
      identity: "many",
      encrypt: "all",
      schema: Sim,
      version: 1,
      schemaFingerprint: fingerprintSchema(Sim, "all"),
      contentHash: true,
      optimisticLock: true,
    });
    const id = await store.create("u1", cryptoHandle, {
      name: "v1",
      addedLiquidity: 1,
    });

    const { result } = renderHook(() => useCollectionStore(store));
    await waitFor(() => expect(result.current.loading).toBe(false));

    // A "concurrent tab" updates the same row directly through the store.
    const [{ hash }] = await store.list("u1", cryptoHandle);
    await store.updateIfMatch!(
      "u1",
      cryptoHandle,
      id,
      { name: "concurrent", addedLiquidity: 99 },
      hash,
    );

    await act(async () => {
      await expect(
        result.current.update(id, { name: "mine", addedLiquidity: 2 }),
      ).rejects.toThrow(OptimisticLockConflictError);
    });

    // Rolled back to what the hook believed was current, not silently overwritten.
    expect(result.current.items).toEqual([
      {
        id,
        data: { name: "v1", addedLiquidity: 1 },
        hash: expect.any(String),
      },
    ]);
  });
});

function assertRowPersisted(
  storage: StorageAdapter & { rows: Map<string, BlobRecord> },
  id: string,
) {
  const raw = storage.rows.get(`rebalance_simulations:u1:${id}`);
  if (!raw) throw new Error(`expected a persisted row for id=${id}`);
}
