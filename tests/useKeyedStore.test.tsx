/**
 * Same infra as useStore.test.tsx — needs jsdom, runs under Vitest.
 */
import { describe, it, expect, afterEach } from "vitest";
import { cleanup, renderHook, act, waitFor } from "@testing-library/react";
import { randomBytes } from "@noble/ciphers/utils.js";
import { z } from "zod";

import { createDekHandle } from "../../crypto/passkey-prf.ts";
import type { DekHandle } from "@crypto/field-crypto";
import {
  configureSecureStore,
  __resetSecureStoreConfig,
  defineStore,
  fingerprintSchema,
  type StorageAdapter,
  type BlobRecord,
  type KeyProvider,
  type CacheAdapter,
} from "../index.ts";
import { useKeyedStore } from "../react/useKeyedStore.ts";

function keyedMemoryStorage(): StorageAdapter & {
  rows: Map<string, BlobRecord>;
} {
  const rows = new Map<string, BlobRecord>();
  return {
    rows,
    async getOne() {
      return null;
    },
    async putOne() {},
    async getByKey(collection, userId, _keyColumn, keyValue) {
      return rows.get(`${collection}:${userId}:${keyValue}`) ?? null;
    },
    async putByKey(collection, userId, _keyColumn, keyValue, record) {
      rows.set(`${collection}:${userId}:${keyValue}`, record);
    },
  };
}

function fakeKeys(initial: DekHandle | null) {
  let dek = initial;
  const subs = new Set<() => void>();
  const provider: KeyProvider = {
    getDek: () => dek,
    getUserId: () => (dek ? "u1" : null),
    subscribe(cb) {
      subs.add(cb);
      return () => subs.delete(cb);
    },
  };
  return {
    provider,
    setDek(next: DekHandle | null) {
      dek = next;
      for (const cb of subs) cb();
    },
  };
}

function memoryCache(): CacheAdapter {
  const data = new Map<string, unknown>();
  const subs = new Map<string, Set<() => void>>();
  return {
    getQueryData: (key) => data.get(key) as never,
    setQueryData: (key, value) => {
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

  it("unlocked: loads via store.load(userId,dek,key), keys are independent per month", async () => {
    const storage = keyedMemoryStorage();
    const dek = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(dek);
    configureSecureStore({ storage, keys: provider, cache: memoryCache() });
    const store = defineStore({
      name: "transaction_blobs",
      identity: { perKey: "year_month" },
      encrypt: "all",
      schema: Batch,
      version: 1,
      schemaFingerprint: fingerprintSchema(Batch, "all"),
    });
    await store.save("u1", dek, "2026-06", { transactions: ["june"] });

    const june = renderHook(() => useKeyedStore(store, "2026-06"));
    const july = renderHook(() => useKeyedStore(store, "2026-07"));

    await waitFor(() => expect(june.result.current.loading).toBe(false));
    await waitFor(() => expect(july.result.current.loading).toBe(false));

    expect(june.result.current.data).toEqual({ transactions: ["june"] });
    expect(july.result.current.data).toEqual({ transactions: [] });
  });

  it("save(): optimistic then persists; rollback on failure", async () => {
    const dek = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(dek);
    let shouldFail = false;
    const storage: StorageAdapter = {
      async getOne() {
        return null;
      },
      async putOne() {},
      async getByKey() {
        return null;
      },
      async putByKey() {
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
});
