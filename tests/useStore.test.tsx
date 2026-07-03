/**
 * Tests the React binding (`useStore`). Needs jsdom + React rendering — runs under
 * Vitest (`npm run test:components`), unlike the rest of datacloak/'s tests which
 * run under plain `node --test` (see config/vitest.config.ts).
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
import { useStore } from "../react/useStore.ts";

function memoryStorage(): StorageAdapter & { rows: Map<string, BlobRecord> } {
  const rows = new Map<string, BlobRecord>();
  return {
    rows,
    async getOne(collection, userId) {
      return rows.get(`${collection}:${userId}`) ?? null;
    },
    async putOne(collection, userId, record) {
      rows.set(`${collection}:${userId}`, record);
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

const Portfolio = z.object({ positions: z.array(z.string()).default([]) });

describe("useStore", () => {
  afterEach(() => {
    cleanup();
    __resetSecureStoreConfig();
  });

  it("locked (no dek): returns no data, not loading, locked:true; save() throws", async () => {
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
    const dek = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(dek);
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
    const dek = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(dek);
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
    const dek = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(dek);
    const cache = memoryCache();
    const failingStorage: StorageAdapter = {
      async getOne() {
        return null;
      },
      async putOne() {
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

  it("lock (dek → null) after being unlocked: cache clears, hook reflects locked state", async () => {
    const storage = memoryStorage();
    const dek = createDekHandle(randomBytes(32));
    const { provider, setDek } = fakeKeys(dek);
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
});
