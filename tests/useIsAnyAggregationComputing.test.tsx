/**
 * Tests the React binding (`useIsAnyAggregationComputing`). Needs jsdom + React
 * rendering — runs under Vitest (`npm run test:components`), unlike the rest of
 * zechinus/'s tests which run under plain `node --test` (see config/vitest.config.ts).
 *
 * The underlying signal (`isAnyAggregationComputing`/`subscribeGlobalAggregationActivity`,
 * `core/aggregation.ts`) has no test-only setter — it's only ever driven by a real
 * aggregation's `triggerRecompute()` lifecycle (by design, see rule 15: no dedicated
 * per-aggregation naming, only "is anything computing"). This test drives it through a
 * real `defineAggregation` with a gated compute, the same technique
 * `aggregation.test.ts`'s own "isAnyAggregationComputing" tests already use — this file
 * only proves the HOOK's reactive wiring, not the counter's own semantics (already
 * covered there).
 */
import { describe, it, expect, afterEach } from "vitest";
import { cleanup, renderHook, waitFor } from "@testing-library/react";
import { randomBytes } from "@noble/ciphers/utils.js";
import { z } from "zod";

import { createDekHandle } from "./testKeyHandle.ts";
import {
  configureSecureStore,
  __resetSecureStoreConfig,
  __resetGlobalAggregationActivity,
  defineStore,
  defineAggregation,
  fingerprintSchema,
  type StorageAdapter,
  type CacheAdapter,
  type CryptoHandle,
  type KeyProvider,
} from "../index.ts";
import { useIsAnyAggregationComputing } from "../react/useIsAnyAggregationComputing.ts";

function memoryAdapter(): StorageAdapter {
  const rows = new Map<string, unknown>();
  return {
    async get(collection, userId, extraKeys) {
      return (rows.get(
        `${collection}:${userId}:${extraKeys[0]?.value ?? ""}`,
      ) ?? null) as never;
    },
    async put(collection, userId, extraKeys, record) {
      rows.set(`${collection}:${userId}:${extraKeys[0]?.value ?? ""}`, record);
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

function fixedKeyProvider(cryptoHandle: CryptoHandle): KeyProvider {
  return {
    getCryptoHandle: () => cryptoHandle,
    getUserId: () => "u1",
    subscribe: () => () => {},
  };
}

const SourceSchema = z.object({ value: z.number().default(0) });
const OutputSchema = z.object({ total: z.number() });

describe("useIsAnyAggregationComputing", () => {
  afterEach(() => {
    cleanup();
    __resetSecureStoreConfig();
    __resetGlobalAggregationActivity();
  });

  it("reflects a real aggregation's compute lifecycle: false -> true while in flight -> false once settled", async () => {
    const cryptoHandle = createDekHandle(randomBytes(32));
    configureSecureStore({
      storage: memoryAdapter(),
      cache: memoryCache(),
      keys: fixedKeyProvider(cryptoHandle),
    });

    const source = defineStore({
      name: "hook_gac_source",
      encrypt: "all",
      schema: SourceSchema,
      version: 1,
      contentHash: true,
      schemaFingerprint: fingerprintSchema(SourceSchema, "all"),
    });
    await source.set({ value: 1 });

    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const agg = defineAggregation({
      version: 1,
      schema: OutputSchema,
      schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
      storage: { table: "hook_gac_agg", key: "__agg__" },
      sources: { src: source },
      compute: async ({ sources }) => {
        await gate;
        return { total: sources.src.value };
      },
    });

    const { result } = renderHook(() => useIsAnyAggregationComputing());
    expect(result.current).toBe(false);

    void agg.get();
    await waitFor(() => expect(result.current).toBe(true));

    release();
    await waitFor(() => expect(result.current).toBe(false));
  });
});
