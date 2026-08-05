/**
 * `zechinus/aggregate` — the declarative operator kit (Task 3 of the "aggregazioni
 * dichiarative persistite" plan): `sum`, `sumWith`, `expr`, `lastDelta`, `custom`.
 *
 * Each operator is a plain descriptor (no computation happens when you call `agg.sum(...)`
 * itself) — `compileFieldOperators` is what turns a `Record<string, FieldOperator>` into a
 * single function shaped exactly like `defineAggregation`'s pure-function `compute` (see
 * `core/aggregation.ts`'s `ComputeFn`). Most tests below exercise `compileFieldOperators`
 * directly (fast, no store/cache machinery needed) — the LAST test wires the record form
 * straight into `defineAggregation` to prove the core genuinely doesn't distinguish the
 * two forms of `compute`.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import { z } from "zod";

import { createDekHandle } from "./testKeyHandle.ts";
import {
  configureSecureStore,
  __resetSecureStoreConfig,
  defineStore,
  defineAggregation,
  fingerprintSchema,
  type StorageAdapter,
  type CacheAdapter,
  type BlobRecord,
  type CryptoHandle,
  type KeyProvider,
} from "../index.ts";
import { sum, sumWith, expr, lastDelta, custom } from "../aggregate/index.ts";
import { compileFieldOperators } from "../aggregate/compile.ts";

function fixedKeyProvider(cryptoHandle: CryptoHandle | null): KeyProvider {
  return {
    getCryptoHandle: () => cryptoHandle,
    getUserId: () => (cryptoHandle ? "u1" : null),
    subscribe: () => () => {},
  };
}

/** Minimal in-memory `StorageAdapter` — copied from `aggregation.test.ts`'s fixture
 * (kept local rather than shared/exported: it's a tiny test-only helper, not framework
 * surface). */
function memoryAdapter(): StorageAdapter {
  const rows = new Map<string, BlobRecord>();
  const rowKey = (
    collection: string,
    userId: string,
    extraKeys: { column: string; value: string }[],
  ) => `${collection}:${userId}:${extraKeys[0]?.value ?? ""}`;
  return {
    async get(collection, userId, extraKeys) {
      return rows.get(rowKey(collection, userId, extraKeys)) ?? null;
    },
    async put(collection, userId, extraKeys, record) {
      rows.set(rowKey(collection, userId, extraKeys), record);
    },
    async getHash(collection, userId, extraKeys) {
      return (
        rows.get(rowKey(collection, userId, extraKeys))?.contentHash ?? null
      );
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

test.beforeEach(() => __resetSecureStoreConfig());

test("sum: adds a numeric field across every row of an array source (no filter)", async () => {
  const compute = compileFieldOperators({
    liquidita: sum("banche", "saldo"),
  });
  const result = await compute({
    sources: {
      banche: [{ saldo: 100 }, { saldo: 50 }, { saldo: 25 }],
    },
    externals: {},
  });
  assert.deepEqual(result, { liquidita: 175 });
});

test("sum: `where` keeps only rows matching every listed field exactly", async () => {
  const compute = compileFieldOperators({
    immobili: sum("assets", "valore", { where: { tipo: "immobile" } }),
  });
  const result = await compute({
    sources: {
      assets: [
        { tipo: "immobile", valore: 300_000 },
        { tipo: "debito", valore: 50_000 },
        { tipo: "immobile", valore: 120_000 },
      ],
    },
    externals: {},
  });
  assert.deepEqual(result, { immobili: 420_000 });
});

test("sumWith: reduces a per-row value computed by a caller-supplied fn, not a raw field", async () => {
  const now = 2026;
  function calcolaDebitoResiduo(a: { anno: number; importo: number }): number {
    // stand-in for a real shared/domain formula — the point of this test is that the
    // operator itself contains ZERO of this logic, it only calls `fn(row)` and reduces.
    return a.importo - (now - a.anno) * 10;
  }
  const compute = compileFieldOperators({
    debitiDiretti: sumWith(
      "assets",
      (row) => calcolaDebitoResiduo(row as { anno: number; importo: number }),
      { where: { tipo: "debito" } },
    ),
  });
  const result = await compute({
    sources: {
      assets: [
        { tipo: "debito", anno: 2020, importo: 1000 },
        { tipo: "immobile", anno: 2020, importo: 999_999 }, // filtered out by `where`
        { tipo: "debito", anno: 2024, importo: 500 },
      ],
    },
    externals: {},
  });
  // (1000 - (2026-2020)*10) + (500 - (2026-2024)*10) = 940 + 480 = 1420
  assert.deepEqual(result, { debitiDiretti: 1420 });
});

test("expr: resolves fields in dependency order even when the object literal declares them out of order", async () => {
  // `totale` and `sub` are declared BEFORE the fields they depend on — proves the
  // resolver does real topological ordering, not `Object.keys()` insertion order.
  const compute = compileFieldOperators({
    totale: expr((f) => (f.sub as number) + 1),
    sub: expr((f) => (f.base as number) * 2),
    base: sum("banche", "saldo"),
  });
  const result = await compute({
    sources: { banche: [{ saldo: 10 }, { saldo: 5 }] },
    externals: {},
  });
  assert.deepEqual(result, { totale: 31, sub: 30, base: 15 });
});

test("expr: a dependency cycle produces an error naming every field involved, never a hang", async () => {
  const compute = compileFieldOperators({
    a: expr((f) => (f.b as number) + 1),
    b: expr((f) => (f.a as number) + 1),
  });
  assert.throws(
    () => compute({ sources: {}, externals: {} }),
    (e: Error) => {
      assert.match(e.message, /circular/i);
      assert.match(e.message, /\ba\b/);
      assert.match(e.message, /\bb\b/);
      return true;
    },
  );
});

test("expr: referencing a `custom` field produces a phase-ordering error, never a false 'circular' claim", async () => {
  // `custom` always runs AFTER phase 2 (`expr`), so `e` can never see `c`'s value — this
  // is NOT a cycle (there is no `expr` field that `c` depends on in return), it's a fixed
  // phase-ordering constraint. The error must name BOTH the blocked field (`e`) and the
  // real cause (`c`), and must NOT claim a "circular dependency".
  const compute = compileFieldOperators({
    c: custom((f) => (f.e as number) ?? 0), // irrelevant body — `custom` never even runs here
    e: expr((f) => (f.c as number) + 1),
  });
  assert.throws(
    () => compute({ sources: {}, externals: {} }),
    (err: Error) => {
      assert.doesNotMatch(err.message, /circular/i);
      assert.match(err.message, /\be\b/);
      assert.match(err.message, /\bc\b/);
      assert.match(err.message, /custom/i);
      return true;
    },
  );
});

test("expr: referencing a field name that isn't declared in the record fails fast with context", async () => {
  const compute = compileFieldOperators({
    total: expr((f) => (f.doesNotExist as number) + 1),
  });
  assert.throws(() => compute({ sources: {}, externals: {} }), /doesNotExist/);
});

test("lastDelta: reads a field off the LAST row of an ordered/time-series source", async () => {
  const compute = compileFieldOperators({
    varEur: lastDelta("storicoPatrimonio", "valore"),
  });
  const result = await compute({
    sources: {
      storicoPatrimonio: [
        { mese: "2026-01", valore: 100 },
        { mese: "2026-02", valore: 150 },
        { mese: "2026-03", valore: 210 },
      ],
    },
    externals: {},
  });
  assert.deepEqual(result, { varEur: 210 });
});

test("lastDelta: an empty source array fails fast with context rather than returning undefined silently", async () => {
  const compute = compileFieldOperators({
    varEur: lastDelta("storicoPatrimonio", "valore"),
  });
  assert.throws(
    () => compute({ sources: { storicoPatrimonio: [] }, externals: {} }),
    /storicoPatrimonio/,
  );
});

test("custom: pass-through escape hatch — receives already-computed fields plus raw sources, calls the given fn verbatim", async () => {
  let receivedFields: unknown;
  let receivedSources: unknown;
  function computeEffScore(f: Record<string, unknown>): number {
    // stand-in for a real shared/domain function — asserts the operator never inlines
    // this logic itself, it only forwards to whatever `fn` the caller passed.
    return (f.liquidita as number) + (f.immobili as number);
  }
  const compute = compileFieldOperators({
    liquidita: sum("banche", "saldo"),
    immobili: sum("assets", "valore"),
    effScore: custom((f, src) => {
      receivedFields = f;
      receivedSources = src;
      return computeEffScore(f);
    }),
  });
  const sources = {
    banche: [{ saldo: 100 }],
    assets: [{ valore: 50 }],
  };
  const result = await compute({ sources, externals: {} });
  assert.deepEqual(result, { liquidita: 100, immobili: 50, effScore: 150 });
  assert.deepEqual(receivedFields, { liquidita: 100, immobili: 50 });
  assert.deepEqual(receivedSources, sources);
});

test("sum: a non-array source fails fast with context instead of silently producing 0", async () => {
  const compute = compileFieldOperators({
    liquidita: sum("banche", "saldo"),
  });
  assert.throws(
    () => compute({ sources: { banche: { not: "an array" } }, externals: {} }),
    /banche/,
  );
});

test("defineAggregation accepts the declarative operator-record form of `compute` directly — the core doesn't distinguish it from the pure-function form", async () => {
  const adapter = memoryAdapter();
  const cache = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const BancheSchema = z.array(z.object({ saldo: z.number() })).default([]);
  const bancheStore = defineStore({
    name: "aggop_banche",
    encrypt: "all",
    schema: BancheSchema,
    version: 1,
    contentHash: true,
    schemaFingerprint: fingerprintSchema(BancheSchema, "all"),
  });
  await bancheStore.set([{ saldo: 100 }, { saldo: 50 }]);

  const OutputSchema = z.object({ liquidita: z.number() });
  const agg = defineAggregation({
    version: 1,
    schema: OutputSchema,
    schemaFingerprint: fingerprintSchema(OutputSchema, "all"),
    storage: { table: "aggop_agg", key: "__agg__" },
    sources: { banche: bancheStore },
    compute: { liquidita: sum("banche", "saldo") },
  });

  const result = await agg.refresh();
  assert.deepEqual(result, { liquidita: 150 });
});
