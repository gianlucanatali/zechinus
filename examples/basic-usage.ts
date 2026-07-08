/**
 * DataCloak — verified usage examples.
 *
 * This file is compiled by `tsc` (part of `npm run typecheck`) and called from
 * `datacloak/tests/examples.test.ts` (part of `npm test`): if DataCloak's API
 * changes, these examples stop compiling or the test fails. It's the source of
 * truth for the snippets shown in `datacloak/README.md` — if you change the API,
 * update this file FIRST, get it passing, THEN mirror the README.
 */

import { z } from "zod";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  configureSecureStore,
  defineStore,
  defineAggregation,
  fingerprintSchema,
  createKeyHandle,
  asRawDekBytes,
  type StorageAdapter,
  type BlobRecord,
  type CacheAdapter,
  type CryptoHandle,
  type KeyProvider,
} from "../index.ts";
import * as agg from "../aggregate/index.ts";

// A real app derives its DEK from a `KeyProvider` adapter (WebAuthn, password KDF,
// hardware token, ...) and picks its own salt/info for `createKeyHandle` — these
// example values are illustrative only, not meant to be reused verbatim.
const EXAMPLE_PID_SALT = new Uint8Array(32).fill(7);
const createDekHandle = (rawBytes: Uint8Array) =>
  createKeyHandle(
    asRawDekBytes(rawBytes),
    EXAMPLE_PID_SALT,
    "example-pid-info",
  );

/**
 * Minimal in-memory adapter, supports all 3 cardinalities. Examples/tests only.
 * `get`/`put` cover BOTH perUser (`extraKeys: []`) and perKey (`extraKeys: [key]`)
 * — same row-address, one map, keyed by however many extra columns were given.
 */
export function memoryAdapter(): StorageAdapter {
  const rows = new Map<string, BlobRecord>();
  const many = new Map<string, BlobRecord>();
  const rowKey = (
    collection: string,
    userId: string,
    extraKeys: { value: string }[],
  ) => [collection, userId, ...extraKeys.map((k) => k.value)].join(":");
  return {
    async get(collection, userId, extraKeys) {
      return rows.get(rowKey(collection, userId, extraKeys)) ?? null;
    },
    async put(collection, userId, extraKeys, record) {
      rows.set(rowKey(collection, userId, extraKeys), record);
    },
    async putIfMatch(collection, userId, extraKeys, record, expectedHash) {
      const key = rowKey(collection, userId, extraKeys);
      const current = rows.get(key) ?? null;
      if (expectedHash === null) {
        if (current) return false; // row already exists — caller's belief was stale
        rows.set(key, record);
        return true;
      }
      if (!current || current.contentHash !== expectedHash) return false;
      rows.set(key, record);
      return true;
    },
    async list(collection, userId) {
      const prefix = `${collection}:${userId}:`;
      return [...many]
        .filter(([key]) => key.startsWith(prefix))
        .map(([key, record]) => ({
          id: key.slice(prefix.length),
          record,
          plain: {},
        }));
    },
    async insert(collection, userId, id, record) {
      many.set(`${collection}:${userId}:${id}`, record);
    },
    async updateById(collection, userId, id, record) {
      many.set(`${collection}:${userId}:${id}`, record);
    },
    async deleteById(collection, userId, id) {
      many.delete(`${collection}:${userId}:${id}`);
    },
    async insertMany(collection, userId, entries) {
      for (const { extraKeys } of entries) {
        const key = rowKey(collection, userId, extraKeys);
        if (rows.has(key)) throw new Error(`insertMany: ${key} already exists`);
      }
      for (const { extraKeys, record } of entries) {
        rows.set(rowKey(collection, userId, extraKeys), record);
      }
    },
  };
}

/** Real subscribable in-memory CacheAdapter — required by `defineAggregation` (it
 * detects a source write through this port, not by re-fetching every source on every
 * read). See `datacloak/tests/aggregation.test.ts`'s identical fixture. */
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

const freshDek = () => createDekHandle(randomBytes(32));

// Ambient calls (`get`/`set`/`mutate`/`createMany`) resolve the CryptoHandle from
// a configured `KeyProvider` instead of taking it as a parameter — this fixed
// provider mirrors a single already-unlocked session, like a real app's bridge
// to its passkey/DEK controller.
const fixedKeyProvider = (cryptoHandle: CryptoHandle): KeyProvider => ({
  getCryptoHandle: () => cryptoHandle,
  getUserId: () => "u1",
  subscribe: () => () => {},
});

// ── 1. perUser — one blob per user (e.g. portfolio, asset) ─────────────────────────
export async function perUserExample() {
  configureSecureStore({ storage: memoryAdapter() });
  const cryptoHandle = freshDek();

  const Portfolio = z.object({ positions: z.array(z.string()).default([]) });
  const portfolioStore = defineStore({
    name: "portfolio_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  await portfolioStore.save("u1", cryptoHandle, {
    positions: ["AAPL", "MSFT"],
  });
  return portfolioStore.load("u1", cryptoHandle);
}

// ── 2. perKey — one blob per (user, domain key) (e.g. transactions per month) ──────
export async function perKeyExample() {
  const cryptoHandle = freshDek();
  configureSecureStore({
    storage: memoryAdapter(),
    keys: fixedKeyProvider(cryptoHandle),
  });

  const Batch = z.object({ transactions: z.array(z.string()).default([]) });
  const transactionStore = defineStore({
    name: "transaction_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await transactionStore.save("u1", cryptoHandle, "2026-07", {
    transactions: ["expense"],
  });

  // Bulk-create N distinct brand-new keys in one round-trip (e.g. seeding many
  // months at once) — a real INSERT, not an upsert: a key that already exists
  // fails the whole batch instead of silently overwriting it.
  await transactionStore.createMany([
    { key: "2026-08", data: { transactions: ["august"] } },
    { key: "2026-09", data: { transactions: ["september"] } },
  ]);

  return transactionStore.load("u1", cryptoHandle, "2026-07");
}

// ── 3. many — a collection with a generated id (e.g. rebalance simulations) ────────
export async function manyExample() {
  configureSecureStore({ storage: memoryAdapter() });
  const cryptoHandle = freshDek();

  const Simulation = z.object({
    name: z.string().default(""),
    addedLiquidity: z.number().default(0),
  });
  const simulationStore = defineStore({
    name: "rebalance_simulations",
    identity: "many",
    encrypt: "all",
    schema: Simulation,
    version: 1,
    schemaFingerprint: fingerprintSchema(Simulation, "all"),
  });

  await simulationStore.create("u1", cryptoHandle, {
    name: "sim-1",
    addedLiquidity: 500,
  });
  return simulationStore.list("u1", cryptoHandle);
}

// ── 4. optimisticLock — reject a write if the row changed since it was last read ───
export async function optimisticLockExample() {
  configureSecureStore({ storage: memoryAdapter() });
  const cryptoHandle = freshDek();

  const Asset = z.object({ label: z.string().default("") });
  const assetStore = defineStore({
    name: "asset_blobs",
    encrypt: "all",
    schema: Asset,
    version: 1,
    schemaFingerprint: fingerprintSchema(Asset, "all"),
    contentHash: true, // required by optimisticLock
    optimisticLock: true,
  });

  const first = await assetStore.saveIfMatch!(
    "u1",
    cryptoHandle,
    { label: "v1" },
    null,
  );
  const second = await assetStore.saveIfMatch!(
    "u1",
    cryptoHandle,
    { label: "v2" },
    first.hash, // the hash saveIfMatch just returned — no extra fetch needed
  );

  // A write using a now-stale hash (as if another tab had already saved) is
  // rejected — `{ ok: false }`, never thrown.
  const conflict = await assetStore.saveIfMatch!(
    "u1",
    cryptoHandle,
    { label: "v3-conflicting" },
    first.hash, // stale: "second" already moved the row past this hash
  );

  return { first, second, conflict };
}

// ── 5. defineAggregation — a persisted, declarative read-model over a store ────────
export async function aggregationExample() {
  const cryptoHandle = freshDek();
  configureSecureStore({
    storage: memoryAdapter(),
    cache: memoryCache(), // required: this is how the aggregate detects a source write
    keys: fixedKeyProvider(cryptoHandle),
  });

  // The source is an array store on purpose — `agg.sum` (the declarative operator
  // kit, `datacloak/aggregate`) only reduces over array/collection sources. See
  // README's "Aggregations" section for the hand-written-function alternative form.
  const InvoiceList = z.array(z.object({ amount: z.number() }));
  const invoiceStore = defineStore({
    name: "invoice_blobs",
    encrypt: "all",
    schema: InvoiceList,
    version: 1,
    empty: [], // array schema — no .default() to derive one from, same as snapshotStore's tuple
    contentHash: true, // lets the aggregate fingerprint this source
    schemaFingerprint: fingerprintSchema(InvoiceList, "all"),
  });
  await invoiceStore.set([{ amount: 120 }, { amount: 30 }]);

  const Totals = z.object({ total: z.number() });
  const totalsAgg = defineAggregation({
    version: 1,
    schema: Totals,
    schemaFingerprint: fingerprintSchema(Totals, "all"),
    storage: { table: "invoice_totals_agg", key: "__totals__" },
    sources: { invoices: invoiceStore },
    compute: { total: agg.sum("invoices", "amount") },
  });

  // `refresh()` forces a recompute and resolves with the freshly persisted value
  // directly — no polling needed in a one-shot script like this one.
  return totalsAgg.refresh();
}
