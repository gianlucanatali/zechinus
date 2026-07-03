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
  fingerprintSchema,
  createKeyHandle,
  type StorageAdapter,
  type BlobRecord,
} from "../index.ts";

// A real app derives its DEK from a `KeyProvider` adapter (WebAuthn, password KDF,
// hardware token, ...) and picks its own salt/info for `createKeyHandle` — these
// example values are illustrative only, not meant to be reused verbatim.
const EXAMPLE_PID_SALT = new Uint8Array(32).fill(7);
const createDekHandle = (rawBytes: Uint8Array) =>
  createKeyHandle(rawBytes, EXAMPLE_PID_SALT, "example-pid-info");

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
  };
}

const freshDek = () => createDekHandle(randomBytes(32));

// ── 1. perUser — one blob per user (e.g. portfolio, asset) ─────────────────────────
export async function perUserExample() {
  configureSecureStore({ storage: memoryAdapter() });
  const dek = freshDek();

  const Portfolio = z.object({ positions: z.array(z.string()).default([]) });
  const portfolioStore = defineStore({
    name: "portfolio_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  await portfolioStore.save("u1", dek, { positions: ["AAPL", "MSFT"] });
  return portfolioStore.load("u1", dek);
}

// ── 2. perKey — one blob per (user, domain key) (e.g. transactions per month) ──────
export async function perKeyExample() {
  configureSecureStore({ storage: memoryAdapter() });
  const dek = freshDek();

  const Batch = z.object({ transactions: z.array(z.string()).default([]) });
  const transactionStore = defineStore({
    name: "transaction_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await transactionStore.save("u1", dek, "2026-07", {
    transactions: ["expense"],
  });
  return transactionStore.load("u1", dek, "2026-07");
}

// ── 3. many — a collection with a generated id (e.g. rebalance simulations) ────────
export async function manyExample() {
  configureSecureStore({ storage: memoryAdapter() });
  const dek = freshDek();

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

  await simulationStore.create("u1", dek, {
    name: "sim-1",
    addedLiquidity: 500,
  });
  return simulationStore.list("u1", dek);
}

// ── 4. optimisticLock — reject a write if the row changed since it was last read ───
export async function optimisticLockExample() {
  configureSecureStore({ storage: memoryAdapter() });
  const dek = freshDek();

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

  const first = await assetStore.saveIfMatch!("u1", dek, { label: "v1" }, null);
  const second = await assetStore.saveIfMatch!(
    "u1",
    dek,
    { label: "v2" },
    first.hash, // the hash saveIfMatch just returned — no extra fetch needed
  );

  // A write using a now-stale hash (as if another tab had already saved) is
  // rejected — `{ ok: false }`, never thrown.
  const conflict = await assetStore.saveIfMatch!(
    "u1",
    dek,
    { label: "v3-conflicting" },
    first.hash, // stale: "second" already moved the row past this hash
  );

  return { first, second, conflict };
}
