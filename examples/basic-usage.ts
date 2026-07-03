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
import { createDekHandle } from "../../crypto/passkey-prf.ts";
import {
  configureSecureStore,
  defineStore,
  fingerprintSchema,
  type StorageAdapter,
  type BlobRecord,
} from "../index.ts";

/** Minimal in-memory adapter, supports all 3 cardinalities. Examples/tests only. */
export function memoryAdapter(): StorageAdapter {
  const perUser = new Map<string, BlobRecord>();
  const perKey = new Map<string, BlobRecord>();
  const many = new Map<string, BlobRecord>();
  return {
    async getOne(collection, userId) {
      return perUser.get(`${collection}:${userId}`) ?? null;
    },
    async putOne(collection, userId, record) {
      perUser.set(`${collection}:${userId}`, record);
    },
    async getByKey(collection, userId, _keyColumn, keyValue) {
      return perKey.get(`${collection}:${userId}:${keyValue}`) ?? null;
    },
    async putByKey(collection, userId, _keyColumn, keyValue, record) {
      perKey.set(`${collection}:${userId}:${keyValue}`, record);
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
