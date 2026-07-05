/**
 * Optimistic locking (`defineStore`'s `optimisticLock: true`) for `identity: "many"`
 * stores — mirrors optimisticLock.test.ts (perUser), exercising `updateIfMatch` /
 * `storage.updateByIdIfMatch`. Unlike perUser/perKey, `many`'s conflict check is
 * scoped to one row's id, not the whole collection: two different rows never
 * conflict with each other.
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
  fingerprintSchema,
  type StorageAdapter,
  type BlobRecord,
} from "../index.ts";

function conditionalCollectionAdapter(): StorageAdapter & {
  rows: Map<string, { record: BlobRecord; plain: Record<string, unknown> }>;
} {
  const rows = new Map<
    string,
    { record: BlobRecord; plain: Record<string, unknown> }
  >();
  const keyOf = (collection: string, userId: string, id: string) =>
    `${collection}:${userId}:${id}`;
  return {
    rows,
    async get() {
      return null;
    },
    async put() {
      /* perUser not used in these tests */
    },
    async list(collection, userId) {
      const prefix = `${collection}:${userId}:`;
      const out: Array<{
        id: string;
        record: BlobRecord;
        plain: Record<string, unknown>;
      }> = [];
      for (const [key, { record, plain }] of rows) {
        if (key.startsWith(prefix))
          out.push({ id: key.slice(prefix.length), record, plain });
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
        if (current) return false; // row already exists — caller's belief was stale
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

const Sim = z.object({
  name: z.string().default(""),
  addedLiquidity: z.number().default(0),
});

test.beforeEach(() => __resetSecureStoreConfig());

test("optimisticLock (many): defineStore throws at definition time if optimisticLock is set without contentHash", () => {
  assert.throws(
    () =>
      defineStore({
        name: "rebalance_simulations",
        identity: "many",
        encrypt: "all",
        schema: Sim,
        version: 1,
        schemaFingerprint: fingerprintSchema(Sim, "all"),
        optimisticLock: true,
      }),
    /optimisticLock.*requires.*contentHash/,
  );
});

test("optimisticLock (many): updateIfMatch succeeds when expectedHash matches the row's current hash", async () => {
  const adapter = conditionalCollectionAdapter();
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

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
    name: "sim-1",
    addedLiquidity: 100,
  });
  const [row] = await store.list("u1", cryptoHandle);
  assert.ok(row.hash);

  const result = await store.updateIfMatch!(
    "u1",
    cryptoHandle,
    id,
    { name: "sim-1", addedLiquidity: 200 },
    row.hash,
  );
  assert.equal(result.ok, true);
  assert.ok(result.hash);
  assert.notEqual(result.hash, row.hash);

  const [updated] = await store.list("u1", cryptoHandle);
  assert.deepEqual(updated.data, { name: "sim-1", addedLiquidity: 200 });
  assert.equal(updated.hash, result.hash);
});

test("optimisticLock (many): updateIfMatch fails (ok:false, no throw) when someone else updated the same row first", async () => {
  const adapter = conditionalCollectionAdapter();
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

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
    name: "sim-1",
    addedLiquidity: 100,
  });
  const [{ hash: staleHash }] = await store.list("u1", cryptoHandle);

  // A "concurrent tab" writes using the same starting hash, winning the race.
  await store.updateIfMatch!(
    "u1",
    cryptoHandle,
    id,
    { name: "sim-1", addedLiquidity: 999 },
    staleHash,
  );

  // Our own write, still using the now-stale hash, must be rejected — not throw.
  const conflict = await store.updateIfMatch!(
    "u1",
    cryptoHandle,
    id,
    { name: "sim-1", addedLiquidity: 2 },
    staleHash,
  );
  assert.equal(conflict.ok, false);
  assert.equal(conflict.hash, null);

  const [row] = await store.list("u1", cryptoHandle);
  assert.deepEqual(row.data, { name: "sim-1", addedLiquidity: 999 });
});

test("optimisticLock (many): a conflict on one row never affects a different row", async () => {
  const adapter = conditionalCollectionAdapter();
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

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

  const idA = await store.create("u1", cryptoHandle, {
    name: "a",
    addedLiquidity: 1,
  });
  const idB = await store.create("u1", cryptoHandle, {
    name: "b",
    addedLiquidity: 2,
  });
  const rows = await store.list("u1", cryptoHandle);
  const hashA = rows.find((r) => r.id === idA)!.hash;
  const hashB = rows.find((r) => r.id === idB)!.hash;

  // Make A's hash stale by writing it through the unconditional path.
  await store.update("u1", cryptoHandle, idA, {
    name: "a",
    addedLiquidity: 999,
  });

  const conflictOnA = await store.updateIfMatch!(
    "u1",
    cryptoHandle,
    idA,
    { name: "a", addedLiquidity: 2 },
    hashA,
  );
  assert.equal(conflictOnA.ok, false);

  // B was never touched — its hash is still valid.
  const okOnB = await store.updateIfMatch!(
    "u1",
    cryptoHandle,
    idB,
    { name: "b", addedLiquidity: 20 },
    hashB,
  );
  assert.equal(okOnB.ok, true);
});

test("optimisticLock (many): adapter without updateByIdIfMatch → explicit error, not silent fallback", async () => {
  configureSecureStore({
    storage: {
      async get() {
        return null;
      },
      async put() {},
      async list() {
        return [];
      },
      async insert() {},
      async updateById() {},
    },
  });
  const cryptoHandle = createDekHandle(randomBytes(32));

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

  await assert.rejects(
    () =>
      store.updateIfMatch!(
        "u1",
        cryptoHandle,
        "some-id",
        { name: "x", addedLiquidity: 1 },
        null,
      ),
    /doesn't support optimistic locking \(updateByIdIfMatch missing\)/,
  );
});
