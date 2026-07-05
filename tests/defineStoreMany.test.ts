import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import { z } from "zod";

import { createDekHandle } from "./testKeyHandle.ts";
import {
  configureSecureStore,
  defineStore,
  fingerprintSchema,
  type StorageAdapter,
  type BlobRecord,
  type CryptoHandle,
  type KeyProvider,
} from "../index.ts";

// `get()`/`add()` resolve the cryptoHandle AND userId ambiently from the configured
// KeyProvider — the caller never sees a `CryptoHandle` or passes a `userId`.
// This fake mirrors a single already-unlocked session, exactly like the real
// `passkeyDekController` at runtime.
function fixedKeyProvider(cryptoHandle: CryptoHandle | null): KeyProvider {
  return {
    getCryptoHandle: () => cryptoHandle,
    getUserId: () => "u1",
    subscribe: () => () => {},
  };
}

// In-memory adapter with 'many' support, indexed by (collection, userId, id).
function collectionMemoryAdapter(): StorageAdapter & {
  rows: Map<string, BlobRecord>;
} {
  const rows = new Map<string, BlobRecord>();
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
      for (const [key, record] of rows) {
        if (key.startsWith(prefix))
          out.push({ id: key.slice(prefix.length), record, plain: {} });
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

// Adapter with no 'many' support, to test the explicit error.
function noManyAdapter(): StorageAdapter {
  return {
    async get() {
      return null;
    },
    async put() {},
  };
}

const Sim = z.object({
  name: z.string().default(""),
  addedLiquidity: z.number().default(0),
});

test("defineStore many: create/list/update/remove roundtrip", async () => {
  const adapter = collectionMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "rebalance_simulations",
    identity: "many",
    encrypt: "all",
    schema: Sim,
    version: 1,
    schemaFingerprint: fingerprintSchema(Sim, "all"),
  });

  assert.deepEqual(await store.list("u1", cryptoHandle), []);

  const id = await store.create("u1", cryptoHandle, {
    name: "sim-1",
    addedLiquidity: 100,
  });
  assert.equal(typeof id, "string");

  const afterCreate = await store.list("u1", cryptoHandle);
  assert.equal(afterCreate.length, 1);
  assert.equal(afterCreate[0].id, id);
  assert.deepEqual(afterCreate[0].data, { name: "sim-1", addedLiquidity: 100 });

  await store.update("u1", cryptoHandle, id, {
    name: "sim-1-renamed",
    addedLiquidity: 200,
  });
  const afterUpdate = await store.list("u1", cryptoHandle);
  assert.deepEqual(afterUpdate[0].data, {
    name: "sim-1-renamed",
    addedLiquidity: 200,
  });

  await store.remove("u1", cryptoHandle, id);
  assert.deepEqual(await store.list("u1", cryptoHandle), []);
});

test("defineStore many: get()/add() work ambiently — no cryptoHandle/userId in sight", async () => {
  const adapter = collectionMemoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "rebalance_simulations",
    identity: "many",
    encrypt: "all",
    schema: Sim,
    version: 1,
    schemaFingerprint: fingerprintSchema(Sim, "all"),
  });

  assert.deepEqual(await store.get(), []);

  const id = await store.add({ name: "sim-1", addedLiquidity: 100 });
  assert.equal(typeof id, "string");

  const afterAdd = await store.get();
  assert.equal(afterAdd.length, 1);
  assert.equal(afterAdd[0].id, id);
  assert.deepEqual(afterAdd[0].data, { name: "sim-1", addedLiquidity: 100 });

  // Same row visible through the explicit path too — same store, same data.
  const viaExplicit = await store.list("u1", cryptoHandle);
  assert.deepEqual(viaExplicit, afterAdd);
});

test("defineStore many: get() throws an explicit error when locked (no active cryptoHandle)", async () => {
  const adapter = collectionMemoryAdapter();
  configureSecureStore({ storage: adapter, keys: fixedKeyProvider(null) });

  const store = defineStore({
    name: "rebalance_simulations",
    identity: "many",
    encrypt: "all",
    schema: Sim,
    version: 1,
    schemaFingerprint: fingerprintSchema(Sim, "all"),
  });

  await assert.rejects(() => store.get(), /no cryptoHandle|locked/i);
});

test("defineStore many: add() throws an explicit error when locked (no active cryptoHandle)", async () => {
  const adapter = collectionMemoryAdapter();
  configureSecureStore({ storage: adapter, keys: fixedKeyProvider(null) });

  const store = defineStore({
    name: "rebalance_simulations",
    identity: "many",
    encrypt: "all",
    schema: Sim,
    version: 1,
    schemaFingerprint: fingerprintSchema(Sim, "all"),
  });

  await assert.rejects(
    () => store.add({ name: "sim-1", addedLiquidity: 100 }),
    /no cryptoHandle|locked/i,
  );
});

test("defineStore many: the AAD is bound to the id (ciphertext not movable between rows)", async () => {
  const adapter = collectionMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "rebalance_simulations",
    identity: "many",
    encrypt: "all",
    schema: Sim,
    version: 1,
    schemaFingerprint: fingerprintSchema(Sim, "all"),
  });

  const id1 = await store.create("u1", cryptoHandle, {
    name: "secret",
    addedLiquidity: 1,
  });
  const stolen = adapter.rows.get(`rebalance_simulations:u1:${id1}`)!;
  // move the ciphertext to a different id: decryption under that id must fail
  // (different AAD.rowId → invalid GCM auth tag).
  adapter.rows.set(`rebalance_simulations:u1:other-id`, stolen);

  await assert.rejects(() => store.list("u1", cryptoHandle));
});

test("defineStore many: adapter without 'list' → explicit error", async () => {
  configureSecureStore({ storage: noManyAdapter() });
  const cryptoHandle = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "rebalance_simulations",
    identity: "many",
    encrypt: "all",
    schema: Sim,
    version: 1,
    schemaFingerprint: fingerprintSchema(Sim, "all"),
  });

  await assert.rejects(
    () => store.list("u1", cryptoHandle),
    /doesn't support 'many' \(list missing\)/,
  );
});

test("defineStore many: Zod validation on create rejects non-conforming data", async () => {
  const adapter = collectionMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "rebalance_simulations",
    identity: "many",
    encrypt: "all",
    schema: Sim,
    version: 1,
    schemaFingerprint: fingerprintSchema(Sim, "all"),
  });

  await assert.rejects(
    // @ts-expect-error — name must be a string: intentional error
    () => store.create("u1", cryptoHandle, { name: 123, addedLiquidity: 1 }),
    /write rejected/,
  );
  assert.equal(adapter.rows.size, 0);
});

test("defineStore many: idGenerator overrides the default UUIDv4 for row ids", async () => {
  const adapter = collectionMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

  let counter = 0;
  const store = defineStore({
    name: "rebalance_simulations",
    identity: "many",
    encrypt: "all",
    schema: Sim,
    version: 1,
    schemaFingerprint: fingerprintSchema(Sim, "all"),
    idGenerator: () => `sim-${++counter}`,
  });

  const id1 = await store.create("u1", cryptoHandle, {
    name: "a",
    addedLiquidity: 0,
  });
  const id2 = await store.create("u1", cryptoHandle, {
    name: "b",
    addedLiquidity: 0,
  });
  assert.equal(id1, "sim-1");
  assert.equal(id2, "sim-2");
});
