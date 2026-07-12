/**
 * `Store/KeyedStore/CollectionStore.rotateEpoch()` — the generic, framework-level
 * DEK rotation wiring (key-custody roadmap Fase 2.3). Every `defineStore`-created
 * store gets this for free, regardless of cardinality — no app-level rotation code
 * per store. Tests use two REAL `KeyHandle`s (old/new DEK, via `testKeyHandle.ts`)
 * so the epoch-tagging from Fase 2.1 and the pid-changes-with-the-DEK fact
 * (`docs/decisions/2026-07-12-dek-epoch-per-row-aad.md`) are exercised for real.
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

const Item = z.object({ label: z.string().default("") });

// perUser: minimal get/put adapter, no rotation-specific capability required.
function perUserAdapter(): StorageAdapter & { rows: Map<string, BlobRecord> } {
  const rows = new Map<string, BlobRecord>();
  return {
    rows,
    async get(collection, userId) {
      return rows.get(`${collection}:${userId}`) ?? null;
    },
    async put(collection, userId, _extraKeys, record) {
      rows.set(`${collection}:${userId}`, record);
    },
  };
}

// perKey: get/put + listAll (the new capability rotateEpoch needs).
function perKeyAdapter(): StorageAdapter & {
  rows: Map<string, BlobRecord>;
} {
  const rows = new Map<string, BlobRecord>();
  return {
    rows,
    async get(collection, userId, extraKeys) {
      return rows.get(`${collection}:${userId}:${extraKeys[0]?.value}`) ?? null;
    },
    async put(collection, userId, extraKeys, record) {
      rows.set(`${collection}:${userId}:${extraKeys[0]?.value}`, record);
    },
    async listAll(collection, userId, _keyColumn) {
      const prefix = `${collection}:${userId}:`;
      const out: Array<{ key: string; record: BlobRecord }> = [];
      for (const [rowKey, record] of rows) {
        if (rowKey.startsWith(prefix))
          out.push({ key: rowKey.slice(prefix.length), record });
      }
      return out;
    },
  };
}

// perKey adapter deliberately missing listAll — exercises the explicit-throw path.
function perKeyAdapterNoListAll(): StorageAdapter {
  return {
    async get() {
      return null;
    },
    async put() {},
  };
}

// many: list/updateById (both already required by CollectionStore.list()/update()).
function manyAdapter(): StorageAdapter & { rows: Map<string, BlobRecord> } {
  const rows = new Map<string, BlobRecord>();
  const keyOf = (collection: string, userId: string, id: string) =>
    `${collection}:${userId}:${id}`;
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
  };
}

test("perUser rotateEpoch: no row ever saved → no-op, nothing to rotate", async () => {
  __resetSecureStoreConfig();
  const adapter = perUserAdapter();
  configureSecureStore({ storage: adapter });
  const oldHandle = createDekHandle(randomBytes(32));
  const newHandle = createDekHandle(randomBytes(32));
  const store = defineStore({
    name: "rot_peruser",
    identity: "perUser",
    encrypt: "all",
    schema: Item,
    version: 1,
    schemaFingerprint: fingerprintSchema(Item, "all"),
  });

  const result = await store.rotateEpoch("u1", oldHandle, newHandle, 2);
  assert.deepEqual(result, { migrated: 0, alreadyMigrated: 0, failed: [] });
});

test("perUser rotateEpoch: migrates the row — old handle can no longer read it, new handle can, data unchanged", async () => {
  __resetSecureStoreConfig();
  const adapter = perUserAdapter();
  configureSecureStore({ storage: adapter });
  const oldHandle = createDekHandle(randomBytes(32));
  const newHandle = createDekHandle(randomBytes(32));
  const store = defineStore({
    name: "rot_peruser2",
    identity: "perUser",
    encrypt: "all",
    schema: Item,
    version: 1,
    schemaFingerprint: fingerprintSchema(Item, "all"),
  });
  await store.save("u1", oldHandle, { label: "hello" });

  const result = await store.rotateEpoch("u1", oldHandle, newHandle, 2);
  assert.deepEqual(result, { migrated: 1, alreadyMigrated: 0, failed: [] });

  assert.deepEqual(await store.load("u1", newHandle), { label: "hello" });
  await assert.rejects(() => store.load("u1", oldHandle));
});

test("perUser rotateEpoch: idempotent — calling it again after a successful rotation reports alreadyMigrated, doesn't re-write", async () => {
  __resetSecureStoreConfig();
  const adapter = perUserAdapter();
  configureSecureStore({ storage: adapter });
  const oldHandle = createDekHandle(randomBytes(32));
  const newHandle = createDekHandle(randomBytes(32));
  const store = defineStore({
    name: "rot_peruser3",
    identity: "perUser",
    encrypt: "all",
    schema: Item,
    version: 1,
    schemaFingerprint: fingerprintSchema(Item, "all"),
  });
  await store.save("u1", oldHandle, { label: "resume-me" });
  await store.rotateEpoch("u1", oldHandle, newHandle, 2);

  const second = await store.rotateEpoch("u1", oldHandle, newHandle, 2);
  assert.deepEqual(second, { migrated: 0, alreadyMigrated: 1, failed: [] });
  assert.deepEqual(await store.load("u1", newHandle), { label: "resume-me" });
});

test("perKey rotateEpoch: throws by name when the adapter doesn't support listAll", async () => {
  __resetSecureStoreConfig();
  configureSecureStore({ storage: perKeyAdapterNoListAll() });
  const oldHandle = createDekHandle(randomBytes(32));
  const newHandle = createDekHandle(randomBytes(32));
  const store = defineStore({
    name: "rot_perkey_nolistall",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Item,
    version: 1,
    schemaFingerprint: fingerprintSchema(Item, "all"),
  });

  await assert.rejects(
    () => store.rotateEpoch("u1", oldHandle, newHandle, 2),
    /listAll missing/,
  );
});

test("perKey rotateEpoch: migrates every key for the user", async () => {
  __resetSecureStoreConfig();
  const adapter = perKeyAdapter();
  configureSecureStore({ storage: adapter });
  const oldHandle = createDekHandle(randomBytes(32));
  const newHandle = createDekHandle(randomBytes(32));
  const store = defineStore({
    name: "rot_perkey",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Item,
    version: 1,
    schemaFingerprint: fingerprintSchema(Item, "all"),
  });
  await store.save("u1", oldHandle, "2026-01", { label: "jan" });
  await store.save("u1", oldHandle, "2026-02", { label: "feb" });

  const result = await store.rotateEpoch("u1", oldHandle, newHandle, 2);
  assert.deepEqual(result, { migrated: 2, alreadyMigrated: 0, failed: [] });

  assert.deepEqual(await store.load("u1", newHandle, "2026-01"), {
    label: "jan",
  });
  assert.deepEqual(await store.load("u1", newHandle, "2026-02"), {
    label: "feb",
  });
  await assert.rejects(() => store.load("u1", oldHandle, "2026-01"));
});

test("perKey rotateEpoch: idempotent — a re-run reports every key as alreadyMigrated", async () => {
  __resetSecureStoreConfig();
  const adapter = perKeyAdapter();
  configureSecureStore({ storage: adapter });
  const oldHandle = createDekHandle(randomBytes(32));
  const newHandle = createDekHandle(randomBytes(32));
  const store = defineStore({
    name: "rot_perkey2",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Item,
    version: 1,
    schemaFingerprint: fingerprintSchema(Item, "all"),
  });
  await store.save("u1", oldHandle, "2026-01", { label: "jan" });
  await store.rotateEpoch("u1", oldHandle, newHandle, 2);

  const second = await store.rotateEpoch("u1", oldHandle, newHandle, 2);
  assert.deepEqual(second, { migrated: 0, alreadyMigrated: 1, failed: [] });
});

test("many rotateEpoch: migrates every row, corrupted rows are collected in failed[] without aborting the others", async () => {
  __resetSecureStoreConfig();
  const adapter = manyAdapter();
  configureSecureStore({ storage: adapter });
  const oldHandle = createDekHandle(randomBytes(32));
  const newHandle = createDekHandle(randomBytes(32));
  const store = defineStore({
    name: "rot_many",
    identity: "many",
    encrypt: "all",
    schema: Item,
    version: 1,
    schemaFingerprint: fingerprintSchema(Item, "all"),
  });
  const goodId = await store.create("u1", oldHandle, { label: "good" });
  const corruptedId = await store.create("u1", oldHandle, {
    label: "corrupted",
  });
  const corruptedKey = `rot_many:u1:${corruptedId}`;
  const corrupted = adapter.rows.get(corruptedKey)!;
  adapter.rows.set(corruptedKey, {
    ...corrupted,
    blob: corrupted.blob.slice(0, -4) + "abcd",
  });

  const result = await store.rotateEpoch("u1", oldHandle, newHandle, 2);
  assert.equal(result.migrated, 1);
  assert.equal(result.alreadyMigrated, 0);
  assert.equal(result.failed.length, 1);
  assert.equal(result.failed[0].key, corruptedId);

  // Read the good row directly (not via store.list(), which decodes every row
  // in the collection uniformly and would itself throw on the still-corrupted one).
  const { decodeBlob } = await import("../core/blobCodec.ts");
  const goodRecord = adapter.rows.get(`rot_many:u1:${goodId}`)!;
  const { data } = await decodeBlob(
    newHandle,
    { userId: newHandle.pid, table: "rot_many", field: "data", rowId: goodId },
    goodRecord,
    1,
    [],
    {},
  );
  assert.deepEqual(data, { label: "good" });
});

test("many rotateEpoch: idempotent — a re-run reports the row as alreadyMigrated", async () => {
  __resetSecureStoreConfig();
  const adapter = manyAdapter();
  configureSecureStore({ storage: adapter });
  const oldHandle = createDekHandle(randomBytes(32));
  const newHandle = createDekHandle(randomBytes(32));
  const store = defineStore({
    name: "rot_many2",
    identity: "many",
    encrypt: "all",
    schema: Item,
    version: 1,
    schemaFingerprint: fingerprintSchema(Item, "all"),
  });
  await store.create("u1", oldHandle, { label: "solo" });
  await store.rotateEpoch("u1", oldHandle, newHandle, 2);

  const second = await store.rotateEpoch("u1", oldHandle, newHandle, 2);
  assert.deepEqual(second, { migrated: 0, alreadyMigrated: 1, failed: [] });
});
