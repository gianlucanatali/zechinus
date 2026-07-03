import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import { z } from "zod";

import { createDekHandle } from "../../crypto/passkey-prf.ts";
import {
  configureSecureStore,
  defineStore,
  fingerprintSchema,
  type StorageAdapter,
  type BlobRecord,
} from "../index.ts";

// In-memory adapter with perKey support, indexed by (collection, userId, keyValue).
function keyedMemoryAdapter(): StorageAdapter & {
  rows: Map<string, BlobRecord>;
} {
  const rows = new Map<string, BlobRecord>();
  return {
    rows,
    async getOne() {
      return null;
    },
    async putOne() {
      /* perUser not used in these tests */
    },
    async getByKey(collection, userId, _keyColumn, keyValue) {
      return rows.get(`${collection}:${userId}:${keyValue}`) ?? null;
    },
    async putByKey(collection, userId, _keyColumn, keyValue, record) {
      rows.set(`${collection}:${userId}:${keyValue}`, record);
    },
    async listByKeyRange(collection, userId, _keyColumn, from, to) {
      const prefix = `${collection}:${userId}:`;
      const out: Array<{ key: string; record: BlobRecord }> = [];
      for (const [rowKey, record] of rows) {
        if (!rowKey.startsWith(prefix)) continue;
        const key = rowKey.slice(prefix.length);
        if (key >= from && key <= to) out.push({ key, record });
      }
      return out.sort((a, b) => a.key.localeCompare(b.key));
    },
  };
}

// perUser-only adapter (no getByKey/putByKey) to test the explicit error.
function perUserOnlyAdapter(): StorageAdapter {
  return {
    async getOne() {
      return null;
    },
    async putOne() {},
  };
}

const Batch = z.object({ transactions: z.array(z.string()).default([]) });

test("defineStore perKey: roundtrip per key + independent keys", async () => {
  const adapter = keyedMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const dek = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "transaction_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  // non-existent key → derived empty
  assert.deepEqual(await store.load("u1", dek, "2026-06"), {
    transactions: [],
  });

  await store.save("u1", dek, "2026-06", { transactions: ["june"] });
  await store.save("u1", dek, "2026-07", { transactions: ["july"] });

  // the two months are distinct, independent rows
  assert.deepEqual(await store.load("u1", dek, "2026-06"), {
    transactions: ["june"],
  });
  assert.deepEqual(await store.load("u1", dek, "2026-07"), {
    transactions: ["july"],
  });

  const raw = adapter.rows.get("transaction_blobs:u1:2026-06");
  assert.ok(raw!.blob.startsWith("enc:"));
  assert.ok(!raw!.blob.includes("june"), "plaintext NOT in the ciphertext");
});

test("defineStore perKey: the AAD is bound to the key (ciphertext isn't movable)", async () => {
  const adapter = keyedMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const dek = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "transaction_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.save("u1", dek, "2026-06", { transactions: ["secret"] });

  // move June's ciphertext into July's slot: decryption under the "2026-07" key
  // must fail (different AAD.rowId → invalid GCM auth tag).
  adapter.rows.set(
    "transaction_blobs:u1:2026-07",
    adapter.rows.get("transaction_blobs:u1:2026-06")!,
  );
  await assert.rejects(() => store.load("u1", dek, "2026-07"));
});

test("defineStore perKey: adapter without getByKey → explicit error", async () => {
  configureSecureStore({ storage: perUserOnlyAdapter() });
  const dek = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "transaction_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await assert.rejects(
    () => store.load("u1", dek, "2026-06"),
    /doesn't support perKey \(getByKey missing\)/,
  );
});

test("defineStore perKey: Zod validation on write rejects non-conforming data", async () => {
  const adapter = keyedMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const dek = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "transaction_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await assert.rejects(
    // @ts-expect-error — transactions must be string[]: intentional error
    () => store.save("u1", dek, "2026-06", { transactions: [123] }),
    /write rejected/,
  );
  assert.equal(adapter.rows.get("transaction_blobs:u1:2026-06"), undefined);
});

test("defineStore perKey: list() range-query returns decrypted entries within [from, to]", async () => {
  const adapter = keyedMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const dek = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "transaction_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.save("u1", dek, "2026-05", { transactions: ["may"] });
  await store.save("u1", dek, "2026-06", { transactions: ["june"] });
  await store.save("u1", dek, "2026-07", { transactions: ["july"] });
  await store.save("u1", dek, "2026-08", { transactions: ["august"] });

  const range = await store.list("u1", dek, { from: "2026-06", to: "2026-07" });

  assert.deepEqual(range, [
    { key: "2026-06", data: { transactions: ["june"] } },
    { key: "2026-07", data: { transactions: ["july"] } },
  ]);
});

test("defineStore perKey: list() range-query still enforces per-key AAD", async () => {
  const adapter = keyedMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const dek = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "transaction_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.save("u1", dek, "2026-06", { transactions: ["secret"] });
  adapter.rows.set(
    "transaction_blobs:u1:2026-07",
    adapter.rows.get("transaction_blobs:u1:2026-06")!,
  );

  await assert.rejects(() =>
    store.list("u1", dek, { from: "2026-06", to: "2026-07" }),
  );
});

test("defineStore perKey: adapter without listByKeyRange → explicit error", async () => {
  const adapter: StorageAdapter = {
    async getOne() {
      return null;
    },
    async putOne() {},
    async getByKey() {
      return null;
    },
    async putByKey() {},
  };
  configureSecureStore({ storage: adapter });
  const dek = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "transaction_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await assert.rejects(
    () => store.list("u1", dek, { from: "2026-06", to: "2026-07" }),
    /doesn't support perKey range queries \(listByKeyRange missing\)/,
  );
});
