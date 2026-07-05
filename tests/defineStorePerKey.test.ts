import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import { z } from "zod";

import { createDekHandle } from "./testKeyHandle.ts";
import {
  configureSecureStore,
  defineStore,
  fingerprintSchema,
  OptimisticLockConflictError,
  type StorageAdapter,
  type BlobRecord,
  type CryptoHandle,
  type KeyProvider,
} from "../index.ts";

// `get()`/`mutate()` resolve the cryptoHandle ambiently from the configured KeyProvider —
// the caller never sees a `CryptoHandle`. This fake mirrors a single
// already-unlocked session, exactly like the real `passkeyDekController` at runtime.
function fixedKeyProvider(cryptoHandle: CryptoHandle | null): KeyProvider {
  return {
    getCryptoHandle: () => cryptoHandle,
    getUserId: () => "u1",
    subscribe: () => () => {},
  };
}

// In-memory adapter with perKey support, indexed by (collection, userId, keyValue).
// Also implements `putIfMatch` (needed by the optimisticLock mutate() test below).
function keyedMemoryAdapter(): StorageAdapter & {
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
    async putIfMatch(collection, userId, extraKeys, record, expectedHash) {
      const key = `${collection}:${userId}:${extraKeys[0]?.value}`;
      const current = rows.get(key) ?? null;
      if (expectedHash === null) {
        if (current) return false;
        rows.set(key, record);
        return true;
      }
      if (!current || current.contentHash !== expectedHash) return false;
      rows.set(key, record);
      return true;
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

const Batch = z.object({ transactions: z.array(z.string()).default([]) });

test("defineStore perKey: get() reads ambiently for the given key — no cryptoHandle in sight", async () => {
  const adapter = keyedMemoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "transaction_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  assert.deepEqual(await store.get("2026-06"), { transactions: [] });
  await store.save("u1", cryptoHandle, "2026-06", { transactions: ["t1"] });
  assert.deepEqual(await store.get("2026-06"), {
    transactions: ["t1"],
  });
});

test("defineStore perKey: set() writes ambiently for the given key, no read involved — no cryptoHandle in sight", async () => {
  const adapter = keyedMemoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "transaction_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.set("2026-06", { transactions: ["t1"] });
  assert.deepEqual(await store.load("u1", cryptoHandle, "2026-06"), {
    transactions: ["t1"],
  });
  // A different key is untouched.
  assert.deepEqual(await store.load("u1", cryptoHandle, "2026-07"), {
    transactions: [],
  });
});

test("defineStore perKey: set() throws an explicit error when locked (no active cryptoHandle)", async () => {
  const adapter = keyedMemoryAdapter();
  configureSecureStore({ storage: adapter, keys: fixedKeyProvider(null) });

  const store = defineStore({
    name: "transaction_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await assert.rejects(
    () => store.set("2026-06", { transactions: [] }),
    /no cryptoHandle|locked/i,
  );
});

test("defineStore perKey: set() refuses to run on an optimisticLock store — a blind overwrite would bypass the lock the store owner asked for", async () => {
  const adapter = keyedMemoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "transaction_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    contentHash: true,
    optimisticLock: true,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await assert.rejects(
    () => store.set("2026-06", { transactions: ["t1"] }),
    /optimisticLock.*mutate/i,
  );
});

test("defineStore perKey: mutate() loads for the given key, applies the transform, saves, and returns the result — no cryptoHandle in sight", async () => {
  const adapter = keyedMemoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "transaction_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.save("u1", cryptoHandle, "2026-06", { transactions: ["t1"] });

  const result = await store.mutate("2026-06", (current) => ({
    transactions: [...current.transactions, "t2"],
  }));

  assert.deepEqual(result, { transactions: ["t1", "t2"] });
  // A different key is untouched.
  assert.deepEqual(await store.load("u1", cryptoHandle, "2026-07"), {
    transactions: [],
  });
});

test("defineStore perKey: mutate() throws an explicit error when locked (no active cryptoHandle)", async () => {
  const adapter = keyedMemoryAdapter();
  configureSecureStore({ storage: adapter, keys: fixedKeyProvider(null) });

  const store = defineStore({
    name: "transaction_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await assert.rejects(
    () => store.mutate("2026-06", (current) => current),
    /no cryptoHandle|locked/i,
  );
});

test("defineStore perKey: mutate() on an optimisticLock store throws OptimisticLockConflictError on conflict", async () => {
  const adapter = keyedMemoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "transaction_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    contentHash: true,
    optimisticLock: true,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.save("u1", cryptoHandle, "2026-06", { transactions: ["t1"] });

  await assert.rejects(
    () =>
      store.mutate("2026-06", (current) => {
        // Simulates someone else writing between our read and our write.
        adapter.rows.delete("transaction_blobs:u1:2026-06");
        return { transactions: [...current.transactions, "t2"] };
      }),
    (error: unknown) => {
      assert.ok(error instanceof OptimisticLockConflictError);
      return true;
    },
  );
});

test("defineStore perKey: roundtrip per key + independent keys", async () => {
  const adapter = keyedMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "transaction_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  // non-existent key → derived empty
  assert.deepEqual(await store.load("u1", cryptoHandle, "2026-06"), {
    transactions: [],
  });

  await store.save("u1", cryptoHandle, "2026-06", { transactions: ["june"] });
  await store.save("u1", cryptoHandle, "2026-07", { transactions: ["july"] });

  // the two months are distinct, independent rows
  assert.deepEqual(await store.load("u1", cryptoHandle, "2026-06"), {
    transactions: ["june"],
  });
  assert.deepEqual(await store.load("u1", cryptoHandle, "2026-07"), {
    transactions: ["july"],
  });

  const raw = adapter.rows.get("transaction_blobs:u1:2026-06");
  assert.ok(raw!.blob.startsWith("enc:"));
  assert.ok(!raw!.blob.includes("june"), "plaintext NOT in the ciphertext");
});

test("defineStore perKey: the AAD is bound to the key (ciphertext isn't movable)", async () => {
  const adapter = keyedMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "transaction_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.save("u1", cryptoHandle, "2026-06", { transactions: ["secret"] });

  // move June's ciphertext into July's slot: decryption under the "2026-07" key
  // must fail (different AAD.rowId → invalid GCM auth tag).
  adapter.rows.set(
    "transaction_blobs:u1:2026-07",
    adapter.rows.get("transaction_blobs:u1:2026-06")!,
  );
  await assert.rejects(() => store.load("u1", cryptoHandle, "2026-07"));
});

test("defineStore perKey: Zod validation on write rejects non-conforming data", async () => {
  const adapter = keyedMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

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
    () => store.save("u1", cryptoHandle, "2026-06", { transactions: [123] }),
    /write rejected/,
  );
  assert.equal(adapter.rows.get("transaction_blobs:u1:2026-06"), undefined);
});

test("defineStore perKey: list() range-query returns decrypted entries within [from, to]", async () => {
  const adapter = keyedMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "transaction_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.save("u1", cryptoHandle, "2026-05", { transactions: ["may"] });
  await store.save("u1", cryptoHandle, "2026-06", { transactions: ["june"] });
  await store.save("u1", cryptoHandle, "2026-07", { transactions: ["july"] });
  await store.save("u1", cryptoHandle, "2026-08", { transactions: ["august"] });

  const range = await store.list("u1", cryptoHandle, {
    from: "2026-06",
    to: "2026-07",
  });

  assert.deepEqual(range, [
    { key: "2026-06", data: { transactions: ["june"] } },
    { key: "2026-07", data: { transactions: ["july"] } },
  ]);
});

test("defineStore perKey: getRange() reads a range ambiently — no cryptoHandle in sight", async () => {
  const adapter = keyedMemoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "transaction_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.save("u1", cryptoHandle, "2026-06", { transactions: ["june"] });
  await store.save("u1", cryptoHandle, "2026-07", { transactions: ["july"] });
  await store.save("u1", cryptoHandle, "2026-08", { transactions: ["august"] });

  const range = await store.getRange({ from: "2026-06", to: "2026-07" });

  assert.deepEqual(range, [
    { key: "2026-06", data: { transactions: ["june"] } },
    { key: "2026-07", data: { transactions: ["july"] } },
  ]);
});

test("defineStore perKey: getRange() throws an explicit error when locked (no active cryptoHandle)", async () => {
  const adapter = keyedMemoryAdapter();
  configureSecureStore({ storage: adapter, keys: fixedKeyProvider(null) });

  const store = defineStore({
    name: "transaction_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await assert.rejects(
    () => store.getRange({ from: "2026-06", to: "2026-07" }),
    /no cryptoHandle|locked/i,
  );
});

test("defineStore perKey: list() range-query still enforces per-key AAD", async () => {
  const adapter = keyedMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "transaction_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.save("u1", cryptoHandle, "2026-06", { transactions: ["secret"] });
  adapter.rows.set(
    "transaction_blobs:u1:2026-07",
    adapter.rows.get("transaction_blobs:u1:2026-06")!,
  );

  await assert.rejects(() =>
    store.list("u1", cryptoHandle, { from: "2026-06", to: "2026-07" }),
  );
});

test("defineStore perKey: adapter without listByKeyRange → explicit error", async () => {
  const adapter: StorageAdapter = {
    async get() {
      return null;
    },
    async put() {},
  };
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "transaction_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await assert.rejects(
    () => store.list("u1", cryptoHandle, { from: "2026-06", to: "2026-07" }),
    /doesn't support perKey range queries \(listByKeyRange missing\)/,
  );
});
