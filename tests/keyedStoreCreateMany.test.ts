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
  type CacheAdapter,
} from "../index.ts";
import { keyedRangeEpochCacheKey } from "../core/store.ts";

function memoryCache(): CacheAdapter {
  const data = new Map<string, unknown>();
  return {
    get: (key) => data.get(key) as never,
    set: (key, value) => {
      data.set(key, value);
    },
    subscribe: () => () => {},
    clear: () => data.clear(),
  };
}

// `createMany()` resolves the cryptoHandle ambiently from the configured
// KeyProvider, same as `get()`/`set()`/`mutate()` — the caller never sees a
// `CryptoHandle`.
function fixedKeyProvider(cryptoHandle: CryptoHandle | null): KeyProvider {
  return {
    getCryptoHandle: () => cryptoHandle,
    getUserId: () => "u1",
    subscribe: () => () => {},
  };
}

// In-memory adapter with perKey + insertMany support, indexed by
// (collection, userId, keyValue). `insertMany` mirrors a real INSERT (not
// upsert): a row that already exists rejects the whole batch, same as a
// Postgres unique-constraint violation would.
function keyedMemoryAdapterWithInsertMany(): StorageAdapter & {
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
    async insertMany(collection, userId, entries) {
      for (const { extraKeys } of entries) {
        const key = `${collection}:${userId}:${extraKeys[0]?.value}`;
        if (rows.has(key)) {
          throw new Error(
            `insertMany(${collection}): duplicate key ${extraKeys[0]?.value} (unique violation)`,
          );
        }
      }
      for (const { extraKeys, record } of entries) {
        rows.set(`${collection}:${userId}:${extraKeys[0]?.value}`, record);
      }
    },
  };
}

const Batch = z.object({ transactions: z.array(z.string()).default([]) });

test("keyed store createMany: writes N distinct keys in one round-trip, each readable back", async () => {
  const adapter = keyedMemoryAdapterWithInsertMany();
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

  await store.createMany([
    { key: "2026-06", data: { transactions: ["june"] } },
    { key: "2026-07", data: { transactions: ["july"] } },
  ]);

  assert.deepEqual(await store.get("2026-06"), { transactions: ["june"] });
  assert.deepEqual(await store.get("2026-07"), { transactions: ["july"] });
});

test("keyed store createMany: empty array is a no-op (no adapter call)", async () => {
  const adapter = keyedMemoryAdapterWithInsertMany();
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

  await store.createMany([]);
  assert.equal(adapter.rows.size, 0);
});

test("keyed store createMany: rejects if any of the N keys already exists (insert, not upsert)", async () => {
  const adapter = keyedMemoryAdapterWithInsertMany();
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

  await store.save("u1", cryptoHandle, "2026-06", {
    transactions: ["existing"],
  });

  await assert.rejects(
    () =>
      store.createMany([
        { key: "2026-06", data: { transactions: ["clobber"] } },
        { key: "2026-07", data: { transactions: ["july"] } },
      ]),
    /duplicate key/,
  );

  // The pre-existing key is untouched by the failed batch.
  assert.deepEqual(await store.get("2026-06"), { transactions: ["existing"] });
});

test("keyed store createMany: the AAD is bound to the key (ciphertext isn't movable)", async () => {
  const adapter = keyedMemoryAdapterWithInsertMany();
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

  await store.createMany([
    { key: "2026-06", data: { transactions: ["secret"] } },
  ]);

  // Move June's ciphertext into July's slot: decryption under the "2026-07"
  // key must fail (different AAD.rowId → invalid GCM auth tag).
  adapter.rows.set(
    "transaction_blobs:u1:2026-07",
    adapter.rows.get("transaction_blobs:u1:2026-06")!,
  );
  await assert.rejects(() => store.get("2026-07"));
});

test("keyed store createMany: Zod validation rejects a bad entry before any I/O", async () => {
  const adapter = keyedMemoryAdapterWithInsertMany();
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

  await assert.rejects(
    () =>
      store.createMany([
        { key: "2026-06", data: { transactions: ["ok"] } },
        // @ts-expect-error — transactions must be string[]: intentional error
        { key: "2026-07", data: { transactions: [123] } },
      ]),
    /write rejected/,
  );
  assert.equal(adapter.rows.size, 0);
});

test("keyed store createMany: adapter without insertMany → explicit error", async () => {
  const adapter: StorageAdapter = {
    async get() {
      return null;
    },
    async put() {},
  };
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

  await assert.rejects(
    () => store.createMany([{ key: "2026-06", data: { transactions: [] } }]),
    /doesn't support bulk keyed creation \(insertMany missing\)/,
  );
});

test("keyed store createMany: cache-aware like set()/mutate() — each key's slot is populated, ONE epoch bump for the whole batch", async () => {
  const adapter = keyedMemoryAdapterWithInsertMany();
  const cache = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    cache,
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

  await store.createMany([
    { key: "2026-06", data: { transactions: ["june"] } },
    { key: "2026-07", data: { transactions: ["july"] } },
  ]);

  // A useKeyedStoreRange mounted on a range covering these months must see
  // them without a full list() — same write-through as an ambient set()/mutate().
  const juneEntry = cache.get<{ data: unknown; hash: string | null }>(
    "transaction_blobs:u1:2026-06",
  );
  const julyEntry = cache.get<{ data: unknown; hash: string | null }>(
    "transaction_blobs:u1:2026-07",
  );
  assert.deepEqual(juneEntry?.data, { transactions: ["june"] });
  assert.deepEqual(julyEntry?.data, { transactions: ["july"] });

  // ONE epoch bump for the whole batch, not one per created key — a mounted
  // useKeyedStoreRange should refetch once, not N times, after a bulk seed.
  const epoch = cache.get<number>(
    keyedRangeEpochCacheKey("transaction_blobs", "u1"),
  );
  assert.equal(epoch, 1);
});
