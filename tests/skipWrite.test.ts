/**
 * Skip-write: `mutate()` avoids the encrypt+upload round-trip when the transform
 * produces content identical to what was just read — compares the new content's hash
 * (computed on the plaintext envelope, no encryption needed) against the hash already
 * known from the load that `mutate()` just did. Only for stores WITHOUT
 * `optimisticLock` (see the safety gate test below) and only in `mutate()` (`set()`/
 * `save()` never read a "current" to compare against).
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
  type CryptoHandle,
  type KeyProvider,
} from "../index.ts";

function fixedKeyProvider(cryptoHandle: CryptoHandle | null): KeyProvider {
  return {
    getCryptoHandle: () => cryptoHandle,
    getUserId: () => "u1",
    subscribe: () => () => {},
  };
}

function countingMemoryAdapter(
  opts: { withPutIfMatch?: boolean } = {},
): StorageAdapter & {
  rows: Map<string, BlobRecord>;
  putCalls: number;
  putIfMatchCalls: number;
} {
  const rows = new Map<string, BlobRecord>();
  const rowKey = (
    collection: string,
    userId: string,
    extraKeys: { column: string; value: string }[],
  ) => `${collection}:${userId}:${extraKeys[0]?.value ?? ""}`;

  const adapter: StorageAdapter & {
    rows: typeof rows;
    putCalls: number;
    putIfMatchCalls: number;
  } = {
    rows,
    putCalls: 0,
    putIfMatchCalls: 0,
    async get(collection, userId, extraKeys) {
      return rows.get(rowKey(collection, userId, extraKeys)) ?? null;
    },
    async put(collection, userId, extraKeys, record) {
      adapter.putCalls++;
      rows.set(rowKey(collection, userId, extraKeys), record);
    },
  };
  if (opts.withPutIfMatch) {
    adapter.putIfMatch = async (
      collection,
      userId,
      extraKeys,
      record,
      expectedHash,
    ) => {
      adapter.putIfMatchCalls++;
      const key = rowKey(collection, userId, extraKeys);
      const current = rows.get(key) ?? null;
      if (expectedHash === null) {
        if (current?.contentHash != null) return false;
        rows.set(key, record);
        return true;
      }
      if (!current || current.contentHash !== expectedHash) return false;
      rows.set(key, record);
      return true;
    };
  }
  return adapter;
}

const Batch = z.object({ count: z.number().default(0) });

test.beforeEach(() => __resetSecureStoreConfig());

test("skip-write: perKey mutate() does not write when the transform produces identical content", async () => {
  const adapter = countingMemoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "skipwrite_perkey",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    contentHash: true,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.save("u1", cryptoHandle, "2026-01", { count: 1 });
  assert.equal(adapter.putCalls, 1);

  const result = await store.mutate("2026-01", (current) => ({
    count: current.count,
  }));
  assert.deepEqual(result, { count: 1 });
  assert.equal(adapter.putCalls, 1, "no-op transform must not trigger a write");
});

test("skip-write: perKey mutate() writes normally when the transform changes content", async () => {
  const adapter = countingMemoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "skipwrite_perkey_changed",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    contentHash: true,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.save("u1", cryptoHandle, "2026-01", { count: 1 });
  assert.equal(adapter.putCalls, 1);

  const result = await store.mutate("2026-01", (current) => ({
    count: current.count + 1,
  }));
  assert.deepEqual(result, { count: 2 });
  assert.equal(adapter.putCalls, 2, "a real change must always be written");
});

test("skip-write: perKey mutate() always writes on the very first save (hash null, row absent)", async () => {
  const adapter = countingMemoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "skipwrite_perkey_first",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    contentHash: true,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  // fn returns the same shape as the store's empty default — nothing to compare
  // against yet (hash is null because the row doesn't exist), so it must still write.
  const result = await store.mutate("2026-01", (current) => ({ ...current }));
  assert.deepEqual(result, { count: 0 });
  assert.equal(adapter.putCalls, 1);
});

test("skip-write: perKey store without contentHash never skips (unchanged behavior)", async () => {
  const adapter = countingMemoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "skipwrite_no_contenthash",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.save("u1", cryptoHandle, "2026-01", { count: 1 });
  assert.equal(adapter.putCalls, 1);

  await store.mutate("2026-01", (current) => ({ count: current.count }));
  assert.equal(
    adapter.putCalls,
    2,
    "skip-write must not apply without contentHash: true",
  );
});

test("skip-write: perUser mutate() does not write when the transform produces identical content", async () => {
  const adapter = countingMemoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "skipwrite_peruser",
    encrypt: "all",
    schema: Batch,
    version: 1,
    contentHash: true,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.save("u1", cryptoHandle, { count: 1 });
  assert.equal(adapter.putCalls, 1);

  const result = await store.mutate((current) => ({ count: current.count }));
  assert.deepEqual(result, { count: 1 });
  assert.equal(adapter.putCalls, 1, "no-op transform must not trigger a write");
});

test("skip-write: CRITICAL — an optimisticLock store always goes through the conflict-checked write, even for a no-op transform", async () => {
  const adapter = countingMemoryAdapter({ withPutIfMatch: true });
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "skipwrite_optimistic_lock",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Batch,
    version: 1,
    contentHash: true,
    optimisticLock: true,
    schemaFingerprint: fingerprintSchema(Batch, "all"),
  });

  await store.save("u1", cryptoHandle, "2026-01", { count: 1 });
  assert.equal(adapter.putIfMatchCalls, 0);

  const result = await store.mutate("2026-01", (current) => ({
    count: current.count,
  }));
  assert.deepEqual(result, { count: 1 });
  assert.equal(
    adapter.putIfMatchCalls,
    1,
    "skip-write must never bypass the conflict check on an optimisticLock store",
  );
});
