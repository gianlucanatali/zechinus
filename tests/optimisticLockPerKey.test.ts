/**
 * Optimistic locking (`defineStore`'s `optimisticLock: true`) for perKey stores —
 * mirrors optimisticLock.test.ts (perUser), exercising the perKey binding in
 * `store.ts` (shares encode/decode/lock orchestration with perUser via
 * `rowStore.ts`, but binds `putByKeyIfMatch`-shaped calls instead of `putOneIfMatch`).
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

function conditionalKeyedAdapter(): StorageAdapter & {
  rows: Map<string, BlobRecord>;
} {
  const rows = new Map<string, BlobRecord>();
  const keyOf = (
    collection: string,
    userId: string,
    extraKeys: { value: string }[],
  ) => `${collection}:${userId}:${extraKeys[0]?.value}`;
  return {
    rows,
    async get(collection, userId, extraKeys) {
      return rows.get(keyOf(collection, userId, extraKeys)) ?? null;
    },
    async put(collection, userId, extraKeys, record) {
      rows.set(keyOf(collection, userId, extraKeys), record);
    },
    async putIfMatch(collection, userId, extraKeys, record, expectedHash) {
      const key = keyOf(collection, userId, extraKeys);
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
  };
}

const Data = z.object({ count: z.number().default(0) });

test.beforeEach(() => __resetSecureStoreConfig());

test("optimisticLock (perKey): defineStore throws at definition time if optimisticLock is set without contentHash", () => {
  assert.throws(
    () =>
      defineStore({
        name: "x_blobs",
        identity: { perKey: "year_month" },
        encrypt: "all",
        schema: Data,
        version: 1,
        schemaFingerprint: fingerprintSchema(Data, "all"),
        optimisticLock: true,
      }),
    /optimisticLock.*requires.*contentHash/,
  );
});

test("optimisticLock (perKey): saveIfMatch succeeds when expectedHash matches, independently per key", async () => {
  const adapter = conditionalKeyedAdapter();
  configureSecureStore({ storage: adapter });
  const dek = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "x_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Data,
    version: 1,
    schemaFingerprint: fingerprintSchema(Data, "all"),
    contentHash: true,
    optimisticLock: true,
  });

  const first = await store.saveIfMatch!(
    "u1",
    dek,
    "2026-06",
    { count: 1 },
    null,
  );
  assert.equal(first.ok, true);
  assert.ok(first.hash);

  const { data, hash } = await store.loadWithHash!("u1", dek, "2026-06");
  assert.deepEqual(data, { count: 1 });
  assert.equal(hash, first.hash);

  // The hash returned by saveIfMatch is directly usable for the next write.
  const second = await store.saveIfMatch!(
    "u1",
    dek,
    "2026-06",
    { count: 2 },
    first.hash,
  );
  assert.equal(second.ok, true);
  assert.ok(second.hash);
  assert.notEqual(second.hash, first.hash);
  assert.deepEqual((await store.loadWithHash!("u1", dek, "2026-06")).data, {
    count: 2,
  });

  // A different key is a fully independent lock — writing it doesn't touch "2026-06"'s.
  const otherKey = await store.saveIfMatch!(
    "u1",
    dek,
    "2026-07",
    { count: 50 },
    null,
  );
  assert.equal(otherKey.ok, true);
  assert.deepEqual((await store.loadWithHash!("u1", dek, "2026-06")).data, {
    count: 2,
  });
});

test("optimisticLock (perKey): saveIfMatch fails (ok:false, no throw) when someone else wrote first", async () => {
  const adapter = conditionalKeyedAdapter();
  configureSecureStore({ storage: adapter });
  const dek = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "x_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Data,
    version: 1,
    schemaFingerprint: fingerprintSchema(Data, "all"),
    contentHash: true,
    optimisticLock: true,
  });

  await store.saveIfMatch!("u1", dek, "2026-06", { count: 1 }, null);
  const { hash: staleHash } = await store.loadWithHash!("u1", dek, "2026-06");

  // A "concurrent tab" writes using the same starting hash, winning the race.
  await store.saveIfMatch!("u1", dek, "2026-06", { count: 99 }, staleHash);

  // Our own write, still using the now-stale hash, must be rejected — not throw.
  const conflict = await store.saveIfMatch!(
    "u1",
    dek,
    "2026-06",
    { count: 2 },
    staleHash,
  );
  assert.equal(conflict.ok, false);
  assert.equal(conflict.hash, null);

  // The winning write's value is untouched by our rejected attempt.
  assert.deepEqual((await store.loadWithHash!("u1", dek, "2026-06")).data, {
    count: 99,
  });
});

test("optimisticLock (perKey): adapter without putIfMatch → explicit error, not silent fallback", async () => {
  configureSecureStore({
    storage: {
      async get() {
        return null;
      },
      async put() {},
    },
  });
  const dek = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "x_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Data,
    version: 1,
    schemaFingerprint: fingerprintSchema(Data, "all"),
    contentHash: true,
    optimisticLock: true,
  });

  await assert.rejects(
    () => store.saveIfMatch!("u1", dek, "2026-06", { count: 1 }, null),
    /doesn't support optimistic locking \(putIfMatch missing\)/,
  );
});
