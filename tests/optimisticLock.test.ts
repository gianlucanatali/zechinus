/**
 * Optimistic locking (`defineBlobStore`'s `contentHash: true` + `optimisticLock: true`)
 * for perUser stores: `saveIfMatch` writes only if the row's current content_hash
 * still matches what the caller last read (`loadWithHash`) — `false` on conflict,
 * never thrown, since a conflict is an expected, recoverable outcome (someone else
 * wrote first), not an error.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import { createDekHandle } from "./testKeyHandle.ts";
import { defineBlobStore } from "../core/blobStore.ts";
import type { StorageAdapter, BlobRecord } from "../core/types.ts";
import {
  configureSecureStore,
  __resetSecureStoreConfig,
} from "../core/config.ts";

function conditionalMemoryAdapter(): StorageAdapter & {
  rows: Map<string, BlobRecord>;
} {
  const rows = new Map<string, BlobRecord>();
  return {
    rows,
    async get(collection, userId) {
      return rows.get(`${collection}:${userId}`) ?? null;
    },
    async put(collection, userId, _extraKeys, record) {
      rows.set(`${collection}:${userId}`, record);
    },
    async putIfMatch(collection, userId, _extraKeys, record, expectedHash) {
      const key = `${collection}:${userId}`;
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

type Data = { count: number };

test.beforeEach(() => __resetSecureStoreConfig());

test("optimisticLock: defineBlobStore throws at definition time if optimisticLock is set without contentHash", () => {
  assert.throws(
    () =>
      defineBlobStore<Data>({
        name: "x_blobs",
        version: 1,
        empty: { count: 0 },
        optimisticLock: true,
      }),
    /optimisticLock.*requires.*contentHash/,
  );
});

test("optimisticLock: saveIfMatch succeeds when expectedHash matches the stored one", async () => {
  const adapter = conditionalMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

  const store = defineBlobStore<Data>({
    name: "x_blobs",
    version: 1,
    empty: { count: 0 },
    contentHash: true,
    optimisticLock: true,
  });

  const first = await store.saveIfMatch!(
    "u1",
    cryptoHandle,
    { count: 1 },
    null,
  );
  assert.equal(first.ok, true);
  assert.ok(first.hash);

  const { data, hash } = await store.loadWithHash!("u1", cryptoHandle);
  assert.deepEqual(data, { count: 1 });
  assert.equal(hash, first.hash);

  // The hash returned by saveIfMatch is directly usable for the next write — no
  // extra fetch needed to learn the new "current" hash.
  const second = await store.saveIfMatch!(
    "u1",
    cryptoHandle,
    { count: 2 },
    first.hash,
  );
  assert.equal(second.ok, true);
  assert.ok(second.hash);
  assert.notEqual(second.hash, first.hash);
  assert.deepEqual((await store.loadWithHash!("u1", cryptoHandle)).data, {
    count: 2,
  });
});

test("optimisticLock: saveIfMatch fails (ok:false, no throw) when someone else wrote first", async () => {
  const adapter = conditionalMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

  const store = defineBlobStore<Data>({
    name: "x_blobs",
    version: 1,
    empty: { count: 0 },
    contentHash: true,
    optimisticLock: true,
  });

  await store.saveIfMatch!("u1", cryptoHandle, { count: 1 }, null);
  const { hash: staleHash } = await store.loadWithHash!("u1", cryptoHandle);

  // A "concurrent tab" writes using the same starting hash, winning the race.
  await store.saveIfMatch!("u1", cryptoHandle, { count: 99 }, staleHash);

  // Our own write, still using the now-stale hash, must be rejected — not throw.
  const conflict = await store.saveIfMatch!(
    "u1",
    cryptoHandle,
    { count: 2 },
    staleHash,
  );
  assert.equal(conflict.ok, false);
  assert.equal(conflict.hash, null); // no misleading hash on a rejected write

  // The winning write's value is untouched by our rejected attempt.
  assert.deepEqual((await store.loadWithHash!("u1", cryptoHandle)).data, {
    count: 99,
  });
});

test("optimisticLock: adapter without putIfMatch → explicit error, not silent fallback", async () => {
  configureSecureStore({
    storage: {
      async get() {
        return null;
      },
      async put() {},
    },
  });
  const cryptoHandle = createDekHandle(randomBytes(32));

  const store = defineBlobStore<Data>({
    name: "x_blobs",
    version: 1,
    empty: { count: 0 },
    contentHash: true,
    optimisticLock: true,
  });

  await assert.rejects(
    () => store.saveIfMatch!("u1", cryptoHandle, { count: 1 }, null),
    /doesn't support optimistic locking \(putIfMatch missing\)/,
  );
});
