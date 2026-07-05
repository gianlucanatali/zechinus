/**
 * Regression test: a pre-existing row with no content_hash yet (legacy data, written
 * before `content_hash` was tracked, or before `contentHash: true` was declared on this
 * store) must NOT be treated as a conflict by `saveIfMatch`/`mutate()` just because
 * `expectedHash` reads back as `null` — `null` means "no REAL hash yet", which covers
 * both "no row exists" and "row exists but its hash column is null", not just the
 * former. Exercises the fix at the `StorageAdapter` contract level through
 * `defineBlobStore`'s public `loadWithHash`/`saveIfMatch` — `pgStorageAdapter`/
 * `supabaseStorageAdapter` have their own dedicated SQL-level tests for the same fix.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import { createDekHandle } from "./testKeyHandle.ts";
import { defineBlobStore } from "../core/blobStore.ts";
import { canonicalAAD } from "../core/rowStore.ts";
import { encodeBlob } from "../core/blobCodec.ts";
import type { StorageAdapter, BlobRecord } from "../core/types.ts";
import {
  configureSecureStore,
  __resetSecureStoreConfig,
} from "../core/config.ts";

/**
 * Mirrors the CORRECTED semantics shipped in `pgStorageAdapter`/`supabaseStorageAdapter`:
 * `expectedHash: null` succeeds unless the existing row already has a REAL (non-null)
 * hash — not "unless a row exists at all".
 */
function fixedConditionalMemoryAdapter(): StorageAdapter & {
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
        if (current?.contentHash != null) return false; // a REAL hash beat us to it
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

test("optimisticLock legacy row: mutate() succeeds on a pre-existing row that was never hashed (no false conflict)", async () => {
  const adapter = fixedConditionalMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

  const store = defineBlobStore<Data>({
    name: "x_blobs",
    version: 1,
    empty: { count: 0 },
    contentHash: true,
    optimisticLock: true,
  });

  // Simulate data written before `content_hash` existed: a valid encrypted row with
  // no hash column populated — NOT written through `store.save()`, which would always
  // compute one now that `contentHash: true` is declared on this store.
  const legacyRecord = await encodeBlob(
    cryptoHandle,
    canonicalAAD(cryptoHandle, "x_blobs"),
    { count: 1 },
    1,
    false, // no content_hash — the legacy case
  );
  adapter.rows.set("x_blobs:u1", legacyRecord);

  const { data, hash } = await store.loadWithHash!("u1", cryptoHandle);
  assert.deepEqual(data, { count: 1 });
  assert.equal(
    hash,
    null,
    "loadWithHash surfaces the legacy row's absent hash as null",
  );

  const result = await store.saveIfMatch!(
    "u1",
    cryptoHandle,
    { count: 2 },
    hash,
  );
  assert.equal(
    result.ok,
    true,
    "a legacy row with no hash must not be treated as a conflict",
  );
  assert.ok(result.hash, "the row now has a real hash after this write");

  assert.deepEqual((await store.loadWithHash!("u1", cryptoHandle)).data, {
    count: 2,
  });
});

test("optimisticLock legacy row: a REAL pre-existing hash still causes a genuine conflict (ok:false, no throw)", async () => {
  const adapter = fixedConditionalMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

  const store = defineBlobStore<Data>({
    name: "x_blobs",
    version: 1,
    empty: { count: 0 },
    contentHash: true,
    optimisticLock: true,
  });

  // Someone else already wrote a real, hashed version.
  const first = await store.saveIfMatch!(
    "u1",
    cryptoHandle,
    { count: 1 },
    null,
  );
  assert.equal(first.ok, true);

  // A caller that (incorrectly) still believes there's no hash yet — e.g. it read
  // stale state before the first write landed — must be rejected, not silently
  // accepted: content_hash is genuinely populated now.
  const conflict = await store.saveIfMatch!(
    "u1",
    cryptoHandle,
    { count: 2 },
    null,
  );
  assert.equal(conflict.ok, false);

  assert.deepEqual((await store.loadWithHash!("u1", cryptoHandle)).data, {
    count: 1,
  });
});
