/**
 * Transition coverage for the content_hash algorithm change (plain SHA-256 →
 * keyed HMAC-SHA256, see `keyDerivation.ts`'s `hashContent`). A row written
 * BEFORE the fix has its `content_hash` column populated with the OLD
 * algorithm (SHA-256 of the plaintext envelope, no key). These tests prove
 * that transition is silent and safe: `loadWithHash` passes the stored value
 * through untouched, and any write after that (`saveIfMatch` or `mutate`)
 * converges the row to the new HMAC on its very first touch — never a false
 * optimistic-lock conflict, and skip-write simply doesn't fire once (an
 * extra write, not a bug) until the row has been rewritten with the new
 * algorithm.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import { z } from "zod";

import { createDekHandle } from "./testKeyHandle.ts";
import { encodeBlob } from "../core/blobCodec.ts";
import { toEnvelope } from "../core/versioning.ts";
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

function fixedKeyProvider(cryptoHandle: CryptoHandle): KeyProvider {
  return {
    getCryptoHandle: () => cryptoHandle,
    getUserId: () => "u1",
    subscribe: () => () => {},
  };
}

/** The pre-fix algorithm: plain (unkeyed) SHA-256 of the JSON-stringified envelope. */
async function legacyPlainHash(payload: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify(payload));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function memoryAdapter(): StorageAdapter & { rows: Map<string, BlobRecord> } {
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
        if (current?.contentHash != null) return false;
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

test("content_hash transition: loadWithHash passes a legacy plain-SHA256 hash through unchanged", async () => {
  const adapter = memoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({ storage: adapter });

  const store = defineStore({
    name: "chtransition_loadwithhash",
    encrypt: "all",
    schema: Data,
    version: 1,
    contentHash: true,
    schemaFingerprint: fingerprintSchema(Data, "all"),
  });

  const data = { count: 1 };
  const envelope = toEnvelope(data, 1);
  const record = await encodeBlob(
    cryptoHandle,
    {
      userId: cryptoHandle.pid,
      table: store.name,
      field: "data",
      rowId: cryptoHandle.pid,
    },
    data,
    1,
    false,
  );
  const legacyHash = await legacyPlainHash(envelope);
  record.contentHash = legacyHash;
  adapter.rows.set(`${store.name}:u1`, record);

  const { data: loaded, hash } = await store.loadWithHash!("u1", cryptoHandle);
  assert.deepEqual(loaded, data);
  assert.equal(
    hash,
    legacyHash,
    "stored value must pass through as-is, no recompute on read",
  );
});

test("content_hash transition: saveIfMatch(oldHash) succeeds and converges to the new HMAC — zero false conflicts", async () => {
  const adapter = memoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({ storage: adapter });

  const store = defineStore({
    name: "chtransition_saveifmatch",
    encrypt: "all",
    schema: Data,
    version: 1,
    contentHash: true,
    optimisticLock: true,
    schemaFingerprint: fingerprintSchema(Data, "all"),
  });

  const data = { count: 1 };
  const envelope = toEnvelope(data, 1);
  const record = await encodeBlob(
    cryptoHandle,
    {
      userId: cryptoHandle.pid,
      table: store.name,
      field: "data",
      rowId: cryptoHandle.pid,
    },
    data,
    1,
    false,
  );
  const legacyHash = await legacyPlainHash(envelope);
  record.contentHash = legacyHash;
  adapter.rows.set(`${store.name}:u1`, record);

  const result = await store.saveIfMatch!(
    "u1",
    cryptoHandle,
    { count: 2 },
    legacyHash,
  );
  assert.equal(
    result.ok,
    true,
    "write against the legacy hash must not be a false conflict",
  );
  assert.notEqual(
    result.hash,
    legacyHash,
    "the new stored hash must be the HMAC, not the old SHA-256",
  );

  const stored = adapter.rows.get(`${store.name}:u1`)!;
  assert.equal(
    stored.contentHash,
    await cryptoHandle.hashContent!(toEnvelope({ count: 2 }, 1)),
  );
});

test("content_hash transition: mutate() no-op does NOT skip against a legacy hash, then DOES skip once converged", async () => {
  const adapter = memoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "chtransition_mutate",
    encrypt: "all",
    schema: Data,
    version: 1,
    contentHash: true,
    schemaFingerprint: fingerprintSchema(Data, "all"),
  });

  const data = { count: 1 };
  const envelope = toEnvelope(data, 1);
  const record = await encodeBlob(
    cryptoHandle,
    {
      userId: cryptoHandle.pid,
      table: store.name,
      field: "data",
      rowId: cryptoHandle.pid,
    },
    data,
    1,
    false,
  );
  record.contentHash = await legacyPlainHash(envelope);
  adapter.rows.set(`${store.name}:u1`, record);

  let putCalls = 0;
  const originalPut = adapter.put.bind(adapter);
  adapter.put = async (...args) => {
    putCalls++;
    return originalPut(...args);
  };

  await store.mutate((current) => ({ count: current.count }));
  assert.equal(
    putCalls,
    1,
    "no-op against a legacy hash must NOT skip — mismatch is expected during transition",
  );

  await store.mutate((current) => ({ count: current.count }));
  assert.equal(
    putCalls,
    1,
    "once the row holds the new HMAC, a second no-op mutate must skip",
  );
});
