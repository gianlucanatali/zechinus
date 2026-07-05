/**
 * `contentHash: true` requires the `CryptoHandle` to implement `hashContent`
 * (see `types.ts`'s TSDoc on `CryptoHandle.hashContent`). A handle that is
 * merely structurally valid (has `pid`/`encryptJson`/`decryptJson` but no
 * `hashContent`) must fail loud at the point it would need to compute a
 * hash — never silently skip the hash or fall back to an unkeyed digest.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import { z } from "zod";

import { encodeBlob } from "../core/blobCodec.ts";
import { encryptJson, decryptJson } from "../core/crypto.ts";
import type { CryptoHandle } from "../core/types.ts";
import {
  configureSecureStore,
  __resetSecureStoreConfig,
  defineStore,
  fingerprintSchema,
  type StorageAdapter,
  type BlobRecord,
} from "../index.ts";

function minimalCryptoHandle(dek: Uint8Array): CryptoHandle {
  return {
    pid: "u1",
    encryptJson: (value, aad) => encryptJson(dek, value, aad),
    decryptJson: (enc, aad) => decryptJson(dek, enc, aad),
  };
}

test.beforeEach(() => __resetSecureStoreConfig());

test("encodeBlob: contentHash requested but the handle lacks hashContent → explicit error, no silent fallback", async () => {
  const handle = minimalCryptoHandle(randomBytes(32));
  const aad = {
    userId: handle.pid,
    table: "no_hash_capability_blobs",
    field: "data",
    rowId: handle.pid,
  };

  await assert.rejects(
    () => encodeBlob(handle, aad, { count: 1 }, 1, true),
    /no_hash_capability_blobs.*hashContent/s,
  );
});

test("encodeBlob: without contentHash requested, a minimal handle without hashContent works fine", async () => {
  const handle = minimalCryptoHandle(randomBytes(32));
  const aad = {
    userId: handle.pid,
    table: "no_hash_capability_blobs",
    field: "data",
    rowId: handle.pid,
  };

  const record = await encodeBlob(handle, aad, { count: 1 }, 1, false);
  assert.equal(record.contentHash, undefined);
});

test("defineStore: save() on a contentHash:true store with a hashContent-less handle throws, naming the store", async () => {
  const rows = new Map<string, BlobRecord>();
  const adapter: StorageAdapter = {
    async get(collection, userId) {
      return rows.get(`${collection}:${userId}`) ?? null;
    },
    async put(collection, userId, _extraKeys, record) {
      rows.set(`${collection}:${userId}`, record);
    },
  };
  configureSecureStore({ storage: adapter });

  const Data = z.object({ count: z.number().default(0) });
  const store = defineStore({
    name: "no_hash_capability_blobs",
    encrypt: "all",
    schema: Data,
    version: 1,
    contentHash: true,
    schemaFingerprint: fingerprintSchema(Data, "all"),
  });

  const handle = minimalCryptoHandle(randomBytes(32));
  await assert.rejects(
    () => store.save("u1", handle, { count: 1 }),
    /no_hash_capability_blobs.*hashContent/s,
  );
});
