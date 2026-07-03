import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";

import { createDekHandle } from "./testKeyHandle.ts";
import {
  configureSecureStore,
  __resetSecureStoreConfig,
  defineBlobStore,
  type StorageAdapter,
  type BlobRecord,
} from "../index.ts";

// In-memory adapter: no Supabase required for the encrypted roundtrip.
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
  };
}

type Data = { items: string[] };

test("defineBlobStore: save→load roundtrip + the saved blob is encrypted", async () => {
  const adapter = memoryAdapter();
  configureSecureStore({ storage: adapter });
  const dek = createDekHandle(randomBytes(32));
  const store = defineBlobStore<Data>({
    name: "test_blobs",
    version: 1,
    empty: { items: [] },
  });

  // load of a non-existent record → empty
  assert.deepEqual(await store.load("u1", dek), { items: [] });

  await store.save("u1", dek, { items: ["secret"] });

  // the persisted blob is ciphertext: enc: prefix, plaintext not present
  const raw = adapter.rows.get("test_blobs:u1");
  assert.ok(raw, "saved record present");
  assert.ok(
    raw!.blob.startsWith("enc:"),
    "blob serialized with the enc: prefix",
  );
  assert.ok(
    !raw!.blob.includes("secret"),
    "plaintext NOT present in the ciphertext",
  );
  assert.equal(raw!.schemaVersion, 1);

  // load → decrypts correctly
  assert.deepEqual(await store.load("u1", dek), { items: ["secret"] });
});

test("defineBlobStore: a different DEK doesn't decrypt (AAD/GCM auth tag)", async () => {
  const adapter = memoryAdapter();
  configureSecureStore({ storage: adapter });
  const store = defineBlobStore<Data>({
    name: "test_blobs",
    version: 1,
    empty: { items: [] },
  });

  const dek1 = createDekHandle(randomBytes(32));
  await store.save("u1", dek1, { items: ["x"] });

  const dek2 = createDekHandle(randomBytes(32));
  await assert.rejects(() => store.load("u1", dek2));
});

test("defineBlobStore: without configureSecureStore throws an explicit error", async () => {
  __resetSecureStoreConfig();
  const dek = createDekHandle(randomBytes(32));
  const store = defineBlobStore<Data>({
    name: "test_blobs",
    version: 1,
    empty: { items: [] },
  });
  await assert.rejects(() => store.load("u1", dek), /framework not configured/);
});
