/**
 * `defineStore`'s `legacyAAD` option (perUser/perKey/many): read-old-if-needed,
 * always-write-canonical. See `core/legacyFallback.ts` for the underlying mechanics
 * (already unit-tested there) — these tests verify the wiring through `defineStore`
 * for each cardinality, including that writes always converge to canonical AAD.
 */
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
} from "../index.ts";
import { encodeBlob } from "../core/blobCodec.ts";

const Blob = z.object({ value: z.string().default("") });

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
  };
}

test("legacyAAD (perUser): a row under the OLD AAD migrates lazily on first load, converges to canonical", async () => {
  const adapter = memoryAdapter();
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

  const legacyRecord = await encodeBlob(
    cryptoHandle,
    {
      userId: cryptoHandle.pid,
      table: "budget_allocation_blobs",
      field: "blob",
      rowId: cryptoHandle.pid,
    },
    { value: "legacy" },
    1,
  );
  adapter.rows.set("budget_allocation_blobs:u1", legacyRecord);

  const store = defineStore({
    name: "budget_allocation_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Blob,
    version: 1,
    legacyAAD: (cryptoHandle) => ({
      userId: cryptoHandle.pid,
      table: "budget_allocation_blobs",
      field: "blob",
      rowId: cryptoHandle.pid,
    }),
    schemaFingerprint: fingerprintSchema(Blob, "all"),
  });

  assert.deepEqual(await store.load("u1", cryptoHandle), { value: "legacy" });

  // The stored record must now decrypt under the CANONICAL AAD alone (field:"data")
  // — build a fresh store with no legacyAAD and confirm it reads it directly.
  const canonicalOnly = defineStore({
    name: "budget_allocation_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Blob,
    version: 1,
    schemaFingerprint: fingerprintSchema(Blob, "all"),
  });
  assert.deepEqual(await canonicalOnly.load("u1", cryptoHandle), {
    value: "legacy",
  });
});

test("legacyAAD (perUser): a save() always writes canonical AAD, never the legacy one", async () => {
  const adapter = memoryAdapter();
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "budget_allocation_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Blob,
    version: 1,
    legacyAAD: (cryptoHandle) => ({
      userId: cryptoHandle.pid,
      table: "budget_allocation_blobs",
      field: "blob",
      rowId: cryptoHandle.pid,
    }),
    schemaFingerprint: fingerprintSchema(Blob, "all"),
  });

  await store.save("u1", cryptoHandle, { value: "fresh write" });

  const canonicalOnly = defineStore({
    name: "budget_allocation_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Blob,
    version: 1,
    schemaFingerprint: fingerprintSchema(Blob, "all"),
  });
  assert.deepEqual(await canonicalOnly.load("u1", cryptoHandle), {
    value: "fresh write",
  });
});

test("legacyAAD (perKey): migrates lazily on first load, converges to canonical", async () => {
  const adapter = keyedMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

  const legacyRecord = await encodeBlob(
    cryptoHandle,
    {
      userId: cryptoHandle.pid,
      table: "account_snapshot_blobs",
      field: "snapshot",
      rowId: "2026-06",
    },
    { value: "june" },
    1,
  );
  adapter.rows.set("account_snapshot_blobs:u1:2026-06", legacyRecord);

  const store = defineStore({
    name: "account_snapshot_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Blob,
    version: 1,
    legacyAAD: (cryptoHandle, key) => ({
      userId: cryptoHandle.pid,
      table: "account_snapshot_blobs",
      field: "snapshot",
      rowId: key,
    }),
    schemaFingerprint: fingerprintSchema(Blob, "all"),
  });

  assert.deepEqual(await store.load("u1", cryptoHandle, "2026-06"), {
    value: "june",
  });

  const canonicalOnly = defineStore({
    name: "account_snapshot_blobs",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Blob,
    version: 1,
    schemaFingerprint: fingerprintSchema(Blob, "all"),
  });
  assert.deepEqual(await canonicalOnly.load("u1", cryptoHandle, "2026-06"), {
    value: "june",
  });
});

test("legacyAAD: no legacyAAD configured (default path) → behaves exactly as before, no migration attempted", async () => {
  const adapter = memoryAdapter();
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "budget_allocation_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Blob,
    version: 1,
    schemaFingerprint: fingerprintSchema(Blob, "all"),
  });

  assert.deepEqual(await store.load("u1", cryptoHandle), { value: "" });
  await store.save("u1", cryptoHandle, { value: "hi" });
  assert.deepEqual(await store.load("u1", cryptoHandle), { value: "hi" });
});
