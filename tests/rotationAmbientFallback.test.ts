/**
 * Ambient read-path fallback to a `previousCryptoHandle` during an in-progress DEK
 * rotation (key-custody roadmap, Fase 2.3/E) — covers all three store cardinalities
 * (`perUser`, `perKey`, `many`). `rotateEpoch()` itself (the explicit batch sweep,
 * Fase 2.2) is untouched and has its own tests (`rotateEpoch.test.ts`); this file
 * covers the OTHER half: an ambient read (`get`/`load`/`getRange`) racing that sweep,
 * hitting a row the sweep hasn't reached yet.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import { z } from "zod";

import { createDekHandle } from "./testKeyHandle.ts";
import { canonicalAAD } from "../core/rowStore.ts";
import { encodeBlob } from "../core/blobCodec.ts";
import {
  configureSecureStore,
  defineStore,
  fingerprintSchema,
  type StorageAdapter,
  type BlobRecord,
  type CryptoHandle,
  type KeyProvider,
} from "../index.ts";

/** KeyProvider stub exposing a togglable `previousCryptoHandle` — mirrors what
 * `passkeyDekController.beginRotation()` sets up for the rest of the session. */
function rotationKeyProvider(
  cryptoHandle: CryptoHandle,
  previousCryptoHandle: CryptoHandle | null,
): KeyProvider {
  return {
    getCryptoHandle: () => cryptoHandle,
    getUserId: () => "u1",
    subscribe: () => () => {},
    getPreviousCryptoHandle: () => previousCryptoHandle,
  };
}

function perUserAdapter(): StorageAdapter & { rows: Map<string, BlobRecord> } {
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

function perKeyAdapter(): StorageAdapter & { rows: Map<string, BlobRecord> } {
  const rows = new Map<string, BlobRecord>();
  return {
    rows,
    async get(collection, userId, extraKeys) {
      return rows.get(`${collection}:${userId}:${extraKeys[0]?.value}`) ?? null;
    },
    async put(collection, userId, extraKeys, record) {
      rows.set(`${collection}:${userId}:${extraKeys[0]?.value}`, record);
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

function manyAdapter(): StorageAdapter & { rows: Map<string, BlobRecord> } {
  const rows = new Map<string, BlobRecord>();
  const keyOf = (collection: string, userId: string, id: string) =>
    `${collection}:${userId}:${id}`;
  return {
    rows,
    async get() {
      return null;
    },
    async put() {},
    async list(collection, userId) {
      const prefix = `${collection}:${userId}:`;
      const out: Array<{
        id: string;
        record: BlobRecord;
        plain: Record<string, unknown>;
      }> = [];
      for (const [key, record] of rows) {
        if (key.startsWith(prefix))
          out.push({ id: key.slice(prefix.length), record, plain: {} });
      }
      return out;
    },
    async insert(collection, userId, id, record) {
      rows.set(keyOf(collection, userId, id), record);
    },
    async updateById(collection, userId, id, record) {
      rows.set(keyOf(collection, userId, id), record);
    },
  };
}

const Item = z.object({ label: z.string().default("") });

// ─── perUser ────────────────────────────────────────────────────────────────

test("perUser get(): no previousCryptoHandle → unchanged behavior, a row under a foreign handle stays unreadable", async () => {
  const adapter = perUserAdapter();
  const currentHandle = createDekHandle(randomBytes(32));
  const foreignHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: rotationKeyProvider(currentHandle, null),
  });

  adapter.rows.set(
    "items:u1",
    await encodeBlob(
      foreignHandle,
      canonicalAAD(foreignHandle, "items"),
      {
        label: "secret",
      },
      1,
    ),
  );

  const store = defineStore({
    name: "items",
    schema: Item,
    version: 1,
    encrypt: "all",
    schemaFingerprint: fingerprintSchema(Item, "all"),
  });

  await assert.rejects(() => store.get());
});

test("perUser get(): previousCryptoHandle present, row still under it → reads through, lazily converges to current handle", async () => {
  const adapter = perUserAdapter();
  const currentHandle = createDekHandle(randomBytes(32));
  const previousHandle = createDekHandle(randomBytes(32));

  adapter.rows.set(
    "items:u1",
    await encodeBlob(
      previousHandle,
      canonicalAAD(previousHandle, "items"),
      { label: "still-old" },
      1,
    ),
  );

  configureSecureStore({
    storage: adapter,
    keys: rotationKeyProvider(currentHandle, previousHandle),
  });
  const store = defineStore({
    name: "items",
    schema: Item,
    version: 1,
    encrypt: "all",
    schemaFingerprint: fingerprintSchema(Item, "all"),
  });

  const data = await store.get();
  assert.deepEqual(data, { label: "still-old" });

  // Rotation "completes": reconfigure with NO previousCryptoHandle at all — a
  // fresh get() must still succeed, proving the row was truly re-encrypted
  // under currentHandle, not merely tolerated via the fallback.
  configureSecureStore({
    storage: adapter,
    keys: rotationKeyProvider(currentHandle, null),
  });
  const store2 = defineStore({
    name: "items",
    schema: Item,
    version: 1,
    encrypt: "all",
    schemaFingerprint: fingerprintSchema(Item, "all"),
  });
  assert.deepEqual(await store2.get(), { label: "still-old" });
});

test("perUser load(userId, cryptoHandle): explicit-handle callers (React hooks) ALSO benefit from the ambient previousCryptoHandle fallback", async () => {
  const adapter = perUserAdapter();
  const currentHandle = createDekHandle(randomBytes(32));
  const previousHandle = createDekHandle(randomBytes(32));

  adapter.rows.set(
    "items:u1",
    await encodeBlob(
      previousHandle,
      canonicalAAD(previousHandle, "items"),
      { label: "from-hook" },
      1,
    ),
  );

  configureSecureStore({
    storage: adapter,
    keys: rotationKeyProvider(currentHandle, previousHandle),
  });
  const store = defineStore({
    name: "items",
    schema: Item,
    version: 1,
    encrypt: "all",
    schemaFingerprint: fingerprintSchema(Item, "all"),
  });

  // useStore.ts resolves cryptoHandle/userId from the SAME ambient KeyProvider
  // and calls .load(userId, cryptoHandle) explicitly — never resolveAmbientIdentity.
  const data = await store.load("u1", currentHandle);
  assert.deepEqual(data, { label: "from-hook" });
});

// ─── perKey ─────────────────────────────────────────────────────────────────

test("perKey get(key): no previousCryptoHandle → unchanged behavior, foreign-handle row stays unreadable", async () => {
  const adapter = perKeyAdapter();
  const currentHandle = createDekHandle(randomBytes(32));
  const foreignHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: rotationKeyProvider(currentHandle, null),
  });

  adapter.rows.set(
    "batches:u1:2026-01",
    await encodeBlob(
      foreignHandle,
      canonicalAAD(foreignHandle, "batches", "2026-01"),
      { label: "secret" },
      1,
    ),
  );

  const store = defineStore({
    name: "batches",
    schema: Item,
    version: 1,
    identity: { perKey: "period" },
    encrypt: "all",
    schemaFingerprint: fingerprintSchema(Item, "all"),
  });

  await assert.rejects(() => store.get("2026-01"));
});

test("perKey get(key): previousCryptoHandle present, row still under it → reads through and lazily converges", async () => {
  const adapter = perKeyAdapter();
  const currentHandle = createDekHandle(randomBytes(32));
  const previousHandle = createDekHandle(randomBytes(32));

  adapter.rows.set(
    "batches:u1:2026-01",
    await encodeBlob(
      previousHandle,
      canonicalAAD(previousHandle, "batches", "2026-01"),
      { label: "still-old" },
      1,
    ),
  );

  configureSecureStore({
    storage: adapter,
    keys: rotationKeyProvider(currentHandle, previousHandle),
  });
  const store = defineStore({
    name: "batches",
    schema: Item,
    version: 1,
    identity: { perKey: "period" },
    encrypt: "all",
    schemaFingerprint: fingerprintSchema(Item, "all"),
  });

  assert.deepEqual(await store.get("2026-01"), { label: "still-old" });

  configureSecureStore({
    storage: adapter,
    keys: rotationKeyProvider(currentHandle, null),
  });
  const store2 = defineStore({
    name: "batches",
    schema: Item,
    version: 1,
    identity: { perKey: "period" },
    encrypt: "all",
    schemaFingerprint: fingerprintSchema(Item, "all"),
  });
  assert.deepEqual(await store2.get("2026-01"), { label: "still-old" });
});

test("perKey get(key): row already on the current handle → no unnecessary rewrite", async () => {
  const adapter = perKeyAdapter();
  const currentHandle = createDekHandle(randomBytes(32));
  const previousHandle = createDekHandle(randomBytes(32));

  adapter.rows.set(
    "batches:u1:2026-01",
    await encodeBlob(
      currentHandle,
      canonicalAAD(currentHandle, "batches", "2026-01"),
      { label: "already-current" },
      1,
    ),
  );
  const originalRecord = adapter.rows.get("batches:u1:2026-01");

  configureSecureStore({
    storage: adapter,
    keys: rotationKeyProvider(currentHandle, previousHandle),
  });
  const store = defineStore({
    name: "batches",
    schema: Item,
    version: 1,
    identity: { perKey: "period" },
    encrypt: "all",
    schemaFingerprint: fingerprintSchema(Item, "all"),
  });

  assert.deepEqual(await store.get("2026-01"), { label: "already-current" });
  assert.strictEqual(
    adapter.rows.get("batches:u1:2026-01"),
    originalRecord,
    "row object must be untouched — no unnecessary re-encrypt/rewrite",
  );
});

test("perKey getRange(): the list()-based path also falls back to previousCryptoHandle", async () => {
  const adapter = perKeyAdapter();
  const currentHandle = createDekHandle(randomBytes(32));
  const previousHandle = createDekHandle(randomBytes(32));

  adapter.rows.set(
    "batches:u1:2026-01",
    await encodeBlob(
      previousHandle,
      canonicalAAD(previousHandle, "batches", "2026-01"),
      { label: "old-jan" },
      1,
    ),
  );
  adapter.rows.set(
    "batches:u1:2026-02",
    await encodeBlob(
      currentHandle,
      canonicalAAD(currentHandle, "batches", "2026-02"),
      { label: "current-feb" },
      1,
    ),
  );

  configureSecureStore({
    storage: adapter,
    keys: rotationKeyProvider(currentHandle, previousHandle),
  });
  const store = defineStore({
    name: "batches",
    schema: Item,
    version: 1,
    identity: { perKey: "period" },
    encrypt: "all",
    schemaFingerprint: fingerprintSchema(Item, "all"),
  });

  const results = await store.getRange({ from: "2026-01", to: "2026-02" });
  const byKey = Object.fromEntries(results.map((r) => [r.key, r.data]));
  assert.deepEqual(byKey, {
    "2026-01": { label: "old-jan" },
    "2026-02": { label: "current-feb" },
  });
});

// ─── many ───────────────────────────────────────────────────────────────────

test("many get(): no previousCryptoHandle → unchanged behavior, foreign-handle row stays unreadable", async () => {
  const adapter = manyAdapter();
  const currentHandle = createDekHandle(randomBytes(32));
  const foreignHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: rotationKeyProvider(currentHandle, null),
  });

  adapter.rows.set(
    "sims:u1:row-1",
    await encodeBlob(
      foreignHandle,
      canonicalAAD(foreignHandle, "sims", "row-1"),
      { label: "secret" },
      1,
    ),
  );

  const store = defineStore({
    name: "sims",
    schema: Item,
    version: 1,
    identity: "many",
    encrypt: "all",
    schemaFingerprint: fingerprintSchema(Item, "all"),
  });

  await assert.rejects(() => store.get());
});

test("many get(): previousCryptoHandle present, row still under it → reads through and lazily converges", async () => {
  const adapter = manyAdapter();
  const currentHandle = createDekHandle(randomBytes(32));
  const previousHandle = createDekHandle(randomBytes(32));

  adapter.rows.set(
    "sims:u1:row-1",
    await encodeBlob(
      previousHandle,
      canonicalAAD(previousHandle, "sims", "row-1"),
      { label: "still-old" },
      1,
    ),
  );

  configureSecureStore({
    storage: adapter,
    keys: rotationKeyProvider(currentHandle, previousHandle),
  });
  const store = defineStore({
    name: "sims",
    schema: Item,
    version: 1,
    identity: "many",
    encrypt: "all",
    schemaFingerprint: fingerprintSchema(Item, "all"),
  });

  const results = await store.get();
  assert.deepEqual(
    results.map((r) => r.data),
    [{ label: "still-old" }],
  );

  configureSecureStore({
    storage: adapter,
    keys: rotationKeyProvider(currentHandle, null),
  });
  const store2 = defineStore({
    name: "sims",
    schema: Item,
    version: 1,
    identity: "many",
    encrypt: "all",
    schemaFingerprint: fingerprintSchema(Item, "all"),
  });
  const results2 = await store2.get();
  assert.deepEqual(
    results2.map((r) => r.data),
    [{ label: "still-old" }],
  );
});
