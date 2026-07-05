/**
 * Lazy convergence of the crypto envelope version itself: `decodeBlob` now treats
 * ANY `parsed.v <= 2` (legacy AAD-v1 serialization, see `crypto.ts`) as "upgraded",
 * even when no schema migrator ran — reusing the exact same lazy write-back
 * mechanism `legacyAAD`/schema `version` migrations already use (`onUpgraded` in
 * `rowStore.ts`, `persistMigrated` in `store.ts`'s `many` list()). A row written
 * before this change (pipe-join AAD, v2 envelope) converges to canonical (AAD-v2,
 * v4) the first time ANY cardinality touches it, with no live migration script.
 *
 * These rows use the store's own CANONICAL field/rowId (no `legacyAAD` config
 * needed) — only the crypto envelope's AAD serialization is legacy, not the AAD
 * shape itself. That's what isolates this test from `legacyAAD.test.ts` (which
 * covers a different historical AAD *shape*, e.g. `field: "snapshot"`).
 */
import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes, clean } from "@noble/ciphers/utils.js";
import { gcm } from "@noble/ciphers/aes.js";
import { z } from "zod";

import { createDekHandle } from "./testKeyHandle.ts";
import { toEnvelope } from "../core/versioning.ts";
import { serializeEncField, parseEncField } from "../core/wireFormat.ts";
import {
  configureSecureStore,
  __resetSecureStoreConfig,
  defineStore,
  fingerprintSchema,
  type StorageAdapter,
  type BlobRecord,
} from "../index.ts";
import type { FieldAAD } from "../core/types.ts";

const ENCODER = new TextEncoder();

function legacyBuildAADBytes(aad: FieldAAD): Uint8Array {
  return ENCODER.encode(`${aad.userId}|${aad.table}|${aad.field}|${aad.rowId}`);
}

function toBase64(bytes: Uint8Array): string {
  const CHUNK = 8192;
  let out = "";
  for (let i = 0; i < bytes.length; i += CHUNK)
    out += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  return btoa(out);
}

/**
 * The lazy write-back (`onUpgraded` in `rowStore.ts`) is fire-and-forget — `loadRow`
 * doesn't await it, so it can still be in flight (gzip goes through a real Streams
 * API round-trip) when the caller's `load()` promise resolves. A single setTimeout(0)
 * flush is NOT enough under load (flaky when the whole suite runs concurrently) —
 * poll the actual side effect instead.
 */
async function waitFor(
  predicate: () => boolean,
  timeoutMs = 2000,
): Promise<void> {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) {
      throw new Error("waitFor: timed out waiting for the lazy write-back");
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

/** Fixed settle window for "and nothing further happens" assertions — nothing to poll for. */
function settle(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 100));
}

async function gzip(bytes: Uint8Array): Promise<Uint8Array> {
  const cs = new CompressionStream("gzip");
  const writer = cs.writable.getWriter();
  writer.write(bytes as Uint8Array<ArrayBuffer>);
  writer.close();
  return new Uint8Array(await new Response(cs.readable).arrayBuffer());
}

/** Builds a v2 (gzip, legacy pipe-join AAD) `BlobRecord` — the pre-Fase-2 wire format. */
async function buildLegacyRecord<T>(
  dek: Uint8Array,
  aad: FieldAAD,
  data: T,
  schemaVersion: number,
): Promise<BlobRecord> {
  const envelope = toEnvelope(data, schemaVersion);
  const compressed = await gzip(ENCODER.encode(JSON.stringify(envelope)));
  const nonce = randomBytes(12);
  const ct = gcm(dek, nonce, legacyBuildAADBytes(aad)).encrypt(compressed);
  const record: BlobRecord = {
    schemaVersion,
    blob: serializeEncField({ ct: toBase64(ct), n: toBase64(nonce), v: 2 }),
  };
  clean(nonce);
  return record;
}

test.beforeEach(() => __resetSecureStoreConfig());

const Blob = z.object({ value: z.string().default("") });

test("aadLazyUpgrade (perUser): a legacy v2/pipe-AAD row converges to v4 on first load, second load is a no-op", async () => {
  const dek = randomBytes(32);
  const cryptoHandle = createDekHandle(dek);
  const rows = new Map<string, BlobRecord>();
  let putCalls = 0;
  const adapter: StorageAdapter = {
    async get(collection, userId) {
      return rows.get(`${collection}:${userId}`) ?? null;
    },
    async put(collection, userId, _extraKeys, record) {
      putCalls++;
      rows.set(`${collection}:${userId}`, record);
    },
  };
  configureSecureStore({ storage: adapter });

  const aad: FieldAAD = {
    userId: cryptoHandle.pid,
    table: "aadupgrade_peruser",
    field: "data",
    rowId: cryptoHandle.pid,
  };
  rows.set(
    "aadupgrade_peruser:u1",
    await buildLegacyRecord(dek, aad, { value: "legacy" }, 1),
  );

  const store = defineStore({
    name: "aadupgrade_peruser",
    encrypt: "all",
    schema: Blob,
    version: 1,
    schemaFingerprint: fingerprintSchema(Blob, "all"),
  });

  assert.deepEqual(await store.load("u1", cryptoHandle), { value: "legacy" });
  await waitFor(() => putCalls === 1);
  assert.equal(
    parseEncField(rows.get("aadupgrade_peruser:u1")!.blob).v,
    4,
    "the rewritten blob must be canonical (v4)",
  );

  assert.deepEqual(await store.load("u1", cryptoHandle), { value: "legacy" });
  await settle();
  assert.equal(
    putCalls,
    1,
    "a second load of an already-canonical row must not rewrite again",
  );
});

test("aadLazyUpgrade (perKey): a legacy v2/pipe-AAD row converges to v4 on first load, second load is a no-op", async () => {
  const dek = randomBytes(32);
  const cryptoHandle = createDekHandle(dek);
  const rows = new Map<string, BlobRecord>();
  let putCalls = 0;
  const rowKey = (userId: string, key: string) =>
    `aadupgrade_perkey:${userId}:${key}`;
  const adapter: StorageAdapter = {
    async get(_collection, userId, extraKeys) {
      return rows.get(rowKey(userId, extraKeys[0]!.value)) ?? null;
    },
    async put(_collection, userId, extraKeys, record) {
      putCalls++;
      rows.set(rowKey(userId, extraKeys[0]!.value), record);
    },
  };
  configureSecureStore({ storage: adapter });

  const aad: FieldAAD = {
    userId: cryptoHandle.pid,
    table: "aadupgrade_perkey",
    field: "data",
    rowId: "2026-01",
  };
  rows.set(
    rowKey("u1", "2026-01"),
    await buildLegacyRecord(dek, aad, { value: "legacy" }, 1),
  );

  const store = defineStore({
    name: "aadupgrade_perkey",
    identity: { perKey: "year_month" },
    encrypt: "all",
    schema: Blob,
    version: 1,
    schemaFingerprint: fingerprintSchema(Blob, "all"),
  });

  assert.deepEqual(await store.load("u1", cryptoHandle, "2026-01"), {
    value: "legacy",
  });
  await waitFor(() => putCalls === 1);
  assert.equal(
    parseEncField(rows.get(rowKey("u1", "2026-01"))!.blob).v,
    4,
    "the rewritten blob must be canonical (v4)",
  );

  assert.deepEqual(await store.load("u1", cryptoHandle, "2026-01"), {
    value: "legacy",
  });
  await settle();
  assert.equal(
    putCalls,
    1,
    "a second load of an already-canonical row must not rewrite again",
  );
});

test("aadLazyUpgrade (many): a legacy v2/pipe-AAD row converges to v4 on list(), second list() is a no-op", async () => {
  const dek = randomBytes(32);
  const cryptoHandle = createDekHandle(dek);
  const rows = new Map<string, BlobRecord>();
  let updateCalls = 0;
  const rowKey = (userId: string, id: string) =>
    `aadupgrade_many:${userId}:${id}`;
  const adapter: StorageAdapter = {
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
    async updateById(_collection, userId, id, record) {
      updateCalls++;
      rows.set(rowKey(userId, id), record);
    },
  };
  configureSecureStore({ storage: adapter });

  const aad: FieldAAD = {
    userId: cryptoHandle.pid,
    table: "aadupgrade_many",
    field: "data",
    rowId: "row1",
  };
  rows.set(
    rowKey("u1", "row1"),
    await buildLegacyRecord(dek, aad, { value: "legacy" }, 1),
  );

  const store = defineStore({
    name: "aadupgrade_many",
    identity: "many",
    encrypt: "all",
    schema: Blob,
    version: 1,
    schemaFingerprint: fingerprintSchema(Blob, "all"),
  });

  const first = await store.list("u1", cryptoHandle);
  assert.deepEqual(
    first.map((r) => r.data),
    [{ value: "legacy" }],
  );
  await waitFor(() => updateCalls === 1);
  assert.equal(
    parseEncField(rows.get(rowKey("u1", "row1"))!.blob).v,
    4,
    "the rewritten blob must be canonical (v4)",
  );

  const second = await store.list("u1", cryptoHandle);
  await settle();
  assert.deepEqual(
    second.map((r) => r.data),
    [{ value: "legacy" }],
  );
  assert.equal(
    updateCalls,
    1,
    "a second list() of an already-canonical row must not rewrite again",
  );
});
