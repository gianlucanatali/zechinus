import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import { z } from "zod";

import { createDekHandle } from "./testKeyHandle.ts";
import {
  configureSecureStore,
  defineStore,
  enc,
  fingerprintSchema,
  type StorageAdapter,
  type BlobRecord,
} from "../index.ts";

// In-memory 'many' adapter with plaintext-column support alongside the blob.
function mixedMemoryAdapter(): StorageAdapter & {
  rows: Map<string, { record: BlobRecord; plain: Record<string, unknown> }>;
} {
  const rows = new Map<
    string,
    { record: BlobRecord; plain: Record<string, unknown> }
  >();
  const keyOf = (collection: string, userId: string, id: string) =>
    `${collection}:${userId}:${id}`;
  return {
    rows,
    async get() {
      return null;
    },
    async put() {},
    async list(collection, userId, _plainColumns) {
      const prefix = `${collection}:${userId}:`;
      const out: Array<{
        id: string;
        record: BlobRecord;
        plain: Record<string, unknown>;
      }> = [];
      for (const [key, row] of rows) {
        if (key.startsWith(prefix))
          out.push({
            id: key.slice(prefix.length),
            record: row.record,
            plain: row.plain,
          });
      }
      return out;
    },
    async insert(collection, userId, id, record, plain) {
      rows.set(keyOf(collection, userId, id), { record, plain });
    },
    async updateById(collection, userId, id, record, plain) {
      rows.set(keyOf(collection, userId, id), { record, plain });
    },
    async deleteById(collection, userId, id) {
      rows.delete(keyOf(collection, userId, id));
    },
  };
}

const Sim = z.object({
  portfolioId: z.string(),
  status: z.enum(["draft", "executed"]).default("draft"),
  name: enc(z.string()),
  addedLiquidity: enc(z.number().default(0)),
});

test("defineStore many + mixed enc(): plaintext columns do NOT go through encryption", async () => {
  const adapter = mixedMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const dek = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "rebalance_simulations",
    identity: "many",
    schema: Sim,
    version: 1,
    schemaFingerprint: fingerprintSchema(Sim, "fields"),
  });

  const id = await store.create(dek.pid, dek, {
    portfolioId: "pf-1",
    status: "draft",
    name: "secret-sim",
    addedLiquidity: 500,
  });

  const raw = adapter.rows.get(`rebalance_simulations:${dek.pid}:${id}`)!;
  // plaintext columns are real values, not ciphertext
  assert.deepEqual(raw.plain, { portfolioId: "pf-1", status: "draft" });
  // the secret never appears in plaintext in the row
  assert.ok(raw.record.blob.startsWith("enc:"));
  assert.ok(!JSON.stringify(raw.plain).includes("secret-sim"));

  const rows = await store.list(dek.pid, dek);
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0].data, {
    portfolioId: "pf-1",
    status: "draft",
    name: "secret-sim",
    addedLiquidity: 500,
  });
});

test("defineStore many + mixed enc(): update/remove roundtrip", async () => {
  const adapter = mixedMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const dek = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "rebalance_simulations",
    identity: "many",
    schema: Sim,
    version: 1,
    schemaFingerprint: fingerprintSchema(Sim, "fields"),
  });

  const id = await store.create(dek.pid, dek, {
    portfolioId: "pf-1",
    status: "draft",
    name: "v1",
    addedLiquidity: 1,
  });

  await store.update(dek.pid, dek, id, {
    portfolioId: "pf-1",
    status: "executed",
    name: "v2",
    addedLiquidity: 2,
  });
  const afterUpdate = await store.list(dek.pid, dek);
  assert.deepEqual(afterUpdate[0].data, {
    portfolioId: "pf-1",
    status: "executed",
    name: "v2",
    addedLiquidity: 2,
  });

  await store.remove(dek.pid, dek, id);
  assert.deepEqual(await store.list(dek.pid, dek), []);
});

test("defineStore many + mixed enc(): the AAD is bound to the id (the blob isn't movable between rows)", async () => {
  const adapter = mixedMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const dek = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "rebalance_simulations",
    identity: "many",
    schema: Sim,
    version: 1,
    schemaFingerprint: fingerprintSchema(Sim, "fields"),
  });

  const id1 = await store.create(dek.pid, dek, {
    portfolioId: "pf-1",
    status: "draft",
    name: "secret",
    addedLiquidity: 1,
  });
  const stolen = adapter.rows.get(`rebalance_simulations:${dek.pid}:${id1}`)!;
  adapter.rows.set(`rebalance_simulations:${dek.pid}:other-id`, {
    record: stolen.record,
    plain: { portfolioId: "pf-1", status: "draft" },
  });

  await assert.rejects(() => store.list(dek.pid, dek));
});

test("defineStore: mixed enc() fields with identity perUser/perKey → explicit error (only 'many' in v1)", () => {
  assert.throws(
    () =>
      defineStore({
        name: "x_blobs",
        identity: "perUser",
        schema: z.object({ a: z.string(), b: enc(z.string()) }),
        version: 1,
      }),
    /supported only with identity:"many"/,
  );
});

test("defineStore many + mixed enc(): Zod validation on create rejects non-conforming data", async () => {
  const adapter = mixedMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const dek = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "rebalance_simulations",
    identity: "many",
    schema: Sim,
    version: 1,
    schemaFingerprint: fingerprintSchema(Sim, "fields"),
  });

  await assert.rejects(
    () =>
      store.create(dek.pid, dek, {
        portfolioId: "pf-1",
        status: "draft",
        // @ts-expect-error — name must be a string: intentional error
        name: 123,
        addedLiquidity: 1,
      }),
    /write rejected/,
  );
  assert.equal(adapter.rows.size, 0);
});
