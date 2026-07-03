import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import { z } from "zod";

import { createDekHandle } from "../../crypto/passkey-prf.ts";
import {
  configureSecureStore,
  __resetSecureStoreConfig,
  defineStore,
  fingerprintSchema,
  type StorageAdapter,
  type BlobRecord,
} from "../index.ts";

// In-memory adapter: no Supabase required for the encrypted roundtrip.
function memoryAdapter(): StorageAdapter & { rows: Map<string, BlobRecord> } {
  const rows = new Map<string, BlobRecord>();
  return {
    rows,
    async getOne(collection, userId) {
      return rows.get(`${collection}:${userId}`) ?? null;
    },
    async putOne(collection, userId, record) {
      rows.set(`${collection}:${userId}`, record);
    },
  };
}

const Portfolio = z.object({
  positions: z.array(z.string()).default([]),
  count: z.number().default(0),
});

test("defineStore: perUser + encrypt:all → roundtrip + encrypted blob + derived empty", async () => {
  const adapter = memoryAdapter();
  configureSecureStore({ storage: adapter });
  const dek = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "portfolio_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  // non-existent record → empty derived from the schema's .default()s
  assert.deepEqual(await store.load("u1", dek), { positions: [], count: 0 });

  await store.save("u1", dek, { positions: ["AAPL"], count: 1 });

  const raw = adapter.rows.get("portfolio_blobs:u1");
  assert.ok(raw, "saved record present");
  assert.ok(raw!.blob.startsWith("enc:"), "blob has the enc: prefix");
  assert.ok(!raw!.blob.includes("AAPL"), "plaintext NOT in the ciphertext");

  assert.deepEqual(await store.load("u1", dek), {
    positions: ["AAPL"],
    count: 1,
  });
});

test("defineStore: Zod validation on WRITE rejects non-conforming data", async () => {
  const adapter = memoryAdapter();
  configureSecureStore({ storage: adapter });
  const dek = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "portfolio_blobs",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  await assert.rejects(
    // @ts-expect-error — count must be a number: intentional error to test runtime validation
    () => store.save("u1", dek, { positions: ["X"], count: "nan" }),
    /doesn't conform to the schema, write rejected/,
  );
  // nothing was persisted
  assert.equal(adapter.rows.get("portfolio_blobs:u1"), undefined);
});

test("defineStore: Zod validation on READ catches a non-conforming blob", async () => {
  const adapter = memoryAdapter();
  configureSecureStore({ storage: adapter });
  const dek = createDekHandle(randomBytes(32));

  // "loose" store that writes a shape the "strict" store will reject on read
  const looseSchema = z.object({ n: z.unknown() });
  const loose = defineStore({
    name: "t_blobs",
    encrypt: "all",
    schema: looseSchema,
    empty: { n: null },
    version: 1,
    schemaFingerprint: fingerprintSchema(looseSchema, "all"),
  });
  await loose.save("u1", dek, { n: "not-a-number" });

  const strictSchema = z.object({ n: z.number() });
  const strict = defineStore({
    name: "t_blobs",
    encrypt: "all",
    schema: strictSchema,
    empty: { n: 0 },
    version: 1,
    schemaFingerprint: fingerprintSchema(strictSchema, "all"),
  });
  await assert.rejects(
    () => strict.load("u1", dek),
    /decrypted data doesn't conform to the schema/,
  );
});

test("defineStore: guardrail — encryption not declared → error at definition", () => {
  assert.throws(
    () =>
      defineStore({
        name: "x_blobs",
        schema: z.object({ a: z.string() }),
        version: 1,
      }),
    /encryption not declared/,
  );
});

test('defineStore: v1 does not support encrypt:"none" yet', () => {
  // encrypt:"none" (fully plaintext row) → guardrail passes, but not implemented in v1
  // (no real consumer). The mixed enc() case with identity 'many' IS supported,
  // see defineStoreManyMixed.test.ts; enc() with identity perUser/perKey stays
  // blocked, see the same file for that regression.
  assert.throws(
    () =>
      defineStore({
        name: "x_blobs",
        encrypt: "none",
        schema: z.object({ id: z.string() }),
        version: 1,
      }),
    /encrypt:"none" not implemented yet/,
  );
});

test("defineStore: guardrail — missing schemaFingerprint → error suggests the correct value", () => {
  const schema = z.object({ a: z.string().default("") });
  assert.throws(
    () =>
      defineStore({
        name: "x_blobs",
        encrypt: "all",
        schema,
        version: 1,
      }),
    new RegExp(fingerprintSchema(schema, "all")),
  );
});

test("defineStore: guardrail — wrong schemaFingerprint (shape changed without updating it) → error", () => {
  assert.throws(
    () =>
      defineStore({
        name: "x_blobs",
        encrypt: "all",
        schema: z.object({
          a: z.string().default(""),
          b: z.number().default(0),
        }),
        version: 1,
        schemaFingerprint: fingerprintSchema(
          z.object({ a: z.string().default("") }), // fingerprint of A PREVIOUS shape
          "all",
        ),
      }),
    /the schema shape has changed/,
  );
});

test("defineStore: guardrail — correct schemaFingerprint doesn't throw", () => {
  const schema = z.object({ a: z.string().default("") });
  assert.doesNotThrow(() =>
    defineStore({
      name: "x_blobs",
      encrypt: "all",
      schema,
      version: 1,
      schemaFingerprint: fingerprintSchema(schema, "all"),
    }),
  );
});

test("defineStore: guardrail — version:1 with no migrators doesn't throw (correct default)", () => {
  const schema = z.object({ a: z.string().default("") });
  assert.doesNotThrow(() =>
    defineStore({
      name: "x_blobs",
      encrypt: "all",
      schema,
      version: 1,
      schemaFingerprint: fingerprintSchema(schema, "all"),
    }),
  );
});

test("defineStore: guardrail — version:4 requires exactly 3 migrators", () => {
  assert.throws(
    () =>
      defineStore({
        name: "x_blobs",
        encrypt: "all",
        schema: z.object({ a: z.string().default("") }),
        version: 4,
        migrators: [(d) => d, (d) => d], // only 2, 3 are needed (v1→v2, v2→v3, v3→v4)
      }),
    /version 4 requires 3 migrator.*2 provided/,
  );
});

test("defineStore: guardrail — version:4 with 3 migrators doesn't throw", () => {
  const schema = z.object({ a: z.string().default("") });
  assert.doesNotThrow(() =>
    defineStore({
      name: "x_blobs",
      encrypt: "all",
      schema,
      version: 4,
      migrators: [(d) => d, (d) => d, (d) => d],
      schemaFingerprint: fingerprintSchema(schema, "all"),
    }),
  );
});

test("defineStore: guardrail — bumping version without adding the migrator throws immediately (not only on read)", () => {
  // The developer bumps version 1→2 "mentally" but forgets the migrator: it must fail
  // at defineStore(), BEFORE reading/writing any data.
  assert.throws(
    () =>
      defineStore({
        name: "x_blobs",
        encrypt: "all",
        schema: z.object({ a: z.string().default("") }),
        version: 2,
        // migrators entirely missing
      }),
    /version 2 requires 1 migrator.*0 provided/,
  );
});

test("defineStore: without configureSecureStore throws an explicit error", async () => {
  __resetSecureStoreConfig();
  const dek = createDekHandle(randomBytes(32));
  const store = defineStore({
    name: "portfolio_blobs",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });
  await assert.rejects(() => store.load("u1", dek), /framework not configured/);
});
