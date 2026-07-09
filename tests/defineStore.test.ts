import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import { z } from "zod";

import { createDekHandle } from "./testKeyHandle.ts";
import {
  configureSecureStore,
  __resetSecureStoreConfig,
  defineStore,
  fingerprintSchema,
  OptimisticLockConflictError,
  type StorageAdapter,
  type BlobRecord,
  type CryptoHandle,
  type KeyProvider,
} from "../index.ts";

// In-memory adapter: no real backend (StorageAdapter) required for the
// encrypted roundtrip. Also implements `putIfMatch` (needed by the
// optimisticLock mutate() tests below) — same conflict semantics as
// `optimisticLock.test.ts`'s `conditionalMemoryAdapter`.
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
        if (current) return false;
        rows.set(key, record);
        return true;
      }
      if (!current || current.contentHash !== expectedHash) return false;
      rows.set(key, record);
      return true;
    },
  };
}

// `get()`/`mutate()` resolve the cryptoHandle ambiently from the configured KeyProvider — the
// caller never sees a `CryptoHandle`. This fake mirrors a single already-unlocked
// session, exactly like the real `passkeyDekController` at runtime.
function fixedKeyProvider(cryptoHandle: CryptoHandle | null): KeyProvider {
  return {
    getCryptoHandle: () => cryptoHandle,
    getUserId: () => "u1",
    subscribe: () => () => {},
  };
}

const Portfolio = z.object({
  positions: z.array(z.string()).default([]),
  count: z.number().default(0),
});

test("defineStore: perUser + encrypt:all → roundtrip + encrypted blob + derived empty", async () => {
  const adapter = memoryAdapter();
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "portfolio_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  // non-existent record → empty derived from the schema's .default()s
  assert.deepEqual(await store.load("u1", cryptoHandle), {
    positions: [],
    count: 0,
  });

  await store.save("u1", cryptoHandle, { positions: ["AAPL"], count: 1 });

  const raw = adapter.rows.get("portfolio_blobs:u1");
  assert.ok(raw, "saved record present");
  assert.ok(raw!.blob.startsWith("enc:"), "blob has the enc: prefix");
  assert.ok(!raw!.blob.includes("AAPL"), "plaintext NOT in the ciphertext");

  assert.deepEqual(await store.load("u1", cryptoHandle), {
    positions: ["AAPL"],
    count: 1,
  });
});

test("defineStore: get() reads ambiently — no cryptoHandle in sight", async () => {
  const adapter = memoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "portfolio_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  assert.deepEqual(await store.get(), { positions: [], count: 0 });
  await store.save("u1", cryptoHandle, { positions: ["AAPL"], count: 1 });
  assert.deepEqual(await store.get(), { positions: ["AAPL"], count: 1 });
});

test("defineStore: set() writes ambiently, no read involved — no cryptoHandle in sight", async () => {
  const adapter = memoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "portfolio_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  await store.set({ positions: ["AAPL"], count: 1 });
  assert.deepEqual(await store.load("u1", cryptoHandle), {
    positions: ["AAPL"],
    count: 1,
  });
});

test("defineStore: set() rejects data that fails Zod validation, and does NOT persist it", async () => {
  const adapter = memoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "portfolio_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });
  await store.save("u1", cryptoHandle, { positions: ["AAPL"], count: 1 });

  await assert.rejects(() =>
    // @ts-expect-error deliberately invalid shape for the test
    store.set({ positions: ["AAPL"], count: "not-a-number" }),
  );

  assert.deepEqual(await store.load("u1", cryptoHandle), {
    positions: ["AAPL"],
    count: 1,
  });
});

test("defineStore: set() throws an explicit error when locked (no active cryptoHandle)", async () => {
  const adapter = memoryAdapter();
  configureSecureStore({ storage: adapter, keys: fixedKeyProvider(null) });

  const store = defineStore({
    name: "portfolio_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  await assert.rejects(
    () => store.set({ positions: [], count: 0 }),
    /no cryptoHandle|locked/i,
  );
});

test("defineStore: set() refuses to run on an optimisticLock store — a blind overwrite would bypass the lock the store owner asked for", async () => {
  const adapter = memoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "portfolio_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    contentHash: true,
    optimisticLock: true,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  await assert.rejects(
    () => store.set({ positions: ["AAPL"], count: 1 }),
    /optimisticLock.*mutate/i,
  );
});

test("defineStore: get() throws an explicit error when locked (no active cryptoHandle)", async () => {
  const adapter = memoryAdapter();
  configureSecureStore({ storage: adapter, keys: fixedKeyProvider(null) });

  const store = defineStore({
    name: "portfolio_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  await assert.rejects(() => store.get(), /no cryptoHandle|locked/i);
});

test("defineStore: mutate() loads, applies the transform, saves, and returns the result — no cryptoHandle in sight", async () => {
  const adapter = memoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "portfolio_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  await store.save("u1", cryptoHandle, { positions: ["AAPL"], count: 1 });

  const result = await store.mutate((current) => ({
    ...current,
    positions: [...current.positions, "MSFT"],
    count: current.count + 1,
  }));

  assert.deepEqual(result, { positions: ["AAPL", "MSFT"], count: 2 });
  assert.deepEqual(await store.load("u1", cryptoHandle), {
    positions: ["AAPL", "MSFT"],
    count: 2,
  });
});

test("defineStore: mutate() supports an async transform function", async () => {
  const adapter = memoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "portfolio_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  const result = await store.mutate(async (current) => {
    await Promise.resolve();
    return { ...current, count: current.count + 5 };
  });

  assert.equal(result.count, 5);
});

test("defineStore: mutate() rejects a transform result that fails Zod validation, and does NOT persist it", async () => {
  const adapter = memoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "portfolio_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });
  await store.save("u1", cryptoHandle, { positions: ["AAPL"], count: 1 });

  await assert.rejects(() =>
    store.mutate(
      // @ts-expect-error deliberately invalid shape for the test
      (current) => ({ ...current, count: "not-a-number" }),
    ),
  );

  // Unchanged — the invalid transform result was never saved.
  assert.deepEqual(await store.load("u1", cryptoHandle), {
    positions: ["AAPL"],
    count: 1,
  });
});

test("defineStore: mutate() throws an explicit error when locked (no active cryptoHandle)", async () => {
  const adapter = memoryAdapter();
  configureSecureStore({ storage: adapter, keys: fixedKeyProvider(null) });

  const store = defineStore({
    name: "portfolio_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  await assert.rejects(
    () => store.mutate((current) => current),
    /no cryptoHandle|locked/i,
  );
});

test("defineStore: mutate() throws an explicit error when no KeyProvider is configured", async () => {
  const adapter = memoryAdapter();
  configureSecureStore({ storage: adapter });

  const store = defineStore({
    name: "portfolio_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  await assert.rejects(() => store.mutate((current) => current), /KeyProvider/);
});

test("defineStore: mutate() on an optimisticLock store throws OptimisticLockConflictError on conflict, WITHOUT retrying", async () => {
  const adapter = memoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "portfolio_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    contentHash: true,
    optimisticLock: true,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  await store.save("u1", cryptoHandle, { positions: ["AAPL"], count: 1 });

  let fnCalls = 0;
  await assert.rejects(
    () =>
      store.mutate((current) => {
        fnCalls += 1;
        // Simulates someone else writing between our read and our write.
        adapter.rows.delete("portfolio_blobs:u1");
        return { ...current, count: current.count + 1 };
      }),
    (error: unknown) => {
      assert.ok(error instanceof OptimisticLockConflictError);
      return true;
    },
  );
  assert.equal(fnCalls, 1, "the transform runs exactly once, no blind retry");
});

test("defineStore: mutate() on an optimisticLock store succeeds and updates the hash when there's no conflict", async () => {
  const adapter = memoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "portfolio_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    contentHash: true,
    optimisticLock: true,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  await store.save("u1", cryptoHandle, { positions: ["AAPL"], count: 1 });

  const result = await store.mutate((current) => ({
    ...current,
    count: current.count + 1,
  }));

  assert.equal(result.count, 2);
  assert.deepEqual(await store.load("u1", cryptoHandle), {
    positions: ["AAPL"],
    count: 2,
  });
});

test("defineStore: mutate() with retryOnConflict re-reads and reapplies fn until it succeeds", async () => {
  const adapter = memoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "portfolio_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    contentHash: true,
    optimisticLock: true,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  await store.save("u1", cryptoHandle, { positions: ["AAPL"], count: 1 });

  let fnCalls = 0;
  // Simulates a concurrent, independent mutate() call finishing first (the real
  // bug: an unrelated auto-save writing its own change to the same row) between
  // our read and our write — tamper the stored content_hash on the FIRST attempt
  // only, so our saveIfMatch's expectedHash no longer matches.
  const result = await store.mutate(
    (current) => {
      fnCalls += 1;
      if (fnCalls === 1) {
        const row = adapter.rows.get("portfolio_blobs:u1")!;
        adapter.rows.set("portfolio_blobs:u1", {
          ...row,
          contentHash: "someone-elses-write",
        });
      }
      return { ...current, positions: [...current.positions, "MSFT"] };
    },
    { retryOnConflict: 3 },
  );

  assert.equal(fnCalls, 2, "fn re-applied once after the first conflict");
  assert.deepEqual(
    result.positions,
    ["AAPL", "MSFT"],
    "retry re-read the concurrent writer's row before appending",
  );
  assert.deepEqual(await store.load("u1", cryptoHandle), {
    positions: ["AAPL", "MSFT"],
    count: 1,
  });
});

test("defineStore: mutate() with retryOnConflict exhausts attempts and throws OptimisticLockConflictError", async () => {
  const adapter = memoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "portfolio_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    contentHash: true,
    optimisticLock: true,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  await store.save("u1", cryptoHandle, { positions: ["AAPL"], count: 1 });

  let fnCalls = 0;
  await assert.rejects(
    () =>
      store.mutate(
        (current) => {
          fnCalls += 1;
          // Every attempt loses the race — persistent conflict, not transient
          // (a different writer keeps winning, not a one-off hiccup).
          const row = adapter.rows.get("portfolio_blobs:u1")!;
          adapter.rows.set("portfolio_blobs:u1", {
            ...row,
            contentHash: `someone-elses-write-${fnCalls}`,
          });
          return { ...current, count: current.count + 1 };
        },
        { retryOnConflict: 3 },
      ),
    (error: unknown) => {
      assert.ok(error instanceof OptimisticLockConflictError);
      return true;
    },
  );
  assert.equal(fnCalls, 3, "exactly retryOnConflict attempts, then gives up");
});

test("defineStore: mutate() WITHOUT retryOnConflict still throws immediately (default unchanged)", async () => {
  const adapter = memoryAdapter();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
  });

  const store = defineStore({
    name: "portfolio_blobs",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    contentHash: true,
    optimisticLock: true,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  await store.save("u1", cryptoHandle, { positions: ["AAPL"], count: 1 });

  let fnCalls = 0;
  await assert.rejects(
    () =>
      store.mutate((current) => {
        fnCalls += 1;
        adapter.rows.delete("portfolio_blobs:u1");
        return { ...current, count: current.count + 1 };
      }),
    (error: unknown) => {
      assert.ok(error instanceof OptimisticLockConflictError);
      return true;
    },
  );
  assert.equal(fnCalls, 1, "no options → no retry, same as before this change");
});

test("defineStore: Zod validation on WRITE rejects non-conforming data", async () => {
  const adapter = memoryAdapter();
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

  const store = defineStore({
    name: "portfolio_blobs",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  await assert.rejects(
    // @ts-expect-error — count must be a number: intentional error to test runtime validation
    () => store.save("u1", cryptoHandle, { positions: ["X"], count: "nan" }),
    /doesn't conform to the schema, write rejected/,
  );
  // nothing was persisted
  assert.equal(adapter.rows.get("portfolio_blobs:u1"), undefined);
});

test("defineStore: Zod validation on READ catches a non-conforming blob", async () => {
  const adapter = memoryAdapter();
  configureSecureStore({ storage: adapter });
  const cryptoHandle = createDekHandle(randomBytes(32));

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
  await loose.save("u1", cryptoHandle, { n: "not-a-number" });

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
    () => strict.load("u1", cryptoHandle),
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
  const cryptoHandle = createDekHandle(randomBytes(32));
  const store = defineStore({
    name: "portfolio_blobs",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });
  await assert.rejects(
    () => store.load("u1", cryptoHandle),
    /framework not configured/,
  );
});
