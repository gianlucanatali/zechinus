/**
 * `alsKeyProvider`/`withIdentity` (`datacloak/node`) — the AsyncLocalStorage-backed
 * `KeyProvider` for Node scripts that must handle multiple users concurrently
 * (unlike `configureSecureStore`'s single module-level identity, safe only for a
 * browser tab with exactly one active user). See `datacloak/node/index.ts` for the
 * full rationale.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { randomBytes } from "@noble/ciphers/utils.js";
import { z } from "zod";

import { createDekHandle } from "./testKeyHandle.ts";
import {
  configureSecureStore,
  defineStore,
  fingerprintSchema,
  type StorageAdapter,
  type BlobRecord,
  type CryptoHandle,
} from "../index.ts";
import { alsKeyProvider, withIdentity } from "../node/index.ts";

// Same minimal in-memory adapter pattern as `defineStore.test.ts`'s `memoryAdapter`:
// no real backend needed for the encrypted roundtrip, keyed by (collection, userId)
// so two different users' rows never collide.
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

const Portfolio = z.object({
  positions: z.array(z.string()).default([]),
});

test("alsKeyProvider: inside withIdentity, getCryptoHandle()/getUserId() return the bound identity", async () => {
  const cryptoHandle = createDekHandle(randomBytes(32));

  await withIdentity("userA", cryptoHandle, async () => {
    assert.equal(alsKeyProvider.getUserId(), "userA");
    assert.equal(alsKeyProvider.getCryptoHandle(), cryptoHandle);
  });
});

test("alsKeyProvider: outside any withIdentity scope, getters return null and an ambient store call fails loud", async () => {
  assert.equal(alsKeyProvider.getUserId(), null);
  assert.equal(alsKeyProvider.getCryptoHandle(), null);

  const adapter = memoryAdapter();
  configureSecureStore({ storage: adapter, keys: alsKeyProvider });
  const store = defineStore({
    name: "als_test_store",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  await assert.rejects(() => store.get(), /no active session/);
});

test("alsKeyProvider: two withIdentity chains run under Promise.all and never see each other's identity", async () => {
  const adapter = memoryAdapter();
  configureSecureStore({ storage: adapter, keys: alsKeyProvider });
  const store = defineStore({
    name: "als_test_store",
    identity: "perUser",
    encrypt: "all",
    schema: Portfolio,
    version: 1,
    schemaFingerprint: fingerprintSchema(Portfolio, "all"),
  });

  const handleA = createDekHandle(randomBytes(32));
  const handleB = createDekHandle(randomBytes(32));

  async function runAs(
    userId: string,
    cryptoHandle: CryptoHandle,
    position: string,
  ) {
    return withIdentity(userId, cryptoHandle, async () => {
      assert.equal(alsKeyProvider.getUserId(), userId);
      await delay(0); // interleave with the sibling chain mid-scope
      assert.equal(
        alsKeyProvider.getUserId(),
        userId,
        "identity must survive an await, never leak the sibling chain's identity",
      );
      await store.set({ positions: [position] });
      await delay(0);
      return store.get();
    });
  }

  const [resultA, resultB] = await Promise.all([
    runAs("userA", handleA, "AAPL"),
    runAs("userB", handleB, "MSFT"),
  ]);

  assert.deepEqual(resultA, { positions: ["AAPL"] });
  assert.deepEqual(resultB, { positions: ["MSFT"] });

  // Each ambient save landed under its OWN userId in the adapter — never cross-written.
  assert.ok(adapter.rows.has("als_test_store:userA"));
  assert.ok(adapter.rows.has("als_test_store:userB"));
});

test("alsKeyProvider: nested withIdentity — the inner identity wins during its scope, the outer one is restored after", async () => {
  const outerHandle = createDekHandle(randomBytes(32));
  const innerHandle = createDekHandle(randomBytes(32));

  await withIdentity("outer", outerHandle, async () => {
    assert.equal(alsKeyProvider.getUserId(), "outer");
    assert.equal(alsKeyProvider.getCryptoHandle(), outerHandle);

    await withIdentity("inner", innerHandle, async () => {
      assert.equal(alsKeyProvider.getUserId(), "inner");
      assert.equal(alsKeyProvider.getCryptoHandle(), innerHandle);
    });

    assert.equal(alsKeyProvider.getUserId(), "outer");
    assert.equal(alsKeyProvider.getCryptoHandle(), outerHandle);
  });
});
