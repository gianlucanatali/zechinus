/**
 * `mobilePersistentCacheAdapter` — the persistent `CacheAdapter` for the mobile
 * workspace (F0.5 of the mobile plan). Unlike `tanstackAdapter` (in-memory only),
 * this adapter mirrors every entry to device-local storage so a cold app launch can
 * paint from the last session's data before any network round trip completes.
 *
 * Pure port-based design (`DeviceKeyStore`/`DeviceBlobStore`), so this whole file
 * runs under plain `node --test` with in-memory fakes — the real Expo-backed ports
 * (`expo-secure-store`/`expo-file-system`) live in `../adapters/expoDeviceCacheStorage.ts`,
 * a separate RN-only file never imported here (mirrors how `webauthnKeyProvider`'s
 * ceremony itself isn't unit-tested — see that file's own test for the same reasoning).
 */
import assert from "node:assert/strict";
import test from "node:test";

import {
  mobilePersistentCacheAdapter,
  type DeviceKeyStore,
  type DeviceBlobStore,
} from "../adapters/mobilePersistentCacheAdapter.ts";

/** In-memory fake standing in for expo-secure-store (the device-local symmetric key). */
function fakeKeyStore(): DeviceKeyStore & { rawStorage: Map<string, string> } {
  const rawStorage = new Map<string, string>();
  return {
    rawStorage,
    async getKey() {
      return rawStorage.get("dek") ?? null;
    },
    async setKey(base64Key: string) {
      rawStorage.set("dek", base64Key);
    },
    async deleteKey() {
      rawStorage.delete("dek");
    },
  };
}

/** In-memory fake standing in for expo-file-system (the persisted ciphertext blobs). */
function fakeBlobStore(): DeviceBlobStore & { files: Map<string, string> } {
  const files = new Map<string, string>();
  return {
    files,
    async readAll() {
      return Object.fromEntries(files);
    },
    async write(cacheKey: string, ciphertextBase64: string) {
      files.set(cacheKey, ciphertextBase64);
    },
    async clear() {
      files.clear();
    },
  };
}

test("mobilePersistentCacheAdapter: set/get roundtrip is synchronous (in-memory mirror)", async () => {
  const adapter = mobilePersistentCacheAdapter({
    keyStore: fakeKeyStore(),
    blobStore: fakeBlobStore(),
  });
  await adapter.ready;

  assert.equal(adapter.get("portfolio_blobs:u1"), undefined);
  adapter.set("portfolio_blobs:u1", { positions: ["AAPL"] });
  assert.deepEqual(adapter.get("portfolio_blobs:u1"), { positions: ["AAPL"] });
});

test("mobilePersistentCacheAdapter: subscribe fires only for the matching key", async () => {
  const adapter = mobilePersistentCacheAdapter({
    keyStore: fakeKeyStore(),
    blobStore: fakeBlobStore(),
  });
  await adapter.ready;

  let fired = 0;
  const unsubscribe = adapter.subscribe("portfolio_blobs:u1", () => {
    fired++;
  });

  adapter.set("portfolio_blobs:u1", { positions: [] });
  assert.equal(fired, 1);

  adapter.set("transaction_blobs:u1", { transactions: [] });
  assert.equal(fired, 1, "a different key must not fire this subscription");

  unsubscribe();
  adapter.set("portfolio_blobs:u1", { positions: ["x"] });
  assert.equal(fired, 1, "unsubscribed callback must not fire again");
});

test("mobilePersistentCacheAdapter: set() write-through persists ENCRYPTED data, not plaintext", async () => {
  const keyStore = fakeKeyStore();
  const blobStore = fakeBlobStore();
  const adapter = mobilePersistentCacheAdapter({ keyStore, blobStore });
  await adapter.ready;

  adapter.set("portfolio_blobs:u1", { positions: ["AAPL"], secret: "s3cr3t" });
  await adapter.flush();

  assert.equal(blobStore.files.size, 1);
  const persisted = blobStore.files.get("portfolio_blobs:u1");
  assert.ok(persisted, "the write-through must have persisted an entry");
  assert.ok(
    !persisted!.includes("s3cr3t") && !persisted!.includes("AAPL"),
    "the persisted blob must be ciphertext, never the plaintext JSON",
  );
  assert.ok(
    keyStore.rawStorage.has("dek"),
    "a device-local symmetric key must have been generated and persisted",
  );
});

test("mobilePersistentCacheAdapter: a second instance hydrates from persisted storage at bootstrap", async () => {
  const keyStore = fakeKeyStore();
  const blobStore = fakeBlobStore();

  const first = mobilePersistentCacheAdapter({ keyStore, blobStore });
  await first.ready;
  first.set("portfolio_blobs:u1", { positions: ["AAPL"] });
  first.set("transaction_blobs:u1", { transactions: [{ id: "t1" }] });
  await first.flush();

  // Simulate a fresh app launch: a brand-new adapter instance, reusing the SAME
  // device-local key store and blob store (as a real relaunch would).
  const second = mobilePersistentCacheAdapter({ keyStore, blobStore });

  // Before hydration finishes, a cache miss is the correct, honest answer — never
  // a crash, never stale/fabricated data.
  assert.equal(second.get("portfolio_blobs:u1"), undefined);

  await second.ready;

  assert.deepEqual(second.get("portfolio_blobs:u1"), { positions: ["AAPL"] });
  assert.deepEqual(second.get("transaction_blobs:u1"), {
    transactions: [{ id: "t1" }],
  });
});

test("mobilePersistentCacheAdapter: a subscriber registered before hydration completes is notified once data arrives", async () => {
  const keyStore = fakeKeyStore();
  const blobStore = fakeBlobStore();

  const first = mobilePersistentCacheAdapter({ keyStore, blobStore });
  await first.ready;
  first.set("portfolio_blobs:u1", { positions: ["AAPL"] });
  await first.flush();

  const second = mobilePersistentCacheAdapter({ keyStore, blobStore });
  let notified = 0;
  second.subscribe("portfolio_blobs:u1", () => {
    notified++;
  });

  await second.ready;

  assert.equal(notified, 1);
  assert.deepEqual(second.get("portfolio_blobs:u1"), { positions: ["AAPL"] });
});

test("mobilePersistentCacheAdapter: clear() empties both the in-memory mirror and persistent storage", async () => {
  const keyStore = fakeKeyStore();
  const blobStore = fakeBlobStore();
  const adapter = mobilePersistentCacheAdapter({ keyStore, blobStore });
  await adapter.ready;

  adapter.set("portfolio_blobs:u1", { positions: ["AAPL"] });
  await adapter.flush();
  assert.equal(blobStore.files.size, 1);
  assert.ok(keyStore.rawStorage.has("dek"));

  adapter.clear();
  // clear() is synchronous by contract (CacheAdapter) — the in-memory mirror is
  // wiped immediately, before the persistent cleanup below even starts.
  assert.equal(adapter.get("portfolio_blobs:u1"), undefined);

  await adapter.flush();

  assert.equal(blobStore.files.size, 0, "persisted blobs must be wiped");
  assert.ok(
    !keyStore.rawStorage.has("dek"),
    "the device-local symmetric key must be deleted, making any leftover " +
      "ciphertext elsewhere permanently undecryptable",
  );
});

test("mobilePersistentCacheAdapter: after clear(), a fresh write re-provisions a new device key", async () => {
  const keyStore = fakeKeyStore();
  const blobStore = fakeBlobStore();
  const adapter = mobilePersistentCacheAdapter({ keyStore, blobStore });
  await adapter.ready;

  adapter.set("portfolio_blobs:u1", { positions: ["AAPL"] });
  await adapter.flush();
  const firstKey = keyStore.rawStorage.get("dek");

  adapter.clear();
  await adapter.flush();

  adapter.set("portfolio_blobs:u1", { positions: ["MSFT"] });
  await adapter.flush();
  const secondKey = keyStore.rawStorage.get("dek");

  assert.ok(secondKey, "a new key must have been provisioned");
  assert.notEqual(
    firstKey,
    secondKey,
    "the post-clear key must be freshly generated, not reused",
  );
});

test("mobilePersistentCacheAdapter: device key store unavailable → falls back to memory-only, never crashes, reports loudly", async () => {
  const brokenKeyStore: DeviceKeyStore = {
    async getKey() {
      throw new Error("SecureStore unavailable on this device");
    },
    async setKey() {
      throw new Error("SecureStore unavailable on this device");
    },
    async deleteKey() {
      throw new Error("SecureStore unavailable on this device");
    },
  };
  const blobStore = fakeBlobStore();
  const reported: Error[] = [];

  const adapter = mobilePersistentCacheAdapter({
    keyStore: brokenKeyStore,
    blobStore,
    onPersistError: (error) => reported.push(error),
  });
  await adapter.ready;

  assert.ok(
    reported.length >= 1,
    "the failure must be reported, never swallowed silently",
  );
  assert.match(reported[0].message, /SecureStore unavailable/);

  // Degraded but functional: get/set still work purely in-memory.
  adapter.set("portfolio_blobs:u1", { positions: ["AAPL"] });
  assert.deepEqual(adapter.get("portfolio_blobs:u1"), { positions: ["AAPL"] });

  await adapter.flush();
  assert.equal(
    blobStore.files.size,
    0,
    "no write-through attempt once persistence is known to be unavailable",
  );
});

test("mobilePersistentCacheAdapter: a corrupted persisted entry is skipped without aborting hydration of the rest", async () => {
  const keyStore = fakeKeyStore();
  const blobStore = fakeBlobStore();

  const first = mobilePersistentCacheAdapter({ keyStore, blobStore });
  await first.ready;
  first.set("portfolio_blobs:u1", { positions: ["AAPL"] });
  first.set("transaction_blobs:u1", { transactions: [] });
  await first.flush();

  // Corrupt one persisted entry directly (simulates a tampered/truncated file).
  blobStore.files.set("portfolio_blobs:u1", "not-valid-ciphertext");

  const reported: Error[] = [];
  const second = mobilePersistentCacheAdapter({
    keyStore,
    blobStore,
    onPersistError: (error) => reported.push(error),
  });
  await second.ready;

  assert.equal(
    second.get("portfolio_blobs:u1"),
    undefined,
    "the corrupted entry must not surface as fabricated data",
  );
  assert.deepEqual(second.get("transaction_blobs:u1"), { transactions: [] });
  assert.ok(reported.length >= 1);
  assert.match(reported[0].message, /portfolio_blobs:u1/);
});

test("mobilePersistentCacheAdapter: no data persisted yet is a legitimate empty state, not an error", async () => {
  const reported: Error[] = [];
  const adapter = mobilePersistentCacheAdapter({
    keyStore: fakeKeyStore(),
    blobStore: fakeBlobStore(),
    onPersistError: (error) => reported.push(error),
  });
  await adapter.ready;

  assert.equal(adapter.get("portfolio_blobs:u1"), undefined);
  assert.equal(reported.length, 0);
});
