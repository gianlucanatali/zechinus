/* eslint-disable no-undef */
/**
 * `webDeviceKeyProvider` runs entirely on `crypto.subtle` (RSA-OAEP), available under
 * plain `node --test` — no browser needed for the crypto itself. What IS browser-only is
 * the IndexedDB-backed `DeviceKeyPairStorage` (`indexedDbDeviceKeyPairStorage`), so these
 * tests inject an in-memory fake storage instead; that also lets "survives reload" be
 * expressed precisely as "a fresh provider instance backed by the same storage".
 */
import assert from "node:assert/strict";
import test from "node:test";
import type { DeviceKeyPairStorage } from "../adapters/deviceKeyProvider.ts";
import {
  webDeviceKeyProvider,
  wrapForDevicePublicKey,
} from "../adapters/deviceKeyProvider.ts";
import { mobileDeviceKeyProvider } from "../adapters/mobileDeviceKeyProvider.ts";

function memoryStorage(): DeviceKeyPairStorage {
  let stored: CryptoKeyPair | null = null;
  return {
    async loadKeyPair() {
      return stored;
    },
    async saveKeyPair(keyPair) {
      stored = keyPair;
    },
  };
}

test("webDeviceKeyProvider: the private key is generated non-extractable", async () => {
  const storage = memoryStorage();
  await webDeviceKeyProvider(storage).getOrCreateDevicePublicKey();

  const keyPair = await storage.loadKeyPair();
  assert.ok(keyPair);
  assert.equal(keyPair.privateKey.extractable, false);
});

test("webDeviceKeyProvider: the public key persists across provider instances backed by the same storage (simulates a reload)", async () => {
  const storage = memoryStorage();
  const { publicKeyB64: keyFromFirstInstance } =
    await webDeviceKeyProvider(storage).getOrCreateDevicePublicKey();

  // A fresh provider instance sharing the same storage stands in for "after reload":
  // no in-memory cache to fall back on, only what was persisted.
  const { publicKeyB64: keyFromSecondInstance } =
    await webDeviceKeyProvider(storage).getOrCreateDevicePublicKey();

  assert.equal(keyFromFirstInstance, keyFromSecondInstance);
});

test("wrapForDevicePublicKey + unwrapWithDeviceKey: round-trips a DEK-sized payload", async () => {
  const storage = memoryStorage();
  const provider = webDeviceKeyProvider(storage);
  const { publicKeyB64 } = await provider.getOrCreateDevicePublicKey();

  const dek = crypto.getRandomValues(new Uint8Array(32));
  const wrapped = await wrapForDevicePublicKey(publicKeyB64, dek);
  const unwrapped = await provider.unwrapWithDeviceKey(wrapped);

  assert.deepEqual(unwrapped, dek);
});

test("unwrapWithDeviceKey: a different device's private key cannot unwrap the wrap (device-bound, not shared)", async () => {
  const storageA = memoryStorage();
  const { publicKeyB64: publicKeyA } =
    await webDeviceKeyProvider(storageA).getOrCreateDevicePublicKey();

  const storageB = memoryStorage();
  const providerB = webDeviceKeyProvider(storageB);
  await providerB.getOrCreateDevicePublicKey(); // B has its own, unrelated keypair

  const dek = crypto.getRandomValues(new Uint8Array(32));
  const wrapped = await wrapForDevicePublicKey(publicKeyA, dek);

  await assert.rejects(() => providerB.unwrapWithDeviceKey(wrapped));
});

test("mobileDeviceKeyProvider: both methods throw a FIXME-referencing error (Fase 3.2 stub, never a silent no-op)", async () => {
  const provider = mobileDeviceKeyProvider();
  await assert.rejects(
    () => provider.getOrCreateDevicePublicKey(),
    /Fase 3\.2/,
  );
  await assert.rejects(
    () => provider.unwrapWithDeviceKey({ ciphertext: "" }),
    /Fase 3\.2/,
  );
});
