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
import { createKeyHandle, asRawDekBytes } from "../core/keyDerivation.ts";

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

test("createKeyHandle + wrapForDevice: the intended real usage — the DEK held by a KeyHandle (e.g. a Worker) is wrapped for a device's public key without ever being handed to the caller as a plain value", async () => {
  const recipientStorage = memoryStorage();
  const { publicKeyB64 } =
    await webDeviceKeyProvider(recipientStorage).getOrCreateDevicePublicKey();

  const dek = crypto.getRandomValues(new Uint8Array(32));
  const handle = createKeyHandle(
    asRawDekBytes(dek),
    new Uint8Array(32).fill(7),
    "test-info",
    {
      wrapForDevice: (key, devicePublicKeyB64) =>
        wrapForDevicePublicKey(devicePublicKeyB64, key),
    },
  );

  // The handle's public surface never returns `dek` — only `wrapForDevice`'s result.
  const wrapped = await handle.wrapForDevice!(publicKeyB64);
  const unwrapped =
    await webDeviceKeyProvider(recipientStorage).unwrapWithDeviceKey(wrapped);

  assert.deepEqual(unwrapped, dek);
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
