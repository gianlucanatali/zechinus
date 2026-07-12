/**
 * `deriveDevicePublicKey`/`wrapForDevicePublicKey`/`unwrapWithDeviceKey` are pure
 * functions of the KEK — no storage, no browser API, so they run directly under
 * `node --test` like the rest of the crypto core. Nothing here needs a fake/in-memory
 * storage double (an earlier version of this file did, before the IndexedDB-persisted
 * design was replaced by derivation from the KEK).
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  deriveDevicePublicKey,
  wrapForDevicePublicKey,
  unwrapWithDeviceKey,
} from "../adapters/deviceKeyProvider.ts";
import { mobileDeviceKeyProvider } from "../adapters/mobileDeviceKeyProvider.ts";
import { createKeyHandle, asRawDekBytes } from "../core/keyDerivation.ts";

function bytesFromRange(len: number, fn: (i: number) => number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = fn(i);
  return out;
}

test("deriveDevicePublicKey: the same KEK always derives the same public key — nothing to persist, nothing to reload", () => {
  const kek = bytesFromRange(32, (i) => i);
  assert.equal(deriveDevicePublicKey(kek), deriveDevicePublicKey(kek));
});

test("deriveDevicePublicKey: a different KEK derives a different public key", () => {
  const kekA = bytesFromRange(32, (i) => i);
  const kekB = bytesFromRange(32, (i) => 31 - i);
  assert.notEqual(deriveDevicePublicKey(kekA), deriveDevicePublicKey(kekB));
});

test("wrapForDevicePublicKey + unwrapWithDeviceKey: round-trips a DEK-sized payload for the device that owns the KEK", () => {
  const kek = bytesFromRange(32, (i) => i);
  const publicKeyB64 = deriveDevicePublicKey(kek);

  const dek = bytesFromRange(32, (i) => (i * 3) % 256);
  const wrapped = wrapForDevicePublicKey(publicKeyB64, dek);
  const unwrapped = unwrapWithDeviceKey(kek, wrapped);

  assert.deepEqual(unwrapped, dek);
});

test("wrapForDevicePublicKey: wrapping the same DEK twice for the same device produces different ciphertexts (fresh ephemeral key each call)", () => {
  const kek = bytesFromRange(32, (i) => i);
  const publicKeyB64 = deriveDevicePublicKey(kek);
  const dek = bytesFromRange(32, (i) => i);

  const wrappedA = wrapForDevicePublicKey(publicKeyB64, dek);
  const wrappedB = wrapForDevicePublicKey(publicKeyB64, dek);

  assert.notEqual(
    wrappedA.ephemeralPublicKeyB64,
    wrappedB.ephemeralPublicKeyB64,
  );
  assert.notEqual(wrappedA.ciphertext, wrappedB.ciphertext);
  assert.deepEqual(unwrapWithDeviceKey(kek, wrappedA), dek);
  assert.deepEqual(unwrapWithDeviceKey(kek, wrappedB), dek);
});

test("unwrapWithDeviceKey: a different device's KEK cannot unwrap the wrap (device-bound, not shared)", () => {
  const kekA = bytesFromRange(32, (i) => i);
  const kekB = bytesFromRange(32, (i) => 31 - i);
  const publicKeyA = deriveDevicePublicKey(kekA);

  const dek = bytesFromRange(32, (i) => i);
  const wrapped = wrapForDevicePublicKey(publicKeyA, dek);

  assert.throws(() => unwrapWithDeviceKey(kekB, wrapped));
});

test("createKeyHandle + wrapForDevice: the intended real usage — the DEK held by a KeyHandle (e.g. a Worker) is wrapped for a device's public key without ever being handed to the caller as a plain value", async () => {
  const recipientKek = bytesFromRange(32, (i) => i * 5);
  const publicKeyB64 = deriveDevicePublicKey(recipientKek);

  const dek = bytesFromRange(32, (i) => (i * 7) % 256);
  const handle = createKeyHandle(
    asRawDekBytes(dek),
    new Uint8Array(32).fill(7),
    "test-info",
    {
      wrapForDevice: async (key, devicePublicKeyB64) =>
        wrapForDevicePublicKey(devicePublicKeyB64, key),
    },
  );

  // The handle's public surface never returns `dek` — only `wrapForDevice`'s result.
  const wrapped = await handle.wrapForDevice!(publicKeyB64);
  const unwrapped = unwrapWithDeviceKey(recipientKek, wrapped);

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
