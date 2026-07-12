/* eslint-disable no-undef */
/**
 * Device-bound key provider — a non-exportable asymmetric keypair generated once per
 * device/browser, used to wrap a raw DEK so that only THIS device's private key can
 * unwrap it (multi-device DEK-rotation delivery, key-custody roadmap Fase 2.3: another
 * device wraps DEK_{N+1} against this device's public key, delivered via the device
 * registry). RSA-OAEP, not ECDH: a direct public-key encrypt of the 32-byte DEK needs no
 * ephemeral key / HKDF step on the sending device — one WebCrypto call, correct by
 * construction, no wrap format beyond a ciphertext.
 *
 * Persistence is injected (`DeviceKeyPairStorage`) rather than hardcoded to IndexedDB, so
 * the crypto itself is testable under plain `node --test` (`crypto.subtle` is available
 * there) — only `indexedDbDeviceKeyPairStorage`, the real browser-backed implementation,
 * needs an actual browser (covered by the consuming app's E2E suite, same split as
 * `webauthnKeyProvider.ts`).
 */

import { bytesToBase64, base64ToBytes } from "../core/keyDerivation.ts";

const RSA_OAEP_PARAMS: RsaHashedKeyGenParams = {
  name: "RSA-OAEP",
  modulusLength: 3072,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
};

/** RSA-OAEP has no external nonce (OAEP padding is randomized internally) — unlike `WrappedKey`. */
export type DeviceWrappedKey = { ciphertext: string };

export interface DeviceKeyPairStorage {
  loadKeyPair(): Promise<CryptoKeyPair | null>;
  saveKeyPair(keyPair: CryptoKeyPair): Promise<void>;
}

export interface DeviceKeyProvider {
  /** Generates the device keypair on first call, persists it, and returns the (exportable) public key. Idempotent. */
  getOrCreateDevicePublicKey(): Promise<{ publicKeyB64: string }>;
  /** Unwraps a DEK wrapped for THIS device's public key. Throws if wrapped for a different device. */
  unwrapWithDeviceKey(wrapped: DeviceWrappedKey): Promise<Uint8Array>;
}

export function webDeviceKeyProvider(
  storage: DeviceKeyPairStorage,
): DeviceKeyProvider {
  let cached: CryptoKeyPair | null = null;

  async function getOrCreateKeyPair(): Promise<CryptoKeyPair> {
    if (cached) return cached;
    const stored = await storage.loadKeyPair();
    if (stored) {
      cached = stored;
      return stored;
    }
    // extractable:false applies to the private key only — the Web Crypto spec always
    // generates the public key of a pair as extractable, regardless of this flag.
    const keyPair = await crypto.subtle.generateKey(RSA_OAEP_PARAMS, false, [
      "encrypt",
      "decrypt",
    ]);
    await storage.saveKeyPair(keyPair);
    cached = keyPair;
    return keyPair;
  }

  return {
    async getOrCreateDevicePublicKey() {
      const keyPair = await getOrCreateKeyPair();
      const raw = await crypto.subtle.exportKey("spki", keyPair.publicKey);
      return { publicKeyB64: bytesToBase64(new Uint8Array(raw)) };
    },

    async unwrapWithDeviceKey(wrapped) {
      const keyPair = await getOrCreateKeyPair();
      const ct = base64ToBytes(wrapped.ciphertext);
      const plain = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        keyPair.privateKey,
        ct,
      );
      return new Uint8Array(plain);
    },
  };
}

/**
 * Wraps a DEK for delivery to a specific device, called from ANY device that already
 * holds the plaintext DEK — needs only the target's public key, never its private key,
 * so it's a standalone function rather than a `DeviceKeyProvider` method.
 */
export async function wrapForDevicePublicKey(
  publicKeyB64: string,
  dek: Uint8Array<ArrayBuffer>,
): Promise<DeviceWrappedKey> {
  const raw = base64ToBytes(publicKeyB64);
  const publicKey = await crypto.subtle.importKey(
    "spki",
    raw,
    RSA_OAEP_PARAMS,
    true,
    ["encrypt"],
  );
  const ct = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, dek);
  return { ciphertext: bytesToBase64(new Uint8Array(ct)) };
}

const DB_NAME = "datacloak-device-key";
const STORE_NAME = "keypair";
const RECORD_KEY = "device-keypair";

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(STORE_NAME);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () =>
      reject(
        new Error(
          `deviceKeyProvider.openDb: ${req.error?.message ?? "unknown IndexedDB error"}`,
        ),
      );
  });
}

/** Real browser-backed storage — persists the non-extractable `CryptoKeyPair` object itself (structured-clonable) via IndexedDB. */
export function indexedDbDeviceKeyPairStorage(): DeviceKeyPairStorage {
  return {
    async loadKeyPair() {
      const db = await openDb();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, "readonly");
        const req = tx.objectStore(STORE_NAME).get(RECORD_KEY);
        req.onsuccess = () => resolve(req.result ?? null);
        req.onerror = () =>
          reject(
            new Error(
              `deviceKeyProvider.loadKeyPair: ${req.error?.message ?? "unknown IndexedDB error"}`,
            ),
          );
      });
    },

    async saveKeyPair(keyPair) {
      const db = await openDb();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, "readwrite");
        tx.objectStore(STORE_NAME).put(keyPair, RECORD_KEY);
        tx.oncomplete = () => resolve();
        tx.onerror = () =>
          reject(
            new Error(
              `deviceKeyProvider.saveKeyPair: ${tx.error?.message ?? "unknown IndexedDB error"}`,
            ),
          );
      });
    },
  };
}
