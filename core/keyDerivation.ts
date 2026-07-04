/**
 * Generic key-derivation primitives — HKDF-based key/PID derivation and AES-GCM key
 * wrapping, operating only on raw bytes. Zero platform dependency (no WebAuthn, no
 * `navigator.credentials`): a `KeyProvider` adapter for ANY platform (WebAuthn PRF on
 * web, native biometrics on React Native, a password KDF, a hardware token) derives
 * its own raw key material however it needs to, then calls `createKeyHandle` here to
 * turn those bytes into a usable `CryptoHandle`. This is the one place that logic
 * lives, so a new platform adapter never reimplements it.
 */
import { gcm } from "@noble/ciphers/aes.js";
import { randomBytes, clean } from "@noble/ciphers/utils.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  encryptField,
  decryptField,
  encryptJson,
  decryptJson,
} from "./crypto.ts";
import type { CryptoHandle, FieldAAD, EncryptedField } from "./types.ts";

/** Generic HKDF-SHA256 derivation. `salt`/`info` are the caller's — this has no defaults. */
export function deriveKey(
  inputKeyMaterial: Uint8Array,
  salt: Uint8Array,
  info: string,
  length: number,
): Uint8Array {
  return hkdf(
    sha256,
    inputKeyMaterial,
    salt,
    new TextEncoder().encode(info),
    length,
  );
}

function bytesToUUID(bytes: Uint8Array): string {
  const h = Array.from(bytes).map((b) => b.toString(16).padStart(2, "0"));
  return `${h.slice(0, 4).join("")}-${h.slice(4, 6).join("")}-${h.slice(6, 8).join("")}-${h.slice(8, 10).join("")}-${h.slice(10, 16).join("")}`;
}

/**
 * Derives a stable pseudonymous id from a key — used as `userId` in every AAD, never
 * written to the DB (the storage layer scopes by the app's own `user_id`/RLS).
 */
export function derivePID(
  dek: Uint8Array,
  salt: Uint8Array,
  info: string,
): string {
  return bytesToUUID(deriveKey(dek, salt, info, 16));
}

export type WrappedKey = { ciphertext: string; nonce: string };

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++)
    binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Wraps (encrypts) a key with another key (a KEK) using AES-256-GCM. Random nonce per call. */
export function wrapKey(kek: Uint8Array, keyToWrap: Uint8Array): WrappedKey {
  const nonce = randomBytes(12);
  const ct = gcm(kek, nonce).encrypt(keyToWrap);
  const result = { ciphertext: bytesToBase64(ct), nonce: bytesToBase64(nonce) };
  clean(nonce);
  return result;
}

/** Unwraps a key. Throws if the GCM tag doesn't match (wrong KEK or corrupted data). */
export function unwrapKey(kek: Uint8Array, wrapped: WrappedKey): Uint8Array {
  const ct = base64ToBytes(wrapped.ciphertext);
  const nonce = base64ToBytes(wrapped.nonce);
  return gcm(kek, nonce).decrypt(ct);
}

/** The richer key handle a `KeyProvider` adapter builds from raw key material. */
export interface KeyHandle extends CryptoHandle {
  encryptField(plaintext: string, aad: FieldAAD): Promise<EncryptedField>;
  decryptField(enc: EncryptedField, aad: FieldAAD): Promise<string>;
  /** Wraps this handle's key with a KEK, without ever exposing the raw bytes. */
  wrapWithKek(kek: Uint8Array): Promise<WrappedKey>;
  /** Zeroes the internal key bytes — call on lock/logout. */
  destroy(): void;
}

/**
 * Builds a `KeyHandle` from raw key bytes. The bytes are copied into a private
 * closure — the caller can zero their own copy immediately after calling this.
 */
export function createKeyHandle(
  rawBytes: Uint8Array,
  pidSalt: Uint8Array,
  pidInfo: string,
): KeyHandle {
  const key = rawBytes.slice();
  const pid = derivePID(key, pidSalt, pidInfo);
  return {
    pid,
    encryptField: (plaintext, aad) => encryptField(key, plaintext, aad),
    decryptField: (enc, aad) => decryptField(key, enc, aad),
    encryptJson: <T>(value: T, aad: FieldAAD) => encryptJson(key, value, aad),
    decryptJson: <T>(enc: EncryptedField, aad: FieldAAD) =>
      decryptJson<T>(key, enc, aad),
    wrapWithKek: (kek) => Promise.resolve(wrapKey(kek, key)),
    destroy() {
      clean(key);
    },
  };
}
