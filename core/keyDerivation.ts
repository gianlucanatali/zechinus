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
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  encryptField,
  decryptField,
  encryptJson,
  decryptJson,
} from "./crypto.ts";
import type { CryptoHandle, FieldAAD, EncryptedField } from "./types.ts";

/**
 * Fixed, PUBLIC HKDF salt for deriving the `content_hash` MAC key from the DEK. It
 * does not need to be secret — HKDF salts are non-secret by design (RFC 5869), their
 * job is domain separation, not confidentiality. Every `KeyHandle` derives the same
 * MAC key from a given DEK, which is exactly what's needed: skip-write/optimistic-lock
 * compare hashes computed by potentially different handle instances for the same user.
 */
const DATACLOAK_MAC_SALT = new TextEncoder().encode(
  "datacloak-content-hash-mac-salt-v1",
);

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

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
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

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++)
    binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
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
 * Branded raw key material — the actual DEK bytes, before being wrapped into a
 * `KeyHandle`. The brand is compile-time-only (erased at runtime — it does NOT stop
 * `console.log`, a debugger, or any other runtime inspection): its job is to make
 * every boundary crossing of this value an explicit, typed decision instead of an
 * accident. A plain `Uint8Array` already in scope (a file buffer, a nonce, an
 * unrelated hash) can't silently flow into a DEK-shaped parameter, and a DEK can't
 * silently flow into a function expecting generic bytes, without an explicit cast at
 * that specific call site. See `asRawDekBytes` — call it exactly once, at the point
 * the key material is first obtained (WebAuthn PRF output, a password KDF result,
 * ...), immediately before handing it to `createKeyHandle`.
 */
export type RawDekBytes = Uint8Array & {
  readonly __rawDekBytes: unique symbol;
};

/** Marks raw bytes as DEK material. See `RawDekBytes` for what this does and doesn't guard against. */
export function asRawDekBytes(bytes: Uint8Array): RawDekBytes {
  return bytes as RawDekBytes;
}

export interface CreateKeyHandleOptions {
  /**
   * Overrides the default HMAC-SHA256-from-DEK `hashContent` — e.g. to delegate the
   * `content_hash` MAC to an external KMS instead of deriving it from the DEK. Receives
   * the same canonical payload `hashContent` always receives (the caller doesn't need
   * to re-derive anything). Omit to use the default (recommended unless you have a
   * concrete reason to source the key elsewhere, like a KMS-managed rotation policy
   * decoupled from the DEK's own lifecycle).
   *
   * MUST be a keyed MAC (HMAC, KMAC, ...) — the result is stored server-side as
   * `content_hash`, so an unkeyed hash (plain SHA-256) would let the server
   * fingerprint plaintext contents, reintroducing the exact leak the keyed default
   * exists to prevent. No guardrail can verify this at runtime; it's on the caller.
   */
  hashContent?(payload: unknown): Promise<string>;
}

/**
 * Builds a `KeyHandle` from raw key bytes. The bytes are copied into a private
 * closure — the caller can zero their own copy immediately after calling this.
 */
export function createKeyHandle(
  rawBytes: RawDekBytes,
  pidSalt: Uint8Array,
  pidInfo: string,
  options?: CreateKeyHandleOptions,
): KeyHandle {
  const key = rawBytes.slice();
  const pid = derivePID(key, pidSalt, pidInfo);
  const macKey = options?.hashContent
    ? null
    : deriveKey(key, DATACLOAK_MAC_SALT, "datacloak/content-hash-v1", 32);
  const hashContent =
    options?.hashContent ??
    (async (payload: unknown) =>
      bytesToHex(
        hmac(
          sha256,
          macKey!,
          new TextEncoder().encode(JSON.stringify(payload)),
        ),
      ));
  return {
    pid,
    encryptField: (plaintext, aad) => encryptField(key, plaintext, aad),
    decryptField: (enc, aad) => decryptField(key, enc, aad),
    encryptJson: <T>(value: T, aad: FieldAAD) => encryptJson(key, value, aad),
    decryptJson: <T>(enc: EncryptedField, aad: FieldAAD) =>
      decryptJson<T>(key, enc, aad),
    hashContent,
    wrapWithKek: (kek) => Promise.resolve(wrapKey(kek, key)),
    destroy() {
      clean(key);
      if (macKey) clean(macKey);
    },
  };
}

/**
 * Binds `createKeyHandle` to a fixed `pidSalt`/`pidInfo`, returning a ready-to-use
 * `(rawBytes) => KeyHandle` factory. Every app ends up writing this exact one-line
 * partial application (its own salt/info are the only thing that ever differs) — so
 * the binding itself lives here, not re-typed per app.
 */
export function bindKeyHandleFactory(
  pidSalt: Uint8Array,
  pidInfo: string,
): (rawBytes: RawDekBytes, options?: CreateKeyHandleOptions) => KeyHandle {
  return (rawBytes, options) =>
    createKeyHandle(rawBytes, pidSalt, pidInfo, options);
}
