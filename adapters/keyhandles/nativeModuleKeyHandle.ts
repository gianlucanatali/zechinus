/**
 * Native-module isolation for a `KeyHandle` (mobile) — the raw key bytes live only inside
 * a native object's memory (Swift/CryptoKit on iOS, Kotlin/javax.crypto on Android), never
 * in the Hermes JS heap shared with every other piece of app code and every installed npm
 * dependency. Same architectural role as `workerKeyHandle.ts` on web, and the same shape:
 * `new nativeModule.CryptoKey(rawBytes)` is this file's `new Worker(...)`. One instance per
 * handle, so two handles alive at once (a DEK rotation keeps `previousCryptoHandle`
 * alongside the current one) can never disturb each other.
 *
 * Bytes cross the bridge as `Uint8Array`, deliberately NOT as base64 strings: a JS string
 * is immutable, so a base64-encoded key could never be zeroed and would sit in the Hermes
 * heap until GC — the exact thing this adapter exists to avoid. It also saves the 33%
 * encoding overhead on every blob.
 *
 * `exportRawBytes` is deliberately NEVER implemented — same principle as `workerKeyHandle.ts`.
 * See `docs/DECISIONS.md` § "Native-module DEK isolation" for the full threat model,
 * including what this does NOT protect against.
 */
import type { KeyHandle, WrappedKey, RawDekBytes } from "../../core/keyDerivation.ts";
import { ZECHINUS_MAC_SALT } from "../../core/keyDerivation.ts";
import type { FieldAAD, EncryptedField } from "../../core/types.ts";
import {
  type AeadDelegate,
  encryptFieldWithDelegate,
  decryptFieldWithDelegate,
  encryptJsonWithDelegate,
  decryptJsonWithDelegate,
} from "../../core/crypto.ts";

/** One native key instance. Mirrors `CryptoKeyRef` in Swift/Kotlin 1:1. */
export interface NativeCryptoKey {
  initMacKey(macKey: Uint8Array): Promise<void>;
  aesGcmEncrypt(nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>;
  aesGcmDecrypt(nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>;
  hkdfDerive(salt: Uint8Array, info: string, length: number): Promise<Uint8Array>;
  hmacSha256(payload: Uint8Array): Promise<string>;
  wrapSelf(kek: Uint8Array): Promise<{ ciphertext: string; nonce: string }>;
  destroy(): void;
}

/**
 * The native module itself. The app wires the real one
 * (`import ExpoZechinusCrypto from "expo-zechinus-crypto"`); tests inject a fake.
 */
export interface NativeCryptoModule {
  CryptoKey: new (rawBytes: Uint8Array) => NativeCryptoKey;
}

/** Same UUID-from-bytes formatting as `core/keyDerivation.ts`'s `bytesToUUID`. */
function bytesToUUIDLocal(bytes: Uint8Array): string {
  const hex = Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

/**
 * Builds a `KeyHandle` around a key the native module already holds. Used by the OS-gated
 * zero-tap cache (Task A9), where the key is restored inside the boundary and no raw bytes
 * exist on the JS side at any point — not even as an argument.
 */
export async function createNativeModuleKeyHandleForLoadedKey(
  nativeKey: NativeCryptoKey,
  pidSalt: Uint8Array,
  pidInfo: string,
): Promise<KeyHandle> {
  const pid = bytesToUUIDLocal(await nativeKey.hkdfDerive(pidSalt, pidInfo, 16));

  // Same derivation as `createKeyHandle`: HKDF(dek, ZECHINUS_MAC_SALT,
  // "zechinus/content-hash-v1", 32). It must match byte for byte, or the `content_hash`
  // mobile computes for a given content won't match web's, and every skip-write /
  // optimistic-lock comparison between the two clients diverges. Verified in Task A6.
  const macKey = await nativeKey.hkdfDerive(ZECHINUS_MAC_SALT, "zechinus/content-hash-v1", 32);
  try {
    await nativeKey.initMacKey(macKey);
  } finally {
    macKey.fill(0); // the native instance holds its own copy
  }

  const delegate: AeadDelegate = {
    seal: (nonce, aad, plaintext) => nativeKey.aesGcmEncrypt(nonce, aad, plaintext),
    open: (nonce, aad, ciphertext) => nativeKey.aesGcmDecrypt(nonce, aad, ciphertext),
  };

  return {
    pid,
    encryptField: (plaintext, aad) => encryptFieldWithDelegate(delegate, plaintext, aad),
    decryptField: (enc, aad) => decryptFieldWithDelegate(delegate, enc, aad),
    encryptJson: <T>(value: T, aad: FieldAAD) => encryptJsonWithDelegate(delegate, value, aad),
    decryptJson: <T>(enc: EncryptedField, aad: FieldAAD) => decryptJsonWithDelegate<T>(delegate, enc, aad),
    // Same canonical serialization as createKeyHandle: JSON.stringify(payload), UTF-8.
    hashContent: (payload: unknown) =>
      nativeKey.hmacSha256(new TextEncoder().encode(JSON.stringify(payload))),
    wrapWithKek: async (kek) => (await nativeKey.wrapSelf(kek)) as WrappedKey,
    destroy: () => nativeKey.destroy(),
  };
}

/**
 * The normal entry point: hands `rawBytes` to a fresh native instance and never touches
 * them again. The caller should `clean()` its copy right after this resolves.
 */
export async function createNativeModuleKeyHandle(
  nativeModule: NativeCryptoModule,
  rawBytes: RawDekBytes,
  pidSalt: Uint8Array,
  pidInfo: string,
): Promise<KeyHandle> {
  return createNativeModuleKeyHandleForLoadedKey(
    new nativeModule.CryptoKey(rawBytes),
    pidSalt,
    pidInfo,
  );
}
