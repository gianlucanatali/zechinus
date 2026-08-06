import { test } from "node:test";
import assert from "node:assert/strict";
import { gcm } from "@noble/ciphers/aes.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { createNativeModuleKeyHandle, type NativeCryptoModule } from "../adapters/keyhandles/nativeModuleKeyHandle.ts";
import { asRawDekBytes } from "../core/keyDerivation.ts";

/** Fake of the native class: one instance per key, exactly like the real native module. */
function makeFakeNativeModule(): NativeCryptoModule {
  return {
    CryptoKey: class {
      #key: Uint8Array | null;
      #macKey: Uint8Array | null = null;
      constructor(rawBytes: Uint8Array) { this.#key = Uint8Array.from(rawBytes); }
      #require() {
        if (!this.#key) throw new Error("CryptoKey: already destroyed");
        return this.#key;
      }
      async initMacKey(macKey: Uint8Array) { this.#require(); this.#macKey = Uint8Array.from(macKey); }
      async aesGcmEncrypt(nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array) {
        return gcm(this.#require(), nonce, aad).encrypt(plaintext);
      }
      async aesGcmDecrypt(nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array) {
        return gcm(this.#require(), nonce, aad).decrypt(ciphertext);
      }
      async hkdfDerive(salt: Uint8Array, info: string, length: number) {
        return hkdf(sha256, this.#require(), salt, new TextEncoder().encode(info), length);
      }
      async hmacSha256(payload: Uint8Array) {
        this.#require();
        return Buffer.from(hmac(sha256, this.#macKey!, payload)).toString("hex");
      }
      async wrapSelf() { return { ciphertext: "ct", nonce: "n" }; }
      destroy() { this.#key = null; this.#macKey = null; }
    },
  } as unknown as NativeCryptoModule;
}

test("createNativeModuleKeyHandle: never exposes the raw bytes", async () => {
  const handle = await createNativeModuleKeyHandle(
    makeFakeNativeModule(), asRawDekBytes(randomBytes(32)), randomBytes(16), "test-pid-info",
  );
  assert.strictEqual(typeof handle.pid, "string");
  assert.strictEqual((handle as unknown as Record<string, unknown>).exportRawBytes, undefined);
});

test("createNativeModuleKeyHandle: encryptField/decryptField round-trip through the native instance", async () => {
  const handle = await createNativeModuleKeyHandle(
    makeFakeNativeModule(), asRawDekBytes(randomBytes(32)), randomBytes(16), "test",
  );
  const aad = { userId: "u1", table: "t", field: "f", rowId: "r1" };
  const enc = await handle.encryptField("secret payload", aad);
  assert.strictEqual(await handle.decryptField(enc, aad), "secret payload");
});

/**
 * The invariant the instance model exists to guarantee: during a rotation
 * `previousCryptoHandle` lives alongside the current one, and destroying it must
 * never touch the other.
 */
test("createNativeModuleKeyHandle: destroy() of one handle never touches the other", async () => {
  const nativeModule = makeFakeNativeModule();
  const aad = { userId: "u1", table: "t", field: "f", rowId: "r1" };
  const previous = await createNativeModuleKeyHandle(nativeModule, asRawDekBytes(randomBytes(32)), randomBytes(16), "test");
  const current = await createNativeModuleKeyHandle(nativeModule, asRawDekBytes(randomBytes(32)), randomBytes(16), "test");

  previous.destroy();

  await assert.doesNotReject(() => current.encryptField("still works", aad));
  await assert.rejects(() => previous.encryptField("gone", aad), /destroyed/);
});
