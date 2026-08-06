/**
 * `core/crypto.ts`'s delegate variants (`encryptFieldWithDelegate`, etc.) — the AEAD
 * operation is injected instead of performed with a raw key, so a `KeyHandle` built
 * around an opaque native reference (`adapters/keyhandles/nativeModuleKeyHandle.ts`)
 * produces byte-identical envelopes to one built around a raw key. These tests prove
 * the wire format never diverges between the two paths.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { gcm } from "@noble/ciphers/aes.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  type AeadDelegate,
  encryptField,
  decryptField,
  encryptJson,
  encryptFieldWithDelegate,
  decryptFieldWithDelegate,
  encryptJsonWithDelegate,
} from "../core/crypto.ts";
import type { FieldAAD } from "../core/types.ts";

test("encryptFieldWithDelegate: the ciphertext is decryptable by decryptField (direct key) — same wire format", async () => {
  const dek = randomBytes(32);
  const delegate: AeadDelegate = {
    seal: async (nonce, aad, plaintext) => gcm(dek, nonce, aad).encrypt(plaintext),
    open: async (nonce, aad, ciphertext) => gcm(dek, nonce, aad).decrypt(ciphertext),
  };
  const aad: FieldAAD = { userId: "u1", table: "t", field: "f", rowId: "r1" };

  const enc = await encryptFieldWithDelegate(delegate, "hello via delegate", aad);

  assert.strictEqual(await decryptFieldWithDelegate(delegate, enc, aad), "hello via delegate");
  assert.strictEqual(await decryptField(dek, enc, aad), "hello via delegate");
});

test("decryptFieldWithDelegate: decrypts a field encrypted by the direct-key encryptField", async () => {
  const dek = randomBytes(32);
  const delegate: AeadDelegate = {
    seal: async (n, a, p) => gcm(dek, n, a).encrypt(p),
    open: async (n, a, c) => gcm(dek, n, a).decrypt(c),
  };
  const aad: FieldAAD = { userId: "u1", table: "t", field: "f", rowId: "r1" };

  const enc = await encryptField(dek, "hello direct", aad);

  assert.strictEqual(await decryptFieldWithDelegate(delegate, enc, aad), "hello direct");
});

test("encryptJsonWithDelegate: emits the same versions as encryptJson (4/6, always compressed)", async () => {
  const dek = randomBytes(32);
  const delegate: AeadDelegate = {
    seal: async (n, a, p) => gcm(dek, n, a).encrypt(p),
    open: async (n, a, c) => gcm(dek, n, a).decrypt(c),
  };
  const small = { a: 1 };
  const aad: FieldAAD = { userId: "u", table: "t", field: "f", rowId: "r" };
  assert.strictEqual((await encryptJsonWithDelegate(delegate, small, aad)).v, 4);
  assert.strictEqual((await encryptJson(dek, small, aad)).v, 4);
});
