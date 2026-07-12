/**
 * Epoch-aware AAD (AAD-v3, `v: 5|6`) — key-custody rotation, Fase 2.1. Mirrors
 * `aadSerialization.test.ts`'s v1→v2 precedent exactly: a new envelope version
 * selected deterministically from `enc.v`/`enc.epoch`, old behavior completely
 * unchanged when the new field (`aad.epoch`) is never supplied.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  encryptField,
  decryptField,
  encryptJson,
  decryptJson,
} from "../core/crypto.ts";
import type { FieldAAD, EncryptedField } from "../core/types.ts";

test("encryptField: no aad.epoch → v:3/4 unchanged, no epoch key on the output (byte-for-byte pre-rotation shape)", async () => {
  const dek = randomBytes(32);
  const aad: FieldAAD = {
    userId: "u1",
    table: "t",
    field: "data",
    rowId: "r1",
  };

  const short = await encryptField(dek, "short", aad);
  assert.equal(short.v, 3);
  assert.equal("epoch" in short, false);

  const long = await encryptField(dek, "x".repeat(200), aad);
  assert.equal(long.v, 4);
  assert.equal("epoch" in long, false);
});

test("encryptField: aad.epoch set → v:5 (raw) below the compression threshold, enc.epoch stamped", async () => {
  const dek = randomBytes(32);
  const aad: FieldAAD = {
    userId: "u1",
    table: "t",
    field: "data",
    rowId: "r1",
    epoch: 2,
  };
  const enc = await encryptField(dek, "short", aad);
  assert.equal(enc.v, 5);
  assert.equal(enc.epoch, 2);
  assert.equal(await decryptField(dek, enc, aad), "short");
});

test("encryptField: aad.epoch set → v:6 (gzip) above the compression threshold", async () => {
  const dek = randomBytes(32);
  const aad: FieldAAD = {
    userId: "u1",
    table: "t",
    field: "data",
    rowId: "r1",
    epoch: 2,
  };
  const longPlaintext = "x".repeat(200);
  const enc = await encryptField(dek, longPlaintext, aad);
  assert.equal(enc.v, 6);
  assert.equal(enc.epoch, 2);
  assert.equal(await decryptField(dek, enc, aad), longPlaintext);
});

test("encryptJson: aad.epoch set → always v:6, roundtrips", async () => {
  const dek = randomBytes(32);
  const aad: FieldAAD = {
    userId: "u1",
    table: "t",
    field: "data",
    rowId: "r1",
    epoch: 7,
  };
  const enc = await encryptJson(dek, { hello: "world" }, aad);
  assert.equal(enc.v, 6);
  assert.equal(enc.epoch, 7);
  assert.deepEqual(await decryptJson(dek, enc, aad), { hello: "world" });
});

test("decryptField: uses enc.epoch (the stored claim), not aad.epoch — the caller's aad.epoch is ignored on decrypt", async () => {
  const dek = randomBytes(32);
  const aad: FieldAAD = {
    userId: "u1",
    table: "t",
    field: "data",
    rowId: "r1",
    epoch: 3,
  };
  const enc = await encryptField(dek, "short", aad);
  assert.equal(enc.epoch, 3);

  // Caller passes a DIFFERENT (wrong) aad.epoch — decrypt must still succeed,
  // because it rebuilds AAD-v3 from enc.epoch, not from this parameter.
  const decoded = await decryptField(dek, enc, { ...aad, epoch: 999 });
  assert.equal(decoded, "short");
});

test("tamper: flipping enc.epoch after encryption (without re-encrypting) fails decryption — the whole point of binding epoch into the AAD, not just storing it as plain metadata", async () => {
  const dek = randomBytes(32);
  const aad: FieldAAD = {
    userId: "u1",
    table: "t",
    field: "data",
    rowId: "r1",
    epoch: 1,
  };
  const enc = await encryptField(dek, "short", aad);
  assert.equal(enc.epoch, 1);

  const tampered: EncryptedField = { ...enc, epoch: 2 };
  await assert.rejects(() => decryptField(dek, tampered, aad));
});

test("mixed-epoch read: two rows, epoch 1 and epoch 2, both under the SAME dek, both decrypt correctly by their own stored epoch (no cross-talk)", async () => {
  const dek = randomBytes(32);
  const aadEpoch1: FieldAAD = {
    userId: "u1",
    table: "t",
    field: "data",
    rowId: "r1",
    epoch: 1,
  };
  const aadEpoch2: FieldAAD = {
    userId: "u1",
    table: "t",
    field: "data",
    rowId: "r2",
    epoch: 2,
  };

  const encEpoch1 = await encryptField(dek, "row at epoch 1", aadEpoch1);
  const encEpoch2 = await encryptField(dek, "row at epoch 2", aadEpoch2);

  assert.equal(await decryptField(dek, encEpoch1, aadEpoch1), "row at epoch 1");
  assert.equal(await decryptField(dek, encEpoch2, aadEpoch2), "row at epoch 2");
});

test("decryptField: v5/v6 with enc.epoch missing throws an explicit error (corrupt envelope, not a silent wrong decrypt)", async () => {
  const dek = randomBytes(32);
  const aad: FieldAAD = {
    userId: "u1",
    table: "t",
    field: "data",
    rowId: "r1",
    epoch: 1,
  };
  const enc = await encryptField(dek, "short", aad);
  const corrupted = { ...enc, epoch: undefined } as EncryptedField;
  await assert.rejects(
    () => decryptField(dek, corrupted, aad),
    /epoch-aware but no epoch/,
  );
});

test("decryptField: v6 still knows to gzip-decompress (epoch doesn't disturb the existing compression dispatch)", async () => {
  const dek = randomBytes(32);
  const aad: FieldAAD = {
    userId: "u1",
    table: "t",
    field: "data",
    rowId: "r1",
    epoch: 5,
  };
  const longPlaintext = "z".repeat(500);
  const enc = await encryptField(dek, longPlaintext, aad);
  assert.equal(enc.v, 6);
  assert.equal(await decryptField(dek, enc, aad), longPlaintext);
});
