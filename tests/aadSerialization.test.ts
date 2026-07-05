/**
 * AAD serialization (`crypto.ts`'s `buildAADBytes`): the pre-fix format joined the 4
 * AAD fields with `|` and no escaping — a `|` inside any component (`field`, `rowId`,
 * ...) makes two DIFFERENT logical AADs serialize to the IDENTICAL byte string, which
 * AES-GCM then treats as interchangeable. The fix is `JSON.stringify` of the 4-tuple
 * (unambiguous — JSON's own string escaping handles any character), selected
 * deterministically by the envelope's `v` field: `1`=raw+AAD-v1, `2`=gzip+AAD-v1 (read
 * -only, legacy), `3`=raw+AAD-v2, `4`=gzip+AAD-v2 (always written from now on).
 *
 * The v1 fixtures below are built with a LOCAL COPY of the pre-fix pipe-join
 * `buildAADBytes`, frozen here exactly as it existed before this change — this is
 * what makes these tests a real regression oracle for legacy data, immune to any
 * future refactor of the real `buildAADBytes`.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { gcm } from "@noble/ciphers/aes.js";
import { randomBytes, clean } from "@noble/ciphers/utils.js";
import {
  encryptField,
  decryptField,
  encryptJson,
  decryptJson,
} from "../core/crypto.ts";
import type { FieldAAD, EncryptedField } from "../core/types.ts";

const ENCODER = new TextEncoder();

/** Frozen copy of the pre-fix (v1) AAD serialization: unescaped pipe-join. */
function legacyBuildAADBytes(aad: FieldAAD): Uint8Array {
  return ENCODER.encode(`${aad.userId}|${aad.table}|${aad.field}|${aad.rowId}`);
}

function toBase64(bytes: Uint8Array): string {
  const CHUNK = 8192;
  let out = "";
  for (let i = 0; i < bytes.length; i += CHUNK)
    out += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  return btoa(out);
}

/** Frozen copy of the pre-fix `encryptJson` — always gzip, always v:2, pipe-join AAD. */
async function legacyEncryptJson<T>(
  dek: Uint8Array,
  value: T,
  aad: FieldAAD,
): Promise<EncryptedField> {
  const json = JSON.stringify(value);
  const raw = ENCODER.encode(json);
  const cs = new CompressionStream("gzip");
  const writer = cs.writable.getWriter();
  writer.write(raw as Uint8Array<ArrayBuffer>);
  writer.close();
  const compressed = new Uint8Array(
    await new Response(cs.readable).arrayBuffer(),
  );

  const nonce = randomBytes(12);
  try {
    const cipher = gcm(dek, nonce, legacyBuildAADBytes(aad));
    return {
      ct: toBase64(cipher.encrypt(compressed)),
      n: toBase64(nonce),
      v: 2,
    };
  } finally {
    clean(nonce);
  }
}

test("decryptJson: decodes a v2 (legacy pipe-join AAD) blob correctly", async () => {
  const dek = randomBytes(32);
  const aad: FieldAAD = {
    userId: "u1",
    table: "t",
    field: "data",
    rowId: "r1",
  };
  const enc = await legacyEncryptJson(dek, { hello: "world" }, aad);
  assert.equal(enc.v, 2);
  const decoded = await decryptJson(dek, enc, aad);
  assert.deepEqual(decoded, { hello: "world" });
});

test("encryptJson: new writes always produce v:4 (gzip + AAD-v2)", async () => {
  const dek = randomBytes(32);
  const aad: FieldAAD = {
    userId: "u1",
    table: "t",
    field: "data",
    rowId: "r1",
  };
  const enc = await encryptJson(dek, { hello: "world" }, aad);
  assert.equal(enc.v, 4);
  assert.deepEqual(await decryptJson(dek, enc, aad), { hello: "world" });
});

test("encryptField: below the compression threshold produces v:3 (raw + AAD-v2)", async () => {
  const dek = randomBytes(32);
  const aad: FieldAAD = {
    userId: "u1",
    table: "t",
    field: "data",
    rowId: "r1",
  };
  const enc = await encryptField(dek, "short", aad);
  assert.equal(enc.v, 3);
  assert.equal(await decryptField(dek, enc, aad), "short");
});

test("encryptField: above the compression threshold produces v:4 (gzip + AAD-v2)", async () => {
  const dek = randomBytes(32);
  const aad: FieldAAD = {
    userId: "u1",
    table: "t",
    field: "data",
    rowId: "r1",
  };
  const longPlaintext = "x".repeat(200);
  const enc = await encryptField(dek, longPlaintext, aad);
  assert.equal(enc.v, 4);
  assert.equal(await decryptField(dek, enc, aad), longPlaintext);
});

test("roundtrip v3/v4: AAD containing '|' in rowId decrypts correctly (no collision under AAD-v2)", async () => {
  const dek = randomBytes(32);
  const aad: FieldAAD = {
    userId: "u1",
    table: "t",
    field: "data",
    rowId: "a|b",
  };

  const encField = await encryptField(dek, "short", aad);
  assert.equal(await decryptField(dek, encField, aad), "short");

  const longPlaintext = "y".repeat(200);
  const encFieldGzip = await encryptField(dek, longPlaintext, aad);
  assert.equal(await decryptField(dek, encFieldGzip, aad), longPlaintext);

  const encJson = await encryptJson(dek, { a: 1 }, aad);
  assert.deepEqual(await decryptJson(dek, encJson, aad), { a: 1 });
});

test("the collision this fix closes: under AAD-v1, field:'f|x'+rowId:'y' and field:'f'+rowId:'x|y' serialize identically", () => {
  const aadA: FieldAAD = { userId: "u", table: "t", field: "f|x", rowId: "y" };
  const aadB: FieldAAD = { userId: "u", table: "t", field: "f", rowId: "x|y" };
  assert.deepEqual(legacyBuildAADBytes(aadA), legacyBuildAADBytes(aadB));
});

test("under AAD-v2 (current), the same two ambiguous FieldAAD values do NOT decrypt each other's ciphertext", async () => {
  const dek = randomBytes(32);
  const aadA: FieldAAD = { userId: "u", table: "t", field: "f|x", rowId: "y" };
  const aadB: FieldAAD = { userId: "u", table: "t", field: "f", rowId: "x|y" };

  const enc = await encryptJson(dek, { secret: true }, aadA);
  await assert.rejects(() => decryptJson(dek, enc, aadB));
});

test("decryptField: unknown envelope version throws an explicit error naming the value", async () => {
  const dek = randomBytes(32);
  const aad: FieldAAD = {
    userId: "u1",
    table: "t",
    field: "data",
    rowId: "r1",
  };
  const enc = await encryptField(dek, "short", aad);
  const corrupted = { ...enc, v: 9 } as unknown as EncryptedField;
  await assert.rejects(() => decryptField(dek, corrupted, aad), /9/);
});
