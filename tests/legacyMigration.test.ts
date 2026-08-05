import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import { createDekHandle } from "./testKeyHandle.ts";
import { encodeBlob, decodeBlob } from "../core/blobCodec.ts";
import { migrateLegacyAAD } from "../core/legacyMigration.ts";
import type { BlobRecord, FieldAAD } from "../core/types.ts";

function oldAAD(userId: string, yearMonth: string): FieldAAD {
  // Historical convention this table used before it was ported to Zechinus.
  return {
    userId,
    table: "transaction_blobs",
    field: "transactions",
    rowId: yearMonth,
  };
}
function newAAD(userId: string, yearMonth: string): FieldAAD {
  // Zechinus's canonical perKey convention (field is always "data").
  return {
    userId,
    table: "transaction_blobs",
    field: "data",
    rowId: yearMonth,
  };
}

test("migrateLegacyAAD: no record yet → migrated:false, does NOT throw (legitimate empty state)", async () => {
  const cryptoHandle = createDekHandle(randomBytes(32));
  const result = await migrateLegacyAAD(
    cryptoHandle,
    null,
    oldAAD(cryptoHandle.pid, "2026-06"),
    newAAD(cryptoHandle.pid, "2026-06"),
  );
  assert.deepEqual(result, { migrated: false });
});

test("migrateLegacyAAD: decrypts under the OLD AAD, re-encrypts under the NEW one, same plaintext", async () => {
  const cryptoHandle = createDekHandle(randomBytes(32));
  const legacyRecord = await encodeBlob(
    cryptoHandle,
    oldAAD(cryptoHandle.pid, "2026-06"),
    { transactions: ["rent"] },
    1,
  );

  const result = await migrateLegacyAAD(
    cryptoHandle,
    legacyRecord,
    oldAAD(cryptoHandle.pid, "2026-06"),
    newAAD(cryptoHandle.pid, "2026-06"),
  );

  assert.equal(result.migrated, true);
  assert.ok(result.record);
  assert.notEqual(
    result.record!.blob,
    legacyRecord.blob,
    "ciphertext must differ (new AAD, new nonce)",
  );

  // decrypting the migrated record under the NEW AAD returns the original plaintext
  const { data } = await decodeBlob<{ transactions: string[] }>(
    cryptoHandle,
    newAAD(cryptoHandle.pid, "2026-06"),
    result.record!,
    1,
    [],
    { transactions: [] },
  );
  assert.deepEqual(data, { transactions: ["rent"] });

  // and it's genuinely no longer decryptable under the OLD AAD (real migration, not a copy)
  await assert.rejects(() =>
    decodeBlobStrict(
      cryptoHandle,
      oldAAD(cryptoHandle.pid, "2026-06"),
      result.record!,
    ),
  );
});

test("migrateLegacyAAD: preserves schemaVersion and contentHash from the source record", async () => {
  const cryptoHandle = createDekHandle(randomBytes(32));
  const legacyRecord = await encodeBlob(
    cryptoHandle,
    oldAAD(cryptoHandle.pid, "2026-06"),
    { transactions: [] },
    3,
    true,
  );

  const result = await migrateLegacyAAD(
    cryptoHandle,
    legacyRecord,
    oldAAD(cryptoHandle.pid, "2026-06"),
    newAAD(cryptoHandle.pid, "2026-06"),
  );

  assert.equal(result.record!.schemaVersion, 3);
  assert.ok(result.record!.contentHash, "contentHash present");
  assert.equal(result.record!.contentHash, legacyRecord.contentHash);
});

test("migrateLegacyAAD: wrong old-AAD guess → propagates the decrypt failure, never swallowed", async () => {
  const cryptoHandle = createDekHandle(randomBytes(32));
  const legacyRecord = await encodeBlob(
    cryptoHandle,
    oldAAD(cryptoHandle.pid, "2026-06"),
    { transactions: ["rent"] },
    1,
  );

  const wrongGuess: FieldAAD = {
    userId: cryptoHandle.pid,
    table: "transaction_blobs",
    field: "WRONG_FIELD_NAME", // app supplied an incorrect legacy AAD
    rowId: "2026-06",
  };

  await assert.rejects(() =>
    migrateLegacyAAD(
      cryptoHandle,
      legacyRecord,
      wrongGuess,
      newAAD(cryptoHandle.pid, "2026-06"),
    ),
  );
});

test("migrateLegacyAAD: row exists but blob is empty → throws explicitly, does NOT silently report migrated:false", async () => {
  const cryptoHandle = createDekHandle(randomBytes(32));
  const corruptRecord: BlobRecord = { schemaVersion: 1, blob: "" };

  await assert.rejects(
    () =>
      migrateLegacyAAD(
        cryptoHandle,
        corruptRecord,
        oldAAD(cryptoHandle.pid, "2026-06"),
        newAAD(cryptoHandle.pid, "2026-06"),
      ),
    /blob is missing\/empty/i,
  );
});

test("migrateLegacyAAD: row exists but blob is malformed (not enc: prefixed) → throws explicitly", async () => {
  const cryptoHandle = createDekHandle(randomBytes(32));
  const corruptRecord: BlobRecord = {
    schemaVersion: 1,
    blob: "not-a-valid-encrypted-field",
  };

  await assert.rejects(() =>
    migrateLegacyAAD(
      cryptoHandle,
      corruptRecord,
      oldAAD(cryptoHandle.pid, "2026-06"),
      newAAD(cryptoHandle.pid, "2026-06"),
    ),
  );
});

// Strict decode (no empty-fallback) used only to assert the OLD AAD genuinely stops working.
async function decodeBlobStrict(
  cryptoHandle: ReturnType<typeof createDekHandle>,
  aad: FieldAAD,
  record: BlobRecord,
): Promise<unknown> {
  const { parseEncField } = await import("../core/wireFormat.ts");
  return cryptoHandle.decryptJson(parseEncField(record.blob), aad);
}
