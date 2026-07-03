import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import type { FieldAAD } from "@crypto/field-crypto";

import { createDekHandle } from "../../crypto/passkey-prf.ts";
import { encodeBlob, decodeBlob } from "../core/blobCodec.ts";
import { migrateLegacyAAD } from "../core/legacyMigration.ts";
import type { BlobRecord } from "../core/types.ts";

function oldAAD(userId: string, yearMonth: string): FieldAAD {
  // Historical convention this table used before it was ported to DataCloak.
  return {
    userId,
    table: "transaction_blobs",
    field: "transactions",
    rowId: yearMonth,
  };
}
function newAAD(userId: string, yearMonth: string): FieldAAD {
  // DataCloak's canonical perKey convention (field is always "data").
  return {
    userId,
    table: "transaction_blobs",
    field: "data",
    rowId: yearMonth,
  };
}

test("migrateLegacyAAD: no record yet → migrated:false, does NOT throw (legitimate empty state)", async () => {
  const dek = createDekHandle(randomBytes(32));
  const result = await migrateLegacyAAD(
    dek,
    null,
    oldAAD(dek.pid, "2026-06"),
    newAAD(dek.pid, "2026-06"),
  );
  assert.deepEqual(result, { migrated: false });
});

test("migrateLegacyAAD: decrypts under the OLD AAD, re-encrypts under the NEW one, same plaintext", async () => {
  const dek = createDekHandle(randomBytes(32));
  const legacyRecord = await encodeBlob(
    dek,
    oldAAD(dek.pid, "2026-06"),
    { transactions: ["rent"] },
    1,
  );

  const result = await migrateLegacyAAD(
    dek,
    legacyRecord,
    oldAAD(dek.pid, "2026-06"),
    newAAD(dek.pid, "2026-06"),
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
    dek,
    newAAD(dek.pid, "2026-06"),
    result.record!,
    1,
    [],
    { transactions: [] },
  );
  assert.deepEqual(data, { transactions: ["rent"] });

  // and it's genuinely no longer decryptable under the OLD AAD (real migration, not a copy)
  await assert.rejects(() =>
    decodeBlobStrict(dek, oldAAD(dek.pid, "2026-06"), result.record!),
  );
});

test("migrateLegacyAAD: preserves schemaVersion and contentHash from the source record", async () => {
  const dek = createDekHandle(randomBytes(32));
  const legacyRecord = await encodeBlob(
    dek,
    oldAAD(dek.pid, "2026-06"),
    { transactions: [] },
    3,
    async () => "precomputed-hash",
  );

  const result = await migrateLegacyAAD(
    dek,
    legacyRecord,
    oldAAD(dek.pid, "2026-06"),
    newAAD(dek.pid, "2026-06"),
  );

  assert.equal(result.record!.schemaVersion, 3);
  assert.equal(result.record!.contentHash, "precomputed-hash");
});

test("migrateLegacyAAD: wrong old-AAD guess → propagates the decrypt failure, never swallowed", async () => {
  const dek = createDekHandle(randomBytes(32));
  const legacyRecord = await encodeBlob(
    dek,
    oldAAD(dek.pid, "2026-06"),
    { transactions: ["rent"] },
    1,
  );

  const wrongGuess: FieldAAD = {
    userId: dek.pid,
    table: "transaction_blobs",
    field: "WRONG_FIELD_NAME", // app supplied an incorrect legacy AAD
    rowId: "2026-06",
  };

  await assert.rejects(() =>
    migrateLegacyAAD(dek, legacyRecord, wrongGuess, newAAD(dek.pid, "2026-06")),
  );
});

test("migrateLegacyAAD: row exists but blob is empty → throws explicitly, does NOT silently report migrated:false", async () => {
  const dek = createDekHandle(randomBytes(32));
  const corruptRecord: BlobRecord = { schemaVersion: 1, blob: "" };

  await assert.rejects(
    () =>
      migrateLegacyAAD(
        dek,
        corruptRecord,
        oldAAD(dek.pid, "2026-06"),
        newAAD(dek.pid, "2026-06"),
      ),
    /blob is missing\/empty/i,
  );
});

test("migrateLegacyAAD: row exists but blob is malformed (not enc: prefixed) → throws explicitly", async () => {
  const dek = createDekHandle(randomBytes(32));
  const corruptRecord: BlobRecord = {
    schemaVersion: 1,
    blob: "not-a-valid-encrypted-field",
  };

  await assert.rejects(() =>
    migrateLegacyAAD(
      dek,
      corruptRecord,
      oldAAD(dek.pid, "2026-06"),
      newAAD(dek.pid, "2026-06"),
    ),
  );
});

// Strict decode (no empty-fallback) used only to assert the OLD AAD genuinely stops working.
async function decodeBlobStrict(
  dek: ReturnType<typeof createDekHandle>,
  aad: FieldAAD,
  record: BlobRecord,
): Promise<unknown> {
  const { parseEncField } = await import("@crypto/field-crypto");
  return dek.decryptJson(parseEncField(record.blob), aad);
}
