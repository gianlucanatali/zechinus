/**
 * One-shot legacy AAD migration — decrypt a `BlobRecord` under an OLD AAD, re-encrypt
 * it under the CURRENT (canonical) AAD, byte-for-byte identical plaintext.
 *
 * The old AAD shape is ALWAYS app-specific: it's whatever historical convention a
 * table used before being ported onto DataCloak (a different `field` name, sometimes
 * a different `rowId` derivation). This module owns only the generic decrypt →
 * re-encrypt mechanics; it never guesses at legacy conventions — the caller supplies
 * `oldAAD`/`newAAD` explicitly. That's the extension point: DataCloak provides the
 * mechanism, the consuming app provides the historical knowledge.
 *
 * No silent failure: a missing record is a legitimate "nothing to migrate" (a user/key
 * that never had data) and returns `{ migrated: false }` without throwing. A record
 * that EXISTS but has a missing or malformed blob is never "nothing to migrate" — that's
 * corruption, and it throws explicitly rather than being reported identically to the
 * legitimate empty case.
 */
import {
  parseEncField,
  isEncryptedField,
  serializeEncField,
} from "./wireFormat.ts";
import type { BlobRecord, CryptoHandle, FieldAAD } from "./types.ts";

export interface LegacyMigrationResult {
  migrated: boolean;
  /** Present only when migrated:true — the caller persists this via its StorageAdapter. */
  record?: BlobRecord;
}

export async function migrateLegacyAAD(
  cryptoHandle: CryptoHandle,
  record: BlobRecord | null,
  oldAAD: FieldAAD,
  newAAD: FieldAAD,
): Promise<LegacyMigrationResult> {
  if (record === null) {
    return { migrated: false };
  }
  if (!record.blob) {
    throw new Error(
      `migrateLegacyAAD(table=${oldAAD.table}, rowId=${oldAAD.rowId}): record exists but blob is missing/empty — ` +
        `this is not a legitimate empty state (that's record === null), it's corruption. Refusing to silently skip it.`,
    );
  }
  if (!isEncryptedField(record.blob)) {
    throw new Error(
      `migrateLegacyAAD(table=${oldAAD.table}, rowId=${oldAAD.rowId}): record.blob is not a validly-serialized ` +
        `EncryptedField (missing the enc: prefix or malformed). Refusing to silently skip it.`,
    );
  }

  // Let this throw naturally on a GCM auth-tag mismatch (wrong oldAAD guess, wrong DEK,
  // or genuinely corrupt ciphertext) — never caught/swallowed here.
  const raw = await cryptoHandle.decryptJson<unknown>(
    parseEncField(record.blob),
    oldAAD,
  );
  const reEncrypted = await cryptoHandle.encryptJson(raw, newAAD);

  return {
    migrated: true,
    record: {
      schemaVersion: record.schemaVersion,
      blob: serializeEncField(reEncrypted),
      // content_hash hashes the plaintext envelope only (see keyDerivation.ts's
      // hashContent) — AAD never enters that computation, so it's invariant under
      // this operation and carried over unchanged rather than recomputed.
      contentHash: record.contentHash,
    },
  };
}
