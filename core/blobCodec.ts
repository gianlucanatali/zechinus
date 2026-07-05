/**
 * blobCodec — pure cryptographic round-trip for a blob-mode store.
 *
 * Extracted from `defineBlobStore` so the different cardinalities (perUser, perKey, …)
 * share the same crypto engine, varying only the **AAD** (i.e. *where* the blob lives:
 * `rowId = pid` for perUser, `rowId = key` for perKey) and the storage method used.
 *
 * No knowledge of Supabase/TanStack: uses only the crypto core and framework types.
 */

import {
  serializeEncField,
  parseEncField,
  isEncryptedField,
} from "./wireFormat.ts";
import {
  toEnvelope,
  fromEnvelope,
  runMigrations,
  type BlobMigrator,
} from "./versioning.ts";
import type {
  BlobRecord,
  CryptoHandle,
  EncryptedField,
  FieldAAD,
} from "./types.ts";

/** Encrypts `data` (versioned envelope) under the given AAD → `BlobRecord` ready for storage. */
export async function encodeBlob<T>(
  cryptoHandle: CryptoHandle,
  aad: FieldAAD,
  data: T,
  version: number,
  computeContentHash?: boolean,
): Promise<BlobRecord> {
  const envelope = toEnvelope(data, version);
  const enc = await cryptoHandle.encryptJson(envelope, aad);
  const record: BlobRecord = {
    schemaVersion: version,
    blob: serializeEncField(enc),
  };
  if (computeContentHash) {
    if (!cryptoHandle.hashContent) {
      throw new Error(
        `encodeBlob(${aad.table}): contentHash: true requires the CryptoHandle to implement ` +
          `hashContent — this handle doesn't (structurally valid CryptoHandle, missing the ` +
          `optional capability). Use createKeyHandle() or implement hashContent yourself.`,
      );
    }
    record.contentHash = await cryptoHandle.hashContent(envelope);
  }
  return record;
}

export interface DecodeResult<T> {
  data: T;
  /** true if migrators updated the shape → the caller can do a lazy re-save. */
  upgraded: boolean;
}

/**
 * Decrypts+migrates a `BlobRecord` (or returns `empty` if missing/not encrypted).
 * The AAD passed MUST match the one used at write time, otherwise the GCM auth tag
 * fails and `decryptJson` throws (this is the guarantee that ciphertext can't move
 * to a different slot).
 */
export async function decodeBlob<T>(
  cryptoHandle: CryptoHandle,
  aad: FieldAAD,
  record: BlobRecord | null,
  version: number,
  migrators: BlobMigrator[],
  empty: T,
): Promise<DecodeResult<T>> {
  if (!record?.blob || !isEncryptedField(record.blob)) {
    return { data: empty, upgraded: false };
  }
  const dbVersion = record.schemaVersion ?? 1;
  const parsed: EncryptedField = parseEncField(record.blob);
  const raw = await cryptoHandle.decryptJson<unknown>(parsed, aad);
  const { data, authenticatedVersion } = fromEnvelope<T>(raw, dbVersion);
  const { data: migrated, upgraded } = runMigrations<T>(
    data,
    authenticatedVersion,
    version,
    migrators,
  );
  return { data: migrated, upgraded };
}
