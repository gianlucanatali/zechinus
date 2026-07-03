/**
 * defineBlobStore — factory for encrypted stores in "blob" mode: one encrypted
 * record per user. Consolidates the load/save pattern duplicated today across
 * the host app's *BlobService files (asset, portfolio, snapshot, ...). No knowledge
 * of Supabase or TanStack: uses the crypto core (@crypto) and the `StorageAdapter`
 * from config.
 *
 * Default AAD: { userId: pid, table: name, field: "data", rowId: pid } — identical
 * to the one used by the *BlobService files, so existing encrypted data stays
 * decryptable.
 * ⚠️ Changing `name` changes the AAD → existing blobs stop decrypting.
 */

import type { DekHandle, FieldAAD } from "@crypto/field-crypto";
import { type BlobMigrator } from "./versioning.ts";
import { encodeBlob, decodeBlob } from "./blobCodec.ts";
import { getSecureStoreConfig } from "./config.ts";

export interface BlobStore<T> {
  readonly name: string;
  readonly version: number;
  load(userId: string, dek: DekHandle): Promise<T>;
  save(userId: string, dek: DekHandle, data: T): Promise<void>;
}

export interface BlobStoreDef<T> {
  /** Collection/table = the `table` value in the AAD. Never change it for existing data. */
  name: string;
  version: number;
  /** Value returned when the record doesn't exist (or isn't encrypted). */
  empty: T;
  migrators?: BlobMigrator[];
  /** AAD override; default { userId: pid, table: name, field: "data", rowId: pid }. */
  buildAAD?: (dek: DekHandle, name: string) => FieldAAD;
  /** If present, computes the envelope's content_hash (e.g. @shared's hashContent). */
  hashContent?: (envelope: unknown) => Promise<string>;
}

function defaultAAD(dek: DekHandle, name: string): FieldAAD {
  return { userId: dek.pid, table: name, field: "data", rowId: dek.pid };
}

export function defineBlobStore<T>(def: BlobStoreDef<T>): BlobStore<T> {
  const migrators = def.migrators ?? [];
  const aadOf = (dek: DekHandle): FieldAAD =>
    (def.buildAAD ?? defaultAAD)(dek, def.name);

  async function save(userId: string, dek: DekHandle, data: T): Promise<void> {
    const { storage } = getSecureStoreConfig();
    const record = await encodeBlob(
      dek,
      aadOf(dek),
      data,
      def.version,
      def.hashContent,
    );
    await storage.putOne(def.name, userId, record);
  }

  async function load(userId: string, dek: DekHandle): Promise<T> {
    const { storage } = getSecureStoreConfig();
    const record = await storage.getOne(def.name, userId);
    const { data, upgraded } = await decodeBlob<T>(
      dek,
      aadOf(dek),
      record,
      def.version,
      migrators,
      def.empty,
    );
    if (upgraded) {
      // lazy upgrade: rewrites the migrated blob without blocking the read
      save(userId, dek, data).catch((e) =>
        console.error(`secure-store(${def.name}): lazy upgrade failed:`, e),
      );
    }
    return data;
  }

  return { name: def.name, version: def.version, load, save };
}
