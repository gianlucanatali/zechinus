/**
 * `decodeWithLegacyFallback` — composes `decodeBlob` + `migrateLegacyAAD` into the
 * "read old if needed, always write new" pattern used by `defineStore`'s `legacyAAD`
 * option. Not a new crypto primitive: pure orchestration of two already-tested pieces.
 *
 * Flow: try the canonical AAD first (the common case — new stores, or rows already
 * migrated). If that throws (decrypt failure — the row may still be under the OLD
 * AAD convention), attempt `migrateLegacyAAD` with the caller-supplied legacy AAD.
 * If the legacy attempt ALSO fails to find anything to migrate, the ORIGINAL
 * (canonical) error is what propagates — it's the more likely real cause (corruption,
 * wrong DEK) when both attempts fail, never masked by the second attempt's error.
 * On a successful legacy decrypt, the row is immediately re-encrypted under the
 * canonical AAD and persisted via `persistMigrated` — every future read (and every
 * write) uses only the canonical AAD from then on.
 */
import { decodeBlob, type DecodeResult } from "./blobCodec.ts";
import { migrateLegacyAAD } from "./legacyMigration.ts";
import type { BlobMigrator } from "./versioning.ts";
import type { BlobRecord, CryptoHandle, FieldAAD } from "./types.ts";

export interface DecodeWithLegacyFallbackParams<T> {
  dek: CryptoHandle;
  record: BlobRecord | null;
  canonicalAAD: FieldAAD;
  /** Omit when the store has no `legacyAAD` configured — the canonical error propagates as-is. */
  legacyAAD?: FieldAAD;
  version: number;
  migrators: BlobMigrator[];
  empty: T;
  /** Called ONLY when a legacy-AAD row was found and successfully migrated. */
  persistMigrated: (record: BlobRecord) => Promise<void>;
}

export async function decodeWithLegacyFallback<T>(
  params: DecodeWithLegacyFallbackParams<T>,
): Promise<DecodeResult<T>> {
  try {
    return await decodeBlob<T>(
      params.dek,
      params.canonicalAAD,
      params.record,
      params.version,
      params.migrators,
      params.empty,
    );
  } catch (canonicalError) {
    if (!params.legacyAAD) throw canonicalError;
    const migration = await migrateLegacyAAD(
      params.dek,
      params.record,
      params.legacyAAD,
      params.canonicalAAD,
    );
    if (!migration.migrated || !migration.record) {
      // Nothing found under the legacy AAD either — the canonical failure is the
      // real, more informative error (corruption, wrong DEK). Never masked.
      throw canonicalError;
    }
    await params.persistMigrated(migration.record);
    return decodeBlob<T>(
      params.dek,
      params.canonicalAAD,
      migration.record,
      params.version,
      params.migrators,
      params.empty,
    );
  }
}
