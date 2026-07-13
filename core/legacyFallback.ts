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
import { decodeBlob, encodeBlob, type DecodeResult } from "./blobCodec.ts";
import { migrateLegacyAAD } from "./legacyMigration.ts";
import type { BlobMigrator } from "./versioning.ts";
import type { BlobRecord, CryptoHandle, FieldAAD } from "./types.ts";

export interface DecodeWithLegacyFallbackParams<T> {
  cryptoHandle: CryptoHandle;
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
      params.cryptoHandle,
      params.canonicalAAD,
      params.record,
      params.version,
      params.migrators,
      params.empty,
    );
  } catch (canonicalError) {
    if (!params.legacyAAD) throw canonicalError;
    let migration;
    try {
      migration = await migrateLegacyAAD(
        params.cryptoHandle,
        params.record,
        params.legacyAAD,
        params.canonicalAAD,
      );
    } catch {
      // In this catch path the blob exists and is a well-formed EncryptedField
      // (decodeBlob returns `empty` for both missing and malformed blobs without
      // throwing), so the only throw migrateLegacyAAD can produce here is a GCM
      // auth-tag mismatch — meaning the row was never a legacy-AAD row. The
      // canonical failure (e.g. a migrator bug) is the real error; surfacing the
      // legacy one would mask it behind a misleading "invalid ghash tag".
      throw canonicalError;
    }
    if (!migration.migrated || !migration.record) {
      // Nothing found under the legacy AAD either — the canonical failure is the
      // real, more informative error (corruption, wrong DEK). Never masked.
      throw canonicalError;
    }
    await params.persistMigrated(migration.record);
    return decodeBlob<T>(
      params.cryptoHandle,
      params.canonicalAAD,
      migration.record,
      params.version,
      params.migrators,
      params.empty,
    );
  }
}

export interface DecodeCandidate {
  cryptoHandle: CryptoHandle;
  canonicalAAD: FieldAAD;
  legacyAAD?: FieldAAD;
}

/**
 * Tries a list of (handle, AAD) candidates IN ORDER — needed when more than one DEK
 * can validly decrypt at read time, which only happens during a DEK rotation window
 * (`rotateEpoch()`'s per-store batch loop, `store.ts`): some rows have already been
 * migrated to the new epoch, some haven't yet, and an ambient reader racing that loop
 * doesn't know which. Each candidate independently goes through
 * `decodeWithLegacyFallback` — a row can be simultaneously "not yet rotated" AND "not
 * yet converged to its store's legacyAAD"; the two fallbacks compose without conflict.
 *
 * INVARIANT: `candidates[0]` MUST be the CURRENT/NEW handle — the one data should
 * converge to — never the previous/old one. When a candidate other than the first
 * wins, the row is re-encrypted under `candidates[0]` as a side effect of this read
 * (lazy convergence, same principle as `legacyAAD`). Reversing the order would
 * silently DE-migrate an already-rotated row, re-encrypting it under the OLD handle —
 * the exact opposite of what a rotation must do. See `legacyFallback.test.ts`'s
 * `decodeWithCandidates` tests for the order-invariant coverage.
 */
export async function decodeWithCandidates<T>(
  candidates: DecodeCandidate[],
  record: BlobRecord | null,
  version: number,
  migrators: BlobMigrator[],
  empty: T,
  persistMigrated: (record: BlobRecord) => Promise<void>,
): Promise<DecodeResult<T>> {
  if (candidates.length === 0) {
    throw new Error(
      "decodeWithCandidates: called with an empty candidate list — needs at least one (cryptoHandle, canonicalAAD) pair to attempt a decode.",
    );
  }
  let firstError: unknown;
  for (let i = 0; i < candidates.length; i++) {
    const candidate = candidates[i];
    let result: DecodeResult<T>;
    try {
      result = await decodeWithLegacyFallback<T>({
        cryptoHandle: candidate.cryptoHandle,
        record,
        canonicalAAD: candidate.canonicalAAD,
        legacyAAD: candidate.legacyAAD,
        version,
        migrators,
        empty,
        persistMigrated,
      });
    } catch (err) {
      if (firstError === undefined) firstError = err;
      continue;
    }
    if (i > 0) {
      // A non-primary candidate won — converge the row to candidates[0] (the
      // current/new handle) so future ambient reads no longer need the fallback.
      const target = candidates[0];
      const migratedRecord = await encodeBlob<T>(
        target.cryptoHandle,
        target.canonicalAAD,
        result.data,
        version,
        record?.contentHash != null,
      );
      await persistMigrated(migratedRecord);
    }
    return { data: result.data, upgraded: result.upgraded || i > 0 };
  }
  throw firstError;
}
