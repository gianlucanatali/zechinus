/**
 * Re-encrypt-per-row migration engine for DEK rotation (key-custody roadmap Fase 2.2).
 * Generic across any store shape — operates at the same level `blobCodec.ts`'s
 * `encodeBlob`/`decodeBlob` already work at (raw `BlobRecord` + explicit `FieldAAD`),
 * never assuming a cardinality (`perUser`/`perKey`/`many`).
 *
 * Deliberately does NOT know how to enumerate "a user's rows for store X" — that's
 * cardinality-specific (a `perUser` row's AAD `rowId` defaults to the handle's own
 * `pid` and is irrelevant to the physical row location; a `perKey`/`many` row's
 * `rowId` is a domain-stable key that IS the physical lookup key and must never
 * change across the migration). The actual per-cardinality wiring — building the
 * `oldAAD`/`newAAD` and calling `reencryptRowIfNeeded` for every row — lives on
 * each store's own `rotateEpoch()` (see `store.ts`'s three `buildXyzStore`
 * functions), which already has `def`/`migrators`/`empty`/`canonicalAADFor` in
 * scope; this file stays a pure, cardinality-blind engine.
 */
import type { CryptoHandle, FieldAAD, BlobRecord } from "./types.ts";
import { decodeBlob, encodeBlob } from "./blobCodec.ts";
import type { BlobMigrator } from "./versioning.ts";

/** Aggregate result of rotating one store's rows to a new epoch — returned by every cardinality's `rotateEpoch()`. */
export interface RotationOutcome {
  migrated: number;
  /** Rows already re-encrypted under the new handle (e.g. by a previous interrupted run) — left untouched. */
  alreadyMigrated: number;
  /** Rows that decrypt under NEITHER handle — genuine corruption, collected rather than aborting the whole rotation. */
  failed: Array<{ key: unknown; error: string }>;
}

/**
 * Re-encrypts ONE row from the old epoch's handle to the new one — decode under
 * `oldAAD` (whatever epoch that handle's own blobs already carry; decrypt itself
 * doesn't need an epoch passed in, see `crypto.ts`), running any pending schema
 * migrators too (so a row lands on both the new epoch AND an up-to-date schema in one
 * write, never two separate passes), re-encode under `newAAD` — which MUST carry
 * `epoch`, otherwise the "re-encrypted" row wouldn't actually be rotation-tagged and
 * would look identical to a row nobody ever migrated.
 */
export async function reencryptRowToNewEpoch<T>(
  oldHandle: CryptoHandle,
  newHandle: CryptoHandle,
  oldAAD: FieldAAD,
  newAAD: FieldAAD,
  record: BlobRecord,
  version: number,
  migrators: BlobMigrator[],
  empty: T,
): Promise<BlobRecord> {
  if (newAAD.epoch === undefined) {
    throw new Error(
      "rotationMigration.reencryptRowToNewEpoch: newAAD.epoch is required — " +
        "re-encrypting without it would silently produce a row indistinguishable from one nobody ever migrated.",
    );
  }
  const { data } = await decodeBlob<T>(
    oldHandle,
    oldAAD,
    record,
    version,
    migrators,
    empty,
  );
  return encodeBlob<T>(
    newHandle,
    newAAD,
    data,
    version,
    record.contentHash != null,
  );
}

/**
 * Row-level rotation decision, used as the `reencryptOne` callback passed to
 * `migrateRotationBatch`. Tries `newHandle` FIRST — if the row already decrypts
 * under the new key/AAD, it was migrated by an earlier (possibly interrupted)
 * run and is left untouched (`"already-migrated"`, no write). Only when that
 * fails does it attempt the real old→new re-encryption. A row that decrypts
 * under NEITHER handle is genuine corruption — the error from `decodeBlob`
 * propagates to the caller (`migrateRotationBatch` catches it and records it
 * in `failed`, it is never silently swallowed here).
 */
export async function reencryptRowIfNeeded<T>(
  oldHandle: CryptoHandle,
  newHandle: CryptoHandle,
  oldAAD: FieldAAD,
  newAAD: FieldAAD,
  record: BlobRecord,
  version: number,
  migrators: BlobMigrator[],
  empty: T,
): Promise<BlobRecord | "already-migrated"> {
  try {
    await decodeBlob<T>(newHandle, newAAD, record, version, migrators, empty);
    return "already-migrated";
  } catch {
    // Not yet migrated under the new key — fall through to the real attempt.
    // (If it's genuinely corrupted, the line below throws for real.)
  }
  return reencryptRowToNewEpoch(
    oldHandle,
    newHandle,
    oldAAD,
    newAAD,
    record,
    version,
    migrators,
    empty,
  );
}

/** One row still at the old epoch, as returned by `RotationBatchIO.listRowsAtOldEpoch`. `key` is opaque — this file never interprets it, only threads it back to `saveIfMatch`. */
export interface RotationCandidateRow {
  key: unknown;
  record: BlobRecord;
}

export interface RotationBatchIO {
  /** Up to `limit` rows still at the old epoch — any consistent order. An empty array means the migration is complete for this table/user. */
  listRowsAtOldEpoch(limit: number): Promise<RotationCandidateRow[]>;
  /**
   * Conditional write — `false` (not thrown) on a stale `expectedHash` (the row
   * changed concurrently, e.g. the user edited it after this batch read it). A
   * conflicted row is simply left at the old epoch — it's picked up again by the
   * NEXT `listRowsAtOldEpoch` call, no special handling needed; this is what makes
   * the whole migration resumable-by-construction rather than needing an explicit
   * "retry" mechanism.
   */
  saveIfMatch(
    key: unknown,
    record: BlobRecord,
    expectedHash: string | null,
  ): Promise<boolean>;
}

export interface RotationBatchResult {
  migrated: number;
  /** Rows `reencryptOne` reported as `"already-migrated"` — left untouched, no write issued. */
  alreadyMigrated: number;
  /** Rows that lost a race against a concurrent write this batch — still at the old epoch, will be retried by the next call. Not an error. */
  conflicted: number;
  /** Rows that threw from `reencryptOne` (genuine corruption/undecryptable under either handle) — collected, not thrown, so one bad row never aborts the rest of the batch. */
  failed: Array<{ key: unknown; error: string }>;
  /** Rows `listRowsAtOldEpoch` returned this call, before migrate/skip/conflict/failure split — 0 means done; call again while > 0. */
  processedThisBatch: number;
}

/**
 * Processes ONE batch (bounded by `batchSize`) and returns. Callers loop this until
 * `processedThisBatch === 0` — deliberately NOT a single call that loops internally
 * until done, so a caller can checkpoint/log/back off between batches, and so an
 * interruption between calls (process killed, request timeout) leaves the migration in
 * a always-valid, resumable state: every row is unambiguously at exactly one epoch at
 * any instant, `listRowsAtOldEpoch` on the next call picks up exactly where the last
 * one left off, no separate "resume" code path.
 */
export async function migrateRotationBatch(
  reencryptOne: (
    row: RotationCandidateRow,
  ) => Promise<BlobRecord | "already-migrated">,
  io: RotationBatchIO,
  batchSize = 50,
): Promise<RotationBatchResult> {
  const rows = await io.listRowsAtOldEpoch(batchSize);
  let migrated = 0;
  let alreadyMigrated = 0;
  let conflicted = 0;
  const failed: Array<{ key: unknown; error: string }> = [];
  for (const row of rows) {
    let result: BlobRecord | "already-migrated";
    try {
      result = await reencryptOne(row);
    } catch (e) {
      failed.push({ key: row.key, error: String(e) });
      continue;
    }
    if (result === "already-migrated") {
      alreadyMigrated++;
      continue;
    }
    const ok = await io.saveIfMatch(
      row.key,
      result,
      row.record.contentHash ?? null,
    );
    if (ok) migrated++;
    else conflicted++;
  }
  return {
    migrated,
    alreadyMigrated,
    conflicted,
    failed,
    processedThisBatch: rows.length,
  };
}
