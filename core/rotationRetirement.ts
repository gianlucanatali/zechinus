/**
 * Retirement of the OLD DEK epoch's wraps — key-custody rotation, Fase 2.4. The
 * plan's mandatory data-safety protocol names two gates before an old epoch's wraps
 * may ever be deleted: (a) zero rows remain at the old epoch (2.2's migration engine
 * completed), (b) a paranoid "verify-before-retire" pass that actually decrypts every
 * row now claiming the new epoch — not just trusting the stored epoch tag — because
 * the cost of being wrong here (deleting the only key that can decrypt some row) is
 * unrecoverable, unlike almost every other mistake in this codebase.
 */
import type { CryptoHandle, FieldAAD, BlobRecord } from "./types.ts";
import { decodeBlob } from "./blobCodec.ts";
import type { BlobMigrator } from "./versioning.ts";

export interface VerificationCandidateRow {
  key: unknown;
  record: BlobRecord;
}

export interface RetirementVerificationIO {
  /**
   * Up to `limit` rows currently claiming `epoch`, keyset-paginated — REQUIRED
   * contract, not "any consistent order": rows must be returned in a STABLE total
   * order (e.g. `ORDER BY key`), and when `afterKey` is non-null, only rows strictly
   * AFTER that key in that same order. This is the piece `migrateRotationBatch`
   * doesn't need (its WHERE-filtered set shrinks as rows migrate, so a plain
   * unordered LIMIT eventually drains it) but verification does: verifying a row
   * never changes its epoch, so an implementation that ignores `afterKey` — or
   * orders inconsistently between calls — would re-return the SAME first `limit`
   * rows forever, silently never verifying the rest. See
   * `zechinus/tests/rotationRetirement.test.ts`'s pagination test for a worked
   * example, and the real bug this exact class of mistake caused live (unordered
   * `LIMIT` in a migration script,
   * `docs/decisions/2026-07-12-dek-rotation-compat-test-2.2b.md`).
   */
  listRowsAtEpoch(
    epoch: number,
    limit: number,
    afterKey: unknown | null,
  ): Promise<VerificationCandidateRow[]>;
}

export interface RetirementVerificationFailure {
  key: unknown;
  error: string;
}

export interface RetirementVerificationBatchResult {
  verified: number;
  failures: RetirementVerificationFailure[];
  /** The last row's key this batch, for the caller's next `afterKey` — undefined when the batch was empty (nothing left to verify). */
  lastKey: unknown | undefined;
  processedThisBatch: number;
}

/**
 * Verifies ONE batch of rows claiming `epoch` actually decrypt under `handle` — a
 * failure here means the migration (2.2) silently produced a row that LOOKS migrated
 * (epoch tag says so) but isn't actually readable with the new key: a corrupted
 * write, a bug, a race the optimistic lock didn't catch. `aadFor` mirrors
 * `migrateRotationBatch`'s design: cardinality-specific AAD construction is the
 * caller's job, this file stays cardinality-agnostic.
 *
 * A failure is collected, NOT thrown — one bad row must never abort verifying the
 * rest (you need the FULL list of what's actually broken to decide what to do, not
 * just the first problem). The caller decides what "any failures" means for
 * retirement eligibility (see `checkRetirementEligibility` below: it always blocks).
 */
export async function verifyRowsDecryptAtEpoch<T>(
  handle: CryptoHandle,
  table: string,
  epoch: number,
  version: number,
  migrators: BlobMigrator[],
  empty: T,
  io: RetirementVerificationIO,
  aadFor: (key: unknown) => FieldAAD,
  batchSize = 100,
  afterKey: unknown | null = null,
): Promise<RetirementVerificationBatchResult> {
  const rows = await io.listRowsAtEpoch(epoch, batchSize, afterKey);
  let verified = 0;
  const failures: RetirementVerificationFailure[] = [];
  for (const row of rows) {
    try {
      await decodeBlob<T>(
        handle,
        aadFor(row.key),
        row.record,
        version,
        migrators,
        empty,
      );
      verified++;
    } catch (err) {
      failures.push({ key: row.key, error: String(err) });
    }
  }
  return {
    verified,
    failures,
    lastKey: rows.length > 0 ? rows[rows.length - 1].key : undefined,
    processedThisBatch: rows.length,
  };
}

export type RetirementReason =
  | "rows-not-fully-migrated"
  | "verification-failures"
  | "eligible";

export interface RetirementEligibility {
  eligible: boolean;
  reason: RetirementReason;
}

/**
 * Decides whether the old epoch's wraps may be deleted — the actual irreversible
 * step. Deliberately does NOT gate on per-device confirmation: a straggler device's
 * OLD wrap is useless to it the moment data migration completes (it would unwrap
 * an old DEK that can no longer decrypt any current row — every row is already on
 * the new epoch), so waiting for that device to catch up before retiring buys
 * nothing. A straggler always needs the handshake (`dekRotationCoordinator.ts`) to
 * get the CURRENT DEK regardless of whether its stale wrap still exists or was
 * already deleted — so retirement can run the instant data is migrated+verified,
 * no grace period needed (an earlier design gated this on device confirmation with
 * a 30-day grace deadline; reconsidered as solving a problem that doesn't exist,
 * see `docs/decisions/2026-07-12-dek-rotation-retirement-policy.md` "Deviazioni").
 * `remainingRowsAtOldEpoch` and `verificationFailureCount` are the caller's
 * responsibility to have already computed (via `migrateRotationBatch`/
 * `verifyRowsDecryptAtEpoch` above, looped to completion) — this function is pure
 * decision logic, no I/O, so it stays trivially testable.
 */
export function checkRetirementEligibility(
  remainingRowsAtOldEpoch: number,
  verificationFailureCount: number,
): RetirementEligibility {
  if (remainingRowsAtOldEpoch > 0) {
    return { eligible: false, reason: "rows-not-fully-migrated" };
  }
  if (verificationFailureCount > 0) {
    return { eligible: false, reason: "verification-failures" };
  }
  return { eligible: true, reason: "eligible" };
}
