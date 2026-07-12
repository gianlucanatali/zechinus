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
  /** Up to `limit` rows currently claiming `epoch` — any consistent order, paged via repeated calls (this file has no notion of "all rows in one call", same reasoning as `migrateRotationBatch`: bounded batches, no assumption about table size). */
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

export interface DeviceEpochStatus {
  deviceId: string;
  /** The highest epoch this device has confirmed a wrap for — `null` if it never has (shouldn't happen for a device that completed enrollment, but defensive: never assume). */
  confirmedEpoch: number | null;
}

export type RetirementReason =
  | "rows-not-fully-migrated"
  | "verification-failures"
  | "devices-still-pending-within-grace"
  | "all-confirmed"
  | "grace-deadline-passed-force-retire";

export interface RetirementEligibility {
  eligible: boolean;
  reason: RetirementReason;
  /** Only meaningful for "grace-deadline-passed-force-retire": these devices will be dropped (their next unlock re-enrolls, per Fase 2.4's spec — never locked out of login, only loses the shortcut and must re-link). */
  devicesToDrop: string[];
}

/**
 * Decides whether the old epoch's wraps may be deleted — the actual irreversible
 * step. Every gate is a hard block except the grace deadline, which the plan
 * explicitly decided should NOT wait forever (2.4: `GRACE_DEADLINE` = 30 days,
 * otherwise a graceful rotation could never terminate if one device never comes back
 * online). `remainingRowsAtOldEpoch` and `verificationFailureCount` are the caller's
 * responsibility to have already computed (via `migrateRotationBatch`/
 * `verifyRowsDecryptAtEpoch` above, looped to completion) — this function is pure
 * decision logic, no I/O, so it stays trivially testable against any combination of
 * inputs without needing a real migration to have run first.
 */
export function checkRetirementEligibility(
  remainingRowsAtOldEpoch: number,
  verificationFailureCount: number,
  devices: DeviceEpochStatus[],
  targetEpoch: number,
  rotationStartedAtMs: number,
  nowMs: number,
  graceDeadlineMs: number,
): RetirementEligibility {
  if (remainingRowsAtOldEpoch > 0) {
    return {
      eligible: false,
      reason: "rows-not-fully-migrated",
      devicesToDrop: [],
    };
  }
  if (verificationFailureCount > 0) {
    return {
      eligible: false,
      reason: "verification-failures",
      devicesToDrop: [],
    };
  }

  const pending = devices.filter((d) => d.confirmedEpoch !== targetEpoch);
  if (pending.length === 0) {
    return { eligible: true, reason: "all-confirmed", devicesToDrop: [] };
  }

  const deadlinePassed = nowMs - rotationStartedAtMs >= graceDeadlineMs;
  if (!deadlinePassed) {
    return {
      eligible: false,
      reason: "devices-still-pending-within-grace",
      devicesToDrop: [],
    };
  }
  return {
    eligible: true,
    reason: "grace-deadline-passed-force-retire",
    devicesToDrop: pending.map((d) => d.deviceId),
  };
}
