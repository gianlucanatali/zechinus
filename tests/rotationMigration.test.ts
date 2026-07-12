/**
 * `rotationMigration.ts` — key-custody rotation's re-encrypt engine (Fase 2.2).
 * Tests use two REAL `KeyHandle`s (old/new DEK, via `testKeyHandle.ts`) so the
 * epoch-tagging from Fase 2.1 and the pid-changes-with-the-DEK fact (documented in
 * `docs/decisions/2026-07-12-dek-epoch-per-row-aad.md`) are exercised for real, not
 * mocked away — and a realistic in-memory `RotationBatchIO` double that actually
 * tracks epoch per row, so "interrupt mid-migration, resume" is a genuine scenario,
 * not just an assertion about call counts.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  reencryptRowToNewEpoch,
  reencryptRowIfNeeded,
  migrateRotationBatch,
  type RotationCandidateRow,
  type RotationBatchIO,
} from "../core/rotationMigration.ts";
import { encodeBlob } from "../core/blobCodec.ts";
import type { FieldAAD, BlobRecord } from "../core/types.ts";
import { createDekHandle } from "./testKeyHandle.ts";

const OLD_EPOCH = 1;
const NEW_EPOCH = 2;
const TABLE = "rotation_test_table";

/**
 * In-memory table: rowKey -> { epoch, record }. `listRowsAtOldEpoch` only returns
 * rows still tagged OLD_EPOCH (via the record's own `dek_epoch`-equivalent bookkeeping
 * kept alongside it, mirroring how a real StorageAdapter would filter by a DB column)
 * — a row disappears from that list the instant `saveIfMatch` succeeds for it, exactly
 * the property that makes resumption automatic.
 */
function fakeRotationTable(
  rows: Record<string, { epoch: number; record: BlobRecord }>,
): RotationBatchIO & { rows: typeof rows } {
  return {
    rows,
    async listRowsAtOldEpoch(limit) {
      return Object.entries(rows)
        .filter(([, v]) => v.epoch === OLD_EPOCH)
        .slice(0, limit)
        .map(([key, v]) => ({ key, record: v.record }) as RotationCandidateRow);
    },
    async saveIfMatch(key, record, expectedHash) {
      const current = rows[key as string];
      if (!current) return false;
      if ((current.record.contentHash ?? null) !== expectedHash) return false;
      rows[key as string] = { epoch: NEW_EPOCH, record };
      return true;
    },
  };
}

function aadFor(
  handle: { pid: string },
  rowId: string,
  epoch?: number,
): FieldAAD {
  return {
    userId: handle.pid,
    table: TABLE,
    field: "data",
    rowId,
    ...(epoch !== undefined ? { epoch } : {}),
  };
}

test("reencryptRowToNewEpoch: roundtrips data from the old handle/AAD to the new handle/AAD+epoch", async () => {
  const oldHandle = createDekHandle(randomBytes(32));
  const newHandle = createDekHandle(randomBytes(32));
  const rowId = "row-1";

  const original = await encodeBlob(
    oldHandle,
    aadFor(oldHandle, rowId),
    { name: "Alice", amount: 42 },
    1,
    false,
  );

  const migrated = await reencryptRowToNewEpoch(
    oldHandle,
    newHandle,
    aadFor(oldHandle, rowId),
    aadFor(newHandle, rowId, NEW_EPOCH),
    original,
    1,
    [],
    {},
  );

  // The new handle, with the new AAD, must be able to read it back correctly.
  const { decodeBlob } = await import("../core/blobCodec.ts");
  const { data } = await decodeBlob(
    newHandle,
    aadFor(newHandle, rowId, NEW_EPOCH),
    migrated,
    1,
    [],
    {},
  );
  assert.deepEqual(data, { name: "Alice", amount: 42 });
});

test("reencryptRowToNewEpoch: the OLD handle can no longer read the migrated row (genuinely re-encrypted, not just re-tagged)", async () => {
  const oldHandle = createDekHandle(randomBytes(32));
  const newHandle = createDekHandle(randomBytes(32));
  const rowId = "row-1";

  const original = await encodeBlob(
    oldHandle,
    aadFor(oldHandle, rowId),
    { secret: true },
    1,
    false,
  );
  const migrated = await reencryptRowToNewEpoch(
    oldHandle,
    newHandle,
    aadFor(oldHandle, rowId),
    aadFor(newHandle, rowId, NEW_EPOCH),
    original,
    1,
    [],
    {},
  );

  const { decodeBlob } = await import("../core/blobCodec.ts");
  await assert.rejects(() =>
    decodeBlob(oldHandle, aadFor(oldHandle, rowId), migrated, 1, [], {}),
  );
});

test("reencryptRowToNewEpoch: throws if newAAD.epoch is missing (would silently produce a non-rotation-tagged row)", async () => {
  const oldHandle = createDekHandle(randomBytes(32));
  const newHandle = createDekHandle(randomBytes(32));
  const rowId = "row-1";
  const original = await encodeBlob(
    oldHandle,
    aadFor(oldHandle, rowId),
    { x: 1 },
    1,
    false,
  );

  await assert.rejects(
    () =>
      reencryptRowToNewEpoch(
        oldHandle,
        newHandle,
        aadFor(oldHandle, rowId),
        aadFor(newHandle, rowId), // no epoch — deliberate misuse
        original,
        1,
        [],
        {},
      ),
    /newAAD.epoch is required/,
  );
});

test("reencryptRowIfNeeded: a row still at the old epoch is genuinely re-encrypted (same behavior as reencryptRowToNewEpoch)", async () => {
  const oldHandle = createDekHandle(randomBytes(32));
  const newHandle = createDekHandle(randomBytes(32));
  const rowId = "row-1";
  const original = await encodeBlob(
    oldHandle,
    aadFor(oldHandle, rowId),
    { name: "Bob" },
    1,
    false,
  );

  const result = await reencryptRowIfNeeded(
    oldHandle,
    newHandle,
    aadFor(oldHandle, rowId),
    aadFor(newHandle, rowId, NEW_EPOCH),
    original,
    1,
    [],
    {},
  );

  assert.notEqual(result, "already-migrated");
  const { decodeBlob } = await import("../core/blobCodec.ts");
  const { data } = await decodeBlob(
    newHandle,
    aadFor(newHandle, rowId, NEW_EPOCH),
    result as BlobRecord,
    1,
    [],
    {},
  );
  assert.deepEqual(data, { name: "Bob" });
});

test('reencryptRowIfNeeded: a row already re-encrypted under the new handle (e.g. a previous interrupted run) is reported as "already-migrated" and left byte-for-byte alone', async () => {
  const oldHandle = createDekHandle(randomBytes(32));
  const newHandle = createDekHandle(randomBytes(32));
  const rowId = "row-1";
  const alreadyMigrated = await encodeBlob(
    newHandle,
    aadFor(newHandle, rowId, NEW_EPOCH),
    { name: "Carol" },
    1,
    false,
  );

  const result = await reencryptRowIfNeeded(
    oldHandle,
    newHandle,
    aadFor(oldHandle, rowId),
    aadFor(newHandle, rowId, NEW_EPOCH),
    alreadyMigrated,
    1,
    [],
    {},
  );

  assert.equal(result, "already-migrated");
});

test("reencryptRowIfNeeded: a row that decrypts under NEITHER handle throws (genuine corruption is never silently reported as already-migrated)", async () => {
  const oldHandle = createDekHandle(randomBytes(32));
  const newHandle = createDekHandle(randomBytes(32));
  const rowId = "row-1";
  const original = await encodeBlob(
    oldHandle,
    aadFor(oldHandle, rowId),
    { name: "Dave" },
    1,
    false,
  );
  const corrupted: BlobRecord = { ...original };
  corrupted.blob = corrupted.blob.slice(0, -4) + "abcd";

  await assert.rejects(() =>
    reencryptRowIfNeeded(
      oldHandle,
      newHandle,
      aadFor(oldHandle, rowId),
      aadFor(newHandle, rowId, NEW_EPOCH),
      corrupted,
      1,
      [],
      {},
    ),
  );
});

test("migrateRotationBatch: migrates every row in one batch when batchSize covers them all", async () => {
  const oldHandle = createDekHandle(randomBytes(32));
  const newHandle = createDekHandle(randomBytes(32));

  const rowIds = ["r1", "r2", "r3"];
  const rows: Record<string, { epoch: number; record: BlobRecord }> = {};
  for (const id of rowIds) {
    rows[id] = {
      epoch: OLD_EPOCH,
      record: await encodeBlob(
        oldHandle,
        aadFor(oldHandle, id),
        { id },
        1,
        false,
      ),
    };
  }
  const io = fakeRotationTable(rows);

  const result = await migrateRotationBatch(
    (row) =>
      reencryptRowToNewEpoch(
        oldHandle,
        newHandle,
        aadFor(oldHandle, row.key as string),
        aadFor(newHandle, row.key as string, NEW_EPOCH),
        row.record,
        1,
        [],
        {},
      ),
    io,
    50,
  );

  assert.deepEqual(result, {
    migrated: 3,
    alreadyMigrated: 0,
    conflicted: 0,
    failed: [],
    processedThisBatch: 3,
  });
  for (const id of rowIds) assert.equal(io.rows[id].epoch, NEW_EPOCH);
});

test("migrateRotationBatch: interrupted mid-migration (small batchSize) resumes on the next call — every row ends up migrated exactly once, none lost, none double-processed", async () => {
  const oldHandle = createDekHandle(randomBytes(32));
  const newHandle = createDekHandle(randomBytes(32));

  const rowIds = Array.from({ length: 9 }, (_, i) => `row-${i}`);
  const rows: Record<string, { epoch: number; record: BlobRecord }> = {};
  for (const id of rowIds) {
    rows[id] = {
      epoch: OLD_EPOCH,
      record: await encodeBlob(
        oldHandle,
        aadFor(oldHandle, id),
        { id },
        1,
        false,
      ),
    };
  }
  const io = fakeRotationTable(rows);
  const reencryptOne = (row: RotationCandidateRow) =>
    reencryptRowToNewEpoch(
      oldHandle,
      newHandle,
      aadFor(oldHandle, row.key as string),
      aadFor(newHandle, row.key as string, NEW_EPOCH),
      row.record,
      1,
      [],
      {},
    );

  // Batch size 4 over 9 rows: 3 calls needed (4 + 4 + 1). Simulate "the process died
  // between calls" by just... calling again later, exactly like a real resume would.
  const batch1 = await migrateRotationBatch(reencryptOne, io, 4);
  assert.equal(batch1.processedThisBatch, 4);
  assert.equal(batch1.migrated, 4);

  const batch2 = await migrateRotationBatch(reencryptOne, io, 4);
  assert.equal(batch2.processedThisBatch, 4);
  assert.equal(batch2.migrated, 4);

  const batch3 = await migrateRotationBatch(reencryptOne, io, 4);
  assert.equal(batch3.processedThisBatch, 1);
  assert.equal(batch3.migrated, 1);

  const done = await migrateRotationBatch(reencryptOne, io, 4);
  assert.equal(done.processedThisBatch, 0);

  for (const id of rowIds) {
    assert.equal(io.rows[id].epoch, NEW_EPOCH);
    const { decodeBlob } = await import("../core/blobCodec.ts");
    const { data } = await decodeBlob(
      newHandle,
      aadFor(newHandle, id, NEW_EPOCH),
      io.rows[id].record,
      1,
      [],
      {},
    );
    assert.deepEqual(data, { id });
  }
});

test("migrateRotationBatch: a row that changes concurrently (contentHash mismatch) is left at the old epoch, not lost — picked up again next call", async () => {
  const oldHandle = createDekHandle(randomBytes(32));
  const newHandle = createDekHandle(randomBytes(32));
  const rowId = "row-1";

  const record = await encodeBlob(
    oldHandle,
    aadFor(oldHandle, rowId),
    { v: 1 },
    1,
    true, // contentHash: true — so a concurrent edit's hash mismatch is detectable
  );
  const rows = { [rowId]: { epoch: OLD_EPOCH, record } };
  const io = fakeRotationTable(rows);

  const reencryptOne = (row: RotationCandidateRow) =>
    reencryptRowToNewEpoch(
      oldHandle,
      newHandle,
      aadFor(oldHandle, rowId),
      aadFor(newHandle, rowId, NEW_EPOCH),
      row.record,
      1,
      [],
      {},
    );

  // Simulate a concurrent user edit landing between listRowsAtOldEpoch and saveIfMatch:
  // bump the stored contentHash to something the migration batch didn't read.
  const originalSaveIfMatch = io.saveIfMatch.bind(io);
  let firstCall = true;
  io.saveIfMatch = async (key, newRecord, expectedHash) => {
    if (firstCall) {
      firstCall = false;
      rows[rowId] = {
        epoch: OLD_EPOCH,
        record: {
          ...rows[rowId].record,
          contentHash: "concurrently-changed-hash",
        },
      };
    }
    return originalSaveIfMatch(key, newRecord, expectedHash);
  };

  const batch1 = await migrateRotationBatch(reencryptOne, io, 50);
  assert.deepEqual(batch1, {
    migrated: 0,
    alreadyMigrated: 0,
    conflicted: 1,
    failed: [],
    processedThisBatch: 1,
  });
  assert.equal(rows[rowId].epoch, OLD_EPOCH); // still there, not lost

  // Next call picks it up again (using the up-to-date hash this time) and succeeds.
  const batch2 = await migrateRotationBatch(reencryptOne, io, 50);
  assert.deepEqual(batch2, {
    migrated: 1,
    alreadyMigrated: 0,
    conflicted: 0,
    failed: [],
    processedThisBatch: 1,
  });
  assert.equal(rows[rowId].epoch, NEW_EPOCH);
});

test("migrateRotationBatch: empty table → processedThisBatch 0 immediately, no error", async () => {
  const io = fakeRotationTable({});
  const result = await migrateRotationBatch(
    () => {
      throw new Error("should never be called — no rows to migrate");
    },
    io,
    50,
  );
  assert.deepEqual(result, {
    migrated: 0,
    alreadyMigrated: 0,
    conflicted: 0,
    failed: [],
    processedThisBatch: 0,
  });
});

test('migrateRotationBatch: reencryptOne reporting "already-migrated" is left untouched — no write, no conflict, counted separately', async () => {
  const oldHandle = createDekHandle(randomBytes(32));
  const rowId = "row-1";
  const record = await encodeBlob(
    oldHandle,
    aadFor(oldHandle, rowId),
    { id: rowId },
    1,
    false,
  );
  const rows = { [rowId]: { epoch: OLD_EPOCH, record } };
  const io = fakeRotationTable(rows);

  const result = await migrateRotationBatch(
    async () => "already-migrated" as const,
    io,
    50,
  );

  assert.deepEqual(result, {
    migrated: 0,
    alreadyMigrated: 1,
    conflicted: 0,
    failed: [],
    processedThisBatch: 1,
  });
  // No write issued — the row is exactly as it was, still tagged OLD_EPOCH in
  // this fake (a real adapter wouldn't have a "current epoch" column to leave
  // stale either, since rotateEpoch never touches storage for this row).
  assert.equal(rows[rowId].epoch, OLD_EPOCH);
});

test("migrateRotationBatch: a row reencryptOne can't decrypt under EITHER handle is collected in failed[], not thrown — the rest of the batch still runs", async () => {
  const oldHandle = createDekHandle(randomBytes(32));
  const newHandle = createDekHandle(randomBytes(32));
  const goodId = "good";
  const corruptedId = "corrupted";
  const goodRecord = await encodeBlob(
    oldHandle,
    aadFor(oldHandle, goodId),
    { id: goodId },
    1,
    false,
  );
  const corruptedRecord: BlobRecord = {
    ...(await encodeBlob(
      oldHandle,
      aadFor(oldHandle, corruptedId),
      { id: corruptedId },
      1,
      false,
    )),
  };
  corruptedRecord.blob = corruptedRecord.blob.slice(0, -4) + "abcd";
  const rows = {
    [goodId]: { epoch: OLD_EPOCH, record: goodRecord },
    [corruptedId]: { epoch: OLD_EPOCH, record: corruptedRecord },
  };
  const io = fakeRotationTable(rows);

  const result = await migrateRotationBatch(
    (row) =>
      reencryptRowIfNeeded(
        oldHandle,
        newHandle,
        aadFor(oldHandle, row.key as string),
        aadFor(newHandle, row.key as string, NEW_EPOCH),
        row.record,
        1,
        [],
        {},
      ),
    io,
    50,
  );

  assert.equal(result.migrated, 1);
  assert.equal(result.failed.length, 1);
  assert.equal(result.failed[0].key, corruptedId);
  assert.equal(rows[goodId].epoch, NEW_EPOCH);
  assert.equal(rows[corruptedId].epoch, OLD_EPOCH); // untouched, will surface on retry too — that's expected, an operator must intervene
});
