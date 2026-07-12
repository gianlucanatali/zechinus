/**
 * `rotationRetirement.ts` — the irreversible step (deleting an old epoch's wraps)
 * gets the most paranoid testing in this whole rotation feature: every gate the plan's
 * data-safety protocol names is exercised as its own scenario, plus the deliberate
 * "grace deadline forces a decision, it doesn't wait forever" policy (Fase 2.4).
 */
import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  verifyRowsDecryptAtEpoch,
  checkRetirementEligibility,
  type VerificationCandidateRow,
  type RetirementVerificationIO,
  type DeviceEpochStatus,
} from "../core/rotationRetirement.ts";
import { encodeBlob } from "../core/blobCodec.ts";
import type { FieldAAD, BlobRecord } from "../core/types.ts";
import { createDekHandle } from "./testKeyHandle.ts";

const EPOCH = 2;
const TABLE = "retirement_test_table";
const GRACE_DEADLINE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days, matches the plan's decided value

function aadFor(handle: { pid: string }, rowId: string): FieldAAD {
  return {
    userId: handle.pid,
    table: TABLE,
    field: "data",
    rowId,
    epoch: EPOCH,
  };
}

test("verifyRowsDecryptAtEpoch: every genuinely-migrated row verifies with zero failures", async () => {
  const handle = createDekHandle(randomBytes(32));
  const rowIds = ["r1", "r2", "r3"];
  const rows: Record<string, BlobRecord> = {};
  for (const id of rowIds) {
    rows[id] = await encodeBlob(handle, aadFor(handle, id), { id }, 1, false);
  }
  const io: RetirementVerificationIO = {
    async listRowsAtEpoch() {
      return Object.entries(rows).map(
        ([key, record]) => ({ key, record }) as VerificationCandidateRow,
      );
    },
  };

  const result = await verifyRowsDecryptAtEpoch(
    handle,
    TABLE,
    EPOCH,
    1,
    [],
    {},
    io,
    (key) => aadFor(handle, key as string),
  );

  assert.equal(result.verified, 3);
  assert.deepEqual(result.failures, []);
  assert.equal(result.processedThisBatch, 3);
});

test("verifyRowsDecryptAtEpoch: a row that CLAIMS the new epoch but is actually corrupted/undecryptable is collected as a failure, not thrown, and doesn't abort verifying the rest", async () => {
  const handle = createDekHandle(randomBytes(32));
  const goodRow = await encodeBlob(
    handle,
    aadFor(handle, "good"),
    { ok: true },
    1,
    false,
  );
  const corruptedRow: BlobRecord = {
    ...(await encodeBlob(
      handle,
      aadFor(handle, "corrupted"),
      { ok: false },
      1,
      false,
    )),
  };
  // Corrupt the ciphertext directly — simulates a write that silently produced garbage.
  corruptedRow.blob = corruptedRow.blob.slice(0, -4) + "abcd";

  const io: RetirementVerificationIO = {
    async listRowsAtEpoch() {
      return [
        { key: "good", record: goodRow },
        { key: "corrupted", record: corruptedRow },
      ];
    },
  };

  const result = await verifyRowsDecryptAtEpoch(
    handle,
    TABLE,
    EPOCH,
    1,
    [],
    {},
    io,
    (key) => aadFor(handle, key as string),
  );

  assert.equal(result.verified, 1);
  assert.equal(result.failures.length, 1);
  assert.equal(result.failures[0].key, "corrupted");
});

test("verifyRowsDecryptAtEpoch: empty result → processedThisBatch 0, lastKey undefined", async () => {
  const handle = createDekHandle(randomBytes(32));
  const io: RetirementVerificationIO = {
    async listRowsAtEpoch() {
      return [];
    },
  };
  const result = await verifyRowsDecryptAtEpoch(
    handle,
    TABLE,
    EPOCH,
    1,
    [],
    {},
    io,
    (k) => aadFor(handle, k as string),
  );
  assert.deepEqual(result, {
    verified: 0,
    failures: [],
    lastKey: undefined,
    processedThisBatch: 0,
  });
});

const NOW = 1_800_000_000_000; // fixed instant, tests never call Date.now()
const ROTATION_STARTED = NOW - 10 * 24 * 60 * 60 * 1000; // 10 days ago — within grace

test("verifyRowsDecryptAtEpoch: keyset pagination across multiple calls covers every row exactly once, no gaps or duplicates — the fake IO here actually implements the ordering/afterKey contract (unlike a naive 'return everything' double), catching the same class of bug a real unordered-LIMIT implementation hit live (docs/decisions/2026-07-12-dek-rotation-compat-test-2.2b.md)", async () => {
  const handle = createDekHandle(randomBytes(32));
  // 25 rows — enough to force multiple calls at batchSize 10, never a
  // coincidental full cover in one shot.
  const rowIds = Array.from(
    { length: 25 },
    (_, i) => `r${String(i).padStart(2, "0")}`,
  );
  const rows: Record<string, BlobRecord> = {};
  for (const id of rowIds) {
    rows[id] = await encodeBlob(handle, aadFor(handle, id), { id }, 1, false);
  }

  // Realistic fake: keyset-filtered by afterKey exactly like a real
  // `WHERE key > afterKey ORDER BY key` would be — this is the contract
  // documented on RetirementVerificationIO.listRowsAtEpoch, exercised for
  // real here instead of assumed.
  const returnedKeysByCall: string[][] = [];
  const io: RetirementVerificationIO = {
    async listRowsAtEpoch(_epoch, limit, afterKey) {
      const sortedKeys = Object.keys(rows).sort();
      const startIndex =
        afterKey === null ? 0 : sortedKeys.findIndex((k) => k === afterKey) + 1;
      const page = sortedKeys.slice(startIndex, startIndex + limit);
      returnedKeysByCall.push(page);
      return page.map(
        (key) => ({ key, record: rows[key] }) as VerificationCandidateRow,
      );
    },
  };

  let cursor: unknown = null;
  let totalVerified = 0;
  let calls = 0;
  for (;;) {
    calls++;
    const result = await verifyRowsDecryptAtEpoch(
      handle,
      TABLE,
      EPOCH,
      1,
      [],
      {},
      io,
      (key) => aadFor(handle, key as string),
      10,
      cursor,
    );
    totalVerified += result.verified;
    assert.deepEqual(result.failures, []);
    if (result.processedThisBatch === 0) break;
    cursor = result.lastKey;
  }

  assert.equal(calls, 4); // 10 + 10 + 5, then a 4th call confirms empty
  assert.equal(totalVerified, 25);

  const allReturnedKeys = returnedKeysByCall.flat();
  assert.equal(allReturnedKeys.length, 25); // no duplicates across calls
  assert.deepEqual([...allReturnedKeys].sort(), Object.keys(rows).sort()); // no gaps
});

test("checkRetirementEligibility: blocked while rows remain at the old epoch, regardless of devices/verification", () => {
  const result = checkRetirementEligibility(
    5,
    0,
    [],
    2,
    ROTATION_STARTED,
    NOW,
    GRACE_DEADLINE_MS,
  );
  assert.equal(result.eligible, false);
  assert.equal(result.reason, "rows-not-fully-migrated");
});

test("checkRetirementEligibility: blocked on any verification failure, even with zero rows remaining", () => {
  const result = checkRetirementEligibility(
    0,
    1,
    [],
    2,
    ROTATION_STARTED,
    NOW,
    GRACE_DEADLINE_MS,
  );
  assert.equal(result.eligible, false);
  assert.equal(result.reason, "verification-failures");
});

test("checkRetirementEligibility: eligible once data is migrated+verified AND every device has confirmed the new epoch", () => {
  const devices: DeviceEpochStatus[] = [
    { deviceId: "A", confirmedEpoch: 2 },
    { deviceId: "B", confirmedEpoch: 2 },
  ];
  const result = checkRetirementEligibility(
    0,
    0,
    devices,
    2,
    ROTATION_STARTED,
    NOW,
    GRACE_DEADLINE_MS,
  );
  assert.equal(result.eligible, true);
  assert.equal(result.reason, "all-confirmed");
  assert.deepEqual(result.devicesToDrop, []);
});

test("checkRetirementEligibility: NOT eligible while a device is still pending and the grace deadline hasn't passed (graceful rotation waits)", () => {
  const devices: DeviceEpochStatus[] = [
    { deviceId: "A", confirmedEpoch: 2 },
    { deviceId: "B", confirmedEpoch: 1 }, // hasn't caught up yet
  ];
  const result = checkRetirementEligibility(
    0,
    0,
    devices,
    2,
    ROTATION_STARTED,
    NOW,
    GRACE_DEADLINE_MS,
  );
  assert.equal(result.eligible, false);
  assert.equal(result.reason, "devices-still-pending-within-grace");
});

test("checkRetirementEligibility: a device that never confirmed anything (confirmedEpoch: null) counts as pending, same as any mismatched epoch", () => {
  const devices: DeviceEpochStatus[] = [
    { deviceId: "A", confirmedEpoch: null },
  ];
  const result = checkRetirementEligibility(
    0,
    0,
    devices,
    2,
    ROTATION_STARTED,
    NOW,
    GRACE_DEADLINE_MS,
  );
  assert.equal(result.eligible, false);
  assert.equal(result.reason, "devices-still-pending-within-grace");
});

test("checkRetirementEligibility: past the 30-day grace deadline, eligible via force-retire — pending devices listed to drop, not left blocking forever", () => {
  const rotationStartedLongAgo = NOW - 31 * 24 * 60 * 60 * 1000; // 31 days ago — past deadline
  const devices: DeviceEpochStatus[] = [
    { deviceId: "A", confirmedEpoch: 2 },
    { deviceId: "B", confirmedEpoch: 1 }, // never came back online
    { deviceId: "C", confirmedEpoch: null },
  ];
  const result = checkRetirementEligibility(
    0,
    0,
    devices,
    2,
    rotationStartedLongAgo,
    NOW,
    GRACE_DEADLINE_MS,
  );
  assert.equal(result.eligible, true);
  assert.equal(result.reason, "grace-deadline-passed-force-retire");
  assert.deepEqual(result.devicesToDrop.sort(), ["B", "C"]);
});

test("checkRetirementEligibility: exactly at the deadline boundary (>=) counts as passed", () => {
  const rotationStartedExactly30DaysAgo = NOW - GRACE_DEADLINE_MS;
  const devices: DeviceEpochStatus[] = [{ deviceId: "A", confirmedEpoch: 1 }];
  const result = checkRetirementEligibility(
    0,
    0,
    devices,
    2,
    rotationStartedExactly30DaysAgo,
    NOW,
    GRACE_DEADLINE_MS,
  );
  assert.equal(result.eligible, true);
  assert.equal(result.reason, "grace-deadline-passed-force-retire");
});
