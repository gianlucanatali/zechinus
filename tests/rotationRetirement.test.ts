/**
 * `rotationRetirement.ts` — the irreversible step (deleting an old epoch's wraps)
 * gets the most paranoid testing in this whole rotation feature: every gate the plan's
 * data-safety protocol names is exercised as its own scenario. No per-device gate —
 * see `checkRetirementEligibility`'s doc comment for why that was reconsidered and
 * dropped (an earlier design gated retirement on every device confirming, with a
 * 30-day grace deadline; turned out to solve a problem that doesn't exist).
 */
import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  verifyRowsDecryptAtEpoch,
  checkRetirementEligibility,
  type VerificationCandidateRow,
  type RetirementVerificationIO,
} from "../core/rotationRetirement.ts";
import { encodeBlob } from "../core/blobCodec.ts";
import type { FieldAAD, BlobRecord } from "../core/types.ts";
import { createDekHandle } from "./testKeyHandle.ts";

const EPOCH = 2;
const TABLE = "retirement_test_table";

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

test("checkRetirementEligibility: blocked while rows remain at the old epoch, regardless of verification", () => {
  const result = checkRetirementEligibility(5, 0);
  assert.equal(result.eligible, false);
  assert.equal(result.reason, "rows-not-fully-migrated");
});

test("checkRetirementEligibility: blocked on any verification failure, even with zero rows remaining", () => {
  const result = checkRetirementEligibility(0, 1);
  assert.equal(result.eligible, false);
  assert.equal(result.reason, "verification-failures");
});

test("checkRetirementEligibility: eligible the instant data is migrated+verified — no device confirmation gate. A straggler device's old wrap is useless to it either way (the old DEK can't decrypt any current row once migration is done), so it always needs the handshake regardless of whether retirement waited for it or not", () => {
  const result = checkRetirementEligibility(0, 0);
  assert.equal(result.eligible, true);
  assert.equal(result.reason, "eligible");
});
