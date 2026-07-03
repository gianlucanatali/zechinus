import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import { createDekHandle } from "./testKeyHandle.ts";
import { encodeBlob } from "../core/blobCodec.ts";
import { decodeWithLegacyFallback } from "../core/legacyFallback.ts";

test("decodeWithLegacyFallback: canonical AAD succeeds → no legacy attempt, no persist", async () => {
  const dek = createDekHandle(randomBytes(32));
  const canonicalAAD = {
    userId: dek.pid,
    table: "t",
    field: "data",
    rowId: "r1",
  };
  const record = await encodeBlob(dek, canonicalAAD, { v: "hello" }, 1);

  let persisted = false;
  const result = await decodeWithLegacyFallback({
    dek,
    record,
    canonicalAAD,
    legacyAAD: { userId: dek.pid, table: "t", field: "legacy", rowId: "r1" },
    version: 1,
    migrators: [],
    empty: { v: "" },
    persistMigrated: async () => {
      persisted = true;
    },
  });

  assert.deepEqual(result.data, { v: "hello" });
  assert.equal(
    persisted,
    false,
    "canonical succeeded — legacy path never touched",
  );
});

test("decodeWithLegacyFallback: no legacyAAD configured → canonical failure propagates as-is", async () => {
  const dek = createDekHandle(randomBytes(32));
  const wrongAAD = { userId: dek.pid, table: "t", field: "other", rowId: "r1" };
  const record = await encodeBlob(
    dek,
    { userId: dek.pid, table: "t", field: "data", rowId: "r1" },
    { v: "hello" },
    1,
  );

  await assert.rejects(() =>
    decodeWithLegacyFallback({
      dek,
      record,
      canonicalAAD: wrongAAD, // deliberately mismatched, no legacyAAD to fall back to
      version: 1,
      migrators: [],
      empty: { v: "" },
      persistMigrated: async () => {},
    }),
  );
});

test("decodeWithLegacyFallback: canonical fails, legacy succeeds → migrates + persists + returns decoded data", async () => {
  const dek = createDekHandle(randomBytes(32));
  const legacyAAD = {
    userId: dek.pid,
    table: "t",
    field: "legacy",
    rowId: "r1",
  };
  const canonicalAAD = {
    userId: dek.pid,
    table: "t",
    field: "data",
    rowId: "r1",
  };
  const legacyRecord = await encodeBlob(dek, legacyAAD, { v: "old data" }, 1);

  let persistedRecord: unknown;
  const result = await decodeWithLegacyFallback({
    dek,
    record: legacyRecord,
    canonicalAAD,
    legacyAAD,
    version: 1,
    migrators: [],
    empty: { v: "" },
    persistMigrated: async (record) => {
      persistedRecord = record;
    },
  });

  assert.deepEqual(result.data, { v: "old data" });
  assert.ok(
    persistedRecord,
    "persistMigrated was called with the re-encrypted record",
  );
});

test("decodeWithLegacyFallback: canonical AND legacy both fail → the ORIGINAL canonical error propagates, not masked", async () => {
  const dek = createDekHandle(randomBytes(32));
  const otherDek = createDekHandle(randomBytes(32)); // wrong key entirely
  const canonicalAAD = {
    userId: dek.pid,
    table: "t",
    field: "data",
    rowId: "r1",
  };
  const legacyAAD = {
    userId: dek.pid,
    table: "t",
    field: "legacy",
    rowId: "r1",
  };
  const record = await encodeBlob(otherDek, canonicalAAD, { v: "hello" }, 1);

  await assert.rejects(() =>
    decodeWithLegacyFallback({
      dek, // wrong DEK for this record — neither AAD attempt will decrypt
      record,
      canonicalAAD,
      legacyAAD,
      version: 1,
      migrators: [],
      empty: { v: "" },
      persistMigrated: async () => {
        throw new Error(
          "must not be called — nothing was successfully migrated",
        );
      },
    }),
  );
});

test("decodeWithLegacyFallback: record is null (never saved) → returns empty, no legacy attempt", async () => {
  const dek = createDekHandle(randomBytes(32));
  const canonicalAAD = {
    userId: dek.pid,
    table: "t",
    field: "data",
    rowId: "r1",
  };

  let legacyAttempted = false;
  const result = await decodeWithLegacyFallback({
    dek,
    record: null,
    canonicalAAD,
    legacyAAD: { userId: dek.pid, table: "t", field: "legacy", rowId: "r1" },
    version: 1,
    migrators: [],
    empty: { v: "default" },
    persistMigrated: async () => {
      legacyAttempted = true;
    },
  });

  assert.deepEqual(result.data, { v: "default" });
  assert.equal(legacyAttempted, false);
});
