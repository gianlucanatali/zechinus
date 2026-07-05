import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import { createDekHandle } from "./testKeyHandle.ts";
import { encodeBlob } from "../core/blobCodec.ts";
import { decodeWithLegacyFallback } from "../core/legacyFallback.ts";

test("decodeWithLegacyFallback: canonical AAD succeeds → no legacy attempt, no persist", async () => {
  const cryptoHandle = createDekHandle(randomBytes(32));
  const canonicalAAD = {
    userId: cryptoHandle.pid,
    table: "t",
    field: "data",
    rowId: "r1",
  };
  const record = await encodeBlob(
    cryptoHandle,
    canonicalAAD,
    { v: "hello" },
    1,
  );

  let persisted = false;
  const result = await decodeWithLegacyFallback({
    cryptoHandle,
    record,
    canonicalAAD,
    legacyAAD: {
      userId: cryptoHandle.pid,
      table: "t",
      field: "legacy",
      rowId: "r1",
    },
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
  const cryptoHandle = createDekHandle(randomBytes(32));
  const wrongAAD = {
    userId: cryptoHandle.pid,
    table: "t",
    field: "other",
    rowId: "r1",
  };
  const record = await encodeBlob(
    cryptoHandle,
    { userId: cryptoHandle.pid, table: "t", field: "data", rowId: "r1" },
    { v: "hello" },
    1,
  );

  await assert.rejects(() =>
    decodeWithLegacyFallback({
      cryptoHandle,
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
  const cryptoHandle = createDekHandle(randomBytes(32));
  const legacyAAD = {
    userId: cryptoHandle.pid,
    table: "t",
    field: "legacy",
    rowId: "r1",
  };
  const canonicalAAD = {
    userId: cryptoHandle.pid,
    table: "t",
    field: "data",
    rowId: "r1",
  };
  const legacyRecord = await encodeBlob(
    cryptoHandle,
    legacyAAD,
    { v: "old data" },
    1,
  );

  let persistedRecord: unknown;
  const result = await decodeWithLegacyFallback({
    cryptoHandle,
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
  const cryptoHandle = createDekHandle(randomBytes(32));
  const otherDek = createDekHandle(randomBytes(32)); // wrong key entirely
  const canonicalAAD = {
    userId: cryptoHandle.pid,
    table: "t",
    field: "data",
    rowId: "r1",
  };
  const legacyAAD = {
    userId: cryptoHandle.pid,
    table: "t",
    field: "legacy",
    rowId: "r1",
  };
  const record = await encodeBlob(otherDek, canonicalAAD, { v: "hello" }, 1);

  await assert.rejects(() =>
    decodeWithLegacyFallback({
      cryptoHandle, // wrong DEK for this record — neither AAD attempt will decrypt
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
  const cryptoHandle = createDekHandle(randomBytes(32));
  const canonicalAAD = {
    userId: cryptoHandle.pid,
    table: "t",
    field: "data",
    rowId: "r1",
  };

  let legacyAttempted = false;
  const result = await decodeWithLegacyFallback({
    cryptoHandle,
    record: null,
    canonicalAAD,
    legacyAAD: {
      userId: cryptoHandle.pid,
      table: "t",
      field: "legacy",
      rowId: "r1",
    },
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
test("decodeWithLegacyFallback: canonical decode fails AFTER decrypt (migrator bug) → canonical error surfaces, not the legacy GCM mismatch", async () => {
  // Regression: the row IS under the canonical AAD, but a migrator throws while
  // decoding it. The legacy attempt then fails to decrypt (auth-tag mismatch —
  // the row was never legacy) and that misleading crypto error used to mask the
  // real one. The migrator's error must be what propagates.
  const cryptoHandle = createDekHandle(randomBytes(32));
  const canonicalAAD = {
    userId: cryptoHandle.pid,
    table: "t",
    field: "data",
    rowId: "r1",
  };
  const record = await encodeBlob(cryptoHandle, canonicalAAD, { v: "old" }, 1);

  await assert.rejects(
    () =>
      decodeWithLegacyFallback({
        cryptoHandle,
        record,
        canonicalAAD,
        legacyAAD: {
          userId: cryptoHandle.pid,
          table: "t",
          field: "legacy",
          rowId: "r1",
        },
        version: 2,
        migrators: [
          () => {
            throw new Error("migrator exploded: v1 payload not parsable");
          },
        ],
        empty: { v: "" },
        persistMigrated: async () => {
          throw new Error("must not persist anything on failure");
        },
      }),
    /migrator exploded/,
    "the canonical (migrator) error must surface, not the legacy decrypt failure",
  );
});
