import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import { createDekHandle } from "./testKeyHandle.ts";
import { encodeBlob } from "../core/blobCodec.ts";
import {
  decodeWithLegacyFallback,
  decodeWithCandidates,
} from "../core/legacyFallback.ts";
import type { BlobRecord } from "../core/types.ts";

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

// --- decodeWithCandidates -------------------------------------------------
// Multi-candidate decode (Fase E, key-custody rotation): during a DEK rotation
// window, a row may still be under the OLD DEK while the session already holds
// the NEW one. `decodeWithCandidates` tries an ordered list of (handle, AAD)
// candidates — the first (current) handle first, older handles as fallback.

test("decodeWithCandidates: single candidate — behaves identically to decodeWithLegacyFallback", async () => {
  const cryptoHandle = createDekHandle(randomBytes(32));
  const canonicalAAD = {
    userId: cryptoHandle.pid,
    table: "t",
    field: "data",
    rowId: "r1",
  };
  const record = await encodeBlob(cryptoHandle, canonicalAAD, { v: "hi" }, 1);

  let persisted = false;
  const result = await decodeWithCandidates(
    [{ cryptoHandle, canonicalAAD }],
    record,
    1,
    [],
    { v: "" },
    async () => {
      persisted = true;
    },
  );

  assert.deepEqual(result.data, { v: "hi" });
  assert.equal(result.upgraded, false);
  assert.equal(
    persisted,
    false,
    "canonical succeeded on first try — no persist",
  );
});

test("decodeWithCandidates: empty candidate list throws explicitly", async () => {
  await assert.rejects(
    () => decodeWithCandidates([], null, 1, [], { v: "" }, async () => {}),
    /empty candidate list/,
  );
});

test("decodeWithCandidates: current handle fails, previous (second candidate) succeeds — row re-encrypted under the FIRST candidate's handle+AAD", async () => {
  const currentHandle = createDekHandle(randomBytes(32));
  const previousHandle = createDekHandle(randomBytes(32));
  const currentAAD = {
    userId: currentHandle.pid,
    table: "t",
    field: "data",
    rowId: "r1",
  };
  const previousAAD = {
    userId: previousHandle.pid,
    table: "t",
    field: "data",
    rowId: "r1",
  };

  // Row is still encrypted under the OLD (previous) handle — rotation hasn't
  // reached this row yet, but the session already promoted to the new one.
  const record = await encodeBlob(
    previousHandle,
    previousAAD,
    { v: "old-key-data" },
    1,
  );

  let persistedRecord: BlobRecord | undefined;
  const result = await decodeWithCandidates(
    [
      { cryptoHandle: currentHandle, canonicalAAD: currentAAD },
      { cryptoHandle: previousHandle, canonicalAAD: previousAAD },
    ],
    record,
    1,
    [],
    { v: "" },
    async (r) => {
      persistedRecord = r;
    },
  );

  assert.deepEqual(result.data, { v: "old-key-data" });
  assert.equal(
    result.upgraded,
    true,
    "won on a non-first candidate → upgraded",
  );
  assert.ok(persistedRecord, "row was re-persisted under the current handle");

  // A second read using ONLY the current handle (no previous candidate at all)
  // must now succeed — proving the persisted record is genuinely re-encrypted
  // under currentHandle/currentAAD, not just a pass-through of the old blob.
  const second = await decodeWithCandidates(
    [{ cryptoHandle: currentHandle, canonicalAAD: currentAAD }],
    persistedRecord!,
    1,
    [],
    { v: "" },
    async () => {
      throw new Error("must not persist again — already converged");
    },
  );
  assert.deepEqual(second.data, { v: "old-key-data" });
  assert.equal(second.upgraded, false);
});

test("decodeWithCandidates: row already on the current handle — decoded on first candidate, no unnecessary re-persist", async () => {
  const currentHandle = createDekHandle(randomBytes(32));
  const previousHandle = createDekHandle(randomBytes(32));
  const currentAAD = {
    userId: currentHandle.pid,
    table: "t",
    field: "data",
    rowId: "r1",
  };
  const record = await encodeBlob(
    currentHandle,
    currentAAD,
    { v: "already-migrated" },
    1,
  );

  let persisted = false;
  const result = await decodeWithCandidates(
    [
      { cryptoHandle: currentHandle, canonicalAAD: currentAAD },
      {
        cryptoHandle: previousHandle,
        canonicalAAD: {
          userId: previousHandle.pid,
          table: "t",
          field: "data",
          rowId: "r1",
        },
      },
    ],
    record,
    1,
    [],
    { v: "" },
    async () => {
      persisted = true;
    },
  );

  assert.deepEqual(result.data, { v: "already-migrated" });
  assert.equal(result.upgraded, false);
  assert.equal(persisted, false, "first candidate won — nothing to re-persist");
});

// --- decodeWithLegacyFallback: legacyAAD as a list of candidate formats ----
// A store can have MORE THAN ONE historical AAD shape to fall back to (e.g. a
// canonical-under-old-table-name format, plus an even older pre-typed-store
// format, from a real store that was ported through two AAD conventions).
// `legacyAAD` accepts either a single `FieldAAD` (unchanged) or an ordered `FieldAAD[]`,
// tried in sequence, stopping at the first one that decrypts.

test("decodeWithLegacyFallback: legacyAAD as a single (non-array) FieldAAD — unchanged regression, still migrates + persists", async () => {
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
    { v: "single-format-data" },
    1,
  );

  let persistedRecord: unknown;
  const result = await decodeWithLegacyFallback({
    cryptoHandle,
    record: legacyRecord,
    canonicalAAD,
    legacyAAD, // single object, not an array
    version: 1,
    migrators: [],
    empty: { v: "" },
    persistMigrated: async (record) => {
      persistedRecord = record;
    },
  });

  assert.deepEqual(result.data, { v: "single-format-data" });
  assert.ok(
    persistedRecord,
    "single-format legacyAAD still migrates as before",
  );
});

test("decodeWithLegacyFallback: legacyAAD array of 2 formats — record matches the FIRST format in the list", async () => {
  const cryptoHandle = createDekHandle(randomBytes(32));
  const legacyAADFirst = {
    userId: cryptoHandle.pid,
    table: "t",
    field: "data",
    rowId: "legacy-first",
  };
  const legacyAADSecond = {
    userId: cryptoHandle.pid,
    table: "t",
    field: "legacy-second-field",
    rowId: cryptoHandle.pid,
  };
  const canonicalAAD = {
    userId: cryptoHandle.pid,
    table: "t",
    field: "data",
    rowId: "r1",
  };
  const legacyRecord = await encodeBlob(
    cryptoHandle,
    legacyAADFirst,
    { v: "first-format-data" },
    1,
  );

  let persistedRecord: unknown;
  const result = await decodeWithLegacyFallback({
    cryptoHandle,
    record: legacyRecord,
    canonicalAAD,
    legacyAAD: [legacyAADFirst, legacyAADSecond],
    version: 1,
    migrators: [],
    empty: { v: "" },
    persistMigrated: async (record) => {
      persistedRecord = record;
    },
  });

  assert.deepEqual(result.data, { v: "first-format-data" });
  assert.ok(
    persistedRecord,
    "matched on the first candidate, migrated + persisted",
  );
});

test("decodeWithLegacyFallback: legacyAAD array of 2 formats — record matches the SECOND format when the first doesn't decrypt", async () => {
  const cryptoHandle = createDekHandle(randomBytes(32));
  const legacyAADFirst = {
    userId: cryptoHandle.pid,
    table: "t",
    field: "data",
    rowId: "legacy-first",
  };
  const legacyAADSecond = {
    userId: cryptoHandle.pid,
    table: "t",
    field: "legacy-second-field",
    rowId: cryptoHandle.pid,
  };
  const canonicalAAD = {
    userId: cryptoHandle.pid,
    table: "t",
    field: "data",
    rowId: "r1",
  };
  // Encrypted under the SECOND legacy format only — the first candidate's AAD
  // will fail to authenticate against this ciphertext.
  const legacyRecord = await encodeBlob(
    cryptoHandle,
    legacyAADSecond,
    { v: "second-format-data" },
    1,
  );

  let persistedRecord: unknown;
  const result = await decodeWithLegacyFallback({
    cryptoHandle,
    record: legacyRecord,
    canonicalAAD,
    legacyAAD: [legacyAADFirst, legacyAADSecond],
    version: 1,
    migrators: [],
    empty: { v: "" },
    persistMigrated: async (record) => {
      persistedRecord = record;
    },
  });

  assert.deepEqual(result.data, { v: "second-format-data" });
  assert.ok(
    persistedRecord,
    "first candidate failed to authenticate, second matched — migrated + persisted",
  );
});

test("decodeWithLegacyFallback: legacyAAD array — none of the formats match → fails clean, the ORIGINAL canonical error propagates (no crash)", async () => {
  const cryptoHandle = createDekHandle(randomBytes(32));
  const otherDek = createDekHandle(randomBytes(32)); // wrong key entirely
  const legacyAADFirst = {
    userId: cryptoHandle.pid,
    table: "t",
    field: "data",
    rowId: "legacy-first",
  };
  const legacyAADSecond = {
    userId: cryptoHandle.pid,
    table: "t",
    field: "legacy-second-field",
    rowId: cryptoHandle.pid,
  };
  const canonicalAAD = {
    userId: cryptoHandle.pid,
    table: "t",
    field: "data",
    rowId: "r1",
  };
  const record = await encodeBlob(otherDek, canonicalAAD, { v: "hello" }, 1);

  await assert.rejects(() =>
    decodeWithLegacyFallback({
      cryptoHandle, // wrong DEK for this record — no candidate can decrypt it
      record,
      canonicalAAD,
      legacyAAD: [legacyAADFirst, legacyAADSecond],
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

test("decodeWithCandidates: all candidates fail — the FIRST candidate's error propagates, not a later one's", async () => {
  const currentHandle = createDekHandle(randomBytes(32));
  const previousHandle = createDekHandle(randomBytes(32));
  const canonicalAAD = {
    userId: currentHandle.pid,
    table: "t",
    field: "data",
    rowId: "r1",
  };
  // Row genuinely IS under currentHandle/canonicalAAD (candidate[0] decrypts
  // fine), but a migrator bug throws afterwards. The second candidate
  // (previousHandle, wrong key entirely) will ALSO fail, with a generic
  // auth-tag mismatch — that must never mask the migrator's real error.
  const record = await encodeBlob(currentHandle, canonicalAAD, { v: "old" }, 1);

  await assert.rejects(
    () =>
      decodeWithCandidates(
        [
          { cryptoHandle: currentHandle, canonicalAAD },
          {
            cryptoHandle: previousHandle,
            canonicalAAD: {
              userId: previousHandle.pid,
              table: "t",
              field: "data",
              rowId: "r1",
            },
          },
        ],
        record,
        2,
        [
          () => {
            throw new Error("migrator exploded: v1 payload not parsable");
          },
        ],
        { v: "" },
        async () => {
          throw new Error("must not persist anything on failure");
        },
      ),
    /migrator exploded/,
  );
});
