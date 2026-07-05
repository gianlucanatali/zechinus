import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import { canonicalAAD } from "../core/rowStore.ts";
import { createDekHandle } from "./testKeyHandle.ts";

test("canonicalAAD: builds the standard {userId, table, field:'data', rowId} shape", () => {
  const cryptoHandle = createDekHandle(randomBytes(32));
  const aad = canonicalAAD(cryptoHandle, "some_table", "some-row-id");
  assert.deepEqual(aad, {
    userId: cryptoHandle.pid,
    table: "some_table",
    field: "data",
    rowId: "some-row-id",
  });
});

test("canonicalAAD: rowId defaults to cryptoHandle.pid when omitted (perUser convention)", () => {
  const cryptoHandle = createDekHandle(randomBytes(32));
  const aad = canonicalAAD(cryptoHandle, "some_table");
  assert.equal(aad.rowId, cryptoHandle.pid);
});

test("canonicalAAD: different table names produce different AAD (not cross-decryptable)", () => {
  const cryptoHandle = createDekHandle(randomBytes(32));
  const aadA = canonicalAAD(cryptoHandle, "table_a", "row-1");
  const aadB = canonicalAAD(cryptoHandle, "table_b", "row-1");
  assert.notDeepEqual(aadA, aadB);
});
