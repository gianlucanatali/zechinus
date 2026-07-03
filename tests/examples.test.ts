/**
 * Runs the examples in `datacloak/examples/basic-usage.ts` and checks the result.
 * This test is what makes the examples "living documentation": if the API's
 * behavior changes without the examples/README being updated, this test breaks.
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  perUserExample,
  perKeyExample,
  manyExample,
  optimisticLockExample,
} from "../examples/basic-usage.ts";

test("example: perUser roundtrip", async () => {
  assert.deepEqual(await perUserExample(), { positions: ["AAPL", "MSFT"] });
});

test("example: perKey roundtrip", async () => {
  assert.deepEqual(await perKeyExample(), { transactions: ["expense"] });
});

test("example: many roundtrip", async () => {
  const rows = await manyExample();
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0].data, { name: "sim-1", addedLiquidity: 500 });
});

test("example: optimisticLock — success, chained hash, rejected stale write", async () => {
  const { first, second, conflict } = await optimisticLockExample();
  assert.equal(first.ok, true);
  assert.equal(second.ok, true);
  assert.notEqual(second.hash, first.hash);
  assert.equal(conflict.ok, false);
  assert.equal(conflict.hash, null);
});
