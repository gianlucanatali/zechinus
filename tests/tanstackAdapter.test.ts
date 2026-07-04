/**
 * QueryClient is plain JS (no DOM), so this runs under `node --test` like the rest
 * of datacloak/'s non-React tests — only the hook itself (`useStore`) needs jsdom.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { QueryClient } from "@tanstack/react-query";
import { tanstackAdapter } from "../adapters/tanstackAdapter.ts";

test("tanstackAdapter: set/get roundtrip", () => {
  const adapter = tanstackAdapter(new QueryClient());

  assert.equal(adapter.get("portfolio_blobs:u1"), undefined);
  adapter.set("portfolio_blobs:u1", { positions: ["AAPL"] });
  assert.deepEqual(adapter.get("portfolio_blobs:u1"), {
    positions: ["AAPL"],
  });
});

test("tanstackAdapter: subscribe fires only for the matching key", () => {
  const adapter = tanstackAdapter(new QueryClient());
  let fired = 0;
  const unsubscribe = adapter.subscribe("portfolio_blobs:u1", () => {
    fired++;
  });

  adapter.set("portfolio_blobs:u1", { positions: [] });
  assert.equal(fired, 1);

  adapter.set("transaction_blobs:u1", { transactions: [] });
  assert.equal(fired, 1, "a different key must not fire this subscription");

  unsubscribe();
  adapter.set("portfolio_blobs:u1", { positions: ["x"] });
  assert.equal(fired, 1, "unsubscribed callback must not fire again");
});

test("tanstackAdapter: clear() wipes everything", () => {
  const adapter = tanstackAdapter(new QueryClient());
  adapter.set("portfolio_blobs:u1", { positions: [] });
  adapter.set("transaction_blobs:u1", { transactions: [] });

  adapter.clear();

  assert.equal(adapter.get("portfolio_blobs:u1"), undefined);
  assert.equal(adapter.get("transaction_blobs:u1"), undefined);
});
