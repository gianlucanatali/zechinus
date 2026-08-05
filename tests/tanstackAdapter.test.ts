/**
 * QueryClient is plain JS (no DOM), so this runs under `node --test` like the rest
 * of zechinus/'s non-React tests — only the hook itself (`useStore`) needs jsdom.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { QueryClient } from "@tanstack/react-query";
import { tanstackAdapter } from "../adapters/tanstackAdapter.ts";

// gcTime: Infinity is required (see the constructor guard tested below) — this
// mirrors the config every real consumer must use, so these tests exercise the
// adapter exactly as it's actually wired.
function validQueryClient(): QueryClient {
  return new QueryClient({ defaultOptions: { queries: { gcTime: Infinity } } });
}

test("tanstackAdapter: set/get roundtrip", () => {
  const adapter = tanstackAdapter(validQueryClient());

  assert.equal(adapter.get("portfolio_blobs:u1"), undefined);
  adapter.set("portfolio_blobs:u1", { positions: ["AAPL"] });
  assert.deepEqual(adapter.get("portfolio_blobs:u1"), {
    positions: ["AAPL"],
  });
});

test("tanstackAdapter: subscribe fires only for the matching key", () => {
  const adapter = tanstackAdapter(validQueryClient());
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
  const adapter = tanstackAdapter(validQueryClient());
  adapter.set("portfolio_blobs:u1", { positions: [] });
  adapter.set("transaction_blobs:u1", { transactions: [] });

  adapter.clear();

  assert.equal(adapter.get("portfolio_blobs:u1"), undefined);
  assert.equal(adapter.get("transaction_blobs:u1"), undefined);
});

test("tanstackAdapter: throws at construction if the queryClient's default gcTime isn't Infinity", () => {
  // This adapter writes via setQueryData/getQueryData without ever mounting a real
  // useQuery observer, so every Query it creates has zero observers for its whole
  // life — TanStack schedules that Query's garbage collection unconditionally at
  // creation time (Query.scheduleGc(), a SEPARATE axis from staleTime) and evicts it
  // once gcTime elapses, no matter how many times it was written to in between. Any
  // finite gcTime silently loses cached data after that many minutes of the consuming
  // app sitting idle — this must fail loudly at wiring time, not 5 minutes into a real
  // user's session (see the host app's src/lib/queryClient.ts for the real-world bug).
  assert.throws(() => tanstackAdapter(new QueryClient()), /gcTime.*Infinity/s);
});

test("tanstackAdapter: does not throw when gcTime: Infinity is configured", () => {
  assert.doesNotThrow(() => tanstackAdapter(validQueryClient()));
});
