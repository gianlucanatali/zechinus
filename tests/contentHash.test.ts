import assert from "node:assert/strict";
import test from "node:test";
import { hashContent } from "../core/contentHash.ts";

test("hashContent: deterministic — same payload → same hash", async () => {
  const h1 = await hashContent({ a: 1, b: [1, 2, 3] });
  const h2 = await hashContent({ a: 1, b: [1, 2, 3] });
  assert.equal(h1, h2);
});

test("hashContent: sensitive — different payload → different hash", async () => {
  const h1 = await hashContent({ a: 1 });
  const h2 = await hashContent({ a: 2 });
  assert.notEqual(h1, h2);
});

test("hashContent: SHA-256 hex (64 char)", async () => {
  const h = await hashContent({ x: "y" });
  assert.equal(h.length, 64);
  assert.match(h, /^[0-9a-f]{64}$/);
});
