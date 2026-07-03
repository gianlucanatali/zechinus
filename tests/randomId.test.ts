import assert from "node:assert/strict";
import test from "node:test";
import { randomId } from "../core/randomId.ts";

const UUID_V4_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

test("randomId: produces a well-formed RFC4122 v4 UUID string", () => {
  const id = randomId();
  assert.match(id, UUID_V4_RE);
});

test("randomId: is not deterministic (two calls differ)", () => {
  const a = randomId();
  const b = randomId();
  assert.notEqual(a, b);
});

test("randomId: 1000 calls are all unique (no collisions, all well-formed)", () => {
  const seen = new Set<string>();
  for (let i = 0; i < 1000; i++) {
    const id = randomId();
    assert.match(id, UUID_V4_RE);
    assert.ok(!seen.has(id), `duplicate id generated: ${id}`);
    seen.add(id);
  }
});
