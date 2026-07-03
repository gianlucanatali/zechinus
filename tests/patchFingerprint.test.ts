import assert from "node:assert/strict";
import test from "node:test";
import { patchFingerprint } from "../scripts/patchFingerprint.mjs";

test("patchFingerprint: replaces an existing (stale) value", () => {
  const source = [
    "const store = defineStore({",
    '  name: "x_blobs",',
    "  version: 1,",
    '  schemaFingerprint: "deadbeef",',
    "});",
  ].join("\n");

  const result = patchFingerprint(source, "cafef00d");

  assert.match(result, /schemaFingerprint: "cafef00d"/);
  assert.doesNotMatch(result, /deadbeef/);
});

test("patchFingerprint: inserts a missing field right after the version line", () => {
  const source = [
    "const store = defineStore({",
    '  name: "x_blobs",',
    '  encrypt: "all",',
    "  version: 1,",
    "  migrators: [],",
    "});",
  ].join("\n");

  const result = patchFingerprint(source, "cafef00d");

  assert.match(
    result,
    /version: 1,\n {2}schemaFingerprint: "cafef00d",\n {2}migrators: \[\]/,
  );
});

test("patchFingerprint: preserves indentation", () => {
  const source = "    version: 2,\n    migrators: [a, b],\n";
  const result = patchFingerprint(source, "12345678");
  assert.match(
    result,
    /^ {4}version: 2,\n {4}schemaFingerprint: "12345678",\n {4}migrators/,
  );
});

test("patchFingerprint: no version line and no existing field → returns source unchanged (caller must detect and fail loudly)", () => {
  const source = "const x = 1;\n";
  const result = patchFingerprint(source, "cafef00d");
  assert.equal(result, source);
});
