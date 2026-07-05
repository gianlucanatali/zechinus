/**
 * Pluggable gzip implementation — test the injection mechanism.
 * Web uses native CompressionStream; React Native injects an fflate-backed impl.
 * CONTRACT: blobs written under one impl MUST decompress under another.
 */
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { gzipSync, gunzipSync } from "node:zlib";
import { setGzipImpl, gzipCompress, gzipDecompress } from "../core/gzip.ts";
import { encryptJson, decryptJson } from "../core/crypto.ts";

const zlibImpl = {
  compress: (d: Uint8Array) => new Uint8Array(gzipSync(d)),
  decompress: (d: Uint8Array) => new Uint8Array(gunzipSync(d)),
};
const AAD = { userId: "u", table: "t", field: "data", rowId: "r" };
const DEK = new Uint8Array(32).fill(7);

afterEach(() => setGzipImpl(null)); // always reset to the runtime default

test("roundtrip with injected impl", async () => {
  setGzipImpl(zlibImpl);
  const out = await gzipDecompress(
    await gzipCompress(new Uint8Array([1, 2, 3])),
  );
  assert.deepEqual([...out], [1, 2, 3]);
});

test("cross-impl: default-compressed blob decrypts under injected impl (and back)", async () => {
  const enc = await encryptJson(DEK, { hello: "world" }, AAD); // default CompressionStream
  setGzipImpl(zlibImpl);
  assert.deepEqual(await decryptJson(DEK, enc, AAD), { hello: "world" });
  const enc2 = await encryptJson(DEK, { a: 1 }, AAD); // injected impl
  setGzipImpl(null);
  assert.deepEqual(await decryptJson(DEK, enc2, AAD), { a: 1 }); // default again
});

test("no CompressionStream and no impl → explicit error naming setGzipImpl", async () => {
  const saved = globalThis.CompressionStream;
  // @ts-expect-error simulate Hermes
  delete globalThis.CompressionStream;
  try {
    await assert.rejects(
      () => gzipCompress(new Uint8Array([1])),
      /setGzipImpl/,
    );
  } finally {
    globalThis.CompressionStream = saved;
  }
});
