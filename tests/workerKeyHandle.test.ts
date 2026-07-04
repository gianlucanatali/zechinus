/**
 * Web Worker isolation for a `KeyHandle` — keeps the raw key bytes off the main
 * thread (DOM/extensions never see them), only the Worker holds them. Any web app
 * doing zero-knowledge E2E encryption wants this same isolation, so the
 * request/response message protocol is generic. What stays app-side: the actual
 * `Worker` construction (`new Worker(new URL(...))` needs a literal, statically
 * analyzable path for Vite's bundler — can't be parametrized through here) and which
 * `KeyHandle` factory the worker-side calls.
 *
 * Tested with fake `Worker`/`WorkerContext` doubles wired directly together (an
 * in-memory event bus) — no real Worker/browser needed, same principle as every other
 * in-memory adapter double in this test suite.
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  createWorkerKeyHandle,
  handleKeyHandleMessages,
} from "../adapters/workerKeyHandle.ts";
import { createKeyHandle } from "../core/keyDerivation.ts";

/** Wires a fake main-thread `Worker` directly to a fake worker-side `WorkerContext` — no real Worker. */
function fakeWorkerPair() {
  const mainListeners: Array<(e: { data: unknown }) => void> = [];
  const workerListeners: Array<(e: { data: unknown }) => void> = [];
  let terminated = false;

  const worker = {
    postMessage(data: unknown) {
      for (const cb of workerListeners) cb({ data });
    },
    addEventListener(_type: "message", cb: (e: { data: unknown }) => void) {
      mainListeners.push(cb);
    },
    terminate() {
      terminated = true;
    },
  };

  const workerCtx = {
    postMessage(data: unknown) {
      for (const cb of mainListeners) cb({ data });
    },
    addEventListener(_type: "message", cb: (e: { data: unknown }) => void) {
      workerListeners.push(cb);
    },
  };

  return { worker, workerCtx, isTerminated: () => terminated };
}

test("createWorkerKeyHandle / handleKeyHandleMessages: init returns the correct pid", async () => {
  const { worker, workerCtx } = fakeWorkerPair();
  handleKeyHandleMessages(
    (rawBytes) =>
      createKeyHandle(rawBytes, new Uint8Array(32).fill(7), "test-info"),
    workerCtx,
  );

  const rawBytes = new Uint8Array(32).fill(1);
  const handle = await createWorkerKeyHandle(worker, rawBytes);
  const expected = createKeyHandle(
    rawBytes,
    new Uint8Array(32).fill(7),
    "test-info",
  );
  assert.equal(handle.pid, expected.pid);
});

test("createWorkerKeyHandle: encryptJson/decryptJson roundtrip through the worker protocol", async () => {
  const { worker, workerCtx } = fakeWorkerPair();
  handleKeyHandleMessages(
    (rawBytes) =>
      createKeyHandle(rawBytes, new Uint8Array(32).fill(7), "test-info"),
    workerCtx,
  );

  const handle = await createWorkerKeyHandle(
    worker,
    new Uint8Array(32).fill(1),
  );
  const aad = { userId: handle.pid, table: "t", field: "f", rowId: "r" };
  const enc = await handle.encryptJson({ hello: "world" }, aad);
  const dec = await handle.decryptJson(enc, aad);
  assert.deepEqual(dec, { hello: "world" });
});

test("createWorkerKeyHandle: encryptField/decryptField roundtrip", async () => {
  const { worker, workerCtx } = fakeWorkerPair();
  handleKeyHandleMessages(
    (rawBytes) =>
      createKeyHandle(rawBytes, new Uint8Array(32).fill(7), "test-info"),
    workerCtx,
  );

  const handle = await createWorkerKeyHandle(
    worker,
    new Uint8Array(32).fill(1),
  );
  const aad = { userId: handle.pid, table: "t", field: "f", rowId: "r" };

  const encF = await handle.encryptField("plain text", aad);
  assert.equal(await handle.decryptField(encF, aad), "plain text");
});

test("createWorkerKeyHandle: wrapWithKek proxies through to the worker's handle", async () => {
  const { worker, workerCtx } = fakeWorkerPair();
  handleKeyHandleMessages(
    (rawBytes) =>
      createKeyHandle(rawBytes, new Uint8Array(32).fill(7), "test-info"),
    workerCtx,
  );

  const rawBytes = new Uint8Array(32).fill(1);
  const handle = await createWorkerKeyHandle(worker, rawBytes);
  const kek = new Uint8Array(32).fill(9);
  const wrapped = await handle.wrapWithKek(kek);
  assert.ok(wrapped.ciphertext);
  assert.ok(wrapped.nonce);
});

test("createWorkerKeyHandle: a worker-side error rejects the caller's promise with context", async () => {
  const { worker, workerCtx } = fakeWorkerPair();
  handleKeyHandleMessages(
    (rawBytes) =>
      createKeyHandle(rawBytes, new Uint8Array(32).fill(7), "test-info"),
    workerCtx,
  );

  const handle = await createWorkerKeyHandle(
    worker,
    new Uint8Array(32).fill(1),
  );
  // Wrong AAD (different rowId) → GCM auth tag mismatch inside the worker → rejected here.
  const aad = { userId: handle.pid, table: "t", field: "f", rowId: "r" };
  const enc = await handle.encryptJson({ x: 1 }, aad);
  await assert.rejects(() =>
    handle.decryptJson(enc, { ...aad, rowId: "different" }),
  );
});

test("createWorkerKeyHandle: destroy() terminates the worker", async () => {
  const { worker, workerCtx, isTerminated } = fakeWorkerPair();
  handleKeyHandleMessages(
    (rawBytes) =>
      createKeyHandle(rawBytes, new Uint8Array(32).fill(7), "test-info"),
    workerCtx,
  );

  const handle = await createWorkerKeyHandle(
    worker,
    new Uint8Array(32).fill(1),
  );
  handle.destroy();
  assert.equal(isTerminated(), true);
});
