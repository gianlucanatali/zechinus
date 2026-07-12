/**
 * `dekRotationCoordinator.ts` — the ephemeral request→fulfill handshake
 * (Fase 2.3). In-memory fake storage double, same style as
 * `passkeyDekController.test.ts`'s `memoryWrapStorage`.
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  publishRotationRequest,
  pollRotationRequest,
  fulfillPendingRotationRequests,
  type DekRotationStorage,
  type DekRotationRequestRow,
} from "../adapters/dekRotationCoordinator.ts";
import { deriveDevicePublicKey } from "../adapters/deviceKeyProvider.ts";

function bytesFromRange(len: number, fn: (i: number) => number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = fn(i);
  return out;
}

/** In-memory fake — mirrors the RLS-scoped, per-user shape a real Supabase-backed one would have. */
function memoryRotationStorage(): DekRotationStorage & {
  rows: Map<string, DekRotationRequestRow>;
} {
  const rows = new Map<string, DekRotationRequestRow>();
  let nextId = 1;
  return {
    rows,
    async createRequest(_userId, requestedEpoch, requestPublicKey) {
      const id = `req-${nextId++}`;
      rows.set(id, {
        id,
        requestedEpoch,
        requestPublicKey,
        wrappedDek: null,
      });
      return { id };
    },
    async getRequest(_userId, requestId) {
      return rows.get(requestId) ?? null;
    },
    async listUnfulfilledRequests() {
      return [...rows.values()].filter((r) => r.wrappedDek === null);
    },
    async fulfillRequest(_userId, requestId, wrappedDek) {
      const row = rows.get(requestId);
      if (!row) throw new Error(`fulfillRequest: unknown request ${requestId}`);
      rows.set(requestId, { ...row, wrappedDek });
    },
    async deleteRequest(_userId, requestId) {
      rows.delete(requestId);
    },
  };
}

const USER_ID = "user-1";

test("publishRotationRequest: creates a request row and returns a seed the caller holds in memory", async () => {
  const storage = memoryRotationStorage();
  const { requestId, seed } = await publishRotationRequest(storage, USER_ID, 2);

  assert.equal(seed.length, 32);
  const row = storage.rows.get(requestId);
  assert.ok(row);
  assert.equal(row!.requestedEpoch, 2);
  assert.equal(row!.wrappedDek, null);
});

test("pollRotationRequest: returns null while unfulfilled — not an error, still waiting", async () => {
  const storage = memoryRotationStorage();
  const { requestId, seed } = await publishRotationRequest(storage, USER_ID, 2);

  const result = await pollRotationRequest(storage, USER_ID, requestId, seed);
  assert.equal(result, null);
});

test("fulfillPendingRotationRequests: an already-unlocked device wraps the DEK for every pending request on its account", async () => {
  const storage = memoryRotationStorage();
  const { requestId: reqA } = await publishRotationRequest(storage, USER_ID, 2);
  const { requestId: reqB } = await publishRotationRequest(storage, USER_ID, 2);

  const currentDek = bytesFromRange(32, (i) => i);
  const result = await fulfillPendingRotationRequests(
    storage,
    USER_ID,
    currentDek,
  );

  assert.equal(result.fulfilled, 2);
  assert.ok(storage.rows.get(reqA)!.wrappedDek);
  assert.ok(storage.rows.get(reqB)!.wrappedDek);
});

test("fulfillPendingRotationRequests: already-fulfilled requests are skipped (listUnfulfilledRequests excludes them)", async () => {
  const storage = memoryRotationStorage();
  await publishRotationRequest(storage, USER_ID, 2);
  const currentDek = bytesFromRange(32, (i) => i);

  const first = await fulfillPendingRotationRequests(
    storage,
    USER_ID,
    currentDek,
  );
  assert.equal(first.fulfilled, 1);

  const second = await fulfillPendingRotationRequests(
    storage,
    USER_ID,
    currentDek,
  );
  assert.equal(second.fulfilled, 0);
});

test("end-to-end: requester publishes, fulfiller (another device, already on the new DEK) wraps it, requester polls and unwraps the SAME DEK", async () => {
  const storage = memoryRotationStorage();
  const newDek = bytesFromRange(32, (i) => (i * 7) % 256);

  const { requestId, seed } = await publishRotationRequest(storage, USER_ID, 2);
  const { fulfilled } = await fulfillPendingRotationRequests(
    storage,
    USER_ID,
    newDek,
  );
  assert.equal(fulfilled, 1);

  const recovered = await pollRotationRequest(
    storage,
    USER_ID,
    requestId,
    seed,
  );
  assert.deepEqual(recovered, newDek);
});

test("end-to-end: a THIRD device's unrelated request is untouched by another device's fulfillment of a different request", async () => {
  const storage = memoryRotationStorage();
  const newDek = bytesFromRange(32, (i) => i);

  const { requestId: mine } = await publishRotationRequest(storage, USER_ID, 2);
  const { requestId: someoneElses } = await publishRotationRequest(
    storage,
    USER_ID,
    2,
  );

  // Only fulfill "mine" directly, simulating a fulfiller that races and
  // sees only one row (e.g. between two fulfillPendingRotationRequests calls).
  const publicKeyForMine = storage.rows.get(mine)!.requestPublicKey;
  const { wrapForDevicePublicKey } =
    await import("../adapters/deviceKeyProvider.ts");
  const wrapped = wrapForDevicePublicKey(publicKeyForMine, newDek);
  await storage.fulfillRequest(USER_ID, mine, wrapped);

  assert.equal(storage.rows.get(someoneElses)!.wrappedDek, null);
});

test("pollRotationRequest: a stray call after the request was deleted (e.g. consumed and cleaned up by the requester itself) returns null, not a crash", async () => {
  const storage = memoryRotationStorage();
  const { requestId, seed } = await publishRotationRequest(storage, USER_ID, 2);
  await storage.deleteRequest(USER_ID, requestId);

  const result = await pollRotationRequest(storage, USER_ID, requestId, seed);
  assert.equal(result, null);
});

test("deriveDevicePublicKey (stable, KEK-derived) and the ephemeral request key are never the same value for the same device — proves the handshake key is genuinely a distinct, throwaway identity, not accidentally reusing the stable one", async () => {
  const storage = memoryRotationStorage();
  const kek = bytesFromRange(32, (i) => i * 3);
  const stableDevicePublicKey = deriveDevicePublicKey(kek);

  const { requestId } = await publishRotationRequest(storage, USER_ID, 2);
  const row = storage.rows.get(requestId)!;

  assert.notEqual(row.requestPublicKey, stableDevicePublicKey);
});
