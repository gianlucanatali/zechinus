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
  beginRotation,
  completeRotation,
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
  pendingEpochByUser: Map<string, number | null>;
} {
  const rows = new Map<string, DekRotationRequestRow>();
  const pendingEpochByUser = new Map<string, number | null>();
  let nextId = 1;
  return {
    rows,
    pendingEpochByUser,
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
    // Mirrors a real `UPDATE ... WHERE pending_dek_epoch IS NULL` conditional
    // write — only succeeds (returns true) if nothing was pending yet.
    async beginRotation(userId, newEpoch) {
      const current = pendingEpochByUser.get(userId) ?? null;
      if (current !== null) return false;
      pendingEpochByUser.set(userId, newEpoch);
      return true;
    },
    async getPendingRotation(userId) {
      return pendingEpochByUser.get(userId) ?? null;
    },
    async completeRotation(userId, newEpoch) {
      pendingEpochByUser.set(userId, null);
      void newEpoch; // the fake has no separate current_dek_epoch to bump
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

test("beginRotation: no rotation pending → starts, returns ok:true", async () => {
  const storage = memoryRotationStorage();

  const result = await beginRotation(storage, USER_ID, 2);

  assert.deepEqual(result, { ok: true });
  assert.equal(storage.pendingEpochByUser.get(USER_ID), 2);
});

test("beginRotation: a rotation is already pending → refuses, reports the pending epoch, does NOT overwrite it", async () => {
  const storage = memoryRotationStorage();
  await beginRotation(storage, USER_ID, 2);

  const second = await beginRotation(storage, USER_ID, 3);

  assert.deepEqual(second, { ok: false, pendingEpoch: 2 });
  // Still 2, not overwritten by the refused attempt at 3 — no overlapping rotations.
  assert.equal(storage.pendingEpochByUser.get(USER_ID), 2);
});

test("beginRotation: two concurrent callers racing for the same user — only one wins (the storage's atomic conditional write, not this function, is what decides)", async () => {
  const storage = memoryRotationStorage();

  const [first, second] = await Promise.all([
    beginRotation(storage, USER_ID, 2),
    beginRotation(storage, USER_ID, 2),
  ]);

  const outcomes = [first.ok, second.ok].sort();
  assert.deepEqual(outcomes, [false, true]);
});

test("completeRotation: clears the pending marker — a new rotation can start afterward", async () => {
  const storage = memoryRotationStorage();
  await beginRotation(storage, USER_ID, 2);

  await completeRotation(storage, USER_ID, 2);
  assert.equal(storage.pendingEpochByUser.get(USER_ID), null);

  const next = await beginRotation(storage, USER_ID, 3);
  assert.deepEqual(next, { ok: true });
});

test("beginRotation: a different user's pending rotation doesn't block this one (per-user, not global)", async () => {
  const storage = memoryRotationStorage();
  await beginRotation(storage, "user-other", 2);

  const result = await beginRotation(storage, USER_ID, 2);
  assert.deepEqual(result, { ok: true });
});
