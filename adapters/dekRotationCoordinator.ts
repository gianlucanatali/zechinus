/**
 * Multi-device DEK rotation coordination (key-custody roadmap Fase 2.3) — the
 * ephemeral request→fulfill handshake: a device that's fallen behind an epoch
 * publishes a one-shot X25519 public key (`deviceKeyProvider.ts`'s
 * `generateEphemeralDeviceKey`, never persisted); any OTHER device on the same
 * account, already on the current epoch, wraps the DEK for it
 * (`wrapForDevicePublicKey`) whenever it happens to come online. Storage
 * (which table, RLS, how rows are found) is injected — this file only
 * orchestrates the crypto+lifecycle, same split as `passkeyDekController.ts`.
 */
import {
  generateEphemeralDeviceKey,
  unwrapWithEphemeralKey,
  wrapForDevicePublicKey,
  type DeviceWrappedKey,
} from "./deviceKeyProvider.ts";
import { clean } from "@noble/ciphers/utils.js";

export interface DekRotationRequestRow {
  id: string;
  requestedEpoch: number;
  requestPublicKey: string;
  wrappedDek: DeviceWrappedKey | null;
}

export interface DekRotationStorage {
  createRequest(
    userId: string,
    requestedEpoch: number,
    requestPublicKey: string,
  ): Promise<{ id: string }>;
  getRequest(
    userId: string,
    requestId: string,
  ): Promise<DekRotationRequestRow | null>;
  /** Requests from OTHER devices on this same account still waiting for a wrap — never this caller's own, storage is expected to exclude rows whose `wrappedDek` is already set. */
  listUnfulfilledRequests(userId: string): Promise<DekRotationRequestRow[]>;
  fulfillRequest(
    userId: string,
    requestId: string,
    wrappedDek: DeviceWrappedKey,
  ): Promise<void>;
  deleteRequest(userId: string, requestId: string): Promise<void>;
}

/**
 * Publishes a fresh handshake request. Returns `seed` (the caller MUST hold it
 * in memory — never persist it — until `pollRotationRequest` either succeeds or
 * the caller gives up and calls `clean(seed)` itself) and `requestId` (to poll
 * and eventually delete).
 */
export async function publishRotationRequest(
  storage: DekRotationStorage,
  userId: string,
  requestedEpoch: number,
): Promise<{ requestId: string; seed: Uint8Array }> {
  const { seed, publicKeyB64 } = generateEphemeralDeviceKey();
  const { id } = await storage.createRequest(
    userId,
    requestedEpoch,
    publicKeyB64,
  );
  return { requestId: id, seed };
}

/**
 * Checks whether the request has been fulfilled yet. Returns `null` (still
 * waiting — not an error) if no other device has wrapped a reply. On success,
 * unwraps the DEK and `clean()`s `seed` itself — the handshake is over the
 * moment this returns a non-null value, the caller must not reuse `seed`
 * afterward regardless of outcome.
 */
export async function pollRotationRequest(
  storage: DekRotationStorage,
  userId: string,
  requestId: string,
  seed: Uint8Array,
): Promise<Uint8Array | null> {
  const row = await storage.getRequest(userId, requestId);
  if (!row?.wrappedDek) return null;
  try {
    return unwrapWithEphemeralKey(seed, row.wrappedDek);
  } finally {
    clean(seed);
  }
}

/**
 * Called by an ALREADY-unlocked device (one that already holds the current
 * DEK) to fulfill every pending request from its OWN account's other devices —
 * meant to piggyback on an existing periodic check (e.g. device-link
 * revalidation), never a dedicated poll loop of its own (see
 * `docs/decisions/2026-07-12-dek-rotation-ephemeral-handshake-key.md` for why:
 * no event system, so discovery rides on a poll that already exists for an
 * unrelated reason instead of adding a new one).
 */
export async function fulfillPendingRotationRequests(
  storage: DekRotationStorage,
  userId: string,
  currentDek: Uint8Array,
): Promise<{ fulfilled: number }> {
  const pending = await storage.listUnfulfilledRequests(userId);
  let fulfilled = 0;
  for (const request of pending) {
    const wrapped = wrapForDevicePublicKey(
      request.requestPublicKey,
      currentDek,
    );
    await storage.fulfillRequest(userId, request.id, wrapped);
    fulfilled++;
  }
  return { fulfilled };
}
