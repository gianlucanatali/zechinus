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
  /**
   * Atomic guard: marks a rotation to `newEpoch` as in progress, but ONLY if
   * none already is — `true` (started) or `false` (a rotation is already
   * pending, no write happened). Must be a single conditional write (e.g.
   * `UPDATE ... WHERE pending_dek_epoch IS NULL`), never read-then-write —
   * two callers racing (two tabs, two devices) must never both succeed.
   */
  beginRotation(userId: string, newEpoch: number): Promise<boolean>;
  /** The in-progress rotation's target epoch, or `null` if none is pending. */
  getPendingRotation(userId: string): Promise<number | null>;
  /**
   * The account's canonical DEK epoch right now (`profiles.current_dek_epoch`,
   * bumped only by `completeRotation`). A device compares its own passkey
   * wrap's `dekEpoch` against this to discover it fell behind a rotation and
   * needs to publish a handshake request. Always defined (the column defaults
   * to 1) — never `null`, unlike `getPendingRotation`.
   */
  getCurrentEpoch(userId: string): Promise<number>;
  /**
   * Clears the in-progress marker and bumps the canonical epoch. Call ONLY
   * after the OLD epoch's key material has actually been retired (Fase 2.4's
   * `checkRetirementEligibility` returned eligible AND the retire itself ran)
   * — not merely after data migration finishes. Until this runs, `beginRotation`
   * keeps refusing every new attempt, on purpose: a second rotation starting
   * before the old epoch is retired risks destroying the only key that can
   * still decrypt rows stuck behind it.
   */
  completeRotation(userId: string, newEpoch: number): Promise<void>;
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

export interface BeginRotationResult {
  ok: boolean;
  /** Set only when `ok: false` — the epoch the already-in-progress rotation targets, for a clear "rotation to N already running" message. */
  pendingEpoch?: number;
}

/**
 * Anti-overlap guard (Fase 2.5): call BEFORE starting any rotation work.
 * Refuses (`ok: false`) if one is already in progress — rotations are
 * strictly sequential, never overlapping (see `DekRotationStorage.completeRotation`'s
 * doc comment for why: overlapping rotations risk destroying key material a
 * straggler row still needs).
 */
export async function beginRotation(
  storage: DekRotationStorage,
  userId: string,
  requestedEpoch: number,
): Promise<BeginRotationResult> {
  const started = await storage.beginRotation(userId, requestedEpoch);
  if (started) return { ok: true };
  const pendingEpoch = await storage.getPendingRotation(userId);
  return { ok: false, pendingEpoch: pendingEpoch ?? undefined };
}

/** Thin pass-through — see `DekRotationStorage.completeRotation`'s doc comment for the ordering requirement (only after the old epoch is actually retired). */
export async function completeRotation(
  storage: DekRotationStorage,
  userId: string,
  newEpoch: number,
): Promise<void> {
  await storage.completeRotation(userId, newEpoch);
}
