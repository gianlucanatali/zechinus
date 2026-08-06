/**
 * Passkey + BIP39-recovery unlock orchestration — the full ceremony (register a
 * passkey, generate a recovery phrase, wrap the DEK under both, unlock via either,
 * add an additional passkey to an already-unlocked DEK) that ANY app doing
 * zero-knowledge E2E encryption with WebAuthn PRF + mnemonic recovery needs. None of
 * this is app-specific business logic — it's the same sequence of steps regardless
 * of which app is asking, which is exactly why it lives here instead of being
 * rewritten per-app on top of `webauthnKeyProvider`/`mnemonicRecovery`.
 *
 * What stays app-side (injected via config, never assumed here):
 * - `storage`: where wrapped keys live (table/column names, the DB client) — this
 *   controller only ever calls the 5 methods on `PasskeyWrapStorage`, never touches
 *   a database directly.
 * - `createHandle`: how raw DEK bytes become a usable `KeyHandle` — plain
 *   `createKeyHandle` or Worker-isolated (`createWorkerKeyHandle`), the app's choice.
 * - `provider`/`recovery`: the app's own `webauthnKeyProvider`/`mnemonicRecovery`
 *   instances, carrying its immutable salts/config (see those adapters' own docs).
 *
 * Framework-agnostic on purpose (no React import anywhere in this file):
 * `getCryptoHandle()`/`subscribe()` already satisfy the `KeyProvider` port, and the plain
 * subscribe-based state shape works identically from a React `useSyncExternalStore`
 * hook, a Vue `ref` + watcher, a Svelte store, or a vanilla JS event listener — see
 * `zechinus/react/usePasskeyDek.ts` for the (thin) React binding.
 */
import { unwrapKey, wrapKey, type KeyHandle } from "../../core/keyDerivation.ts";
import { asRawDekBytes, type RawDekBytes } from "../../core/keyDerivation.ts";
import { clean, randomBytes } from "@noble/ciphers/utils.js";
import type { WebauthnKeyProvider } from "../keyproviders/webauthnKeyProvider.ts";
import type { MnemonicRecovery } from "../keyproviders/mnemonicRecovery.ts";
import {
  deriveDevicePublicKey,
  unwrapWithDeviceKey,
  type DeviceWrappedKey,
} from "../crypto/deviceKeyProvider.ts";

export type WrappedKeyRow = { ciphertext: string; nonce: string };

/**
 * Optional local cache for the wrapped DEK, keyed by (userId, credentialId).
 * When configured, `unlockWithPasskey` falls back to this cache if the live
 * `storage.loadPasskeyWraps` call fails for any reason (offline, transient
 * network error, RLS hiccup — no need to distinguish which, same permissive
 * philosophy as any other "fail open to cache" read in this codebase) — and
 * refreshes the cache with the freshest wrap on every successful online
 * fetch, so a later offline unlock always uses whatever was freshest last
 * time the device was online.
 *
 * Caching the wrap changes nothing about the security model: it's opaque
 * ciphertext, useless without a KEK that can only ever be derived from a
 * LIVE WebAuthn PRF ceremony (a biometric touch on THIS device's Secure
 * Enclave) — a live touch is still required on every single unlock, cached
 * wrap or not. Left unconfigured (e.g. the web app, always-online), the
 * controller behaves exactly as it did before this type existed — a storage
 * failure throws immediately, same as any other unhandled I/O error.
 */
export interface PasskeyWrapCache {
  get(
    userId: string,
    credentialId: string,
  ): Promise<(WrappedKeyRow & { dekEpoch: number }) | null>;
  set(
    userId: string,
    credentialId: string,
    wrap: WrappedKeyRow & { dekEpoch: number },
  ): Promise<void>;
}

/**
 * Where wrapped keys are persisted. `many` passkeys per user (one row per
 * credential), exactly one recovery wrap per user — mirrors the real shape of any
 * app doing this (a user has N devices, one recovery phrase).
 */
export interface PasskeyWrapStorage {
  countPasskeyWraps(userId: string): Promise<number>;
  /** ALL rows for this credential — 0, 1, or 2 (old epoch + new epoch) if a
   * rotation is mid-flight. See `passkey_key_wraps_user_id_credential_id_epoch_key`
   * (unique on user_id, credential_id, dek_epoch). */
  loadPasskeyWraps(
    userId: string,
    credentialId: string,
  ): Promise<Array<WrappedKeyRow & { dekEpoch: number }>>;
  savePasskeyWrap(
    userId: string,
    credentialId: string,
    wrapped: WrappedKeyRow,
    dekEpoch: number,
  ): Promise<void>;
  loadRecoveryWrap(userId: string): Promise<WrappedKeyRow | null>;
  saveRecoveryWrap(userId: string, wrapped: WrappedKeyRow): Promise<void>;
}

/**
 * "pending" = caller hasn't checked yet (e.g. still waiting on auth). "needed" = no
 * passkey registered for this user. "done" = registered, or the user explicitly
 * skipped for this session (`markSetupDone`).
 */
export type PasskeySetupStatus = "pending" | "needed" | "done";

/** How the DEK became active in the current session — drives app-level policy
 * decisions (e.g. requiring the strongest factor before an irreversible action
 * like invalidating a recovery phrase). `null` when locked. */
export type UnlockMethod = "passkey" | "recovery";

/**
 * Zero-tap cache for handles whose key never leaves an isolation boundary — a native
 * module on mobile, a Worker with persistent storage anywhere else. The port never sees
 * a byte of key material: it hands back an already-built `KeyHandle`, because the key is
 * restored INSIDE the boundary and only an opaque reference comes out.
 *
 * The implementor owns the OS-level gate (Keychain `biometryCurrentSet` on iOS, Keystore
 * `setUserAuthenticationRequired` + BiometricPrompt on Android). Having the OS enforce it
 * rather than app code is the whole point: an app-level check is one refactor away from
 * being forgotten — which is exactly what shipped in TestFlight build 20 — and cannot
 * survive a biometric re-enrollment the way the OS flag does.
 *
 * Deliberately NOT a "give me the raw bytes" port. There is no such port in zechinus, on
 * purpose: see `docs/DECISIONS.md` § "Native-module DEK isolation".
 */
export interface IsolatedKeyCache {
  /** Persists the currently-active key inside the boundary, with the metadata needed to validate it later. */
  persist(
    userId: string,
    meta: { dekEpoch: number; credentialId: string },
  ): Promise<void>;
  /**
   * OS-gated restore. Resolves `null` — never throws — when there's nothing cached, the
   * gate is unavailable, or the user failed/cancelled authentication: all expected
   * outcomes, and the caller falls through to a real ceremony.
   */
  restore(
    userId: string,
  ): Promise<{ handle: KeyHandle; dekEpoch: number; credentialId: string } | null>;
  clear(userId: string): Promise<void>;
}

export interface PasskeyDekControllerConfig {
  provider: WebauthnKeyProvider;
  recovery: MnemonicRecovery;
  storage: PasskeyWrapStorage;
  /** Builds the real `KeyHandle` from freshly-unwrapped raw bytes — plain or Worker-isolated. */
  createHandle: (rawBytes: RawDekBytes) => Promise<KeyHandle> | KeyHandle;
  /** See `PasskeyWrapCache`'s own doc comment. Optional — omit for an
   * always-online app (e.g. the web client); required for offline unlock
   * support (e.g. the mobile client). */
  wrapCache?: PasskeyWrapCache;
  /** See `IsolatedKeyCache`. Optional — mobile-only today; web stays always-online. */
  isolatedKeyCache?: IsolatedKeyCache;
  /**
   * Reads the account's CURRENT dek_epoch from the server — used exclusively by
   * `tryZeroTapRestore()` to detect a rotation that happened elsewhere (this
   * controller never initiates one). Optional; when omitted, or when it throws
   * (offline), fails OPEN on the cached entry, same permissive philosophy as
   * the rotation-handshake paths elsewhere in this file.
   */
  getCurrentEpoch?: (userId: string) => Promise<number>;
}

/** Returned by `registerPasskey` — nothing is persisted until `confirm()` runs, so the
 * caller can show the recovery words and require explicit acknowledgement first. */
export interface PendingPasskeySetup {
  recoveryWords: string;
  confirm(): Promise<void>;
}

/** Returned by `regenerateRecoveryWords` — same "show once, persist on confirm"
 * shape as `PendingPasskeySetup`. */
export interface PendingRecoveryRegeneration {
  recoveryWords: string;
  confirm(): Promise<void>;
}

export interface PasskeyDekController {
  /** Matches the `KeyProvider` port shape — usable directly as one. */
  getCryptoHandle(): KeyHandle | null;
  getUserId(): string | null;
  getSetupStatus(): PasskeySetupStatus;
  /** How the DEK was unlocked this session — `null` when locked. See `UnlockMethod`. */
  getUnlockMethod(): UnlockMethod | null;
  /** The passkey credential id that unlocked/created the current DEK (base64url,
   * as returned by WebAuthn) — `null` when locked, or when the session was unlocked
   * via recovery phrase (no passkey credential involved). Any app tracking which
   * specific passkey a device is bound to (e.g. to point a user at the right one to
   * remove during a security incident) needs this — it's not derivable from
   * `getUnlockMethod()` alone, which only says "passkey" vs "recovery". */
  getUnlockCredentialId(): string | null;
  /** This device's X25519 public key, deterministically derived from the current
   * session's KEK (see `adapters/deviceKeyProvider.ts`) — `null` when locked, or when
   * the session was unlocked via recovery phrase (no passkey KEK involved, mirrors
   * `getUnlockCredentialId()`). Register this on the device's registry row so another
   * device can address a rotated DEK to it later (key-custody roadmap Fase 2.3). Never
   * persisted by this controller itself — nothing to persist, it re-derives identically
   * every time the same passkey unlocks. */
  getDevicePublicKey(): string | null;
  /** Matches `KeyProvider.getPreviousCryptoHandle`. Populated by whichever of two
   * writers ran most recently: (1) `beginRotation()` — cleared by
   * `completeRotationSession()` or `lock()`, see those two methods' doc comments;
   * or (2) `unlockWithPasskey()` — when a second, older-epoch `passkey_key_wraps`
   * row exists for the credential being unlocked (a rotation is mid-flight on this
   * device), reconstructed straight from that row on disk, independent of whether
   * THIS session ever calls `beginRotation()`. Either writer's failure to produce
   * a previous handle leaves this `null`; `unlockWithPasskey()`'s decode failure
   * on that second row specifically never fails the unlock itself. */
  getPreviousCryptoHandle(): KeyHandle | null;
  subscribe(callback: () => void): () => void;

  /** Activates a caller-supplied raw DEK directly — dev/test injection, or after a
   * ceremony that derived the bytes some other way. `credentialId` is optional and
   * `null` by default (mirrors `activate`'s own default) — passing one populates
   * `getUnlockCredentialId()` exactly as a real `unlockWithPasskey()`/`registerPasskey()`
   * would, which a dev/test caller needs when it also wants to exercise
   * `rewrapCurrentCredentialAtEpoch`/`consumePendingDeviceWrap` (both require a non-null
   * `getUnlockCredentialId()`) without a real WebAuthn ceremony — e.g. an E2E test
   * driving a DEK-rotation flow end-to-end. Omitting it keeps today's behavior
   * unchanged (`getUnlockCredentialId()` stays `null`). */
  setDek(
    userId: string,
    rawBytes: RawDekBytes,
    credentialId?: string | null,
  ): Promise<void>;
  /** Destroys the current handle (if any) and clears state. Idempotent. Also
   * destroys and clears any in-progress rotation's previous handle — a locked
   * session must never leak a stale rotation candidate into the next unlock. */
  lock(): void;

  /** Refreshes `getSetupStatus()` from storage — "needed" iff zero wraps exist and
   * no dek is currently active (an active dek always means setup is effectively done). */
  checkSetupNeeded(userId: string): Promise<void>;
  /** Forces status to "done" without requiring a wrap (user skipped for this session). */
  markSetupDone(): void;

  /** Authenticates with an existing passkey and unlocks the DEK from its wrap.
   * `credentialId` omitted lets the platform show every available passkey. */
  unlockWithPasskey(userId: string, credentialId?: string): Promise<void>;
  /** Unlocks the DEK using a BIP39 recovery phrase. */
  unlockWithRecovery(userId: string, words: string): Promise<void>;

  /**
   * Registers a brand-new passkey + a fresh recovery phrase, wrapping a NEWLY
   * GENERATED DEK under both. Nothing is persisted until the returned `confirm()`
   * is called — the caller shows `recoveryWords` and requires acknowledgement first.
   */
  registerPasskey(
    userId: string,
    userName: string,
  ): Promise<PendingPasskeySetup>;

  /**
   * Registers an additional passkey for the CURRENTLY UNLOCKED dek (re-wrap, not
   * rotation — the dek's bytes never change, see `KeyHandle.wrapWithKek`). Requires
   * `getCryptoHandle()` to be non-null; throws otherwise. Returns the new credential
   * id so the caller can, e.g., apply a user-chosen label to that specific row.
   */
  addPasskeyToExistingDek(
    userId: string,
    userName: string,
  ): Promise<{ credentialId: string }>;

  /**
   * Regenerates the recovery phrase for the CURRENTLY UNLOCKED dek (rewrap, not
   * rotation — same shape as `addPasskeyToExistingDek`, the dek's bytes never
   * change). Requires `getCryptoHandle()` to be non-null; throws otherwise.
   * Nothing is persisted until `confirm()` is called — mirrors `registerPasskey`
   * so the caller can require the user acknowledge the new words first. The old
   * recovery wrap is replaced (storage keeps exactly one recovery wrap per user).
   */
  regenerateRecoveryWords(userId: string): Promise<PendingRecoveryRegeneration>;

  /**
   * Starts a DEK rotation SESSION for the device driving it (key-custody roadmap
   * Fase 2.3/E). Builds a `KeyHandle` for `rawNewDekBytes`, promotes it to
   * `getCryptoHandle()` immediately (every NEW ambient write from this point uses
   * the new epoch), and keeps the CURRENT handle as `getPreviousCryptoHandle()` —
   * the read-side fallback every store's ambient read path (`load`/`get`/`list`/
   * `getRange`) consults so rows the rotation batch (`rotateEpoch`) hasn't reached
   * yet still decrypt. Requires `getCryptoHandle()` to already be non-null (unlock
   * first); throws otherwise. Purely a local/session-state operation — the DB-level
   * rotation guard (`profiles.pending_dek_epoch`, see `dekRotationCoordinator.ts`'s
   * own `beginRotation`) is a SEPARATE step the orchestrator calls FIRST, before
   * this one. A device that only RECEIVES an already-rotated DEK via the handshake
   * (`dekRotationCoordinator.ts`, not the device driving the rotation) never calls
   * this — it gets the new DEK already resolved and just re-wraps it.
   */
  beginRotation(rawNewDekBytes: RawDekBytes): Promise<void>;
  /**
   * Ends the rotation session: destroys and clears `getPreviousCryptoHandle()`.
   * The CURRENT handle (`getCryptoHandle()`) is untouched. Call ONLY after the
   * orchestrator has verified+retired the old epoch (`checkRetirementEligibility`
   * eligible, old epoch's wraps deleted) — see this module's top-level doc comment
   * for the full call order. Deliberately named differently from
   * `dekRotationCoordinator.ts`'s `completeRotation` (that one is DB-level
   * bookkeeping — `pending_dek_epoch`/`current_dek_epoch`; this one is local
   * session state) — never confuse the two. Idempotent: safe to call with no
   * rotation in progress. Note this is NOT the only writer that can leave
   * `getPreviousCryptoHandle()` non-null — `unlockWithPasskey()` can also
   * populate it from a pre-existing second wrap row found on disk, without this
   * session ever calling `beginRotation()`; calling `completeRotationSession()`
   * still clears it in that case too, same as any other rotation-session teardown.
   */
  completeRotationSession(): void;

  /**
   * Wraps the currently-unlocked DEK for another device's ephemeral public key —
   * used to fulfil a pending rotation handshake request (`dek_rotation_requests`)
   * from a device that fell behind. Delegates to `KeyHandle.wrapForDevice` — raw
   * DEK bytes never leave this call, unlike `wrapForDevicePublicKey` (which the
   * rotation-driving device uses transiently in `beginRotation`, before this
   * handle even exists). Requires `getCryptoHandle()` non-null; throws otherwise,
   * and throws if the current handle was built without `wrapForDevice` support.
   */
  wrapCurrentDekForDevice(devicePublicKeyB64: string): Promise<{
    ciphertext: string;
    nonce: string;
    ephemeralPublicKeyB64: string;
  }>;

  /**
   * Re-derives this device's KEK via a fresh WebAuthn PRF prompt on the SAME
   * credential that unlocked the current session, and re-wraps the CURRENT
   * crypto handle under it at `newEpoch` — a new `passkey_key_wraps` row
   * coexists with the old one (dek_epoch differs), never overwrites or deletes
   * it. Call AFTER `beginRotation(rawNewDekBytes)` has already promoted
   * `getCryptoHandle()` to the new DEK — this method never generates or
   * touches raw DEK bytes itself, it only re-wraps whatever `getCryptoHandle()`
   * currently returns. Used by the rotation-driving device to keep its own
   * passkey working after a rotation. Requires the current session to have
   * been unlocked via passkey (`getUnlockCredentialId()` non-null) and
   * `getCryptoHandle()` non-null; throws otherwise (e.g. unlocked via recovery
   * phrase — no credential to re-wrap under).
   */
  rewrapCurrentCredentialAtEpoch(newEpoch: number): Promise<void>;

  /**
   * Consumes a DEK proactively delivered to THIS device's stable
   * `device_public_key` (key-custody roadmap Fase E, point 3 — a device that
   * missed a rotation entirely, e.g. was offline the whole time, finds this
   * waiting for it instead of depending on the reactive ephemeral handshake).
   * Re-derives this device's KEK via a fresh WebAuthn PRF prompt on the
   * credential that unlocked the current session (same credential as
   * `rewrapCurrentCredentialAtEpoch` — requires `getUnlockCredentialId()`
   * non-null), unwraps `wrapped` with it (`unwrapWithDeviceKey` — the KEK
   * doubles as the seed for this device's stable X25519 keypair, see
   * `deviceKeyProvider.ts`), promotes the resulting DEK to `getCryptoHandle()`
   * (the OLD handle becomes `getPreviousCryptoHandle()`, same invariant as
   * `beginRotation` — an in-flight ambient read still falls back correctly),
   * then re-wraps THIS device's own passkey under the new DEK at `newEpoch`
   * (mirrors `rewrapCurrentCredentialAtEpoch`'s persistence, same KEK, no
   * second PRF prompt needed for that half). Requires `getCryptoHandle()`
   * non-null (already unlocked) and `getUnlockCredentialId()` non-null
   * (unlocked via passkey, not recovery); throws otherwise. Persists the
   * re-wrap (`storage.savePasskeyWrap`) BEFORE promoting anything in memory —
   * mirrors `registerPasskey().confirm()`, which persists first and only
   * activates last. If EITHER the unwrap (e.g. `wrapped` was encrypted for a
   * different device's public key) or the persist call fails, the error
   * propagates and NOTHING is promoted — `getCryptoHandle()` and
   * `getPreviousCryptoHandle()` stay exactly as they were before the call, so
   * a caller may safely retry the whole method without risking a
   * double-promotion that would overwrite the true `previousCryptoHandle`.
   */
  consumePendingDeviceWrap(
    wrapped: DeviceWrappedKey,
    newEpoch: number,
  ): Promise<void>;

  /**
   * Persists the CURRENTLY-ACTIVE key through `isolatedKeyCache`, so a later
   * `tryZeroTapRestore()` can skip a whole ceremony. No-op (never throws) when no cache
   * is configured, when locked, or when the current epoch can't be read (offline —
   * writing an entry we can't validate later is worse than writing none).
   */
  persistForZeroTap(userId: string): Promise<void>;
  /**
   * Attempts a zero-ceremony unlock from `isolatedKeyCache`. Returns `false` — never
   * throws — whenever the path isn't usable: no cache configured, nothing stored, the OS
   * gate refused, or a detected epoch mismatch (stale entry destroyed and cleared, caller
   * falls through to a real ceremony).
   */
  tryZeroTapRestore(userId: string): Promise<boolean>;
}

export function createPasskeyDekController(
  config: PasskeyDekControllerConfig,
): PasskeyDekController {
  const { provider, recovery, storage, createHandle, wrapCache } = config;

  let cryptoHandle: KeyHandle | null = null;
  let previousCryptoHandle: KeyHandle | null = null;
  let userId: string | null = null;
  let setupStatus: PasskeySetupStatus = "pending";
  let unlockMethod: UnlockMethod | null = null;
  let unlockCredentialId: string | null = null;
  let devicePublicKey: string | null = null;
  const listeners = new Set<() => void>();

  function notify(): void {
    for (const cb of listeners) cb();
  }

  // Extracted so both lock() and checkSetupNeeded() share the exact same
  // teardown, never letting a handle survive an identity mismatch.
  function destroyHandle(): void {
    if (cryptoHandle) {
      cryptoHandle.destroy();
      cryptoHandle = null;
    }
    if (previousCryptoHandle) {
      previousCryptoHandle.destroy();
      previousCryptoHandle = null;
    }
    userId = null;
    unlockMethod = null;
    unlockCredentialId = null;
    devicePublicKey = null;
  }

  // Extracted from activate() so the zero-tap restore path (which already has a built
  // KeyHandle, never raw bytes) can share the exact same promotion logic.
  function adoptHandle(
    uid: string,
    handle: KeyHandle,
    method: UnlockMethod,
    credentialId: string | null,
    devicePublicKeyB64: string | null = null,
  ): void {
    cryptoHandle = handle;
    userId = uid;
    setupStatus = "done";
    unlockMethod = method;
    unlockCredentialId = credentialId;
    devicePublicKey = devicePublicKeyB64;
    notify();
  }

  async function activate(
    uid: string,
    rawBytes: RawDekBytes,
    method: UnlockMethod,
    credentialId: string | null = null,
    devicePublicKeyB64: string | null = null,
  ): Promise<void> {
    const handle = await createHandle(rawBytes);
    clean(rawBytes);
    adoptHandle(uid, handle, method, credentialId, devicePublicKeyB64);
  }

  return {
    getCryptoHandle: () => cryptoHandle,
    getUserId: () => userId,
    getSetupStatus: () => setupStatus,
    getUnlockMethod: () => unlockMethod,
    getUnlockCredentialId: () => unlockCredentialId,
    getDevicePublicKey: () => devicePublicKey,
    getPreviousCryptoHandle: () => previousCryptoHandle,
    subscribe(callback) {
      listeners.add(callback);
      return () => listeners.delete(callback);
    },

    async setDek(uid, rawBytes, credentialId = null) {
      await activate(uid, rawBytes, "passkey", credentialId);
    },

    lock() {
      destroyHandle();
      notify();
    },

    async checkSetupNeeded(uid) {
      if (cryptoHandle && userId !== uid) {
        // Identity changed underneath an active handle (e.g. a different
        // user's session replaced this one in the same tab/browser context —
        // multi-tab session sync, no reload, no intermediate SIGNED_OUT).
        // Never let a stale handle answer for a new identity.
        destroyHandle();
        notify();
      }
      if (cryptoHandle) return; // already unlocked for this exact user — nothing to check
      const count = await storage.countPasskeyWraps(uid);
      setupStatus = count === 0 ? "needed" : "done";
      notify();
    },

    markSetupDone() {
      setupStatus = "done";
      notify();
    },

    async unlockWithPasskey(uid, credentialId) {
      const { prfOutput, credentialId: usedCredentialId } =
        await provider.getPRFOutputWithCredentialId(credentialId);

      let wraps: Array<WrappedKeyRow & { dekEpoch: number }>;
      try {
        wraps = await storage.loadPasskeyWraps(uid, usedCredentialId);
        if (wrapCache && wraps.length > 0) {
          const [freshest] = [...wraps].sort((a, b) => b.dekEpoch - a.dekEpoch);
          await wrapCache.set(uid, usedCredentialId, freshest);
        }
      } catch (e) {
        if (!wrapCache) throw e;
        const cached = await wrapCache.get(uid, usedCredentialId);
        if (!cached) throw e;
        wraps = [cached];
      }
      if (wraps.length === 0) {
        throw new Error(
          "passkeyDekController.unlockWithPasskey: no wrap found for this credential — complete setup first.",
        );
      }
      // Highest dek_epoch is the row to unlock as CURRENT. A second (lower-epoch)
      // row means a rotation is mid-flight on this device — see
      // passkey_key_wraps_user_id_credential_id_epoch_key.
      const [currentWrap, previousWrap] = [...wraps].sort(
        (a, b) => b.dekEpoch - a.dekEpoch,
      );

      const kek = provider.deriveKEKFromPRF(prfOutput);
      try {
        const rawBytes = unwrapKey(kek, currentWrap);
        const devicePublicKeyB64 = deriveDevicePublicKey(kek);
        await activate(
          uid,
          asRawDekBytes(rawBytes),
          "passkey",
          usedCredentialId,
          devicePublicKeyB64,
        );

        if (previousWrap) {
          // Same KEK/credential — only which wrapped_key gets decrypted
          // differs. A failure here must never fail the unlock: the current
          // row above is already valid and activated; the ambient rotation
          // fallback (`getPreviousCryptoHandle()`) is simply unavailable for
          // this session.
          try {
            const previousRawBytes = unwrapKey(kek, previousWrap);
            if (previousCryptoHandle) previousCryptoHandle.destroy();
            previousCryptoHandle = await createHandle(
              asRawDekBytes(previousRawBytes),
            );
            // beginRotation/completeRotationSession both notify() on every
            // previousCryptoHandle mutation — mirror that here so subscribers
            // (e.g. usePasskeyDek's useSyncExternalStore binding) re-read
            // state now that getPreviousCryptoHandle() went non-null. This
            // fires AFTER activate()'s own notify() above, as a second,
            // separate state transition.
            notify();
          } catch (e) {
            // Never fails the whole unlock — see comment above. Still must
            // be observable, not silent (AGENTS.md "never swallow" rule):
            // mirrors expoDeviceCacheStorage.ts's onPersistError and
            // onSourceWrite.ts's logFailure, same log-but-don't-throw shape.
            console.error(
              `passkeyDekController.unlockWithPasskey: previous-epoch wrap decode failed for credential ${usedCredentialId} — read-side rotation fallback unavailable this session:`,
              e,
            );
          }
        }
      } catch {
        throw new Error(
          "passkeyDekController.unlockWithPasskey: passkey not recognized — data cannot be decrypted.",
        );
      } finally {
        clean(kek);
      }
    },

    async unlockWithRecovery(uid, words) {
      if (!recovery.validateWords(words)) {
        throw new Error(
          "passkeyDekController.unlockWithRecovery: invalid recovery words.",
        );
      }
      const wrap = await storage.loadRecoveryWrap(uid);
      if (!wrap) {
        throw new Error(
          "passkeyDekController.unlockWithRecovery: no recovery wrap found — complete passkey setup first.",
        );
      }

      const kek = recovery.deriveKEK(words);
      try {
        const rawBytes = unwrapKey(kek, wrap);
        await activate(uid, asRawDekBytes(rawBytes), "recovery");
      } catch {
        throw new Error(
          "passkeyDekController.unlockWithRecovery: incorrect words — no data was decrypted.",
        );
      } finally {
        clean(kek);
      }
    },

    async registerPasskey(uid, userName) {
      const { credentialId, prfOutput: prfFromCreate } =
        await provider.registerPasskeyWithPRF(userName);
      const prfOutput =
        prfFromCreate ?? (await provider.getPRFOutput(credentialId));

      const masterKey = randomBytes(32);

      const kekPasskey = provider.deriveKEKFromPRF(prfOutput);
      const wrappedPasskey = wrapKey(kekPasskey, masterKey);
      const devicePublicKeyB64 = deriveDevicePublicKey(kekPasskey);
      clean(kekPasskey);

      const recoveryWords = recovery.generateWords();
      const kekRecovery = recovery.deriveKEK(recoveryWords);
      const wrappedRecovery = wrapKey(kekRecovery, masterKey);
      clean(kekRecovery);

      return {
        recoveryWords,
        async confirm() {
          try {
            await storage.savePasskeyWrap(uid, credentialId, wrappedPasskey, 1);
            await storage.saveRecoveryWrap(uid, wrappedRecovery);
            await activate(
              uid,
              asRawDekBytes(new Uint8Array(masterKey)),
              "passkey",
              credentialId,
              devicePublicKeyB64,
            );
          } finally {
            clean(masterKey);
          }
        },
      };
    },

    async addPasskeyToExistingDek(uid, userName) {
      if (!cryptoHandle) {
        throw new Error(
          "passkeyDekController.addPasskeyToExistingDek: no crypto handle currently unlocked — unlock first.",
        );
      }
      const { credentialId, prfOutput: prfFromCreate } =
        await provider.registerPasskeyWithPRF(userName);
      const prfOutput =
        prfFromCreate ?? (await provider.getPRFOutput(credentialId));

      const kek = provider.deriveKEKFromPRF(prfOutput);
      try {
        const wrapped = await cryptoHandle.wrapWithKek(kek);
        await storage.savePasskeyWrap(uid, credentialId, wrapped, 1);
        unlockMethod = "passkey";
        devicePublicKey = deriveDevicePublicKey(kek);
        notify();
        return { credentialId };
      } finally {
        clean(kek);
      }
    },

    async regenerateRecoveryWords(uid) {
      if (!cryptoHandle) {
        throw new Error(
          "passkeyDekController.regenerateRecoveryWords: no crypto handle currently unlocked — unlock first.",
        );
      }
      const recoveryWords = recovery.generateWords();
      const kekRecovery = recovery.deriveKEK(recoveryWords);
      try {
        const wrapped = await cryptoHandle.wrapWithKek(kekRecovery);
        return {
          recoveryWords,
          async confirm() {
            await storage.saveRecoveryWrap(uid, wrapped);
          },
        };
      } finally {
        clean(kekRecovery);
      }
    },

    async beginRotation(rawNewDekBytes) {
      if (!cryptoHandle) {
        throw new Error(
          "passkeyDekController.beginRotation: no crypto handle currently unlocked — unlock before rotating.",
        );
      }
      const newHandle = await createHandle(rawNewDekBytes);
      clean(rawNewDekBytes);
      // Destroy any handle left over from a previous, already-completed rotation
      // session before overwriting the reference — completeRotationSession()
      // should always have cleared this, but never leak a KeyHandle either way.
      if (previousCryptoHandle) previousCryptoHandle.destroy();
      previousCryptoHandle = cryptoHandle;
      cryptoHandle = newHandle;
      notify();
    },

    completeRotationSession() {
      if (previousCryptoHandle) {
        previousCryptoHandle.destroy();
        previousCryptoHandle = null;
        notify();
      }
    },

    async wrapCurrentDekForDevice(devicePublicKeyB64) {
      if (!cryptoHandle) {
        throw new Error(
          "passkeyDekController.wrapCurrentDekForDevice: no crypto handle currently unlocked — unlock first.",
        );
      }
      if (!cryptoHandle.wrapForDevice) {
        throw new Error(
          "passkeyDekController.wrapCurrentDekForDevice: current handle was not built with wrapForDevice support.",
        );
      }
      return cryptoHandle.wrapForDevice(devicePublicKeyB64);
    },

    async rewrapCurrentCredentialAtEpoch(newEpoch) {
      if (!cryptoHandle) {
        throw new Error(
          "passkeyDekController.rewrapCurrentCredentialAtEpoch: no crypto handle currently unlocked — unlock first.",
        );
      }
      if (!userId || !unlockCredentialId) {
        throw new Error(
          "passkeyDekController.rewrapCurrentCredentialAtEpoch: current session was not unlocked via passkey — no credential to re-wrap.",
        );
      }
      const prfOutput = await provider.getPRFOutput(unlockCredentialId);
      const kek = provider.deriveKEKFromPRF(prfOutput);
      try {
        const wrapped = await cryptoHandle.wrapWithKek(kek);
        await storage.savePasskeyWrap(
          userId,
          unlockCredentialId,
          wrapped,
          newEpoch,
        );
      } finally {
        clean(kek);
      }
    },

    async consumePendingDeviceWrap(wrapped, newEpoch) {
      if (!cryptoHandle) {
        throw new Error(
          "passkeyDekController.consumePendingDeviceWrap: no crypto handle currently unlocked — unlock first.",
        );
      }
      if (!userId || !unlockCredentialId) {
        throw new Error(
          "passkeyDekController.consumePendingDeviceWrap: current session was not unlocked via passkey — no credential to re-wrap.",
        );
      }
      const prfOutput = await provider.getPRFOutput(unlockCredentialId);
      const kek = provider.deriveKEKFromPRF(prfOutput);
      try {
        const newRawBytes = unwrapWithDeviceKey(kek, wrapped);
        const newHandle = await createHandle(asRawDekBytes(newRawBytes));
        clean(newRawBytes);
        try {
          // Persist BEFORE mutating any in-memory state — savePasskeyWrap is a
          // genuinely fallible I/O call (transient DB/network error). Mirrors
          // registerPasskey().confirm(), which also persists first and only
          // promotes (activate()) last. If this throws, nothing below has run
          // yet — cryptoHandle/previousCryptoHandle are byte-for-byte what they
          // were before this call, so a caller retrying the whole method sees a
          // clean, un-promoted session, never a double-promotion that would
          // clobber the true previousCryptoHandle with a duplicate of the
          // (already current) new DEK.
          const rewrapped = await newHandle.wrapWithKek(kek);
          await storage.savePasskeyWrap(
            userId,
            unlockCredentialId,
            rewrapped,
            newEpoch,
          );
        } catch (e) {
          // newHandle never got promoted — nothing else references it, so it
          // would otherwise be GC'd with its key material never explicitly
          // zeroed. Same key-hygiene discipline as every other handle this
          // file builds (see beginRotation/unlockWithPasskey).
          newHandle.destroy();
          throw e;
        }
        if (previousCryptoHandle) previousCryptoHandle.destroy();
        previousCryptoHandle = cryptoHandle;
        cryptoHandle = newHandle;
        notify();
      } finally {
        clean(kek);
      }
    },

    async persistForZeroTap(uid) {
      const cache = config.isolatedKeyCache;
      if (!cache || !cryptoHandle || !unlockCredentialId) return;
      let epoch: number;
      try {
        epoch = config.getCurrentEpoch ? await config.getCurrentEpoch(uid) : 1;
      } catch {
        // Offline: an entry with an epoch we couldn't read isn't validatable
        // on the next launch. No cache beats a blind one.
        return;
      }
      await cache.persist(uid, {
        dekEpoch: epoch,
        credentialId: unlockCredentialId,
      });
    },

    async tryZeroTapRestore(uid) {
      const cache = config.isolatedKeyCache;
      if (!cache) return false;
      const cached = await cache.restore(uid);
      if (!cached) return false;

      if (config.getCurrentEpoch) {
        try {
          if ((await config.getCurrentEpoch(uid)) !== cached.dekEpoch) {
            cached.handle.destroy();
            await cache.clear(uid);
            return false;
          }
        } catch {
          // Offline — fail open, same permissive philosophy as the rotation
          // handshake paths elsewhere in this file.
        }
      }

      adoptHandle(uid, cached.handle, "passkey", cached.credentialId);
      return true;
    },
  };
}
