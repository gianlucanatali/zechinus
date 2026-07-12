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
 * `datacloak/react/usePasskeyDek.ts` for the (thin) React binding.
 */
import { unwrapKey, wrapKey, type KeyHandle } from "../core/keyDerivation.ts";
import { asRawDekBytes, type RawDekBytes } from "../core/keyDerivation.ts";
import { clean, randomBytes } from "@noble/ciphers/utils.js";
import type { WebauthnKeyProvider } from "./webauthnKeyProvider.ts";
import type { MnemonicRecovery } from "./mnemonicRecovery.ts";

export type WrappedKeyRow = { ciphertext: string; nonce: string };

/**
 * Where wrapped keys are persisted. `many` passkeys per user (one row per
 * credential), exactly one recovery wrap per user — mirrors the real shape of any
 * app doing this (a user has N devices, one recovery phrase).
 */
export interface PasskeyWrapStorage {
  countPasskeyWraps(userId: string): Promise<number>;
  loadPasskeyWrap(
    userId: string,
    credentialId: string,
  ): Promise<WrappedKeyRow | null>;
  savePasskeyWrap(
    userId: string,
    credentialId: string,
    wrapped: WrappedKeyRow,
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

export interface PasskeyDekControllerConfig {
  provider: WebauthnKeyProvider;
  recovery: MnemonicRecovery;
  storage: PasskeyWrapStorage;
  /** Builds the real `KeyHandle` from freshly-unwrapped raw bytes — plain or Worker-isolated. */
  createHandle: (rawBytes: RawDekBytes) => Promise<KeyHandle> | KeyHandle;
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
  subscribe(callback: () => void): () => void;

  /** Activates a caller-supplied raw DEK directly — dev/test injection, or after a
   * ceremony that derived the bytes some other way. */
  setDek(userId: string, rawBytes: RawDekBytes): Promise<void>;
  /** Destroys the current handle (if any) and clears state. Idempotent. */
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
}

export function createPasskeyDekController(
  config: PasskeyDekControllerConfig,
): PasskeyDekController {
  const { provider, recovery, storage, createHandle } = config;

  let cryptoHandle: KeyHandle | null = null;
  let userId: string | null = null;
  let setupStatus: PasskeySetupStatus = "pending";
  let unlockMethod: UnlockMethod | null = null;
  let unlockCredentialId: string | null = null;
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
    userId = null;
    unlockMethod = null;
    unlockCredentialId = null;
  }

  async function activate(
    uid: string,
    rawBytes: RawDekBytes,
    method: UnlockMethod,
    credentialId: string | null = null,
  ): Promise<void> {
    const handle = await createHandle(rawBytes);
    clean(rawBytes);
    cryptoHandle = handle;
    userId = uid;
    setupStatus = "done";
    unlockMethod = method;
    unlockCredentialId = credentialId;
    notify();
  }

  return {
    getCryptoHandle: () => cryptoHandle,
    getUserId: () => userId,
    getSetupStatus: () => setupStatus,
    getUnlockMethod: () => unlockMethod,
    getUnlockCredentialId: () => unlockCredentialId,
    subscribe(callback) {
      listeners.add(callback);
      return () => listeners.delete(callback);
    },

    async setDek(uid, rawBytes) {
      await activate(uid, rawBytes, "passkey");
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

      const wrap = await storage.loadPasskeyWrap(uid, usedCredentialId);
      if (!wrap) {
        throw new Error(
          "passkeyDekController.unlockWithPasskey: no wrap found for this credential — complete setup first.",
        );
      }

      const kek = provider.deriveKEKFromPRF(prfOutput);
      try {
        const rawBytes = unwrapKey(kek, wrap);
        await activate(
          uid,
          asRawDekBytes(rawBytes),
          "passkey",
          usedCredentialId,
        );
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
      clean(kekPasskey);

      const recoveryWords = recovery.generateWords();
      const kekRecovery = recovery.deriveKEK(recoveryWords);
      const wrappedRecovery = wrapKey(kekRecovery, masterKey);
      clean(kekRecovery);

      return {
        recoveryWords,
        async confirm() {
          try {
            await storage.savePasskeyWrap(uid, credentialId, wrappedPasskey);
            await storage.saveRecoveryWrap(uid, wrappedRecovery);
            await activate(
              uid,
              asRawDekBytes(new Uint8Array(masterKey)),
              "passkey",
              credentialId,
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
        await storage.savePasskeyWrap(uid, credentialId, wrapped);
        unlockMethod = "passkey";
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
  };
}
