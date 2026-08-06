/**
 * React binding for `passkeyDekController` — a free function, not a class method, so
 * `adapters/controllers/passkeyDekController.ts` stays React-free (usable from Vue/Svelte/vanilla
 * JS via the same `subscribe`-based state shape). All the actual ceremony logic
 * (unlock, register, recovery, add-passkey) lives in the controller; this hook only
 * re-renders the calling component when the controller's state changes.
 */
import { useSyncExternalStore } from "react";
import type {
  PasskeyDekController,
  PasskeySetupStatus,
  PendingPasskeySetup,
  PendingRecoveryRegeneration,
  UnlockMethod,
} from "../adapters/controllers/passkeyDekController.ts";
import type { KeyHandle, RawDekBytes } from "../core/keyDerivation.ts";

export interface UsePasskeyDekResult {
  cryptoHandle: KeyHandle | null;
  userId: string | null;
  setupStatus: PasskeySetupStatus;
  unlockMethod: UnlockMethod | null;
  unlockCredentialId: string | null;
  devicePublicKey: string | null;
  checkSetupNeeded: (userId: string) => Promise<void>;
  markSetupDone: () => void;
  setDek: (userId: string, rawBytes: RawDekBytes) => Promise<void>;
  lock: () => void;
  unlockWithPasskey: (userId: string, credentialId?: string) => Promise<void>;
  unlockWithRecovery: (userId: string, words: string) => Promise<void>;
  registerPasskey: (
    userId: string,
    userName: string,
  ) => Promise<PendingPasskeySetup>;
  addPasskeyToExistingDek: (
    userId: string,
    userName: string,
  ) => Promise<{ credentialId: string }>;
  regenerateRecoveryWords: (
    userId: string,
  ) => Promise<PendingRecoveryRegeneration>;
}

export function usePasskeyDek(
  controller: PasskeyDekController,
): UsePasskeyDekResult {
  const cryptoHandle = useSyncExternalStore(
    controller.subscribe,
    controller.getCryptoHandle,
  );
  const userId = useSyncExternalStore(
    controller.subscribe,
    controller.getUserId,
  );
  const setupStatus = useSyncExternalStore(
    controller.subscribe,
    controller.getSetupStatus,
  );
  const unlockMethod = useSyncExternalStore(
    controller.subscribe,
    controller.getUnlockMethod,
  );
  const unlockCredentialId = useSyncExternalStore(
    controller.subscribe,
    controller.getUnlockCredentialId,
  );
  const devicePublicKey = useSyncExternalStore(
    controller.subscribe,
    controller.getDevicePublicKey,
  );

  return {
    cryptoHandle,
    userId,
    setupStatus,
    unlockMethod,
    unlockCredentialId,
    devicePublicKey,
    checkSetupNeeded: controller.checkSetupNeeded,
    markSetupDone: controller.markSetupDone,
    setDek: controller.setDek,
    lock: controller.lock,
    unlockWithPasskey: controller.unlockWithPasskey,
    unlockWithRecovery: controller.unlockWithRecovery,
    registerPasskey: controller.registerPasskey,
    addPasskeyToExistingDek: controller.addPasskeyToExistingDek,
    regenerateRecoveryWords: controller.regenerateRecoveryWords,
  };
}
